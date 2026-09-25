//! Cryptographic operations service
//!
//! Handles encrypt, decrypt, sign, verify operations with:
//! - Quota tracking
//! - Metrics recording
//! - Base64 encoding/decoding

use crate::rotation::OperationCounter;
use crate::{ApiError, KmsMetrics, KmsState, Result, quota::TenantQuotaTracker};
use kms_core::key::{Ciphertext, KeyMeta, Signature};
use kms_core::sanitize::sanitize_for_log;
use std::sync::Arc;
use uuid::Uuid;

use super::{IntoApiError, ServiceError};

/// Service for cryptographic operations
pub struct CryptoService {
    keystore: Arc<dyn kms_keystore::KeystoreBackend>,
    quota_tracker: Option<Arc<TenantQuotaTracker>>,
    op_counter: Option<Arc<dyn OperationCounter>>,
    metrics: Arc<KmsMetrics>,
}

impl CryptoService {
    /// Create a new CryptoService from shared state
    pub fn new(state: &KmsState) -> Self {
        Self {
            keystore: state.keystore.clone(),
            quota_tracker: state.quota_tracker.clone(),
            op_counter: state.op_counter.clone(),
            metrics: state.metrics.clone(),
        }
    }

    /// Fetch key metadata and confirm the key belongs to `tenant_id`.
    ///
    /// Returns `ApiError::KeyNotFound` for BOTH cases:
    /// - the key does not exist in the keystore
    /// - the key exists but is owned by another tenant
    ///
    /// The two cases are deliberately conflated so a probing client cannot
    /// distinguish "this key_id is not in the system" from "this key_id
    /// exists but you don't own it" — that distinction is a key-enumeration
    /// oracle. Performing the check before any cryptographic operation
    /// also prevents the keystore from spending HSM/TPM signing quotas on
    /// requests the caller is not authorised to make.
    async fn fetch_owned_key_meta(&self, key_id: &Uuid, tenant_id: &str) -> Result<KeyMeta> {
        let meta = self
            .keystore
            .get_key_metadata(key_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        if meta.tenant_id != tenant_id {
            // Possible enumeration attempt; record server-side but never
            // distinguish from a missing key in the API response.
            tracing::warn!(
                key_id = %key_id,
                requester_tenant = %sanitize_for_log(tenant_id),
                owner_tenant = %sanitize_for_log(&meta.tenant_id),
                "tenant mismatch on key access — possible enumeration attempt"
            );
            return Err(ApiError::KeyNotFound(key_id.to_string()));
        }

        Ok(meta)
    }

    /// Encrypt data
    pub async fn encrypt(
        &self,
        key_id: &uuid::Uuid,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Ciphertext> {
        // Check quota
        if let Some(ref tracker) = self.quota_tracker {
            let quota_ok = tracker.record_request(tenant_id).await;
            if let Err(quota_err) = quota_ok {
                tracing::warn!(
                    "Quota exceeded for tenant {}: {}",
                    sanitize_for_log(tenant_id),
                    quota_err
                );
                return Err(ApiError::QuotaExceeded {
                    resource: quota_err.resource,
                    current: quota_err.current,
                    limit: quota_err.limit,
                });
            }
        }

        // Verify the key exists and is owned by `tenant_id` before
        // spending any encryption quota on it.
        let meta = self.fetch_owned_key_meta(key_id, tenant_id).await?;

        // Encrypt
        let ciphertext = self
            .keystore
            .encrypt(key_id, plaintext, aad, tenant_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        // Record metrics (algorithm-aware; ownership already verified)
        self.metrics.record_key_op_with_spec("encrypt", &meta.spec);
        self.metrics.record_key_access(key_id);

        if let Some(ref counter) = self.op_counter {
            counter.increment(key_id).await;
        }

        tracing::debug!(
            "Key {} encrypted ({} bytes) by user {}",
            key_id,
            plaintext.len(),
            sanitize_for_log(user_id)
        );

        Ok(ciphertext)
    }

    /// Decrypt data
    pub async fn decrypt(
        &self,
        key_id: &uuid::Uuid,
        ciphertext: &Ciphertext,
        aad: Option<&[u8]>,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Vec<u8>> {
        // Check quota
        if let Some(ref tracker) = self.quota_tracker {
            let quota_ok = tracker.record_request(tenant_id).await;
            if let Err(quota_err) = quota_ok {
                tracing::warn!(
                    "Quota exceeded for tenant {}: {}",
                    sanitize_for_log(tenant_id),
                    quota_err
                );
                return Err(ApiError::QuotaExceeded {
                    resource: quota_err.resource,
                    current: quota_err.current,
                    limit: quota_err.limit,
                });
            }
        }

        // Verify the key exists and is owned by `tenant_id` before any
        // decryption work happens (and before any side-channel
        // distinguishing key existence from nonce absence).
        let meta = self.fetch_owned_key_meta(key_id, tenant_id).await?;

        // Decrypt
        let plaintext = self
            .keystore
            .decrypt(key_id, ciphertext, aad, tenant_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        // Record metrics (algorithm-aware; ownership already verified)
        self.metrics.record_key_op_with_spec("decrypt", &meta.spec);
        self.metrics.record_key_access(key_id);

        if let Some(ref counter) = self.op_counter {
            counter.increment(key_id).await;
        }

        tracing::debug!(
            "Key {} decrypted ({} bytes) by user {}",
            key_id,
            ciphertext.ciphertext.len(),
            sanitize_for_log(user_id)
        );

        Ok(plaintext)
    }

    /// Sign data
    pub async fn sign(
        &self,
        key_id: &uuid::Uuid,
        data: &[u8],
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Signature> {
        // Check quota
        if let Some(ref tracker) = self.quota_tracker {
            let quota_ok = tracker.record_request(tenant_id).await;
            if let Err(quota_err) = quota_ok {
                tracing::warn!(
                    "Quota exceeded for tenant {}: {}",
                    sanitize_for_log(tenant_id),
                    quota_err
                );
                return Err(ApiError::QuotaExceeded {
                    resource: quota_err.resource,
                    current: quota_err.current,
                    limit: quota_err.limit,
                });
            }
        }

        // Verify the key exists and is owned by `tenant_id` BEFORE
        // spending a remote HSM/TPM signing quota on it.
        let meta = self.fetch_owned_key_meta(key_id, tenant_id).await?;

        // Sign
        let signature = self
            .keystore
            .sign(key_id, data, tenant_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        // Record metrics (algorithm-aware; ownership already verified)
        self.metrics.record_key_op_with_spec("sign", &meta.spec);
        self.metrics.record_key_access(key_id);

        if let Some(ref counter) = self.op_counter {
            counter.increment(key_id).await;
        }

        tracing::debug!(
            "Key {} signed ({} bytes) by user {}",
            key_id,
            data.len(),
            sanitize_for_log(user_id)
        );

        Ok(signature)
    }

    /// Verify signature
    pub async fn verify(
        &self,
        key_id: &uuid::Uuid,
        data: &[u8],
        signature: &Signature,
        tenant_id: &str,
    ) -> Result<bool> {
        // Check quota
        if let Some(ref tracker) = self.quota_tracker {
            let quota_ok = tracker.record_request(tenant_id).await;
            if let Err(quota_err) = quota_ok {
                tracing::warn!(
                    "Quota exceeded for tenant {}: {}",
                    sanitize_for_log(tenant_id),
                    quota_err
                );
                return Err(ApiError::QuotaExceeded {
                    resource: quota_err.resource,
                    current: quota_err.current,
                    limit: quota_err.limit,
                });
            }
        }

        // Verify the key exists and is owned by `tenant_id` before any
        // verification work. Without this pre-check, a verification on
        // another tenant's key would leak its key_id via timing and via
        // the distinction between Forbidden and KeyNotFound.
        let meta = self.fetch_owned_key_meta(key_id, tenant_id).await?;

        // Verify
        let result = self
            .keystore
            .verify(key_id, data, signature, tenant_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        // Record metrics (algorithm-aware; ownership already verified)
        self.metrics.record_key_op_with_spec("verify", &meta.spec);
        self.metrics.record_key_access(key_id);

        if let Some(ref counter) = self.op_counter {
            counter.increment(key_id).await;
        }

        tracing::debug!(
            "Key {} verified by tenant {}",
            key_id,
            sanitize_for_log(tenant_id)
        );

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rotation::OperationCounter;
    use kms_core::key::KeySpec;
    use kms_keystore::{KeystoreBackend, SoftwareKeystore};
    use std::sync::Arc;

    use crate::test_utils::MockOperationCounter;

    fn build_test_service(
        keystore: Arc<dyn kms_keystore::KeystoreBackend>,
        op_counter: Option<Arc<dyn OperationCounter>>,
    ) -> CryptoService {
        CryptoService {
            keystore,
            quota_tracker: None,
            op_counter,
            metrics: Arc::new(KmsMetrics::new()),
        }
    }

    #[test]
    fn test_service_creation() {
        // Basic test to verify module structure
    }

    #[test]
    fn test_ciphertext_structure() {
        let ciphertext = kms_core::key::Ciphertext {
            key_id: uuid::Uuid::new_v4(),
            version: 1,
            format_version: 1,
            nonce: vec![0u8; 12],
            ciphertext: vec![1u8, 2, 3, 4],
            tag: vec![0u8; 16],
        };

        assert_eq!(ciphertext.version, 1);
        assert_eq!(ciphertext.format_version, 1);
        assert_eq!(ciphertext.nonce.len(), 12);
        assert_eq!(ciphertext.tag.len(), 16);
    }

    #[test]
    fn test_signature_structure() {
        let signature = kms_core::key::Signature {
            key_id: uuid::Uuid::new_v4(),
            version: 1,
            signature: vec![0u8; 64],
        };

        assert_eq!(signature.version, 1);
        assert_eq!(signature.signature.len(), 64);
    }

    // ── CryptoService + OperationCounter integration tests ──

    /// Encrypt through CryptoService increments per-key operation counter
    #[tokio::test]
    async fn test_encrypt_increments_op_counter() {
        let store = Arc::new(SoftwareKeystore::new());
        let counter = Arc::new(MockOperationCounter::new());
        let svc = build_test_service(store.clone(), Some(counter.clone()));

        let meta = store
            .generate_key(&KeySpec::Aes256Gcm, "ctr-enc", "test-tenant")
            .await
            .unwrap();
        let key_id = meta.id;

        assert_eq!(counter.get(&key_id), 0);

        svc.encrypt(&key_id, b"data", None, "test-tenant", "user1")
            .await
            .unwrap();
        assert_eq!(counter.get(&key_id), 1);

        svc.encrypt(&key_id, b"more data", None, "test-tenant", "user1")
            .await
            .unwrap();
        assert_eq!(counter.get(&key_id), 2);
    }

    /// Decrypt through CryptoService increments per-key operation counter
    #[tokio::test]
    async fn test_decrypt_increments_op_counter() {
        let store = Arc::new(SoftwareKeystore::new());
        let counter = Arc::new(MockOperationCounter::new());
        let svc = build_test_service(store.clone(), Some(counter.clone()));

        let meta = store
            .generate_key(&KeySpec::Aes256Gcm, "ctr-dec", "test-tenant")
            .await
            .unwrap();
        let key_id = meta.id;

        let ct = store
            .encrypt(&key_id, b"secret", None, "test-tenant")
            .await
            .unwrap();

        assert_eq!(counter.get(&key_id), 0);
        svc.decrypt(&key_id, &ct, None, "test-tenant", "user1")
            .await
            .unwrap();
        assert_eq!(counter.get(&key_id), 1);
    }

    /// Sign through CryptoService increments per-key operation counter
    #[tokio::test]
    async fn test_sign_increments_op_counter() {
        let store = Arc::new(SoftwareKeystore::new());
        let counter = Arc::new(MockOperationCounter::new());
        let svc = build_test_service(store.clone(), Some(counter.clone()));

        let meta = store
            .generate_key(&KeySpec::Ed25519, "ctr-sign", "test-tenant")
            .await
            .unwrap();
        let key_id = meta.id;

        assert_eq!(counter.get(&key_id), 0);
        svc.sign(&key_id, b"message", "test-tenant", "user1")
            .await
            .unwrap();
        assert_eq!(counter.get(&key_id), 1);
    }

    /// Verify through CryptoService increments per-key operation counter
    #[tokio::test]
    async fn test_verify_increments_op_counter() {
        let store = Arc::new(SoftwareKeystore::new());
        let counter = Arc::new(MockOperationCounter::new());
        let svc = build_test_service(store.clone(), Some(counter.clone()));

        let meta = store
            .generate_key(&KeySpec::Ed25519, "ctr-verify", "test-tenant")
            .await
            .unwrap();
        let key_id = meta.id;

        let sig = store.sign(&key_id, b"msg", "test-tenant").await.unwrap();

        assert_eq!(counter.get(&key_id), 0);
        svc.verify(&key_id, b"msg", &sig, "test-tenant")
            .await
            .unwrap();
        assert_eq!(counter.get(&key_id), 1);
    }

    /// Different key operations increment the same key's count
    #[tokio::test]
    async fn test_mixed_operations_increment_same_counter() {
        let store = Arc::new(SoftwareKeystore::new());
        let counter = Arc::new(MockOperationCounter::new());
        let svc = build_test_service(store.clone(), Some(counter.clone()));

        let meta = store
            .generate_key(&KeySpec::Aes256Gcm, "ctr-mixed", "test-tenant")
            .await
            .unwrap();
        let key_id = meta.id;

        let ct = svc
            .encrypt(&key_id, b"hello", None, "test-tenant", "user1")
            .await
            .unwrap();
        svc.decrypt(&key_id, &ct, None, "test-tenant", "user1")
            .await
            .unwrap();
        svc.encrypt(&key_id, b"world", None, "test-tenant", "user1")
            .await
            .unwrap();

        // encrypt + decrypt + encrypt = 3 operations on same key
        assert_eq!(counter.get(&key_id), 3);
    }

    /// Per-key isolation: operations on key A don't affect key B's count
    #[tokio::test]
    async fn test_crypto_service_per_key_isolation() {
        let store = Arc::new(SoftwareKeystore::new());
        let counter = Arc::new(MockOperationCounter::new());
        let svc = build_test_service(store.clone(), Some(counter.clone()));

        let meta_a = store
            .generate_key(&KeySpec::Aes256Gcm, "iso-a", "test-tenant")
            .await
            .unwrap();
        let meta_b = store
            .generate_key(&KeySpec::Aes256Gcm, "iso-b", "test-tenant")
            .await
            .unwrap();

        svc.encrypt(&meta_a.id, b"data a", None, "test-tenant", "user1")
            .await
            .unwrap();
        svc.encrypt(&meta_a.id, b"data a2", None, "test-tenant", "user1")
            .await
            .unwrap();
        svc.encrypt(&meta_b.id, b"data b", None, "test-tenant", "user1")
            .await
            .unwrap();

        assert_eq!(counter.get(&meta_a.id), 2);
        assert_eq!(counter.get(&meta_b.id), 1);
    }

    /// When op_counter is None, CryptoService operations do not panic
    #[tokio::test]
    async fn test_crypto_service_no_counter_does_not_panic() {
        let store = Arc::new(SoftwareKeystore::new());
        let svc = build_test_service(store.clone(), None); // no counter

        let meta = store
            .generate_key(&KeySpec::Aes256Gcm, "ctr-none", "test-tenant")
            .await
            .unwrap();
        let key_id = meta.id;

        // All operations should succeed without counter
        let ct = svc
            .encrypt(&key_id, b"data", None, "test-tenant", "user1")
            .await
            .unwrap();
        let pt = svc
            .decrypt(&key_id, &ct, None, "test-tenant", "user1")
            .await
            .unwrap();
        assert_eq!(pt, b"data");

        let meta_ed = store
            .generate_key(&KeySpec::Ed25519, "ctr-none-ed", "test-tenant")
            .await
            .unwrap();
        let sig = svc
            .sign(&meta_ed.id, b"msg", "test-tenant", "user1")
            .await
            .unwrap();
        let valid = svc
            .verify(&meta_ed.id, b"msg", &sig, "test-tenant")
            .await
            .unwrap();
        assert!(valid);
    }

    /// Operation count persists across key rotation (counter is per-key, not per-version)
    #[tokio::test]
    async fn test_op_counter_survives_rotation() {
        let store = Arc::new(SoftwareKeystore::new());
        let counter = Arc::new(MockOperationCounter::new());
        let svc = build_test_service(store.clone(), Some(counter.clone()));

        let meta = store
            .generate_key(&KeySpec::Aes256Gcm, "ctr-rot", "test-tenant")
            .await
            .unwrap();
        let key_id = meta.id;

        // Operations before rotation
        svc.encrypt(&key_id, b"pre-rot", None, "test-tenant", "user1")
            .await
            .unwrap();
        assert_eq!(counter.get(&key_id), 1);

        // Rotate the key
        store.rotate_key(&key_id, "test-tenant").await.unwrap();

        // More operations after rotation — same key_id, count continues
        svc.encrypt(&key_id, b"post-rot", None, "test-tenant", "user1")
            .await
            .unwrap();
        svc.encrypt(&key_id, b"post-rot2", None, "test-tenant", "user1")
            .await
            .unwrap();

        assert_eq!(counter.get(&key_id), 3);
    }

    // ── Tenant isolation regression tests ──

    /// Encrypt: key owned by tenant-A, request from tenant-B → rejected
    #[tokio::test]
    async fn test_tenant_isolation_encrypt_wrong_tenant_rejected() {
        let store = Arc::new(SoftwareKeystore::new());
        let svc = build_test_service(store.clone(), None);

        let meta = store
            .generate_key(&KeySpec::Aes256Gcm, "iso-enc", "tenant-a")
            .await
            .unwrap();
        let key_id = meta.id;

        // Encrypt with correct tenant — works
        let ct = svc
            .encrypt(&key_id, b"data", None, "tenant-a", "user1")
            .await
            .unwrap();

        // Decrypt with wrong tenant — rejected
        let result = svc.decrypt(&key_id, &ct, None, "tenant-b", "user1").await;
        assert!(result.is_err());
    }

    /// Encrypt: correct tenant works, wrong tenant rejected
    #[tokio::test]
    async fn test_tenant_isolation_encrypt_correct_tenant_succeeds() {
        let store = Arc::new(SoftwareKeystore::new());
        let svc = build_test_service(store.clone(), None);

        let meta = store
            .generate_key(&KeySpec::Aes256Gcm, "iso-ok", "tenant-x")
            .await
            .unwrap();
        let key_id = meta.id;

        // Encrypt with wrong tenant
        let result = svc
            .encrypt(&key_id, b"data", None, "tenant-y", "user1")
            .await;
        assert!(result.is_err());

        // Encrypt with correct tenant
        let ct = svc
            .encrypt(&key_id, b"data", None, "tenant-x", "user1")
            .await
            .unwrap();
        // And decrypt with correct tenant
        let pt = svc
            .decrypt(&key_id, &ct, None, "tenant-x", "user1")
            .await
            .unwrap();
        assert_eq!(pt, b"data");
    }

    /// Key operations (sign/verify) also enforce tenant isolation
    #[tokio::test]
    async fn test_tenant_isolation_sign_wrong_tenant_rejected() {
        let store = Arc::new(SoftwareKeystore::new());
        let svc = build_test_service(store.clone(), None);

        let meta = store
            .generate_key(&KeySpec::Ed25519, "iso-sign", "tenant-s")
            .await
            .unwrap();
        let key_id = meta.id;

        // Sign with correct tenant
        let sig = store.sign(&key_id, b"msg", "tenant-s").await.unwrap();

        // Verify with wrong tenant — rejected
        let result = svc.verify(&key_id, b"msg", &sig, "tenant-t").await;
        assert!(result.is_err());
    }

    // ── PR-1.2 tenant isolation + Kafka enumeration audit ──

    /// Helper: encrypt a plaintext under a tenant, return the ciphertext.
    async fn encrypt_under(
        store: &Arc<SoftwareKeystore>,
        key_id: &Uuid,
        tenant: &str,
    ) -> Ciphertext {
        store
            .encrypt(key_id, b"plaintext", None, tenant)
            .await
            .expect("encryption under owning tenant should succeed")
    }

    /// Sign with a tenant that does not own the key must return
    /// `KeyNotFound`, NOT `Forbidden`. The two are deliberately conflated
    /// to close the key-enumeration oracle.
    #[tokio::test]
    async fn test_pr12_sign_cross_tenant_returns_keynotfound() {
        let store = Arc::new(SoftwareKeystore::new());
        let svc = build_test_service(store.clone(), None);

        let meta = store
            .generate_key(&KeySpec::Ed25519, "p12-sign", "tenant-a")
            .await
            .unwrap();
        let key_id = meta.id;

        let result = svc.sign(&key_id, b"msg", "tenant-b", "user1").await;
        assert!(
            matches!(result, Err(ApiError::KeyNotFound(_))),
            "cross-tenant sign must return KeyNotFound, got {result:?}"
        );
    }

    /// Decrypt with a tenant that does not own the key must return
    /// `KeyNotFound`.
    #[tokio::test]
    async fn test_pr12_decrypt_cross_tenant_returns_keynotfound() {
        let store = Arc::new(SoftwareKeystore::new());
        let svc = build_test_service(store.clone(), None);

        let meta = store
            .generate_key(&KeySpec::Aes256Gcm, "p12-dec", "tenant-a")
            .await
            .unwrap();
        let key_id = meta.id;
        let ct = encrypt_under(&store, &key_id, "tenant-a").await;

        let result = svc.decrypt(&key_id, &ct, None, "tenant-b", "user1").await;
        assert!(
            matches!(result, Err(ApiError::KeyNotFound(_))),
            "cross-tenant decrypt must return KeyNotFound, got {result:?}"
        );
    }

    /// Encrypt with a tenant that does not own the key must return
    /// `KeyNotFound`.
    #[tokio::test]
    async fn test_pr12_encrypt_cross_tenant_returns_keynotfound() {
        let store = Arc::new(SoftwareKeystore::new());
        let svc = build_test_service(store.clone(), None);

        let meta = store
            .generate_key(&KeySpec::Aes256Gcm, "p12-enc", "tenant-a")
            .await
            .unwrap();
        let key_id = meta.id;

        let result = svc
            .encrypt(&key_id, b"data", None, "tenant-b", "user1")
            .await;
        assert!(
            matches!(result, Err(ApiError::KeyNotFound(_))),
            "cross-tenant encrypt must return KeyNotFound, got {result:?}"
        );
    }

    /// Verify with a tenant that does not own the key must return
    /// `KeyNotFound`.
    #[tokio::test]
    async fn test_pr12_verify_cross_tenant_returns_keynotfound() {
        let store = Arc::new(SoftwareKeystore::new());
        let svc = build_test_service(store.clone(), None);

        let meta = store
            .generate_key(&KeySpec::Ed25519, "p12-verify", "tenant-a")
            .await
            .unwrap();
        let key_id = meta.id;
        let sig = store.sign(&key_id, b"msg", "tenant-a").await.unwrap();

        let result = svc.verify(&key_id, b"msg", &sig, "tenant-b").await;
        assert!(
            matches!(result, Err(ApiError::KeyNotFound(_))),
            "cross-tenant verify must return KeyNotFound, got {result:?}"
        );
    }

    /// Sign with a fully non-existent key_id must also return
    /// `KeyNotFound` — same shape as the cross-tenant case.
    #[tokio::test]
    async fn test_pr12_sign_nonexistent_key_returns_keynotfound() {
        let store = Arc::new(SoftwareKeystore::new());
        let svc = build_test_service(store.clone(), None);

        let bogus = Uuid::new_v4();
        let result = svc.sign(&bogus, b"msg", "tenant-a", "user1").await;
        assert!(
            matches!(result, Err(ApiError::KeyNotFound(_))),
            "non-existent key must return KeyNotFound, got {result:?}"
        );
    }

    /// Cross-tenant and non-existent-key responses must produce byte-
    /// identical `IntoResponse` output: same HTTP status, same body.
    /// This is the core anti-enumeration assertion.
    #[tokio::test]
    async fn test_pr12_cross_tenant_and_nonexistent_have_identical_responses() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        // Set up: tenant-a owns a key; tenant-b is the attacker.
        let store = Arc::new(SoftwareKeystore::new());
        let svc = build_test_service(store.clone(), None);

        let meta = store
            .generate_key(&KeySpec::Aes256Gcm, "p12-idem", "tenant-a")
            .await
            .unwrap();
        let key_id = meta.id;
        let ct = encrypt_under(&store, &key_id, "tenant-a").await;

        // Response 1: tenant-b decrypts a key owned by tenant-a (cross-tenant).
        let resp1 = svc
            .decrypt(&key_id, &ct, None, "tenant-b", "user1")
            .await
            .expect_err("cross-tenant decrypt must error")
            .into_response();
        let status1 = resp1.status();
        let body1 = to_bytes(resp1.into_body(), 1024).await.unwrap();

        // Response 2: tenant-a decrypts with a fully bogus key_id (non-existent).
        let bogus = Uuid::new_v4();
        let resp2 = svc
            .decrypt(&bogus, &ct, None, "tenant-a", "user1")
            .await
            .expect_err("non-existent key decrypt must error")
            .into_response();
        let status2 = resp2.status();
        let body2 = to_bytes(resp2.into_body(), 1024).await.unwrap();

        // Must be indistinguishable to the client.
        assert_eq!(status1, status2, "HTTP status must match");
        assert_eq!(
            body1, body2,
            "response body must match byte-for-byte to prevent enumeration"
        );
        assert_eq!(
            status1.as_u16(),
            404,
            "both responses must surface as HTTP 404 (NOT 403)"
        );
    }

    /// The pre-check must reject a cross-tenant request BEFORE the keystore
    /// spends the signing computation. We verify by wrapping the keystore
    /// in a counter that fails `sign` calls; if the pre-check is working,
    /// the cross-tenant request returns `KeyNotFound` (not the sign-fault
    /// error), and the counter shows zero `sign` calls.
    #[tokio::test]
    async fn test_pr12_sign_does_not_call_keystore_on_tenant_mismatch() {
        use async_trait::async_trait;
        use kms_core::BackendType;
        use kms_core::key::{Ciphertext, KeyFilter, KeyMeta, Signature};
        use kms_keystore::KeystoreBackend;

        struct SignCountingKeystore {
            inner: Arc<SoftwareKeystore>,
            sign_calls: Arc<std::sync::atomic::AtomicUsize>,
        }

        #[async_trait]
        impl KeystoreBackend for SignCountingKeystore {
            fn backend_type(&self) -> BackendType {
                self.inner.backend_type()
            }
            async fn generate_key(
                &self,
                spec: &KeySpec,
                name: &str,
                tenant_id: &str,
            ) -> kms_core::Result<KeyMeta> {
                self.inner.generate_key(spec, name, tenant_id).await
            }
            async fn get_key_metadata(&self, key_id: &Uuid) -> kms_core::Result<KeyMeta> {
                self.inner.get_key_metadata(key_id).await
            }
            async fn encrypt(
                &self,
                key_id: &Uuid,
                plaintext: &[u8],
                aad: Option<&[u8]>,
                tenant_id: &str,
            ) -> kms_core::Result<Ciphertext> {
                self.inner.encrypt(key_id, plaintext, aad, tenant_id).await
            }
            async fn decrypt(
                &self,
                key_id: &Uuid,
                ct: &Ciphertext,
                aad: Option<&[u8]>,
                tenant_id: &str,
            ) -> kms_core::Result<Vec<u8>> {
                self.inner.decrypt(key_id, ct, aad, tenant_id).await
            }
            async fn sign(
                &self,
                _key_id: &Uuid,
                _data: &[u8],
                _tenant_id: &str,
            ) -> kms_core::Result<Signature> {
                self.sign_calls
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err(kms_core::Error::Internal("sign disabled for test".into()))
            }
            async fn verify(
                &self,
                key_id: &Uuid,
                data: &[u8],
                sig: &Signature,
                tenant_id: &str,
            ) -> kms_core::Result<bool> {
                self.inner.verify(key_id, data, sig, tenant_id).await
            }
            async fn rotate_key(
                &self,
                key_id: &Uuid,
                tenant_id: &str,
            ) -> kms_core::Result<KeyMeta> {
                self.inner.rotate_key(key_id, tenant_id).await
            }
            async fn delete_key(&self, key_id: &Uuid, tenant_id: &str) -> kms_core::Result<()> {
                self.inner.delete_key(key_id, tenant_id).await
            }
            async fn destroy_key(&self, key_id: &Uuid) -> kms_core::Result<()> {
                self.inner.destroy_key(key_id).await
            }
            async fn destroy_key_with_proof(
                &self,
                key_id: &Uuid,
            ) -> kms_core::Result<kms_core::DestructionProof> {
                self.inner.destroy_key_with_proof(key_id).await
            }
            async fn list_keys(&self, filter: &KeyFilter) -> kms_core::Result<Vec<KeyMeta>> {
                self.inner.list_keys(filter).await
            }
            async fn export_key_material(
                &self,
                key_id: &Uuid,
                _tenant_id: &str,
            ) -> kms_core::Result<Vec<u8>> {
                self.inner.export_key_material(key_id, _tenant_id).await
            }
            async fn get_key_material(
                &self,
                key_id: &Uuid,
                tenant_id: &str,
            ) -> kms_core::Result<Vec<u8>> {
                self.inner.get_key_material(key_id, tenant_id).await
            }
            async fn get_key_material_version(
                &self,
                key_id: &Uuid,
                version: u32,
                tenant_id: &str,
            ) -> kms_core::Result<Vec<u8>> {
                self.inner
                    .get_key_material_version(key_id, version, tenant_id)
                    .await
            }
            async fn health(&self) -> kms_core::Result<kms_core::HealthStatus> {
                self.inner.health().await
            }
            async fn import_key_material(
                &self,
                spec: &KeySpec,
                name: &str,
                tenant_id: &str,
                material: Vec<u8>,
            ) -> kms_core::Result<KeyMeta> {
                self.inner
                    .import_key_material(spec, name, tenant_id, material)
                    .await
            }
            async fn derive_shared_secret(
                &self,
                key_id: &Uuid,
                peer_public_key: &[u8],
                algorithm: kms_core::dh::DhAlgorithm,
            ) -> kms_core::Result<kms_core::dh::SharedSecret> {
                self.inner
                    .derive_shared_secret(key_id, peer_public_key, algorithm)
                    .await
            }
        }

        let store = Arc::new(SoftwareKeystore::new());
        let meta = store
            .generate_key(&KeySpec::Ed25519, "p12-pre", "tenant-a")
            .await
            .unwrap();
        let key_id = meta.id;
        let sign_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let counting: Arc<dyn KeystoreBackend> = Arc::new(SignCountingKeystore {
            inner: store,
            sign_calls: sign_calls.clone(),
        });
        let svc = build_test_service(counting, None);

        // Cross-tenant attempt: pre-check rejects; `sign` must NOT be called.
        let result = svc.sign(&key_id, b"msg", "tenant-b", "user1").await;
        assert!(
            matches!(result, Err(ApiError::KeyNotFound(_))),
            "cross-tenant sign must return KeyNotFound without invoking keystore, got {result:?}"
        );
        assert_eq!(
            sign_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "keystore.sign must NOT be called on cross-tenant access (was 0)"
        );

        // Correct-tenant attempt: pre-check passes, then keystore.sign is
        // invoked and fails with our injected "sign disabled" error.
        let result2 = svc.sign(&key_id, b"msg", "tenant-a", "user1").await;
        assert!(
            result2.is_err(),
            "correct-tenant sign must fail (sign disabled), got {result2:?}"
        );
        assert_eq!(
            sign_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "keystore.sign must be called exactly once for the correct-tenant attempt"
        );
        assert!(
            !matches!(result2, Err(ApiError::KeyNotFound(_))),
            "correct-tenant attempt must NOT be conflated with cross-tenant; \
             must surface the underlying sign-disabled error"
        );
    }
}
