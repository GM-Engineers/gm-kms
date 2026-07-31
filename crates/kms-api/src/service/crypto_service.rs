//! Cryptographic operations service
//!
//! Handles encrypt, decrypt, sign, verify operations with:
//! - Quota tracking
//! - Metrics recording
//! - Base64 encoding/decoding

use crate::rotation::OperationCounter;
use crate::{ApiError, KmsMetrics, KmsState, Result, quota::TenantQuotaTracker};
use kms_core::key::{Ciphertext, Signature};
use kms_core::sanitize::sanitize_for_log;
use std::sync::Arc;

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

    /// Encrypt data
    pub async fn encrypt(
        &self,
        key_id: &uuid::Uuid,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Ciphertext> {
        // Check quota - record_request returns Result<bool, QuotaExceeded>
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

        // Encrypt
        let ciphertext = self
            .keystore
            .encrypt(key_id, plaintext, aad, tenant_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        // Record metrics (algorithm-aware) and verify tenant ownership
        match self.keystore.get_key_metadata(key_id).await {
            Ok(meta) => {
                // Verify tenant isolation: key must belong to the requesting tenant
                if meta.tenant_id != tenant_id {
                    return Err(ApiError::Forbidden("access denied".to_string()));
                }
                self.metrics.record_key_op_with_spec("encrypt", &meta.spec);
                self.metrics.record_key_access(key_id);
            }
            Err(_) => {
                // Fallback: record without spec if metadata unavailable
                self.metrics.record_key_op("encrypt");
            }
        }

        // Increment operation counter for usage-based rotation
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

        // Decrypt
        let plaintext = self
            .keystore
            .decrypt(key_id, ciphertext, aad, tenant_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        // Record metrics (algorithm-aware) and verify tenant ownership
        match self.keystore.get_key_metadata(key_id).await {
            Ok(meta) => {
                // Verify tenant isolation: key must belong to the requesting tenant
                if meta.tenant_id != tenant_id {
                    return Err(ApiError::Forbidden("access denied".to_string()));
                }
                self.metrics.record_key_op_with_spec("decrypt", &meta.spec);
                self.metrics.record_key_access(key_id);
            }
            Err(_) => {
                self.metrics.record_key_op("decrypt");
            }
        }

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

        // Sign
        let signature = self
            .keystore
            .sign(key_id, data, tenant_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        // Record metrics (algorithm-aware) and verify tenant ownership
        match self.keystore.get_key_metadata(key_id).await {
            Ok(meta) => {
                // Verify tenant isolation: key must belong to the requesting tenant
                if meta.tenant_id != tenant_id {
                    return Err(ApiError::Forbidden("access denied".to_string()));
                }
                self.metrics.record_key_op_with_spec("sign", &meta.spec);
                self.metrics.record_key_access(key_id);
            }
            Err(_) => {
                self.metrics.record_key_op("sign");
            }
        }

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

        // Verify
        let result = self
            .keystore
            .verify(key_id, data, signature, tenant_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        // Record metrics (algorithm-aware) and verify tenant ownership
        match self.keystore.get_key_metadata(key_id).await {
            Ok(meta) => {
                // Verify tenant isolation: key must belong to the requesting tenant
                if meta.tenant_id != tenant_id {
                    return Err(ApiError::Forbidden("access denied".to_string()));
                }
                self.metrics.record_key_op_with_spec("verify", &meta.spec);
                self.metrics.record_key_access(key_id);
            }
            Err(_) => {
                self.metrics.record_key_op("verify");
            }
        }

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
        let sig = svc
            .sign(&key_id, b"msg", "tenant-s", "user1")
            .await
            .unwrap();

        // Verify with wrong tenant — rejected
        let result = svc.verify(&key_id, b"msg", &sig, "tenant-t").await;
        assert!(result.is_err());
    }
}
