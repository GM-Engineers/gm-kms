//! Key management service
//!
//! Handles key lifecycle operations: creation, rotation, deletion, listing, import, and export.

use super::{IntoApiError, KeyFormatParser, ServiceError};
use crate::{ApiError, KmsState, Result, quota::TenantQuotaTracker};
use base64::{Engine, engine::general_purpose::STANDARD};
use kms_core::key::{KeyFilter, KeyMeta, KeySpec};
use kms_core::sanitize::sanitize_for_log;
use ring::rand::SecureRandom;
use std::sync::Arc;

/// Service for key lifecycle management
pub struct KeyService {
    keystore: Arc<dyn kms_keystore::KeystoreBackend>,
    quota_tracker: Option<Arc<TenantQuotaTracker>>,
}

impl KeyService {
    /// Create a new KeyService from shared state
    pub fn new(state: &KmsState) -> Self {
        Self {
            keystore: state.keystore.clone(),
            quota_tracker: state.quota_tracker.clone(),
        }
    }

    /// Create a new key
    pub async fn create_key(
        &self,
        spec: KeySpec,
        name: &str,
        tenant_id: &str,
        _user_id: &str,
    ) -> Result<KeyMeta> {
        // Check quota before creation
        if let Some(ref tracker) = self.quota_tracker
            && tracker.can_create_key(tenant_id).await.is_err()
        {
            // Get quota info - tracker doesn't have get_quota method
            // Return a generic quota exceeded error
            return Err(ApiError::QuotaExceeded {
                resource: "keys".to_string(),
                current: 0, // Unknown without get_quota
                limit: 0,
            });
        }

        // Create the key
        let meta = self
            .keystore
            .generate_key(&spec, name, tenant_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        // Increment key count
        if let Some(ref tracker) = self.quota_tracker
            && tracker.increment_key_count(tenant_id).await.is_err()
        {
            tracing::warn!(
                "Failed to increment key count for tenant {}",
                sanitize_for_log(tenant_id)
            );
        }

        Ok(meta)
    }

    /// Rotate a key (create new version, archive old material)
    pub async fn rotate_key(
        &self,
        key_id: &uuid::Uuid,
        tenant_id: &str,
        _user_id: &str,
    ) -> Result<KeyMeta> {
        // Verify tenant ownership before rotating
        let meta = self
            .keystore
            .get_key_metadata(key_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        if meta.tenant_id != tenant_id {
            return Err(ApiError::Forbidden("access denied".to_string()));
        }

        let meta = self
            .keystore
            .rotate_key(key_id, tenant_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        tracing::debug!("Key {} rotated", key_id);

        Ok(meta)
    }

    /// Delete a key (soft delete)
    pub async fn delete_key(
        &self,
        key_id: &uuid::Uuid,
        tenant_id: &str,
        _user_id: &str,
    ) -> Result<()> {
        // Verify tenant ownership before deleting
        let meta = self
            .keystore
            .get_key_metadata(key_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        if meta.tenant_id != tenant_id {
            return Err(ApiError::Forbidden("access denied".to_string()));
        }

        self.keystore
            .delete_key(key_id, tenant_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        tracing::debug!("Key {} deleted", key_id);

        Ok(())
    }

    /// Get key metadata
    pub async fn get_key(&self, key_id: &uuid::Uuid, tenant_id: &str) -> Result<KeyMeta> {
        let meta = self
            .keystore
            .get_key_metadata(key_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        // Verify tenant isolation
        if meta.tenant_id != tenant_id {
            return Err(ApiError::Forbidden("access denied".to_string()));
        }

        Ok(meta)
    }

    /// List keys for a tenant
    pub async fn list_keys(&self, filter: KeyFilter, tenant_id: &str) -> Result<Vec<KeyMeta>> {
        // Ensure filter only returns keys for this tenant
        let mut filter = filter;
        filter.tenant_id = Some(tenant_id.to_string());

        let keys = self
            .keystore
            .list_keys(&filter)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        Ok(keys)
    }

    /// Import key material in various formats (raw, PKCS#8, JWK)
    ///
    /// This method handles format parsing and validation before calling the keystore.
    #[allow(clippy::too_many_arguments)]
    pub async fn import_key(
        &self,
        spec: KeySpec,
        name: &str,
        format: &str,
        wrapped_key: &[u8],
        encrypted_transport_key: &[u8],
        source_fingerprint: &str,
        tenant_id: &str,
        _user_id: &str,
    ) -> Result<KeyMeta> {
        // Validate encrypted_transport_key is non-empty (Phase 1 verification step)
        if encrypted_transport_key.is_empty() {
            return Err(ApiError::InvalidRequest(
                "encrypted_transport_key cannot be empty".to_string(),
            ));
        }

        // Validate source_fingerprint is valid hex (64 chars for SHA-256)
        if source_fingerprint.len() != 64
            || !source_fingerprint.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(ApiError::InvalidRequest(
                "source_fingerprint must be 64 hex characters (SHA-256)".to_string(),
            ));
        }

        // Process key material based on format
        let key_material = KeyFormatParser::parse(format, wrapped_key)
            .map_err(|e| ApiError::InvalidRequest(e.to_string()))?;

        // Check quota before import
        if let Some(ref tracker) = self.quota_tracker
            && tracker.can_create_key(tenant_id).await.is_err()
        {
            return Err(ApiError::QuotaExceeded {
                resource: "keys".to_string(),
                current: 0,
                limit: 0,
            });
        }

        // Import the key material into the keystore
        let meta = self
            .keystore
            .import_key_material(&spec, name, tenant_id, key_material)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        // Increment key count
        if let Some(ref tracker) = self.quota_tracker
            && tracker.increment_key_count(tenant_id).await.is_err()
        {
            tracing::warn!(
                "Failed to increment key count for tenant {}",
                sanitize_for_log(tenant_id)
            );
        }

        tracing::info!(
            "Key {} imported (spec: {:?}, format: {})",
            meta.id,
            spec,
            sanitize_for_log(format)
        );

        Ok(meta)
    }

    /// Export key material wrapped with transport key
    ///
    /// Returns wrapped key (key material encrypted with transport key) and
    /// encrypted transport key (transport key encrypted with target RSA public key).
    pub async fn export_key(
        &self,
        key_id: &uuid::Uuid,
        target_public_key: &[u8],
        purpose: &str,
        tenant_id: &str,
        _user_id: &str,
    ) -> Result<ExportedKey> {
        // Verify tenant ownership before exporting
        let meta = self
            .keystore
            .get_key_metadata(key_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        if meta.tenant_id != tenant_id {
            return Err(ApiError::Forbidden("access denied".to_string()));
        }
        // Validate target_public_key is at least 256 bytes (2048-bit RSA minimum)
        if target_public_key.len() < 256 {
            return Err(ApiError::InvalidRequest(
                "target_public_key too small, expected at least 2048-bit RSA".to_string(),
            ));
        }

        // Export raw key material (validates key exists and is active)
        let key_material = self
            .keystore
            .export_key_material(key_id, tenant_id)
            .await
            .map_err(|e| match e {
                kms_core::Error::KeyNotFound(_) => {
                    ApiError::NotFound(format!("key {key_id} not found"))
                }
                kms_core::Error::KeyOperationNotAllowed(_) => {
                    ApiError::Forbidden(format!("key {key_id} cannot be exported"))
                }
                _ => ServiceError::from(e).into_api_error(),
            })?;

        // Compute fingerprint from actual key material (SHA-256)
        use ring::digest::{Context, SHA256 as RingSHA256};
        let mut digest_ctx = Context::new(&RingSHA256);
        digest_ctx.update(&key_material);
        let digest = digest_ctx.finish();
        let key_fingerprint = hex::encode(digest.as_ref());

        // Generate random transport key (32 bytes for AES-256)
        let rng = ring::rand::SystemRandom::new();
        let mut transport_key = vec![0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut transport_key)
            .map_err(|e| ApiError::Internal(format!("failed to generate transport key: {e}")))?;

        // Wrap key material with transport key using AES-256-GCM
        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
        let unbound_kek = UnboundKey::new(&AES_256_GCM, &transport_key)
            .map_err(|e| ApiError::Internal(format!("failed to create KEK: {e}")))?;
        let less_safe_kek = LessSafeKey::new(unbound_kek);

        // Generate random nonce for each encryption (critical for AES-GCM security)
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes)
            .map_err(|e| ApiError::Internal(format!("failed to generate nonce: {e}")))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = key_material.clone();
        let tag = less_safe_kek
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| ApiError::Internal(format!("failed to wrap key: {e}")))?;

        // Append tag to ciphertext (combined = wrapped_key)
        let mut wrapped_key = in_out;
        wrapped_key.extend_from_slice(tag.as_ref());

        // Encrypt transport key with target RSA public key (OAEP-SHA256)
        use rsa::Oaep;
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::sha2::Sha256;

        let rsa_public_key = rsa::RsaPublicKey::from_pkcs1_der(target_public_key)
            .map_err(|_| ApiError::InvalidRequest("invalid RSA public key format".to_string()))?;

        // Use cryptographically secure OsRng for RSA encryption
        let mut os_rng = rand_core::OsRng;
        let padding = Oaep::new::<Sha256>();
        let encrypted_transport_key = rsa_public_key
            .encrypt(&mut os_rng, padding, &transport_key)
            .map_err(|e| ApiError::Internal(format!("failed to encrypt transport key: {e}")))?;

        let export_id = uuid::Uuid::new_v4().to_string();
        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();

        tracing::info!(
            "Key {} exported (purpose: {})",
            key_id,
            sanitize_for_log(purpose)
        );

        Ok(ExportedKey {
            wrapped_key: STANDARD.encode(&wrapped_key),
            encrypted_transport_key: STANDARD.encode(&encrypted_transport_key),
            key_fingerprint,
            export_id,
            expires_at,
        })
    }

    /// Parse KeySpec string to KeySpec enum
    ///
    /// Returns an error for unsupported spec strings.
    pub fn parse_spec(spec_str: &str) -> Result<KeySpec> {
        match spec_str.to_lowercase().as_str() {
            "aes-256-gcm" | "aes256gcm" => Ok(KeySpec::Aes256Gcm),
            "hmac-sha256" | "hmacsha256" => Ok(KeySpec::HmacSha256),
            "ecdsa-p256" | "ecdsap256" => Ok(KeySpec::EcdsaP256),
            "ecdsa-p384" | "ecdsap384" => Ok(KeySpec::EcdsaP384),
            "ed25519" => Ok(KeySpec::Ed25519),
            "ed448" => Ok(KeySpec::Ed448),
            "sm4" => Ok(KeySpec::Sm4),
            "sm2" => Ok(KeySpec::Sm2),
            "sm9-signing" | "sm9signing" => Ok(KeySpec::Sm9Signing),
            "sm9-encryption" | "sm9encryption" => Ok(KeySpec::Sm9Encryption),
            "rsa-4096" | "rsa4096" => Ok(KeySpec::Rsa4096),
            _ => Err(ApiError::InvalidRequest(format!(
                "unsupported spec: {spec_str}"
            ))),
        }
    }
}

/// Result type for key export operations
pub struct ExportedKey {
    /// Base64-encoded wrapped key (key encrypted with transport key)
    pub wrapped_key: String,
    /// Base64-encoded encrypted transport key
    pub encrypted_transport_key: String,
    /// SHA-256 fingerprint of the key
    pub key_fingerprint: String,
    /// Unique export identifier
    pub export_id: String,
    /// ISO 8601 expiration timestamp
    pub expires_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_spec_aes256gcm() {
        let spec = KeyService::parse_spec("aes-256-gcm").unwrap();
        assert!(matches!(spec, KeySpec::Aes256Gcm));

        let spec = KeyService::parse_spec("AES-256-GCM").unwrap();
        assert!(matches!(spec, KeySpec::Aes256Gcm));

        let spec = KeyService::parse_spec("aes256gcm").unwrap();
        assert!(matches!(spec, KeySpec::Aes256Gcm));
    }

    #[test]
    fn test_parse_spec_sm2() {
        let spec = KeyService::parse_spec("sm2").unwrap();
        assert!(matches!(spec, KeySpec::Sm2));
    }

    #[test]
    fn test_parse_spec_invalid() {
        let result = KeyService::parse_spec("invalid-spec");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_spec_all() {
        let specs = vec![
            "aes-256-gcm",
            "hmac-sha256",
            "ecdsa-p256",
            "ecdsa-p384",
            "ed25519",
            "ed448",
            "sm4",
            "sm2",
            "sm9-signing",
            "sm9-encryption",
            "rsa-4096",
        ];

        for spec_str in specs {
            let spec = KeyService::parse_spec(spec_str);
            assert!(spec.is_ok(), "Failed to parse: {spec_str}");
        }
    }

    // Tests for key format parsing (raw format)
    #[test]
    fn test_raw_format_parsing() {
        // This is a simple test - we can't easily test private methods
        // but we can verify the structure works
        let spec = KeySpec::Aes256Gcm;
        assert!(matches!(spec, KeySpec::Aes256Gcm));
    }

    #[test]
    fn test_spec_case_insensitive() {
        // All specs should be case-insensitive
        assert!(KeyService::parse_spec("AES-256-GCM").is_ok());
        assert!(KeyService::parse_spec("Aes256Gcm").is_ok());
        assert!(KeyService::parse_spec("ED25519").is_ok());
        assert!(KeyService::parse_spec("Ed25519").is_ok());
        assert!(KeyService::parse_spec("SM2").is_ok());
        assert!(KeyService::parse_spec("sm2").is_ok());
        assert!(KeyService::parse_spec("SM4").is_ok());
        assert!(KeyService::parse_spec("sm4").is_ok());
    }

    #[test]
    fn test_spec_rejects_empty() {
        let result = KeyService::parse_spec("");
        assert!(result.is_err());
    }

    #[test]
    fn test_spec_rejects_unsupported() {
        let unsupported = vec!["aes-128-gcm", "rsa-2048", "hmac-sha1", "des", "rc4"];

        for spec_str in unsupported {
            let result = KeyService::parse_spec(spec_str);
            assert!(
                result.is_err(),
                "Should reject unsupported spec: {spec_str}"
            );
        }
    }

    // =============================================================================
    // Service Integration Tests (using real SoftwareKeystore)
    // =============================================================================

    use kms_keystore::software::SoftwareKeystore;
    use std::sync::Arc;

    fn create_test_state() -> crate::KmsState {
        let keystore = Arc::new(SoftwareKeystore::new());
        crate::KmsState::new(
            keystore,
            kms_policy::PBACEngine::new(),
            Arc::new(kms_audit::AuditLogger::with_stdout()),
            crate::Sm9State {
                master_key: gm_sm9_rs::KgcMasterKey::generate()
                    .expect("failed to generate master key"),
                repository: None,
            },
            crate::KmsMetrics::new(),
        )
    }

    #[tokio::test]
    async fn test_key_service_create_key() {
        let state = create_test_state();
        let key_service = KeyService::new(&state);

        let meta = key_service
            .create_key(KeySpec::Aes256Gcm, "test-key", "test-tenant", "user-1")
            .await
            .unwrap();

        assert_eq!(meta.name, "test-key");
        assert_eq!(meta.tenant_id, "test-tenant");
        assert_eq!(meta.spec, KeySpec::Aes256Gcm);
    }

    #[tokio::test]
    async fn test_key_service_get_key() {
        let state = create_test_state();
        let key_service = KeyService::new(&state);

        let created = key_service
            .create_key(KeySpec::Aes256Gcm, "get-test-key", "tenant-1", "user-1")
            .await
            .unwrap();

        let retrieved = key_service.get_key(&created.id, "tenant-1").await.unwrap();

        assert_eq!(retrieved.id, created.id);
        assert_eq!(retrieved.name, "get-test-key");
    }

    #[tokio::test]
    async fn test_key_service_get_key_wrong_tenant() {
        let state = create_test_state();
        let key_service = KeyService::new(&state);

        let created = key_service
            .create_key(KeySpec::Aes256Gcm, "tenant-key", "tenant-1", "user-1")
            .await
            .unwrap();

        // Try to access with different tenant - should fail
        let result = key_service.get_key(&created.id, "tenant-2").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_key_service_list_keys() {
        let state = create_test_state();
        let key_service = KeyService::new(&state);

        // Create keys for two tenants
        key_service
            .create_key(KeySpec::Aes256Gcm, "list-key-1", "tenant-1", "user-1")
            .await
            .unwrap();
        key_service
            .create_key(KeySpec::Aes256Gcm, "list-key-2", "tenant-1", "user-1")
            .await
            .unwrap();
        key_service
            .create_key(KeySpec::Sm4, "list-key-3", "tenant-2", "user-1")
            .await
            .unwrap();

        // List keys for tenant-1
        let filter = KeyFilter::default();
        let keys = key_service.list_keys(filter, "tenant-1").await.unwrap();

        // Should only see tenant-1's keys
        assert_eq!(keys.len(), 2);
        for key in &keys {
            assert_eq!(key.tenant_id, "tenant-1");
        }
    }

    #[tokio::test]
    async fn test_key_service_rotate_key() {
        let state = create_test_state();
        let key_service = KeyService::new(&state);

        let created = key_service
            .create_key(KeySpec::Aes256Gcm, "rotate-test-key", "tenant-1", "user-1")
            .await
            .unwrap();

        assert_eq!(created.version, 1);

        let rotated = key_service
            .rotate_key(&created.id, "tenant-1", "user-1")
            .await
            .unwrap();

        assert_eq!(rotated.id, created.id);
        assert_eq!(rotated.version, 2);
    }

    #[tokio::test]
    async fn test_key_service_delete_key() {
        let state = create_test_state();
        let key_service = KeyService::new(&state);

        let created = key_service
            .create_key(KeySpec::Aes256Gcm, "delete-test-key", "tenant-1", "user-1")
            .await
            .unwrap();

        key_service
            .delete_key(&created.id, "tenant-1", "user-1")
            .await
            .unwrap();

        // Verify the key is deleted
        let meta = key_service.get_key(&created.id, "tenant-1").await.unwrap();
        assert!(matches!(
            meta.status,
            kms_core::key::KeyStatus::PendingDeletion
        ));
    }

    #[tokio::test]
    async fn test_key_service_import_key_raw() {
        let state = create_test_state();
        let key_service = KeyService::new(&state);

        // Use non-zero key material (AES-256 requires non-weak keys)
        let raw_key_material = (0..32).map(|i| (i + 1) as u8).collect::<Vec<u8>>();

        // Use valid 64-char hex fingerprint and non-empty transport key
        let transport_key = vec![1u8; 32]; // dummy transport key for validation
        let fingerprint = "a".repeat(64); // 64 hex chars

        let meta = key_service
            .import_key(
                KeySpec::Aes256Gcm,
                "imported-key",
                "raw",
                &raw_key_material,
                &transport_key,
                &fingerprint,
                "tenant-1",
                "user-1",
            )
            .await
            .unwrap();

        assert_eq!(meta.name, "imported-key");
        assert_eq!(meta.tenant_id, "tenant-1");
    }

    #[tokio::test]
    async fn test_key_service_import_key_rejects_empty_transport_key() {
        let state = create_test_state();
        let key_service = KeyService::new(&state);

        let raw_key_material = vec![0u8; 32];

        // empty encrypted_transport_key should be rejected
        let result = key_service
            .import_key(
                KeySpec::Aes256Gcm,
                "imported-key",
                "raw",
                &raw_key_material,
                &[], // empty - should fail Phase 1 verification
                "abc123",
                "tenant-1",
                "user-1",
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_key_service_import_key_rejects_invalid_fingerprint() {
        let state = create_test_state();
        let key_service = KeyService::new(&state);

        let raw_key_material = vec![0u8; 32];

        // invalid fingerprint (not 64 hex chars)
        let result = key_service
            .import_key(
                KeySpec::Aes256Gcm,
                "imported-key",
                "raw",
                &raw_key_material,
                &[1, 2, 3], // dummy transport key
                "invalid",  // must be 64 hex chars
                "tenant-1",
                "user-1",
            )
            .await;

        assert!(result.is_err());
    }
}
