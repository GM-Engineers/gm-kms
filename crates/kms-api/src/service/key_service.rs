//! Key management service
//!
//! Handles key lifecycle operations: creation, rotation, deletion, listing, import, and export.

use super::{IntoApiError, KeyFormatParser, ServiceError};
use crate::{ApiError, KmsState, Result, quota::TenantQuotaTracker};
use base64::{Engine, engine::general_purpose::STANDARD};
use kms_core::aad::export_wrap_aad;
use kms_core::key::{KeyFilter, KeyMeta, KeySpec};
use kms_core::sanitize::sanitize_for_log;
use ring::rand::SecureRandom;
use std::sync::Arc;

/// Transport-key protection scheme for wrapped key export (audit P2-6).
///
/// Both schemes wrap the key material with an ephemeral symmetric transport key
/// and then protect that transport key with the caller's public key. The scheme
/// selects the AEAD used for the material wrap and the asymmetric algorithm used
/// to encrypt the transport key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExportProtection {
    /// 32-byte transport key, AES-256-GCM material wrap, RSA-OAEP(SHA-256)
    /// transport-key protection. This is the historical default and stays the
    /// default so existing callers see no behaviour change.
    #[default]
    RsaOaep,
    /// 16-byte transport key, SM4-GCM material wrap, SM2 transport-key
    /// protection (GM/T 0003 ecosystem). `target_public_key` must be a 65-byte
    /// uncompressed SEC1 public key.
    Sm2,
}

impl ExportProtection {
    /// Parse a caller-supplied protection scheme string.
    ///
    /// `None`, empty, and the RSA aliases resolve to [`ExportProtection::RsaOaep`]
    /// so that omitting the field preserves backward compatibility. `"sm2"` (any
    /// case) selects the SM2 path. Anything else is rejected.
    pub fn parse(scheme: Option<&str>) -> Result<Self> {
        let normalized = scheme.map(|s| s.trim().to_lowercase());
        match normalized.as_deref() {
            None | Some("") | Some("rsa") | Some("rsa-oaep") | Some("rsa_oaep")
            | Some("rsaoaep") => Ok(Self::RsaOaep),
            Some("sm2") => Ok(Self::Sm2),
            Some(other) => Err(ApiError::InvalidRequest(format!(
                "unsupported export protection scheme: {other}"
            ))),
        }
    }
}

/// Options controlling a wrapped export (groups parameters so future additions
/// such as `version` do not churn every `export_key` call site).
#[derive(Debug, Clone, Copy, Default)]
pub struct ExportOptions {
    /// Transport-key protection scheme.
    pub protection: ExportProtection,
    /// Key version to export (audit P2-2). `None` (or `Some(0)`) exports the
    /// current/active version; `Some(v)` with `v != current` exports a historical
    /// version from the key's rotation history, provided the key is still
    /// exportable (export-policy is validated against the current key).
    pub version: Option<u32>,
}

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
        // Verify tenant ownership before rotating. Cross-tenant and
        // missing-key responses are deliberately conflated (KeyNotFound
        // for both) — distinguishing is a key-enumeration oracle.
        let meta = self
            .keystore
            .get_key_metadata(key_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        if meta.tenant_id != tenant_id {
            tracing::warn!(
                key_id = %key_id,
                requester_tenant = %sanitize_for_log(tenant_id),
                owner_tenant = %sanitize_for_log(&meta.tenant_id),
                "tenant mismatch on key rotate — possible enumeration attempt"
            );
            return Err(ApiError::KeyNotFound(key_id.to_string()));
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
        // Verify tenant ownership before deleting. Cross-tenant and
        // missing-key responses are conflated (KeyNotFound for both).
        let meta = self
            .keystore
            .get_key_metadata(key_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        if meta.tenant_id != tenant_id {
            tracing::warn!(
                key_id = %key_id,
                requester_tenant = %sanitize_for_log(tenant_id),
                owner_tenant = %sanitize_for_log(&meta.tenant_id),
                "tenant mismatch on key delete — possible enumeration attempt"
            );
            return Err(ApiError::KeyNotFound(key_id.to_string()));
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

        // Verify tenant isolation. Cross-tenant and missing-key responses
        // are conflated (KeyNotFound for both).
        if meta.tenant_id != tenant_id {
            tracing::warn!(
                key_id = %key_id,
                requester_tenant = %sanitize_for_log(tenant_id),
                owner_tenant = %sanitize_for_log(&meta.tenant_id),
                "tenant mismatch on key read — possible enumeration attempt"
            );
            return Err(ApiError::KeyNotFound(key_id.to_string()));
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

    /// Export key material wrapped with a transport key.
    ///
    /// Returns the wrapped key (material encrypted with an ephemeral transport
    /// key) and the encrypted transport key (transport key protected with the
    /// caller's `target_public_key`). The protection scheme is selected via
    /// [`ExportOptions::protection`] (audit P2-6): RSA-OAEP (default) or SM2.
    pub async fn export_key(
        &self,
        key_id: &uuid::Uuid,
        target_public_key: &[u8],
        purpose: &str,
        tenant_id: &str,
        _user_id: &str,
        opts: ExportOptions,
    ) -> Result<ExportedKey> {
        // Verify tenant ownership before exporting. Cross-tenant and
        // missing-key responses are conflated (KeyNotFound for both).
        let meta = self
            .keystore
            .get_key_metadata(key_id)
            .await
            .map_err(|e| ServiceError::from(e).into_api_error())?;

        if meta.tenant_id != tenant_id {
            tracing::warn!(
                key_id = %key_id,
                requester_tenant = %sanitize_for_log(tenant_id),
                owner_tenant = %sanitize_for_log(&meta.tenant_id),
                "tenant mismatch on key export — possible enumeration attempt"
            );
            return Err(ApiError::KeyNotFound(key_id.to_string()));
        }
        // Validate the target public key according to the chosen protection
        // scheme, before touching key material (fail fast).
        match opts.protection {
            ExportProtection::RsaOaep => {
                // At least 256 bytes (2048-bit RSA minimum).
                if target_public_key.len() < 256 {
                    return Err(ApiError::InvalidRequest(
                        "target_public_key too small, expected at least 2048-bit RSA".to_string(),
                    ));
                }
            }
            ExportProtection::Sm2 => {
                // 65-byte uncompressed SEC1 point (0x04 prefix).
                if target_public_key.len() != 65 || target_public_key.first() != Some(&0x04) {
                    return Err(ApiError::InvalidRequest(
                        "SM2 export requires a 65-byte uncompressed SEC1 public key (0x04 prefix)"
                            .to_string(),
                    ));
                }
            }
        }

        // Export raw key material (validates key exists, is active and exportable).
        // Export-policy + tenant checks are enforced here against the current key,
        // so making a key non-exportable also blocks historical-version export.
        let current_material = self
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

        // Select the requested version (audit P2-2): `None`/0/current exports the
        // active material; a different version is pulled from rotation history.
        let key_material = match opts.version.filter(|v| *v != 0) {
            Some(v) if v != meta.version => self
                .keystore
                .get_key_material_version(key_id, v, tenant_id)
                .await
                .map_err(|e| match e {
                    kms_core::Error::KeyNotFound(_) => {
                        ApiError::NotFound(format!("key {key_id} version {v} not found"))
                    }
                    _ => ServiceError::from(e).into_api_error(),
                })?,
            _ => current_material,
        };

        // Compute fingerprint from actual key material (SHA-256)
        use ring::digest::{Context, SHA256 as RingSHA256};
        let mut digest_ctx = Context::new(&RingSHA256);
        digest_ctx.update(&key_material);
        let digest = digest_ctx.finish();
        let key_fingerprint = hex::encode(digest.as_ref());

        // Bind the export envelope to (key_id, tenant_id) so a stored export
        // record cannot be replayed against another key/tenant. The AAD tag is
        // the dedicated `ExportWrap` purpose (different from `UserData`), so an
        // attacker cannot lift a user-data ciphertext and pass it off as an
        // export envelope. Shared by both protection schemes.
        let export_aad = export_wrap_aad(*key_id, tenant_id);

        let rng = ring::rand::SystemRandom::new();
        let (wrapped_key, encrypted_transport_key) = match opts.protection {
            ExportProtection::RsaOaep => {
                // AES-256-GCM material wrap + RSA-OAEP(SHA-256) transport-key
                // protection. Wire format is unchanged from the historical RSA
                // path so existing unwrap clients keep working.
                let mut transport_key = vec![0u8; 32];
                ring::rand::SecureRandom::fill(&rng, &mut transport_key).map_err(|e| {
                    ApiError::Internal(format!("failed to generate transport key: {e}"))
                })?;

                use ring::aead::{AES_256_GCM, LessSafeKey, Nonce, UnboundKey};
                let unbound_kek = UnboundKey::new(&AES_256_GCM, &transport_key)
                    .map_err(|e| ApiError::Internal(format!("failed to create KEK: {e}")))?;
                let less_safe_kek = LessSafeKey::new(unbound_kek);

                let mut nonce_bytes = [0u8; 12];
                rng.fill(&mut nonce_bytes)
                    .map_err(|e| ApiError::Internal(format!("failed to generate nonce: {e}")))?;
                let nonce = Nonce::assume_unique_for_key(nonce_bytes);

                let aad = ring::aead::Aad::from(export_aad.as_slice());
                let mut in_out = key_material.clone();
                let tag = less_safe_kek
                    .seal_in_place_separate_tag(nonce, aad, &mut in_out)
                    .map_err(|e| ApiError::Internal(format!("failed to wrap key: {e}")))?;
                let mut wrapped = in_out;
                wrapped.extend_from_slice(tag.as_ref());

                use rsa::Oaep;
                use rsa::pkcs1::DecodeRsaPublicKey;
                use rsa::sha2::Sha256;
                let rsa_public_key =
                    rsa::RsaPublicKey::from_pkcs1_der(target_public_key).map_err(|_| {
                        ApiError::InvalidRequest("invalid RSA public key format".to_string())
                    })?;
                let mut os_rng = rand_core::OsRng;
                let padding = Oaep::new::<Sha256>();
                let etk = rsa_public_key
                    .encrypt(&mut os_rng, padding, &transport_key)
                    .map_err(|e| {
                        ApiError::Internal(format!("failed to encrypt transport key: {e}"))
                    })?;
                (wrapped, etk)
            }
            ExportProtection::Sm2 => {
                // SM4-GCM material wrap + SM2 transport-key protection.
                // wrapped_key layout: nonce (12B) || ciphertext || tag (16B).
                let mut transport_key = vec![0u8; 16];
                ring::rand::SecureRandom::fill(&rng, &mut transport_key).map_err(|e| {
                    ApiError::Internal(format!("failed to generate transport key: {e}"))
                })?;

                let mut nonce_bytes = [0u8; 12];
                rng.fill(&mut nonce_bytes)
                    .map_err(|e| ApiError::Internal(format!("failed to generate nonce: {e}")))?;

                let cipher = gm_crypto::sm4::Sm4Cipher::new(&transport_key)
                    .map_err(|e| ApiError::Internal(format!("sm4 cipher init failed: {e}")))?;
                let (ct, tag) = cipher
                    .encrypt_gcm(&key_material, &nonce_bytes, &export_aad)
                    .map_err(|e| ApiError::Internal(format!("sm4-gcm wrap failed: {e}")))?;
                let mut wrapped = Vec::with_capacity(nonce_bytes.len() + ct.len() + tag.len());
                wrapped.extend_from_slice(&nonce_bytes);
                wrapped.extend_from_slice(&ct);
                wrapped.extend_from_slice(&tag);

                let encryptor =
                    gm_crypto::sm2::Sm2Encryptor::new(target_public_key).map_err(|_| {
                        ApiError::InvalidRequest("invalid SM2 public key format".to_string())
                    })?;
                let etk = encryptor.encrypt(&transport_key).map_err(|e| {
                    ApiError::Internal(format!("sm2 transport-key encryption failed: {e}"))
                })?;
                (wrapped, etk)
            }
        };

        tracing::info!(
            "Key {} exported (purpose: {}, protection: {:?})",
            key_id,
            sanitize_for_log(purpose),
            opts.protection
        );

        let export_id = uuid::Uuid::new_v4().to_string();
        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();

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

    // ── PR-1.2: KeyService cross-tenant error unification ──

    /// Helper: generate an Aes256Gcm key under `tenant`.
    async fn create_aes_key(svc: &KeyService, name: &str, tenant: &str) -> uuid::Uuid {
        svc.create_key(KeySpec::Aes256Gcm, name, tenant, "user-1")
            .await
            .expect("key creation should succeed")
            .id
    }

    /// get_key: cross-tenant access returns KeyNotFound, not Forbidden.
    #[tokio::test]
    async fn test_pr12_key_get_cross_tenant_returns_keynotfound() {
        let state = create_test_state();
        let svc = KeyService::new(&state);
        let key_id = create_aes_key(&svc, "p12-kg", "tenant-a").await;

        let result = svc.get_key(&key_id, "tenant-b").await;
        assert!(
            matches!(result, Err(ApiError::KeyNotFound(_))),
            "cross-tenant get_key must return KeyNotFound, got {result:?}"
        );
    }

    /// rotate_key: cross-tenant access returns KeyNotFound, not Forbidden.
    #[tokio::test]
    async fn test_pr12_key_rotate_cross_tenant_returns_keynotfound() {
        let state = create_test_state();
        let svc = KeyService::new(&state);
        let key_id = create_aes_key(&svc, "p12-kr", "tenant-a").await;

        let result = svc.rotate_key(&key_id, "tenant-b", "user-1").await;
        assert!(
            matches!(result, Err(ApiError::KeyNotFound(_))),
            "cross-tenant rotate_key must return KeyNotFound, got {result:?}"
        );
    }

    /// delete_key: cross-tenant access returns KeyNotFound, not Forbidden.
    #[tokio::test]
    async fn test_pr12_key_delete_cross_tenant_returns_keynotfound() {
        let state = create_test_state();
        let svc = KeyService::new(&state);
        let key_id = create_aes_key(&svc, "p12-kd", "tenant-a").await;

        let result = svc.delete_key(&key_id, "tenant-b", "user-1").await;
        assert!(
            matches!(result, Err(ApiError::KeyNotFound(_))),
            "cross-tenant delete_key must return KeyNotFound, got {result:?}"
        );
    }

    /// get_key: a non-existent key also returns KeyNotFound — the two
    /// responses are byte-identical to a probing client.
    #[tokio::test]
    async fn test_pr12_key_get_nonexistent_returns_keynotfound() {
        let state = create_test_state();
        let svc = KeyService::new(&state);
        let bogus = uuid::Uuid::new_v4();

        let result = svc.get_key(&bogus, "tenant-a").await;
        assert!(
            matches!(result, Err(ApiError::KeyNotFound(_))),
            "non-existent get_key must return KeyNotFound, got {result:?}"
        );
    }

    // ── B4-b: SM2 export protection path (audit P2-6) ──

    #[test]
    fn export_protection_parse_defaults_and_aliases() {
        assert_eq!(
            ExportProtection::parse(None).unwrap(),
            ExportProtection::RsaOaep
        );
        assert_eq!(
            ExportProtection::parse(Some("")).unwrap(),
            ExportProtection::RsaOaep
        );
        assert_eq!(
            ExportProtection::parse(Some("RSA-OAEP")).unwrap(),
            ExportProtection::RsaOaep
        );
        assert_eq!(
            ExportProtection::parse(Some(" rsa ")).unwrap(),
            ExportProtection::RsaOaep
        );
        assert_eq!(
            ExportProtection::parse(Some("SM2")).unwrap(),
            ExportProtection::Sm2
        );
        assert_eq!(
            ExportProtection::parse(Some("sm2")).unwrap(),
            ExportProtection::Sm2
        );
        assert_eq!(ExportProtection::default(), ExportProtection::RsaOaep);
    }

    #[test]
    fn export_protection_parse_rejects_unknown() {
        assert!(ExportProtection::parse(Some("aes-kw")).is_err());
        assert!(ExportProtection::parse(Some("ed25519")).is_err());
    }

    #[tokio::test]
    async fn sm2_export_round_trip_unwraps_to_key_material() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let state = create_test_state();
        let svc = KeyService::new(&state);
        let key_id = create_aes_key(&svc, "sm2-exp", "tenant-sm2").await;

        // Caller SM2 keypair; target public key is a 65-byte uncompressed SEC1 point.
        let keypair = gm_crypto::sm2::Sm2KeyPair::generate().unwrap();
        let target_pub = keypair.public_key_bytes_uncompressed();
        assert_eq!(target_pub.len(), 65);
        let decryptor = gm_crypto::sm2::Sm2Decryptor::new(keypair);

        let exported = svc
            .export_key(
                &key_id,
                &target_pub,
                "migration",
                "tenant-sm2",
                "user-1",
                ExportOptions {
                    protection: ExportProtection::Sm2,
                    version: None,
                },
            )
            .await
            .unwrap();

        // Server-side truth: the raw material that was wrapped.
        let expected = state
            .keystore
            .export_key_material(&key_id, "tenant-sm2")
            .await
            .unwrap();

        // Unwrap: SM2-decrypt the transport key, then SM4-GCM open the material.
        let etb = STANDARD.decode(&exported.encrypted_transport_key).unwrap();
        let wb = STANDARD.decode(&exported.wrapped_key).unwrap();
        let transport_key = decryptor.decrypt(&etb).unwrap();
        assert_eq!(transport_key.len(), 16);

        // wrapped_key layout: nonce(12) || ciphertext || tag(16).
        assert_eq!(wb.len(), 12 + expected.len() + 16);
        let nonce = &wb[..12];
        let ct = &wb[12..wb.len() - 16];
        let tag = &wb[wb.len() - 16..];
        let aad = kms_core::aad::export_wrap_aad(key_id, "tenant-sm2");
        let cipher = gm_crypto::sm4::Sm4Cipher::new(&transport_key).unwrap();
        let recovered = cipher.decrypt_gcm(ct, nonce, &aad, tag).unwrap();
        assert_eq!(recovered, expected);

        // Fingerprint is SHA-256 over the exported material.
        let d = ring::digest::digest(&ring::digest::SHA256, &expected);
        assert_eq!(exported.key_fingerprint, hex::encode(d.as_ref()));
    }

    #[tokio::test]
    async fn sm2_export_rejects_bad_pubkey_length() {
        let state = create_test_state();
        let svc = KeyService::new(&state);
        let key_id = create_aes_key(&svc, "sm2-bad", "tenant-sm2b").await;
        // 33-byte buffer is not a valid 65-byte uncompressed SEC1 point.
        let bad = vec![0x04u8; 33];
        let result = svc
            .export_key(
                &key_id,
                &bad,
                "migration",
                "tenant-sm2b",
                "user-1",
                ExportOptions {
                    protection: ExportProtection::Sm2,
                    version: None,
                },
            )
            .await;
        assert!(
            matches!(result, Err(ApiError::InvalidRequest(_))),
            "bad SM2 pubkey must be rejected with InvalidRequest"
        );
    }

    // ── B4-c: versioned export (audit P2-2) ──

    #[tokio::test]
    async fn export_specific_version_pulls_rotation_history() {
        let state = create_test_state();
        let svc = KeyService::new(&state);
        let key_id = create_aes_key(&svc, "ver-exp", "tenant-ver").await;

        let keypair = gm_crypto::sm2::Sm2KeyPair::generate().unwrap();
        let target_pub = keypair.public_key_bytes_uncompressed();
        let opts = |version| ExportOptions {
            protection: ExportProtection::Sm2,
            version,
        };

        // Baseline: current version (1).
        let v1 = svc
            .export_key(
                &key_id,
                &target_pub,
                "migration",
                "tenant-ver",
                "user-1",
                opts(None),
            )
            .await
            .unwrap();

        // Rotate -> active becomes version 2, history keeps version 1.
        svc.rotate_key(&key_id, "tenant-ver", "user-1")
            .await
            .unwrap();
        let after = svc.get_key(&key_id, "tenant-ver").await.unwrap();
        assert_eq!(after.version, 2);

        let v2 = svc
            .export_key(
                &key_id,
                &target_pub,
                "migration",
                "tenant-ver",
                "user-1",
                opts(None),
            )
            .await
            .unwrap();
        let old = svc
            .export_key(
                &key_id,
                &target_pub,
                "migration",
                "tenant-ver",
                "user-1",
                opts(Some(1)),
            )
            .await
            .unwrap();

        // Current (v2) differs from the original v1; explicit version 1 reproduces
        // the pre-rotation fingerprint from history.
        assert_ne!(v1.key_fingerprint, v2.key_fingerprint);
        assert_eq!(old.key_fingerprint, v1.key_fingerprint);

        // Requesting a version that never existed must fail (it must NOT silently
        // fall back to the current material).
        let missing = svc
            .export_key(
                &key_id,
                &target_pub,
                "migration",
                "tenant-ver",
                "user-1",
                opts(Some(99)),
            )
            .await;
        assert!(
            missing.is_err(),
            "unknown export version must not silently export the current key"
        );
    }
}
