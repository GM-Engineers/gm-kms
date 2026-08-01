//! Envelope encryption service
//!
//! Handles envelope encryption (DEK/KEK两层加密).
//!
//! This service provides envelope encryption where:
//! 1. A random DEK is generated
//! 2. Data is encrypted with the DEK using AES-256-GCM
//! 3. The DEK is wrapped (encrypted) with the KEK using AES-256-GCM
//! 4. The wrapped DEK and ciphertext are returned

use crate::{ApiError, KmsState, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::SecureRandom;
use std::sync::Arc;

/// Response type for DEK rewrapping (KEK rotation support)
#[derive(Debug, Clone)]
pub struct RewrapDekResponse {
    /// Base64-encoded rewrapped DEK (DEK encrypted with new KEK version)
    pub wrapped_dek: String,
    /// Base64-encoded DEK nonce (new nonce generated for rewrapping)
    pub dek_nonce: String,
    /// New KEK version used for rewrapping
    pub kek_version: u32,
    /// Old KEK version from which the DEK was migrated
    pub old_kek_version: u32,
}

/// Response type for envelope encryption (Base64-encoded for REST API)
#[derive(Debug, Clone)]
pub struct EnvelopeEncryptResponse {
    /// Base64-encoded wrapped DEK (DEK encrypted with KEK)
    pub wrapped_dek: String,
    /// Base64-encoded DEK nonce
    pub dek_nonce: String,
    /// Base64-encoded ciphertext (data encrypted with DEK)
    pub ciphertext: String,
    /// Base64-encoded data nonce
    pub data_nonce: String,
    /// Base64-encoded authentication tag
    pub tag: String,
    /// KEK version used
    pub kek_version: u32,
}

/// Service for envelope encryption operations
pub struct EnvelopeService {
    keystore: Arc<dyn kms_keystore::KeystoreBackend>,
}

impl EnvelopeService {
    /// Create a new EnvelopeService from shared state
    pub fn new(state: &KmsState) -> Self {
        Self {
            keystore: state.keystore.clone(),
        }
    }

    /// Encrypt data using envelope encryption (DEK/KEK两层加密)
    ///
    /// Returns Base64-encoded response for REST API compatibility.
    pub async fn encrypt(
        &self,
        kek_id: &uuid::Uuid,
        plaintext: &[u8],
        _aad: Option<&[u8]>,
        tenant_id: &str,
        _user_id: &str,
    ) -> Result<EnvelopeEncryptResponse> {
        // Get KEK metadata and verify it's AES-256-GCM
        let kek_meta = self
            .keystore
            .get_key_metadata(kek_id)
            .await
            .map_err(|e| match e {
                kms_core::Error::KeyNotFound(_) => {
                    ApiError::NotFound(format!("KEK {} not found", kek_id))
                }
                _ => ApiError::Internal(e.to_string()),
            })?;

        if !matches!(kek_meta.spec, kms_core::KeySpec::Aes256Gcm) {
            return Err(ApiError::InvalidRequest(
                "KEK must be AES-256-GCM".to_string(),
            ));
        }

        // Get KEK bytes for wrapping DEK
        let kek_bytes = self
            .keystore
            .get_key_material(kek_id, tenant_id)
            .await
            .map_err(|e| match e {
                kms_core::Error::KeyNotFound(_) => {
                    ApiError::NotFound(format!("KEK {} not found", kek_id))
                }
                kms_core::Error::NotImplemented(_) => ApiError::Internal(
                    "KEK material not available for envelope encryption".to_string(),
                ),
                _ => ApiError::Internal(e.to_string()),
            })?;

        let dek_length = 32; // 256-bit DEK
        let rng = ring::rand::SystemRandom::new();

        // Generate DEK (Data Encryption Key)
        let mut dek_bytes = vec![0u8; dek_length];
        rng.fill(&mut dek_bytes)
            .map_err(|e| ApiError::Internal(format!("failed to generate DEK: {}", e)))?;

        // Generate DEK nonce (12 bytes for AES-GCM)
        let mut dek_nonce_bytes = [0u8; 12];
        rng.fill(&mut dek_nonce_bytes)
            .map_err(|e| ApiError::Internal(format!("failed to generate dek nonce: {}", e)))?;

        // Wrap DEK with KEK using AES-256-GCM
        let unbound_kek = UnboundKey::new(&AES_256_GCM, &kek_bytes)
            .map_err(|e| ApiError::Internal(format!("invalid KEK: {}", e)))?;
        let less_safe_kek = LessSafeKey::new(unbound_kek);

        let mut in_out = dek_bytes.clone();
        let tag = less_safe_kek
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(dek_nonce_bytes),
                Aad::empty(),
                &mut in_out,
            )
            .map_err(|e| ApiError::Internal(format!("failed to wrap DEK: {}", e)))?;

        // wrapped_dek = in_out (encrypted DEK) + tag
        let mut wrapped_dek = in_out;
        wrapped_dek.extend_from_slice(tag.as_ref());

        // Generate data nonce and encrypt plaintext with DEK
        let mut data_nonce_bytes = [0u8; 12];
        rng.fill(&mut data_nonce_bytes)
            .map_err(|e| ApiError::Internal(format!("failed to generate data nonce: {}", e)))?;

        let unbound_dek = UnboundKey::new(&AES_256_GCM, &dek_bytes)
            .map_err(|e| ApiError::Internal(format!("invalid DEK: {}", e)))?;
        let less_safe_dek = LessSafeKey::new(unbound_dek);

        let mut in_out = plaintext.to_vec();
        less_safe_dek
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(data_nonce_bytes),
                Aad::empty(),
                &mut in_out,
            )
            .map_err(|e| ApiError::Internal(format!("encryption failed: {}", e)))?;

        // in_out now contains ciphertext + tag (ring appends tag automatically)
        let ciphertext_with_tag = in_out;
        let tag_len = 16; // AES-GCM tag is 16 bytes
        let (ciphertext, tag_from_encrypt) =
            ciphertext_with_tag.split_at(ciphertext_with_tag.len() - tag_len);

        Ok(EnvelopeEncryptResponse {
            wrapped_dek: STANDARD.encode(&wrapped_dek),
            dek_nonce: STANDARD.encode(dek_nonce_bytes),
            ciphertext: STANDARD.encode(ciphertext),
            data_nonce: STANDARD.encode(data_nonce_bytes),
            tag: STANDARD.encode(tag_from_encrypt),
            kek_version: kek_meta.version,
        })
    }

    /// Rewrap a DEK from an old KEK version to the current KEK version.
    ///
    /// This is used after KEK rotation to migrate existing envelope-encrypted
    /// data to the new KEK version without re-encrypting the underlying plaintext.
    ///
    /// 1. Unwrap DEK using the old KEK version
    /// 2. Re-wrap DEK using the current KEK version
    /// 3. Return the new wrapped DEK and nonce
    pub async fn rewrap_dek(
        &self,
        kek_id: &uuid::Uuid,
        wrapped_dek: &[u8],
        dek_nonce: &[u8],
        old_kek_version: u32,
        tenant_id: &str,
    ) -> Result<RewrapDekResponse> {
        // Get KEK metadata to find current version
        let kek_meta = self
            .keystore
            .get_key_metadata(kek_id)
            .await
            .map_err(|e| match e {
                kms_core::Error::KeyNotFound(_) => {
                    ApiError::NotFound(format!("KEK {} not found", kek_id))
                }
                _ => ApiError::Internal(e.to_string()),
            })?;

        if !matches!(kek_meta.spec, kms_core::KeySpec::Aes256Gcm) {
            return Err(ApiError::InvalidRequest(
                "KEK must be AES-256-GCM".to_string(),
            ));
        }

        let new_kek_version = kek_meta.version;

        // If already at current version, no rewrap needed
        if old_kek_version == new_kek_version {
            return Ok(RewrapDekResponse {
                wrapped_dek: STANDARD.encode(wrapped_dek),
                dek_nonce: STANDARD.encode(dek_nonce),
                kek_version: new_kek_version,
                old_kek_version,
            });
        }

        // Get old KEK material for unwrapping
        let old_kek_bytes = self
            .keystore
            .get_key_material_version(kek_id, old_kek_version, tenant_id)
            .await
            .map_err(|e| match e {
                kms_core::Error::KeyNotFound(_) => {
                    ApiError::NotFound(format!("KEK {} not found", kek_id))
                }
                _ => ApiError::Internal(e.to_string()),
            })?;

        // Get current KEK material for re-wrapping
        let new_kek_bytes = self
            .keystore
            .get_key_material(kek_id, tenant_id)
            .await
            .map_err(|e| match e {
                kms_core::Error::KeyNotFound(_) => {
                    ApiError::NotFound(format!("KEK {} not found", kek_id))
                }
                _ => ApiError::Internal(e.to_string()),
            })?;

        // Unwrap DEK with old KEK
        if wrapped_dek.len() < 48 {
            return Err(ApiError::InvalidRequest(
                "invalid wrapped_dek length".to_string(),
            ));
        }

        let mut wrapped_dek_vec = wrapped_dek.to_vec();
        let tag_len = 16;
        let (encrypted_dek, stored_tag) = wrapped_dek_vec.split_at_mut(wrapped_dek.len() - tag_len);

        let unbound_old_kek = UnboundKey::new(&AES_256_GCM, &old_kek_bytes)
            .map_err(|e| ApiError::Internal(format!("invalid old KEK: {}", e)))?;
        let less_safe_old_kek = LessSafeKey::new(unbound_old_kek);

        let mut dek_nonce_array = [0u8; 12];
        dek_nonce_array.copy_from_slice(&dek_nonce[..12.min(dek_nonce.len())]);

        let mut in_out = encrypted_dek.to_vec();
        in_out.extend_from_slice(stored_tag);

        let dek_bytes = less_safe_old_kek
            .open_in_place(
                Nonce::assume_unique_for_key(dek_nonce_array),
                Aad::empty(),
                &mut in_out,
            )
            .map_err(|_| {
                ApiError::InvalidArgument(
                    "DEK unwrap failed during rewrap - old KEK version mismatch or corrupted data"
                        .to_string(),
                )
            })?
            .to_vec();

        // Re-wrap DEK with new KEK
        let rng = ring::rand::SystemRandom::new();
        let mut new_dek_nonce = [0u8; 12];
        rng.fill(&mut new_dek_nonce)
            .map_err(|e| ApiError::Internal(format!("failed to generate dek nonce: {}", e)))?;

        let unbound_new_kek = UnboundKey::new(&AES_256_GCM, &new_kek_bytes)
            .map_err(|e| ApiError::Internal(format!("invalid new KEK: {}", e)))?;
        let less_safe_new_kek = LessSafeKey::new(unbound_new_kek);

        let mut rewrapped_dek = dek_bytes.clone();
        let new_tag = less_safe_new_kek
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(new_dek_nonce),
                Aad::empty(),
                &mut rewrapped_dek,
            )
            .map_err(|e| ApiError::Internal(format!("failed to rewrap DEK: {}", e)))?;

        rewrapped_dek.extend_from_slice(new_tag.as_ref());

        Ok(RewrapDekResponse {
            wrapped_dek: STANDARD.encode(&rewrapped_dek),
            dek_nonce: STANDARD.encode(new_dek_nonce),
            kek_version: new_kek_version,
            old_kek_version,
        })
    }

    /// Decrypt data using envelope encryption
    ///
    /// 1. Unwrap DEK using KEK
    /// 2. Decrypt ciphertext using DEK
    /// 3. Return plaintext
    #[allow(clippy::too_many_arguments)]
    pub async fn decrypt(
        &self,
        kek_id: &uuid::Uuid,
        ciphertext: &[u8],
        wrapped_dek: &[u8],
        dek_nonce: &[u8],
        data_nonce: &[u8],
        #[allow(unused)] tag: &[u8],
        _aad: Option<&[u8]>,
        tenant_id: &str,
        _user_id: &str,
    ) -> Result<Vec<u8>> {
        // Delegate to version-aware decrypt with kek_version=0 (current)
        self.decrypt_with_kek_version(
            kek_id,
            ciphertext,
            wrapped_dek,
            dek_nonce,
            data_nonce,
            tag,
            _aad,
            tenant_id,
            _user_id,
            0,
        )
        .await
    }

    /// Decrypt data using envelope encryption with explicit KEK version.
    ///
    /// This allows decrypting data that was encrypted with an older KEK version
    /// after KEK rotation, using `get_key_material_version` to retrieve the
    /// correct key material.
    #[allow(clippy::too_many_arguments)]
    pub async fn decrypt_with_kek_version(
        &self,
        kek_id: &uuid::Uuid,
        ciphertext: &[u8],
        wrapped_dek: &[u8],
        dek_nonce: &[u8],
        data_nonce: &[u8],
        #[allow(unused)] tag: &[u8],
        _aad: Option<&[u8]>,
        tenant_id: &str,
        _user_id: &str,
        kek_version: u32,
    ) -> Result<Vec<u8>> {
        // Get KEK bytes for unwrapping DEK (version-aware)
        let kek_bytes = self
            .keystore
            .get_key_material_version(kek_id, kek_version, tenant_id)
            .await
            .map_err(|e| match e {
                kms_core::Error::KeyNotFound(_) => {
                    ApiError::NotFound(format!("KEK {} not found", kek_id))
                }
                _ => ApiError::Internal(e.to_string()),
            })?;

        // Unwrap DEK (reverse the seal_in_place_separate_tag operation)
        // wrapped_dek format: encrypted_dek (32 bytes) + tag (16 bytes)
        if wrapped_dek.len() < 48 {
            return Err(ApiError::InvalidRequest(
                "invalid wrapped_dek length".to_string(),
            ));
        }

        let mut wrapped_dek_vec = wrapped_dek.to_vec();
        let tag_len = 16;
        let (encrypted_dek, stored_tag) = wrapped_dek_vec.split_at_mut(wrapped_dek.len() - tag_len);

        // Unwrap DEK using AES-256-GCM
        let unbound_kek = UnboundKey::new(&AES_256_GCM, &kek_bytes)
            .map_err(|e| ApiError::Internal(format!("invalid KEK: {}", e)))?;
        let less_safe_kek = LessSafeKey::new(unbound_kek);

        // Use the provided dek_nonce for unwrapping
        let mut dek_nonce_array = [0u8; 12];
        dek_nonce_array.copy_from_slice(&dek_nonce[..12.min(dek_nonce.len())]);

        let mut in_out = encrypted_dek.to_vec();
        in_out.extend_from_slice(stored_tag);

        let dek_bytes = less_safe_kek
            .open_in_place(
                Nonce::assume_unique_for_key(dek_nonce_array),
                Aad::empty(),
                &mut in_out,
            )
            .map_err(|_| {
                ApiError::InvalidArgument(
                    "DEK unwrap failed - KEK mismatch or corrupted data".to_string(),
                )
            })?
            .to_vec();

        // Now decrypt the actual data using the unwrapped DEK
        let mut data_nonce_array = [0u8; 12];
        data_nonce_array.copy_from_slice(&data_nonce[..12.min(data_nonce.len())]);

        let unbound_key = UnboundKey::new(&AES_256_GCM, &dek_bytes)
            .map_err(|e| ApiError::Internal(format!("invalid DEK after unwrap: {}", e)))?;
        let less_safe_dek = LessSafeKey::new(unbound_key);

        // Append the data tag (passed as parameter) for decryption
        let mut ciphertext_with_tag = ciphertext.to_vec();
        ciphertext_with_tag.extend_from_slice(tag);

        let mut in_out = ciphertext_with_tag;
        let plaintext = less_safe_dek
            .open_in_place(
                Nonce::assume_unique_for_key(data_nonce_array),
                Aad::empty(),
                &mut in_out,
            )
            .map_err(|_| {
                ApiError::Internal("decryption failed - invalid ciphertext or key".to_string())
            })?
            .to_vec();

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_response_structure() {
        let response = EnvelopeEncryptResponse {
            wrapped_dek: "test_wrapped_dek".to_string(),
            dek_nonce: "test_dek_nonce".to_string(),
            ciphertext: "test_ciphertext".to_string(),
            data_nonce: "test_data_nonce".to_string(),
            tag: "test_tag".to_string(),
            kek_version: 1,
        };

        assert_eq!(response.wrapped_dek, "test_wrapped_dek");
        assert_eq!(response.kek_version, 1);
    }

    #[test]
    fn test_envelope_response_clone() {
        let response = EnvelopeEncryptResponse {
            wrapped_dek: "test".to_string(),
            dek_nonce: "nonce".to_string(),
            ciphertext: "ct".to_string(),
            data_nonce: "dn".to_string(),
            tag: "tag".to_string(),
            kek_version: 2,
        };

        let cloned = response.clone();
        assert_eq!(cloned.wrapped_dek, response.wrapped_dek);
        assert_eq!(cloned.kek_version, response.kek_version);
    }

    use kms_keystore::KeystoreBackend;

    #[tokio::test]
    async fn test_rewrap_dek_after_kek_rotation() {
        use kms_core::KeySpec;
        use kms_keystore::software::SoftwareKeystore;

        let keystore = Arc::new(SoftwareKeystore::new());
        let state = crate::KmsState::new(
            keystore.clone(),
            kms_policy::PBACEngine::new(),
            Arc::new(kms_audit::AuditLogger::with_stdout()),
            crate::Sm9State {
                master_key: gm_sm9_rs::KgcMasterKey::generate()
                    .expect("failed to generate master key"),
                repository: None,
            },
            crate::KmsMetrics::new(),
        );

        let envelope_svc = EnvelopeService::new(&state);

        // 1. Generate a KEK
        let kek_meta = keystore
            .generate_key(&KeySpec::Aes256Gcm, "test-kek", "test-tenant")
            .await
            .unwrap();
        let kek_id = kek_meta.id;
        let old_version = kek_meta.version; // should be 1

        // 2. Encrypt some data with envelope encryption
        let plaintext = b"secret data for rewrap test";
        let enc_result = envelope_svc
            .encrypt(&kek_id, plaintext, None, "test-tenant", "test-user")
            .await
            .unwrap();

        let wrapped_dek = STANDARD.decode(&enc_result.wrapped_dek).unwrap();
        let dek_nonce = STANDARD.decode(&enc_result.dek_nonce).unwrap();

        // 3. Rotate the KEK
        let new_meta = keystore.rotate_key(&kek_id, "test-tenant").await.unwrap();
        let new_version = new_meta.version;
        assert_eq!(new_version, old_version + 1);

        // 4. Decrypt with old version should still work (version-aware decrypt)
        let ciphertext = STANDARD.decode(&enc_result.ciphertext).unwrap();
        let data_nonce = STANDARD.decode(&enc_result.data_nonce).unwrap();
        let tag = STANDARD.decode(&enc_result.tag).unwrap();

        let decrypted_old = envelope_svc
            .decrypt_with_kek_version(
                &kek_id,
                &ciphertext,
                &wrapped_dek,
                &dek_nonce,
                &data_nonce,
                &tag,
                None,
                "test-tenant",
                "test-user",
                old_version,
            )
            .await
            .unwrap();
        assert_eq!(decrypted_old, plaintext);

        // 5. Rewrap the DEK to the new KEK version
        let rewrap_result = envelope_svc
            .rewrap_dek(
                &kek_id,
                &wrapped_dek,
                &dek_nonce,
                old_version,
                "test-tenant",
            )
            .await
            .unwrap();

        assert_eq!(rewrap_result.kek_version, new_version);
        assert_eq!(rewrap_result.old_kek_version, old_version);

        // 6. Decrypt with rewrapped DEK and new KEK version
        let rewrapped_dek = STANDARD.decode(&rewrap_result.wrapped_dek).unwrap();
        let new_dek_nonce = STANDARD.decode(&rewrap_result.dek_nonce).unwrap();

        let decrypted_new = envelope_svc
            .decrypt_with_kek_version(
                &kek_id,
                &ciphertext,
                &rewrapped_dek,
                &new_dek_nonce,
                &data_nonce,
                &tag,
                None,
                "test-tenant",
                "test-user",
                new_version,
            )
            .await
            .unwrap();
        assert_eq!(decrypted_new, plaintext);

        // 7. Old wrapped_dek should NOT work with new KEK version
        let decrypt_wrong = envelope_svc
            .decrypt_with_kek_version(
                &kek_id,
                &ciphertext,
                &wrapped_dek,
                &dek_nonce,
                &data_nonce,
                &tag,
                None,
                "test-tenant",
                "test-user",
                new_version,
            )
            .await;
        assert!(
            decrypt_wrong.is_err(),
            "old wrapped DEK should fail with new KEK version"
        );
    }

    #[tokio::test]
    async fn test_rewrap_same_version_noop() {
        use kms_core::KeySpec;
        use kms_keystore::software::SoftwareKeystore;

        let keystore = Arc::new(SoftwareKeystore::new());
        let state = crate::KmsState::new(
            keystore.clone(),
            kms_policy::PBACEngine::new(),
            Arc::new(kms_audit::AuditLogger::with_stdout()),
            crate::Sm9State {
                master_key: gm_sm9_rs::KgcMasterKey::generate()
                    .expect("failed to generate master key"),
                repository: None,
            },
            crate::KmsMetrics::new(),
        );

        let envelope_svc = EnvelopeService::new(&state);

        let kek_meta = keystore
            .generate_key(&KeySpec::Aes256Gcm, "test-kek", "test-tenant")
            .await
            .unwrap();
        let kek_id = kek_meta.id;

        let plaintext = b"test data";
        let enc_result = envelope_svc
            .encrypt(&kek_id, plaintext, None, "test-tenant", "test-user")
            .await
            .unwrap();

        let wrapped_dek = STANDARD.decode(&enc_result.wrapped_dek).unwrap();
        let dek_nonce = STANDARD.decode(&enc_result.dek_nonce).unwrap();

        // Rewrap with same version should be a no-op
        let rewrap_result = envelope_svc
            .rewrap_dek(&kek_id, &wrapped_dek, &dek_nonce, 1, "test-tenant")
            .await
            .unwrap();

        assert_eq!(rewrap_result.kek_version, 1);
        assert_eq!(rewrap_result.old_kek_version, 1);
    }
}
