//! PostgreSQL-backed keystore implementation
//!
//! Combines in-memory key material storage with PostgreSQL metadata persistence.

use async_trait::async_trait;
use chrono::Utc;
use kms_core::{
    BackendType, Result,
    dh::SharedSecret,
    error::Error,
    key::{Ciphertext, DestructionProof, KeyFilter, KeyMeta, KeySpec, KeyStatus, Signature},
};
use ring::rand::{SecureRandom, SystemRandom};
use ring::{digest, signature::KeyPair};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::repository::PostgresKeyRepository;
use super::software::SoftwareKeystore;

/// In-memory key entry with material (zeroized on drop)
#[derive(Clone)]
struct KeyEntry {
    meta: KeyMeta,
    material: Zeroizing<Vec<u8>>,
}

/// PostgreSQL-backed keystore
///
/// Stores key metadata in PostgreSQL while keeping key material in memory
/// for cryptographic operations.
pub struct PostgresKeystore {
    /// In-memory key material storage
    keys: Arc<RwLock<std::collections::HashMap<Uuid, KeyEntry>>>,
    /// PostgreSQL repository for metadata
    repo: PostgresKeyRepository,
    /// Key encryption key (KEK) for encrypting key material before DB storage
    /// In production, this should come from an HSM or Vault
    kek: Zeroizing<[u8; 32]>,
}

impl PostgresKeystore {
    /// Create a new PostgreSQL-backed keystore
    pub async fn new(repo: PostgresKeyRepository) -> Result<Self> {
        let kek = Zeroizing::new(Self::load_or_generate_kek()?);
        let store = Self {
            keys: Arc::new(RwLock::new(std::collections::HashMap::new())),
            repo,
            kek,
        };
        // Run migrations
        store
            .repo
            .migrate()
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;
        Ok(store)
    }

    /// Load KEK from environment variable or generate a warning
    ///
    /// In production, KEK should be managed by an HSM or Vault.
    /// In development, KMS_DEV_MODE=1 generates a random KEK at startup.
    fn load_or_generate_kek() -> Result<[u8; 32]> {
        // If KMS_KEK is set, use it (hex-decoded)
        if let Ok(kek_hex) = std::env::var("KMS_KEK") {
            let kek = hex::decode(&kek_hex)
                .map_err(|e| Error::Internal(format!("Invalid KMS_KEK hex: {e}")))?
                .try_into()
                .map_err(|_| {
                    Error::Internal("KMS_KEK must be 32 bytes (64 hex characters)".to_string())
                })?;
            return Ok(kek);
        }

        // KMS_KEK not set — check DEV mode
        if std::env::var("KMS_DEV_MODE").as_deref() == Ok("1") {
            tracing::warn!(
                "KMS_KEK not set and KMS_DEV_MODE=1: generating a random KEK. \
                DO NOT use this configuration in production. \
                WARNING: All encrypted data will be unrecoverable after restart \
                because the random KEK is not persisted."
            );
            let mut kek = [0u8; 32];
            use rand::Rng;
            rand::rng().fill_bytes(&mut kek);
            return Ok(kek);
        }

        // Production: fail hard
        eprintln!("ERROR: KMS_KEK must be set in production. Exiting.");
        std::process::exit(1);
    }

    /// Encrypt key material with KEK for storage
    fn encrypt_material(&self, material: &[u8]) -> Result<Vec<u8>> {
        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

        let unbound_key = UnboundKey::new(&AES_256_GCM, self.kek.as_ref())
            .map_err(|e| Error::EncryptionFailed(e.to_string()))?;
        let sealing_key = LessSafeKey::new(unbound_key);

        // Generate random 12-byte nonce (CSPRNG)
        let mut nonce_bytes = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| Error::EncryptionFailed("failed to generate nonce".to_string()))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = material.to_vec();
        let tag = sealing_key
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

        // Format: nonce (12 bytes) || ciphertext || tag (16 bytes)
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&in_out);
        result.extend_from_slice(tag.as_ref());

        Ok(result)
    }

    /// Decrypt key material with KEK after loading from storage
    fn decrypt_material(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

        if encrypted.len() < 12 + 16 {
            return Err(Error::DecryptionFailed(
                "Encrypted material too short".to_string(),
            ));
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&encrypted[..12]);

        let unbound_key = UnboundKey::new(&AES_256_GCM, self.kek.as_ref())
            .map_err(|e| Error::DecryptionFailed(e.to_string()))?;
        let opening_key = LessSafeKey::new(unbound_key);

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let ciphertext_len = encrypted.len() - 12 - 16;
        let mut in_out = encrypted[12..12 + ciphertext_len].to_vec();
        let tag = &encrypted[12 + ciphertext_len..];

        in_out.extend_from_slice(tag);

        let plaintext = opening_key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| Error::InvalidCiphertext)?;

        Ok(plaintext.to_vec())
    }

    fn generate_key_material(spec: &KeySpec) -> Result<Vec<u8>> {
        let len = match spec {
            KeySpec::Aes256Gcm | KeySpec::HmacSha256 => 32,
            KeySpec::EcdsaP256 | KeySpec::EcdsaP384 | KeySpec::Ed25519 | KeySpec::Ed448 => 32,
            KeySpec::Sm4 => 16,
            KeySpec::Sm2 => 32,
            KeySpec::Sm9Signing | KeySpec::Sm9Encryption => {
                return Err(Error::NotImplemented("SM9 not yet implemented".to_string()));
            }
            KeySpec::Rsa4096 => {
                return Err(Error::NotImplemented("RSA not yet implemented".to_string()));
            }
        };
        let mut key = vec![0u8; len];
        SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| Error::Internal("failed to generate random key material".to_string()))?;
        Ok(key)
    }

    /// Load all keys from PostgreSQL into memory
    ///
    /// This decrypts key material using the KEK and loads it into the in-memory store.
    /// Keys that fail to decrypt (e.g., KEK changed) are logged but don't stop loading.
    pub async fn load_keys(&self) -> Result<()> {
        let keys = self.repo.list_all_tenants(None, None).await?;

        for meta in keys {
            match self.repo.find_encrypted_material(&meta.id).await? {
                Some(encrypted) => match self.decrypt_material(&encrypted) {
                    Ok(material) => {
                        let entry = KeyEntry {
                            meta: meta.clone(),
                            material: Zeroizing::new(material),
                        };
                        self.keys.write().await.insert(meta.id, entry);
                        tracing::info!("Loaded key {} from database", meta.id);
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to decrypt key {} from database: {}. \
                                This may indicate the KEK has changed.",
                            meta.id,
                            e
                        );
                    }
                },
                None => {
                    tracing::warn!(
                        "Key {} found in DB but has no encrypted material. \
                        It may have been created before persistence was enabled.",
                        meta.id
                    );
                }
            }
        }

        Ok(())
    }

    /// Get the version history of a key
    pub async fn get_key_versions(
        &self,
        key_id: &Uuid,
    ) -> Result<Vec<super::repository::KeyVersionEntity>> {
        self.repo
            .list_versions(key_id)
            .await
            .map_err(|e| Error::Internal(e.to_string()))
    }

    /// Get a specific version of a key
    pub async fn get_key_version(
        &self,
        key_id: &Uuid,
        version: u32,
    ) -> Result<Option<super::repository::KeyVersionEntity>> {
        self.repo
            .get_version(key_id, version)
            .await
            .map_err(|e| Error::Internal(e.to_string()))
    }

    async fn crypto_encrypt(
        material: &[u8],
        spec: &KeySpec,
        key_id: &Uuid,
        version: u32,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Ciphertext> {
        match spec {
            KeySpec::Aes256Gcm | KeySpec::HmacSha256 => {
                use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

                let unbound_key = UnboundKey::new(&AES_256_GCM, material)
                    .map_err(|e| Error::EncryptionFailed(e.to_string()))?;
                let sealing_key = LessSafeKey::new(unbound_key);

                // Generate random 12-byte nonce (CSPRNG)
                let mut nonce_bytes = [0u8; 12];
                SystemRandom::new()
                    .fill(&mut nonce_bytes)
                    .map_err(|_| Error::EncryptionFailed("failed to generate nonce".to_string()))?;
                let nonce = Nonce::assume_unique_for_key(nonce_bytes);

                // Use provided AAD or empty if not provided
                let aad_bytes = aad.unwrap_or(&[]);
                let aad = Aad::from(aad_bytes);

                let mut in_out = plaintext.to_vec();
                let tag = sealing_key
                    .seal_in_place_separate_tag(nonce, aad, &mut in_out)
                    .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

                Ok(Ciphertext {
                    key_id: *key_id,
                    version,
                    format_version: 1,
                    nonce: nonce_bytes.to_vec(),
                    ciphertext: in_out,
                    tag: tag.as_ref().to_vec(),
                })
            }
            KeySpec::Sm4 => {
                use gm_crypto::sm4::Sm4Cipher;

                let cipher =
                    Sm4Cipher::new(material).map_err(|e| Error::EncryptionFailed(e.to_string()))?;

                let mut nonce = [0u8; 12];
                SystemRandom::new()
                    .fill(&mut nonce)
                    .map_err(|_| Error::EncryptionFailed("failed to generate nonce".to_string()))?;

                // Use provided AAD or empty if not provided
                let aad_bytes = aad.unwrap_or(&[]);

                let (ciphertext, tag) = cipher
                    .encrypt_gcm(plaintext, &nonce, aad_bytes)
                    .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

                Ok(Ciphertext {
                    key_id: *key_id,
                    version,
                    format_version: 1,
                    nonce: nonce.to_vec(),
                    ciphertext,
                    tag,
                })
            }
            KeySpec::Sm2 => {
                use gm_crypto::sm2::{Sm2Encryptor, Sm2KeyPair};

                let key_pair = Sm2KeyPair::from_private_key(material)
                    .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

                let encryptor = Sm2Encryptor::new(&key_pair.public_key_bytes_uncompressed())
                    .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

                let encrypted = encryptor
                    .encrypt(plaintext)
                    .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

                // SM2 encrypted output format: C1 (65 bytes) || C3 (32 bytes) || C2 (variable)
                let c1 = &encrypted[..65];
                let c3 = &encrypted[65..97];
                let c2 = &encrypted[97..];

                Ok(Ciphertext {
                    key_id: *key_id,
                    version,
                    format_version: 1,
                    nonce: c1.to_vec(),
                    ciphertext: c2.to_vec(),
                    tag: c3.to_vec(),
                })
            }
            _ => Err(Error::InvalidAlgorithm(format!(
                "Encryption not supported for {:?}",
                spec
            ))),
        }
    }

    async fn crypto_decrypt(
        material: &[u8],
        spec: &KeySpec,
        ciphertext: &Ciphertext,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match spec {
            KeySpec::Aes256Gcm | KeySpec::HmacSha256 => {
                use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

                let unbound_key = UnboundKey::new(&AES_256_GCM, material)
                    .map_err(|e| Error::DecryptionFailed(e.to_string()))?;
                let opening_key = LessSafeKey::new(unbound_key);

                // Use nonce from ciphertext
                if ciphertext.nonce.len() != 12 {
                    return Err(Error::InvalidCiphertext);
                }
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes.copy_from_slice(&ciphertext.nonce);
                let nonce = Nonce::assume_unique_for_key(nonce_bytes);

                // Use provided AAD or empty if not provided
                let aad_bytes = aad.unwrap_or(&[]);
                let aad = Aad::from(aad_bytes);

                let mut in_out = ciphertext.ciphertext.clone();
                in_out.extend_from_slice(&ciphertext.tag);

                let plaintext = opening_key
                    .open_in_place(nonce, aad, &mut in_out)
                    .map_err(|_| Error::InvalidCiphertext)?;

                Ok(plaintext.to_vec())
            }
            KeySpec::Sm4 => {
                use gm_crypto::sm4::Sm4Cipher;

                let cipher =
                    Sm4Cipher::new(material).map_err(|e| Error::DecryptionFailed(e.to_string()))?;

                // Use provided AAD or empty if not provided
                let aad_bytes = aad.unwrap_or(&[]);

                let plaintext = cipher
                    .decrypt_gcm(
                        &ciphertext.ciphertext,
                        &ciphertext.nonce,
                        aad_bytes,
                        &ciphertext.tag,
                    )
                    .map_err(|_| Error::InvalidCiphertext)?;

                Ok(plaintext)
            }
            KeySpec::Sm2 => {
                use gm_crypto::sm2::{Sm2Decryptor, Sm2KeyPair};

                let key_pair = Sm2KeyPair::from_private_key(material)
                    .map_err(|e| Error::DecryptionFailed(e.to_string()))?;

                // Reconstruct SM2 ciphertext: C1 || C3 || C2
                let c1 = &ciphertext.nonce;
                let c3 = &ciphertext.tag;
                let c2 = &ciphertext.ciphertext;

                if c1.len() != 65 || c3.len() != 32 {
                    return Err(Error::InvalidCiphertext);
                }

                let mut encrypted_data = Vec::with_capacity(65 + 32 + c2.len());
                encrypted_data.extend_from_slice(c1);
                encrypted_data.extend_from_slice(c3);
                encrypted_data.extend_from_slice(c2);

                let decryptor = Sm2Decryptor::new(key_pair);
                let plaintext = decryptor
                    .decrypt(&encrypted_data)
                    .map_err(|_| Error::InvalidCiphertext)?;

                Ok(plaintext)
            }
            _ => Err(Error::InvalidAlgorithm(format!(
                "Decryption not supported for {:?}",
                spec
            ))),
        }
    }

    async fn crypto_sign(
        material: &[u8],
        spec: &KeySpec,
        key_id: &Uuid,
        version: u32,
        data: &[u8],
    ) -> Result<Signature> {
        match spec {
            KeySpec::Ed25519 => {
                use ring::signature::Ed25519KeyPair;

                let key_pair = Ed25519KeyPair::from_seed_unchecked(material)
                    .map_err(|e| Error::SignatureFailed(e.to_string()))?;

                let signature_bytes = key_pair.sign(data).as_ref().to_vec();

                Ok(Signature {
                    key_id: *key_id,
                    version,
                    signature: signature_bytes,
                })
            }
            KeySpec::Sm2 => {
                use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer};

                let key_pair = Sm2KeyPair::from_private_key(material)
                    .map_err(|e| Error::SignatureFailed(e.to_string()))?;
                let signer =
                    Sm2Signer::new(&key_pair).map_err(|e| Error::SignatureFailed(e.to_string()))?;
                let sig = signer
                    .sign(data)
                    .map_err(|e| Error::SignatureFailed(e.to_string()))?;

                Ok(Signature {
                    key_id: *key_id,
                    version,
                    signature: sig,
                })
            }
            _ => Err(Error::InvalidAlgorithm(format!(
                "Signing not supported for {:?}",
                spec
            ))),
        }
    }

    async fn crypto_verify(
        material: &[u8],
        spec: &KeySpec,
        _key_id: &Uuid,
        data: &[u8],
        sig: &Signature,
    ) -> Result<bool> {
        match spec {
            KeySpec::Ed25519 => {
                use ring::signature::{ED25519, UnparsedPublicKey};

                let key_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(material)
                    .map_err(|e| Error::VerificationFailed(e.to_string()))?;

                let public_key = UnparsedPublicKey::new(&ED25519, key_pair.public_key().as_ref());
                Ok(public_key.verify(data, sig.signature.as_ref()).is_ok())
            }
            KeySpec::Sm2 => {
                use gm_crypto::sm2::{Sm2KeyPair, Sm2Verifier};

                let key_pair = Sm2KeyPair::from_private_key(material)
                    .map_err(|e| Error::VerificationFailed(e.to_string()))?;
                let verifier = Sm2Verifier::new(&key_pair.public_key_bytes(), key_pair.distid())
                    .map_err(|e| Error::VerificationFailed(e.to_string()))?;
                match verifier.verify(data, &sig.signature) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            _ => Err(Error::InvalidAlgorithm(format!(
                "Verification not supported for {:?}",
                spec
            ))),
        }
    }
}

#[async_trait]
impl super::KeystoreBackend for PostgresKeystore {
    fn backend_type(&self) -> BackendType {
        BackendType::Database
    }

    async fn generate_key(&self, spec: &KeySpec, name: &str, tenant_id: &str) -> Result<KeyMeta> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let material = Self::generate_key_material(spec)?;

        // Encrypt material with KEK for storage
        let encrypted_material = self.encrypt_material(&material)?;

        let meta = KeyMeta {
            id,
            tenant_id: tenant_id.to_string(),
            name: name.to_string(),
            spec: spec.clone(),
            status: KeyStatus::Active,
            created_at: now,
            rotated_at: None,
            version: 1,
            description: None,
            metadata: Default::default(),
        };

        let entry = KeyEntry {
            meta: meta.clone(),
            material: Zeroizing::new(material),
        };

        // Store in memory
        self.keys.write().await.insert(id, entry);

        // Persist metadata to PostgreSQL (with encrypted material)
        self.repo
            .insert(&meta)
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;

        // Store encrypted material
        self.repo
            .update_encrypted_material(&id, &encrypted_material)
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(meta)
    }

    async fn get_key_metadata(&self, key_id: &Uuid) -> Result<KeyMeta> {
        // Try in-memory first
        {
            let keys = self.keys.read().await;
            if let Some(entry) = keys.get(key_id) {
                return Ok(entry.meta.clone());
            }
        }

        // Fall back to PostgreSQL
        self.repo
            .find_by_id(key_id)
            .await?
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))
    }

    async fn encrypt(
        &self,
        key_id: &Uuid,
        plaintext: &[u8],
        _aad: Option<&[u8]>,
        _tenant_id: &str,
    ) -> Result<Ciphertext> {
        // Get key material from memory
        let entry = {
            let keys = self.keys.read().await;
            keys.get(key_id).cloned()
        }
        .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        if entry.meta.status != KeyStatus::Active {
            return Err(Error::KeyOperationNotAllowed(format!(
                "Key {key_id} is not active")));
        }

        Self::crypto_encrypt(
            &entry.material,
            &entry.meta.spec,
            key_id,
            entry.meta.version,
            plaintext,
            _aad,
        )
        .await
    }

    async fn decrypt(
        &self,
        key_id: &Uuid,
        ciphertext: &Ciphertext,
        _aad: Option<&[u8]>,
        _tenant_id: &str,
    ) -> Result<Vec<u8>> {
        let entry = {
            let keys = self.keys.read().await;
            keys.get(key_id).cloned()
        }
        .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        if !entry.meta.status.can_decrypt() {
            return Err(Error::KeyOperationNotAllowed(format!(
                "Key {key_id} cannot decrypt")));
        }

        Self::crypto_decrypt(&entry.material, &entry.meta.spec, ciphertext, _aad).await
    }

    async fn sign(&self, key_id: &Uuid, data: &[u8], _tenant_id: &str) -> Result<Signature> {
        let entry = {
            let keys = self.keys.read().await;
            keys.get(key_id).cloned()
        }
        .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        if entry.meta.status != KeyStatus::Active {
            return Err(Error::KeyOperationNotAllowed(format!(
                "Key {key_id} is not active")));
        }

        Self::crypto_sign(
            &entry.material,
            &entry.meta.spec,
            key_id,
            entry.meta.version,
            data,
        )
        .await
    }

    async fn verify(
        &self,
        key_id: &Uuid,
        data: &[u8],
        sig: &Signature,
        _tenant_id: &str,
    ) -> Result<bool> {
        let entry = {
            let keys = self.keys.read().await;
            keys.get(key_id).cloned()
        }
        .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        Self::crypto_verify(&entry.material, &entry.meta.spec, key_id, data, sig).await
    }

    async fn rotate_key(&self, key_id: &Uuid, _tenant_id: &str) -> Result<KeyMeta> {
        let (old_meta, new_meta, old_material) = {
            let mut keys = self.keys.write().await;
            let entry = keys
                .get_mut(key_id)
                .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

            if !entry.meta.status.can_rotate() {
                return Err(Error::KeyOperationNotAllowed(format!(
                    "Key {key_id} cannot be rotated")));
            }

            entry.meta.status = KeyStatus::Obsolete;
            let old_meta = entry.meta.clone();
            let old_material = entry.material.clone();
            let new_material = Self::generate_key_material(&entry.meta.spec)?;

            let new_id = Uuid::new_v4();
            let new_meta = KeyMeta {
                id: new_id,
                tenant_id: entry.meta.tenant_id.clone(),
                name: entry.meta.name.clone(),
                spec: entry.meta.spec.clone(),
                status: KeyStatus::Active,
                created_at: Utc::now(),
                rotated_at: Some(entry.meta.created_at),
                version: entry.meta.version + 1,
                description: entry.meta.description.clone(),
                metadata: entry.meta.metadata.clone(),
            };

            let new_entry = KeyEntry {
                meta: new_meta.clone(),
                material: Zeroizing::new(new_material),
            };

            keys.insert(new_id, new_entry);
            (old_meta, new_meta, old_material)
        };

        // Persist new key metadata and update old key status
        self.repo
            .insert(&new_meta)
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;
        self.repo
            .update_status(&old_meta.id, KeyStatus::Obsolete)
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;

        // Store version history with KEK-encrypted DEK (AES-256-GCM).
        // Explicit drop of old_material right after encryption ensures the
        // plaintext clone does not outlive the IO operation.
        let encrypted_dek = self.encrypt_material(&old_material)?;
        drop(old_material);
        self.repo
            .insert_version(
                &old_meta.id,
                old_meta.version,
                Some(&encrypted_dek),
                "Rotated",
            )
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;

        // Update the rotated_at timestamp for the old version
        self.repo
            .update_version_rotated_at(&old_meta.id, old_meta.version)
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(new_meta)
    }

    async fn delete_key(&self, key_id: &Uuid, _tenant_id: &str) -> Result<()> {
        {
            let mut keys = self.keys.write().await;
            let entry = keys
                .get_mut(key_id)
                .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

            entry.meta.status = KeyStatus::PendingDeletion;
        }

        // Soft delete in PostgreSQL
        self.repo
            .soft_delete(key_id, "kms-system")
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(())
    }

    async fn destroy_key(&self, key_id: &Uuid) -> Result<()> {
        {
            let mut keys = self.keys.write().await;
            keys.remove(key_id)
                .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;
        }

        Ok(())
    }

    async fn destroy_key_with_proof(&self, key_id: &Uuid) -> Result<DestructionProof> {
        let (material_hash, key_size) = {
            let mut keys = self.keys.write().await;
            let mut entry = keys
                .remove(key_id)
                .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

            // Compute hash of key material before removal for audit trail
            let hash = hex::encode(digest::digest(&digest::SHA256, &entry.material).as_ref());
            let size = entry.material.len();

            // Securely zero the material before dropping
            entry.material.iter_mut().for_each(|b| *b = 0);

            (hash, size)
        };

        Ok(DestructionProof::new(
            *key_id,
            material_hash,
            key_size,
            true,
            None, // hmac_signature - should be added during proof storage with proper key
        ))
    }

    async fn list_keys(&self, filter: &KeyFilter) -> Result<Vec<KeyMeta>> {
        let tenant_id = filter.tenant_id.as_deref().ok_or_else(|| {
            Error::Internal(
                "list_keys called without tenant_id — tenant isolation violated".to_string(),
            )
        })?;
        self.repo
            .list(
                tenant_id,
                filter
                    .status
                    .as_ref()
                    .map(|s| format!("{:?}", s))
                    .as_deref(),
                filter.limit.map(|l| l as i64),
                filter.offset.map(|o| o as i64),
            )
            .await
            .map_err(|e| Error::Internal(e.to_string()))
    }

    async fn health(&self) -> Result<kms_core::types::HealthStatus> {
        // Use internal sentinel; health only needs to verify DB reachability.
        match self.repo.list_all_tenants(Some(1), None).await {
            Ok(_) => Ok(kms_core::types::HealthStatus::Healthy),
            Err(_) => Ok(kms_core::types::HealthStatus::Degraded),
        }
    }

    async fn import_key_material(
        &self,
        spec: &KeySpec,
        name: &str,
        tenant_id: &str,
        material: Vec<u8>,
    ) -> Result<KeyMeta> {
        // Validate material size matches the spec
        let expected_size = match spec {
            KeySpec::Aes256Gcm | KeySpec::HmacSha256 => 32,
            KeySpec::Sm4 => 16,
            KeySpec::Sm2 => 32,
            KeySpec::Ed25519 => 32,
            KeySpec::EcdsaP256 => 32,
            KeySpec::EcdsaP384 => 48,
            KeySpec::Ed448 => 57,
            KeySpec::Rsa4096 => 512,
            KeySpec::Sm9Signing | KeySpec::Sm9Encryption => 0,
        };

        if expected_size > 0 && material.len() != expected_size {
            return Err(Error::InvalidAlgorithm(format!(
                "expected {} bytes for {:?}, got {}",
                expected_size,
                spec,
                material.len()
            )));
        }

        let id = Uuid::new_v4();
        let now = Utc::now();

        let meta = KeyMeta {
            id,
            tenant_id: tenant_id.to_string(),
            name: name.to_string(),
            spec: spec.clone(),
            status: KeyStatus::Active,
            created_at: now,
            rotated_at: None,
            version: 1,
            description: Some("imported".to_string()),
            metadata: Default::default(),
        };

        // Encrypt material with KEK for storage (before moving to Zeroizing)
        let encrypted_material = self.encrypt_material(&material)?;

        let entry = KeyEntry {
            meta: meta.clone(),
            material: Zeroizing::new(material),
        };

        // Store in memory
        self.keys.write().await.insert(id, entry);

        // Persist metadata to PostgreSQL
        self.repo
            .insert(&meta)
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;

        // Store encrypted material
        self.repo
            .update_encrypted_material(&id, &encrypted_material)
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(meta)
    }

    async fn export_key_material(&self, key_id: &Uuid, _tenant_id: &str) -> Result<Vec<u8>> {
        // Get key material from memory
        let entry = {
            let keys = self.keys.read().await;
            keys.get(key_id).cloned()
        }
        .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        if entry.meta.status != KeyStatus::Active {
            return Err(Error::KeyOperationNotAllowed(format!(
                "Key {key_id} is not active for export")));
        }

        Ok(entry.material.to_vec())
    }

    async fn get_key_material(&self, key_id: &Uuid, _tenant_id: &str) -> Result<Vec<u8>> {
        // Get key material from memory
        let entry = {
            let keys = self.keys.read().await;
            keys.get(key_id).cloned()
        }
        .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        Ok(entry.material.to_vec())
    }

    async fn derive_shared_secret(
        &self,
        key_id: &Uuid,
        peer_public_key: &[u8],
        algorithm: kms_core::dh::DhAlgorithm,
    ) -> Result<SharedSecret> {
        use kms_core::dh::SharedSecret;

        // Get key material from memory
        let entry = {
            let keys = self.keys.read().await;
            keys.get(key_id).cloned()
        }
        .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        // Use SoftwareKeystore's DH derivation methods
        let store = SoftwareKeystore::new();
        let shared_secret = match algorithm {
            kms_core::dh::DhAlgorithm::EcdsaP256 => {
                store.derive_ecdh_p256(&entry.material, peer_public_key)?
            }
            kms_core::dh::DhAlgorithm::EcdsaP384 => {
                store.derive_ecdh_p384(&entry.material, peer_public_key)?
            }
            kms_core::dh::DhAlgorithm::X25519 => {
                store.derive_x25519(&entry.material, peer_public_key)?
            }
            kms_core::dh::DhAlgorithm::Sm2Kex => {
                store.derive_sm2_kex(&entry.material, peer_public_key)?
            }
        };

        Ok(SharedSecret {
            secret: shared_secret,
            kdf: Some("HKDF-SHA256".to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::KeystoreBackend;

    #[tokio::test]
    #[ignore] // Requires running server (Redis/PostgreSQL)
    async fn test_postgres_keystore_basic() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://kms:kms123@localhost:5432/kms".to_string());

        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("Failed to connect to PostgreSQL");

        let repo = PostgresKeyRepository::new(pool);
        repo.migrate().await.expect("Migration failed");

        let keystore = PostgresKeystore::new(repo)
            .await
            .expect("Failed to create keystore");

        // Generate a key
        let spec = KeySpec::Aes256Gcm;
        let meta = keystore
            .generate_key(&spec, "pg-test-key", "test-tenant")
            .await
            .expect("Failed to generate key");

        assert_eq!(meta.name, "pg-test-key");
        assert_eq!(meta.tenant_id, "test-tenant");

        // Get metadata
        let fetched = keystore
            .get_key_metadata(&meta.id)
            .await
            .expect("Failed to get metadata");
        assert_eq!(fetched.id, meta.id);

        // Encrypt/Decrypt
        let plaintext = b"Hello from PostgreSQL!";
        let ciphertext = keystore
            .encrypt(&meta.id, plaintext, None, "test-tenant")
            .await
            .expect("Failed to encrypt");
        let decrypted = keystore
            .decrypt(&meta.id, &ciphertext, None, "test-tenant")
            .await
            .expect("Failed to decrypt");
        assert_eq!(&decrypted, plaintext);

        println!("PostgreSQL keystore basic test passed!");
    }

    #[tokio::test]
    #[ignore] // Requires running server (Redis/PostgreSQL)
    async fn test_postgres_keystore_rotation() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://kms:kms123@localhost:5432/kms".to_string());

        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("Failed to connect to PostgreSQL");

        let repo = PostgresKeyRepository::new(pool);
        repo.migrate().await.expect("Migration failed");

        let keystore = PostgresKeystore::new(repo)
            .await
            .expect("Failed to create keystore");

        // Generate a key
        let spec = KeySpec::Aes256Gcm;
        let original = keystore
            .generate_key(&spec, "rotate-test-key", "test-tenant")
            .await
            .expect("Failed to generate key");

        let original_version = original.version;

        // Rotate the key
        let rotated = keystore
            .rotate_key(&original.id, "test-tenant")
            .await
            .expect("Failed to rotate key");

        assert!(rotated.version > original_version);

        // Check version history
        let versions = keystore
            .get_key_versions(&original.id)
            .await
            .expect("Failed to get versions");
        assert!(!versions.is_empty());

        println!("PostgreSQL keystore rotation test passed!");
    }
}
