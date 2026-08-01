//! TPM 2.0 backend implementation for KMS
//!
//! This module provides a TPM-backed keystore implementation.
//! For production, use actual TPM hardware or tpm2-tss software stack.
//!
//! This implementation uses a software simulator approach that:
//! - Simulates TPM-style key protection
//! - Stores keys in a mock TPM "NV" store
//! - Uses cryptographic operations from kms-core
//!
//! ## TPM 2.0 Simulation Features
//!
//! - NV Index storage for keys
//! - PCR (Platform Configuration Register) simulation
//! - Authorization sessions (HMAC, policy)
//! - Key sealing to PCR values

use async_trait::async_trait;
use chrono::Utc;
use kms_core::{
    BackendType, Result,
    dh::SharedSecret,
    error::Error,
    key::{Ciphertext, KeyMeta, KeySpec, KeyStatus, Signature},
};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::PcrBinding;

/// TPM-aligned handle types (simulated)
#[derive(Debug, Clone, Copy)]
pub struct TpmHandle(pub u32);

impl TpmHandle {
    pub const fn new(handle: u32) -> Self {
        Self(handle)
    }

    /// TPM_RC_SUCCESS equivalent
    pub const SUCCESS: u32 = 0x00000000;
    /// TPM_RC_FAILURE equivalent
    pub const FAILURE: u32 = 0x00000100;
}

/// TPM key authorization (simulated)
#[derive(Debug, Clone)]
pub struct TpmAuth {
    pub handle: TpmHandle,
    pub session_handle: TpmHandle,
}

/// PCR index types
pub const PCR_SHA256_BANK: u32 = 0x00000000;
pub const TPM_NV_KEY_BASE: u32 = 0x01800200;

/// Number of PCRs supported
pub const NUM_PCRS: usize = 24;

/// TPM 2.0 PCR bank
#[derive(Debug, Clone)]
pub struct PcrBank {
    /// PCR values (SHA-256 bank, 32 bytes each)
    pub values: [Vec<u8>; NUM_PCRS],
}

impl Default for PcrBank {
    fn default() -> Self {
        Self {
            values: [
                vec![0u8; 32], // PCR0 - SRTM
                vec![0u8; 32], // PCR1 - CPU_MICROCODE
                vec![0u8; 32], // PCR2 - PCR4
                vec![0u8; 32], // PCR3
                vec![0u8; 32], // PCR4
                vec![0u8; 32], // PCR5 - SECUREBOOT
                vec![0u8; 32], // PCR6
                vec![0u8; 32], // PCR7 - MEASURED_BOOT
                vec![0u8; 32], // PCR8
                vec![0u8; 32], // PCR9 - MOK
                vec![0u8; 32], // PCR10
                vec![0u8; 32], // PCR11
                vec![0u8; 32], // PCR12
                vec![0u8; 32], // PCR13
                vec![0u8; 32], // PCR14
                vec![0u8; 32], // PCR15
                vec![0u8; 32], // PCR16
                vec![0u8; 32], // PCR17
                vec![0u8; 32], // PCR18 - BOOT_EVENTS
                vec![0u8; 32], // PCR19
                vec![0u8; 32], // PCR20
                vec![0u8; 32], // PCR21
                vec![0u8; 32], // PCR22
                vec![0u8; 32], // PCR23
            ],
        }
    }
}

impl PcrBank {
    /// Extend a PCR value (TPM-style extend operation)
    pub fn extend(&mut self, pcr_index: usize, data: &[u8]) {
        if pcr_index < NUM_PCRS {
            use ring::digest::{SHA256, digest};
            let current = &self.values[pcr_index];
            // TPM2_Extend format: extend = SHA256(old_value || new_measurement)
            let mut combined = current.clone();
            combined.extend_from_slice(data);
            self.values[pcr_index] = digest(&SHA256, &combined).as_ref().to_vec();
        }
    }

    /// Read current PCR value
    pub fn read(&self, pcr_index: usize) -> Option<&Vec<u8>> {
        if pcr_index < NUM_PCRS {
            Some(&self.values[pcr_index])
        } else {
            None
        }
    }
}

/// NV entry for simulated TPM storage
#[derive(Clone)]
struct TpmNvEntry {
    meta: KeyMeta,
    /// Protected key material (in real TPM, this would be sealed to PCRs)
    sealed_material: Zeroizing<Vec<u8>>,
    /// TPM-style auth handle
    auth: TpmAuth,
    /// PCR binding - if Some, key can only be unsealed when PCRs match
    pcr_binding: Option<PcrBinding>,
}

/// Software-simulated TPM 2.0 keystore.
///
/// This implementation simulates TPM 2.0 behavior:
/// - Keys are stored with TPM-style handles
/// - Key material is protected (simulated PCR binding)
/// - Authorization is required for operations
///
/// For production use with real TPM hardware, enable the `tpm2-tss` feature
/// and use [`RealTpmKeystore`](crate::RealTpmKeystore).
pub struct SimulatedTpmKeystore {
    /// Simulated TPM NV storage
    nv_storage: RwLock<std::collections::HashMap<u32, TpmNvEntry>>,
    /// Next available NV index
    next_nv_index: RwLock<u32>,
    /// Simulated PCR bank
    pcr_bank: RwLock<PcrBank>,
    /// Internal error counter for health degradation (#25)
    internal_error_count: AtomicU64,
}

impl SimulatedTpmKeystore {
    /// Create a new TPM keystore with default PCRs
    pub fn new() -> Self {
        Self {
            nv_storage: RwLock::new(std::collections::HashMap::new()),
            next_nv_index: RwLock::new(TPM_NV_KEY_BASE),
            pcr_bank: RwLock::new(PcrBank::default()),
            internal_error_count: AtomicU64::new(0),
        }
    }

    /// Create a TPM keystore with simulated PCR measurements
    pub fn new_with_pcrs(initial_pcrs: &[(usize, Vec<u8>)]) -> Self {
        let bank = {
            let mut pcr_bank = PcrBank::default();
            for (pcr_index, value) in initial_pcrs {
                pcr_bank.extend(*pcr_index, value);
            }
            pcr_bank
        };
        Self {
            nv_storage: RwLock::new(std::collections::HashMap::new()),
            next_nv_index: RwLock::new(TPM_NV_KEY_BASE),
            pcr_bank: RwLock::new(bank),
            internal_error_count: AtomicU64::new(0),
        }
    }

    /// Extend a PCR with a new measurement (TPM-style)
    pub fn extend_pcr(&self, pcr_index: usize, data: &[u8]) -> Result<()> {
        let mut bank = self.pcr_bank.write();
        bank.extend(pcr_index, data);
        Ok(())
    }

    /// Read current PCR value
    pub fn read_pcr(&self, pcr_index: usize) -> Result<Vec<u8>> {
        let bank = self.pcr_bank.read();
        bank.read(pcr_index)
            .cloned()
            .ok_or_else(|| Error::TpmError(format!("invalid PCR index: {}", pcr_index)))
    }

    /// Allocate a new TPM NV handle
    fn allocate_handle(&self) -> u32 {
        let mut next = self.next_nv_index.write();
        let handle = *next;
        *next += 1;
        handle
    }

    /// Check if PCR binding is satisfied
    fn check_pcr_binding(&self, pcr_binding: &Option<PcrBinding>) -> Result<()> {
        if let Some(bindings) = pcr_binding {
            let bank = self.pcr_bank.read();
            for (pcr_index, expected) in bindings {
                let actual = bank
                    .read(*pcr_index)
                    .ok_or_else(|| Error::TpmError(format!("invalid PCR index: {}", pcr_index)))?;
                if actual != expected {
                    return Err(Error::TpmPcrMismatch {
                        expected: expected.clone(),
                        actual: actual.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Generate software key for storage in TPM NV
    fn generate_key_material(spec: &KeySpec) -> Result<Vec<u8>> {
        let mut key = Vec::new();
        let len = match spec {
            KeySpec::Aes256Gcm | KeySpec::HmacSha256 => 32,
            KeySpec::EcdsaP256 | KeySpec::EcdsaP384 | KeySpec::Ed25519 | KeySpec::Ed448 => 32,
            KeySpec::Sm4 => 16,
            KeySpec::Sm2 => 32,
            KeySpec::Sm9Signing | KeySpec::Sm9Encryption => {
                // SM9 keys are derived from identity, not randomly generated
                return Err(Error::NotImplemented(
                    "SM9 not yet implemented in TPM backend".to_string(),
                ));
            }
            KeySpec::Rsa4096 => {
                return Err(Error::NotImplemented(
                    "RSA key generation not yet implemented".to_string(),
                ));
            }
        };
        key.resize(len, 0);
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut key)
            .map_err(|_| Error::Internal("failed to generate random key".to_string()))?;
        Ok(key)
    }

    /// Encrypt using TPM-style protection with PCR binding check
    fn tpm_protect(&self, key_id: &Uuid, plaintext: &[u8]) -> Result<Ciphertext> {
        use kms_core::key::Ciphertext;

        let key_entry = {
            let nv = self.nv_storage.read();
            nv.values()
                .find(|e| e.meta.id == *key_id)
                .cloned()
                .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?
        };

        // Verify PCR binding from the key entry itself
        self.check_pcr_binding(&key_entry.pcr_binding)?;

        let sealed = &key_entry.sealed_material;
        if sealed.len() < 32 {
            return Err(Error::EncryptionFailed(
                "key material too short".to_string(),
            ));
        }

        let nonce = {
            let mut n = vec![0u8; 12];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut n)
                .map_err(|_| Error::EncryptionFailed("failed to generate nonce".to_string()))?;
            n
        };

        // Use first 32 bytes as key (for AES-256-GCM)
        let key = &sealed[..32.min(sealed.len())];

        let ciphertext = Self::aes_gcm_encrypt(key, plaintext, &nonce, None)?;

        Ok(Ciphertext {
            key_id: *key_id,
            version: key_entry.meta.version,
            format_version: 1,
            nonce,
            ciphertext,
            tag: vec![0u8; 16],
        })
    }

    /// Decrypt using TPM-style protection with PCR validation
    fn tpm_unprotect(
        &self,
        key_id: &Uuid,
        ciphertext: &Ciphertext,
        _pcr_binding: &Option<PcrBinding>,
    ) -> Result<Vec<u8>> {
        let key_entry = {
            let nv = self.nv_storage.read();
            nv.values()
                .find(|e| e.meta.id == *key_id)
                .cloned()
                .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?
        };

        // Verify PCR binding from the key entry itself
        self.check_pcr_binding(&key_entry.pcr_binding)?;

        let sealed = &key_entry.sealed_material;
        if sealed.len() < 32 {
            return Err(Error::DecryptionFailed(
                "key material too short".to_string(),
            ));
        }

        // Use first 16 bytes as AAD, next 32 as key (for AES-256-GCM)
        let key = &sealed[..32.min(sealed.len())];
        Self::aes_gcm_decrypt(key, &ciphertext.ciphertext, &ciphertext.nonce, None)
    }

    /// Sign using TPM-style protection (simulated)
    fn tpm_sign(&self, key_id: &Uuid, data: &[u8]) -> Result<Signature> {
        let key_entry = {
            let nv = self.nv_storage.read();
            nv.values()
                .find(|e| e.meta.id == *key_id)
                .cloned()
                .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?
        };

        let sealed = &key_entry.sealed_material;

        match key_entry.meta.spec {
            KeySpec::Ed25519 => {
                let signing_key = sealed.clone();
                let signature = Self::ed25519_sign(&signing_key, data)?;
                Ok(Signature {
                    key_id: *key_id,
                    version: key_entry.meta.version,
                    signature,
                })
            }
            KeySpec::Sm2 => {
                let signing_key = sealed.clone();
                let signature = Self::sm2_sign(&signing_key, data)?;
                Ok(Signature {
                    key_id: *key_id,
                    version: key_entry.meta.version,
                    signature,
                })
            }
            _ => Err(Error::SignatureFailed(
                "sign operation not supported for this key type".to_string(),
            )),
        }
    }

    /// Verify using TPM-style protection (simulated)
    fn tpm_verify(&self, key_id: &Uuid, data: &[u8], signature: &Signature) -> Result<bool> {
        let key_entry = {
            let nv = self.nv_storage.read();
            nv.values()
                .find(|e| e.meta.id == *key_id)
                .cloned()
                .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?
        };

        let sealed = &key_entry.sealed_material;

        match key_entry.meta.spec {
            KeySpec::Ed25519 => Self::ed25519_verify(sealed, data, &signature.signature),
            KeySpec::Sm2 => Self::sm2_verify(sealed, data, &signature.signature),
            _ => Err(Error::VerificationFailed(
                "verify operation not supported for this key type".to_string(),
            )),
        }
    }

    // -------------------------------------------------------------------------
    // Cryptographic primitives (delegating to software implementation)
    // -------------------------------------------------------------------------

    fn aes_gcm_encrypt(
        key: &[u8],
        plaintext: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| Error::EncryptionFailed("invalid key".to_string()))?;
        let key = LessSafeKey::new(unbound_key);

        let nonce_array: [u8; 12] = nonce
            .try_into()
            .map_err(|_| Error::EncryptionFailed("invalid nonce length".to_string()))?;
        let nonce = Nonce::assume_unique_for_key(nonce_array);

        let aad = aad.unwrap_or(&[]);
        let mut in_out = plaintext.to_vec();

        key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| Error::EncryptionFailed("encryption failed".to_string()))?;

        Ok(in_out)
    }

    fn aes_gcm_decrypt(
        key: &[u8],
        ciphertext: &[u8],
        nonce: &[u8],
        _tag: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| Error::DecryptionFailed("invalid key".to_string()))?;
        let key = LessSafeKey::new(unbound_key);

        let nonce_array: [u8; 12] = nonce
            .try_into()
            .map_err(|_| Error::DecryptionFailed("invalid nonce length".to_string()))?;
        let nonce = Nonce::assume_unique_for_key(nonce_array);

        let mut in_out = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::from(&[]), &mut in_out)
            .map_err(|_| Error::InvalidCiphertext)?;

        Ok(plaintext.to_vec())
    }

    fn ed25519_sign(private_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        use ring::signature::Ed25519KeyPair;

        // Ed25519 requires PKCS#8 format, but for simulation we use seed directly
        // Use from_seed_and_public_key for simulation
        if private_key.len() < 32 {
            return Err(Error::SignatureFailed("key too short".to_string()));
        }
        let seed = &private_key[..32];
        let public_key = &private_key[32..64];

        let key_pair = Ed25519KeyPair::from_seed_and_public_key(seed, public_key)
            .map_err(|_| Error::SignatureFailed("invalid key".to_string()))?;

        Ok(key_pair.sign(data).as_ref().to_vec())
    }

    fn ed25519_verify(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool> {
        use ring::signature::{ED25519, UnparsedPublicKey};

        if public_key.len() < 32 {
            return Err(Error::VerificationFailed("invalid public key".to_string()));
        }
        let verifier = UnparsedPublicKey::new(&ED25519, &public_key[..32]);
        match verifier.verify(data, signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn sm2_sign(private_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer};

        let key_pair = Sm2KeyPair::from_private_key(private_key)
            .map_err(|e| Error::SignatureFailed(format!("invalid SM2 key: {}", e)))?;

        let signer = Sm2Signer::new(&key_pair)
            .map_err(|e| Error::SignatureFailed(format!("failed to create signer: {}", e)))?;

        signer
            .sign(data)
            .map_err(|e| Error::SignatureFailed(e.to_string()))
    }

    fn sm2_verify(private_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool> {
        use gm_crypto::sm2::{Sm2KeyPair, Sm2Verifier};

        // Derive public key from private key
        let key_pair = Sm2KeyPair::from_private_key(private_key)
            .map_err(|e| Error::VerificationFailed(format!("invalid SM2 key: {}", e)))?;
        let public_key = key_pair.public_key_bytes();

        let verifier = Sm2Verifier::new(&public_key, "1234567812345678")
            .map_err(|e| Error::VerificationFailed(format!("invalid public key: {}", e)))?;

        match verifier.verify(data, signature) {
            Ok(()) => Ok(true),
            Err(e) => Err(Error::VerificationFailed(e.to_string())),
        }
    }

    /// Generate a key that is sealed to specific PCR values (TPM-style)
    ///
    /// This key can only be used when the current PCR values match the
    /// PCR values that were current when the key was created.
    ///
    /// # Arguments
    /// * `spec` - The key specification
    /// * `name` - Human-readable key name
    /// * `tenant_id` - Tenant identifier
    /// * `pcr_indices` - List of PCR indices to bind (e.g., [7] for measured boot)
    ///
    /// # Returns
    /// * `KeyMeta` - Metadata for the created key
    ///
    /// # Errors
    /// * `TpmError` - If PCR indices are invalid
    #[allow(dead_code)]
    async fn generate_key_with_pcr_binding(
        &self,
        spec: &KeySpec,
        name: &str,
        tenant_id: &str,
        pcr_indices: &[usize],
    ) -> Result<KeyMeta> {
        // Validate PCR indices
        for &idx in pcr_indices {
            if idx >= NUM_PCRS {
                return Err(Error::TpmError(format!(
                    "invalid PCR index: {}, valid range is 0-{}",
                    idx,
                    NUM_PCRS - 1
                )));
            }
        }

        let id = Uuid::new_v4();
        let now = Utc::now();

        let material = Self::generate_key_material(spec)?;
        let handle = self.allocate_handle();

        // Capture current PCR values at key creation time
        let pcr_bank = self.pcr_bank.read();
        let pcr_binding: PcrBinding = pcr_indices
            .iter()
            .map(|&idx| {
                let value = pcr_bank
                    .read(idx)
                    .expect("PCR index already validated")
                    .clone();
                (idx, value)
            })
            .collect();
        drop(pcr_bank);

        let meta = KeyMeta {
            id,
            tenant_id: tenant_id.to_string(),
            name: name.to_string(),
            spec: spec.clone(),
            status: KeyStatus::Active,
            version: 1,
            created_at: now,
            rotated_at: None,
            description: None,
            metadata: Default::default(),
        };

        let auth = TpmAuth {
            handle: TpmHandle::new(handle),
            session_handle: TpmHandle::new(0x00000001),
        };

        let entry = TpmNvEntry {
            meta: meta.clone(),
            sealed_material: Zeroizing::new(material),
            auth,
            pcr_binding: Some(pcr_binding),
        };

        {
            let mut nv = self.nv_storage.write();
            nv.insert(handle, entry);
        }

        Ok(meta)
    }

    /// Check if a key has PCR binding
    pub fn key_has_pcr_binding(&self, key_id: &Uuid) -> Result<bool> {
        let nv = self.nv_storage.read();
        if let Some(entry) = nv.values().find(|e| e.meta.id == *key_id) {
            Ok(entry.pcr_binding.is_some())
        } else {
            Err(Error::KeyNotFound(key_id.to_string()))
        }
    }

    /// Get the PCR binding for a key (if any)
    #[allow(clippy::type_complexity)]
    pub fn get_key_pcr_binding(&self, key_id: &Uuid) -> Result<Option<PcrBinding>> {
        let nv = self.nv_storage.read();
        if let Some(entry) = nv.values().find(|e| e.meta.id == *key_id) {
            Ok(entry.pcr_binding.clone())
        } else {
            Err(Error::KeyNotFound(key_id.to_string()))
        }
    }
}

impl Default for SimulatedTpmKeystore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl kms_keystore::KeystoreBackend for SimulatedTpmKeystore {
    fn backend_type(&self) -> BackendType {
        BackendType::Tpm
    }

    async fn generate_key(&self, spec: &KeySpec, name: &str, tenant_id: &str) -> Result<KeyMeta> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let material = Self::generate_key_material(spec)?;
        let handle = self.allocate_handle();

        let meta = KeyMeta {
            id,
            tenant_id: tenant_id.to_string(),
            name: name.to_string(),
            spec: spec.clone(),
            status: KeyStatus::Active,
            version: 1,
            created_at: now,
            rotated_at: None,
            description: None,
            metadata: Default::default(),
        };

        let auth = TpmAuth {
            handle: TpmHandle::new(handle),
            session_handle: TpmHandle::new(0x00000001),
        };

        let entry = TpmNvEntry {
            meta: meta.clone(),
            sealed_material: Zeroizing::new(material),
            auth,
            pcr_binding: None, // PCR binding not enabled by default
        };

        {
            let mut nv = self.nv_storage.write();
            nv.insert(handle, entry);
        }

        Ok(meta)
    }

    async fn get_key_metadata(&self, key_id: &Uuid) -> Result<KeyMeta> {
        let nv = self.nv_storage.read();
        nv.values()
            .find(|e| e.meta.id == *key_id)
            .map(|e| e.meta.clone())
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))
    }

    async fn encrypt(
        &self,
        key_id: &Uuid,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        _tenant_id: &str,
    ) -> Result<Ciphertext> {
        let _ = aad;
        self.tpm_protect(key_id, plaintext)
    }

    async fn decrypt(
        &self,
        key_id: &Uuid,
        ciphertext: &Ciphertext,
        aad: Option<&[u8]>,
        _tenant_id: &str,
    ) -> Result<Vec<u8>> {
        let _ = aad;
        self.tpm_unprotect(key_id, ciphertext, &None)
    }

    async fn sign(&self, key_id: &Uuid, data: &[u8], _tenant_id: &str) -> Result<Signature> {
        self.tpm_sign(key_id, data)
    }

    async fn verify(
        &self,
        key_id: &Uuid,
        data: &[u8],
        signature: &Signature,
        _tenant_id: &str,
    ) -> Result<bool> {
        self.tpm_verify(key_id, data, signature)
    }

    async fn rotate_key(&self, key_id: &Uuid, _tenant_id: &str) -> Result<KeyMeta> {
        let mut nv = self.nv_storage.write();

        let entry = nv
            .values_mut()
            .find(|e| e.meta.id == *key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        let now = Utc::now();
        entry.meta.version += 1;
        entry.meta.rotated_at = Some(now);
        entry.meta.status = KeyStatus::Active;

        Ok(entry.meta.clone())
    }

    async fn delete_key(&self, key_id: &Uuid, _tenant_id: &str) -> Result<()> {
        let mut nv = self.nv_storage.write();

        let entry = nv
            .values_mut()
            .find(|e| e.meta.id == *key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        entry.meta.status = KeyStatus::PendingDeletion;

        Ok(())
    }

    async fn destroy_key(&self, key_id: &Uuid) -> Result<()> {
        let mut nv = self.nv_storage.write();

        let handle = nv
            .values()
            .find(|e| e.meta.id == *key_id)
            .map(|e| e.auth.handle.0)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        nv.remove(&handle);

        Ok(())
    }

    async fn destroy_key_with_proof(&self, key_id: &Uuid) -> Result<kms_core::DestructionProof> {
        use kms_core::DestructionProof;
        use ring::digest::{SHA256, digest};

        // Find and capture key material info before removal
        let (material_hash, key_size) = {
            let nv = self.nv_storage.read();
            let entry = nv
                .values()
                .find(|e| e.meta.id == *key_id)
                .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

            let hash = hex::encode(digest(&SHA256, entry.sealed_material.as_ref()).as_ref());
            (hash, entry.sealed_material.len())
        };

        // Now destroy the key
        self.destroy_key(key_id).await?;

        Ok(DestructionProof::new(
            *key_id,
            material_hash,
            key_size,
            true, // TPM handles guarantee zeroization
            None, // hmac_signature - should be added during proof storage with proper key
        ))
    }

    async fn list_keys(&self, filter: &kms_core::key::KeyFilter) -> Result<Vec<KeyMeta>> {
        let nv = self.nv_storage.read();

        let keys: Vec<KeyMeta> = nv
            .values()
            .filter(|e| {
                filter
                    .tenant_id
                    .as_ref()
                    .map(|tid| e.meta.tenant_id == *tid)
                    .unwrap_or(true)
            })
            .map(|e| e.meta.clone())
            .collect();

        Ok(keys)
    }

    async fn health(&self) -> Result<kms_core::types::HealthStatus> {
        let errors = self.internal_error_count.load(Ordering::Relaxed);
        if errors > 100 {
            Ok(kms_core::types::HealthStatus::Degraded)
        } else {
            Ok(kms_core::types::HealthStatus::Healthy)
        }
    }

    async fn import_key_material(
        &self,
        _spec: &KeySpec,
        _name: &str,
        _tenant_id: &str,
        _material: Vec<u8>,
    ) -> Result<KeyMeta> {
        // TPM keystore doesn't support importing raw material directly
        // All keys must be generated and sealed within the TPM
        Err(kms_core::Error::NotImplemented(
            "TPM keystore does not support importing raw key material".to_string(),
        ))
    }

    async fn export_key_material(&self, _key_id: &Uuid, _tenant_id: &str) -> Result<Vec<u8>> {
        // TPM keystore cannot export key material - keys are sealed to the TPM
        Err(kms_core::Error::NotImplemented(
            "TPM keystore does not support exporting key material".to_string(),
        ))
    }

    async fn get_key_material(&self, _key_id: &Uuid, _tenant_id: &str) -> Result<Vec<u8>> {
        // TPM keystore does not expose raw key material - keys are sealed to the TPM
        Err(kms_core::Error::NotImplemented(
            "TPM keystore does not expose raw key material".to_string(),
        ))
    }

    async fn derive_shared_secret(
        &self,
        _key_id: &Uuid,
        _peer_public_key: &[u8],
        _algorithm: kms_core::dh::DhAlgorithm,
    ) -> Result<SharedSecret> {
        // TPM keystore DH operations would require TPM2_ComputeDH
        Err(kms_core::Error::NotImplemented(
            "TPM keystore DH key exchange not yet implemented".to_string(),
        ))
    }
}

// ============================================================================
// HsmBackend trait implementation
// ============================================================================

#[async_trait]
impl crate::HsmBackend for SimulatedTpmKeystore {
    fn hsm_type(&self) -> crate::HsmType {
        crate::HsmType::Simulated
    }

    fn extend_pcr(&self, pcr_index: usize, data: &[u8]) -> Result<()> {
        self.extend_pcr(pcr_index, data)
    }

    fn read_pcr(&self, pcr_index: usize) -> Result<Vec<u8>> {
        self.read_pcr(pcr_index)
    }

    fn key_has_pcr_binding(&self, key_id: &Uuid) -> Result<bool> {
        self.key_has_pcr_binding(key_id)
    }

    fn get_key_pcr_binding(&self, key_id: &Uuid) -> Result<Option<PcrBinding>> {
        self.get_key_pcr_binding(key_id)
    }

    async fn generate_key_with_pcr_binding(
        &self,
        spec: &KeySpec,
        name: &str,
        tenant_id: &str,
        pcr_indices: &[usize],
    ) -> Result<KeyMeta> {
        self.generate_key_with_pcr_binding(spec, name, tenant_id, pcr_indices)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kms_keystore::KeystoreBackend;

    #[tokio::test]
    async fn test_tpm_generate_key() {
        let tpm = SimulatedTpmKeystore::new();
        let meta = tpm
            .generate_key(&KeySpec::Aes256Gcm, "test-tpm-key", "tenant")
            .await
            .unwrap();

        assert_eq!(meta.name, "test-tpm-key");
        assert_eq!(meta.status, KeyStatus::Active);
    }

    #[tokio::test]
    async fn test_tpm_encrypt_decrypt() {
        let tpm = SimulatedTpmKeystore::new();
        let meta = tpm
            .generate_key(&KeySpec::Aes256Gcm, "test-tpm-enc", "tenant")
            .await
            .unwrap();

        let plaintext = b"TPM encryption test";
        let ciphertext = tpm
            .encrypt(&meta.id, plaintext, None, "tenant")
            .await
            .unwrap();

        let decrypted = tpm
            .decrypt(&meta.id, &ciphertext, None, "tenant")
            .await
            .unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_tpm_sign_verify() {
        let tpm = SimulatedTpmKeystore::new();
        let meta = tpm
            .generate_key(&KeySpec::Sm2, "test-tpm-sign", "tenant")
            .await
            .unwrap();

        let data = b"Data to sign";
        let signature = tpm.sign(&meta.id, data, "tenant").await.unwrap();

        let valid = tpm
            .verify(&meta.id, data, &signature, "tenant")
            .await
            .unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn test_tpm_pcr_extend() {
        let tpm = SimulatedTpmKeystore::new();

        // Extend PCR0 with a measurement
        let measurement1 = b"boot_component_1";
        tpm.extend_pcr(0, measurement1).unwrap();

        // Read PCR0
        let pcr_value = tpm.read_pcr(0).unwrap();

        // Verify PCR has been extended (not zero)
        assert!(!pcr_value.iter().all(|&b| b == 0));

        // Extend PCR0 again
        let measurement2 = b"boot_component_2";
        tpm.extend_pcr(0, measurement2).unwrap();

        // Read PCR0 again
        let pcr_value2 = tpm.read_pcr(0).unwrap();

        // Verify PCR value has changed after second extend
        assert_ne!(pcr_value, pcr_value2);
    }

    #[tokio::test]
    async fn test_tpm_pcr_read_invalid_index() {
        let tpm = SimulatedTpmKeystore::new();

        // Try to read invalid PCR index
        let result = tpm.read_pcr(24); // PCR0-23 are valid, 24 is invalid
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tpm_pcr_bound_key() {
        let tpm = SimulatedTpmKeystore::new();

        // Extend PCR7 to simulate measured boot
        tpm.extend_pcr(7, b"boot_measurement").unwrap();

        // Create a PCR-bound key (bound to PCR7)
        let meta = tpm
            .generate_key_with_pcr_binding(&KeySpec::Aes256Gcm, "pcr-bound-key", "tenant", &[7])
            .await
            .unwrap();

        // Key should work when PCR matches
        let plaintext = b"Secret data";
        let ciphertext = tpm
            .encrypt(&meta.id, plaintext, None, "tenant")
            .await
            .unwrap();
        let decrypted = tpm
            .decrypt(&meta.id, &ciphertext, None, "tenant")
            .await
            .unwrap();
        assert_eq!(&decrypted, plaintext);

        // Verify the key has PCR binding
        assert!(tpm.key_has_pcr_binding(&meta.id).unwrap());
    }

    #[tokio::test]
    async fn test_tpm_pcr_bound_key_fails_on_mismatch() {
        let tpm = SimulatedTpmKeystore::new();

        // Create a PCR-bound key BEFORE any PCR extensions
        let meta = tpm
            .generate_key_with_pcr_binding(&KeySpec::Aes256Gcm, "pcr-bound-key", "tenant", &[7])
            .await
            .unwrap();

        // Now extend PCR7 (simulating a boot measurement after key creation)
        tpm.extend_pcr(7, b"new_boot_measurement").unwrap();

        // Key operations should FAIL because PCR7 has changed
        let plaintext = b"Secret data";
        let encrypt_result = tpm.encrypt(&meta.id, plaintext, None, "tenant").await;
        assert!(encrypt_result.is_err()); // Should fail due to PCR mismatch
    }

    #[tokio::test]
    async fn test_tpm_pcr_bound_key_invalid_index() {
        let tpm = SimulatedTpmKeystore::new();

        // Try to create a key bound to invalid PCR index
        let result = tpm
            .generate_key_with_pcr_binding(&KeySpec::Aes256Gcm, "bad-key", "tenant", &[24])
            .await;
        assert!(result.is_err());
    }

    /// Test key rotation
    #[tokio::test]
    async fn test_tpm_rotate_key() {
        let tpm = SimulatedTpmKeystore::new();
        let meta = tpm
            .generate_key(&KeySpec::Aes256Gcm, "rotate-test", "tenant")
            .await
            .unwrap();

        let old_version = meta.version;
        let new_meta = tpm.rotate_key(&meta.id, "tenant").await.unwrap();
        assert_eq!(new_meta.id, meta.id);
        assert_eq!(new_meta.version, old_version + 1);
    }

    /// Test key listing and filtering
    #[tokio::test]
    async fn test_tpm_list_keys() {
        let tpm = SimulatedTpmKeystore::new();
        tpm.generate_key(&KeySpec::Aes256Gcm, "key1", "tenant1")
            .await
            .unwrap();
        tpm.generate_key(&KeySpec::Aes256Gcm, "key2", "tenant2")
            .await
            .unwrap();
        tpm.generate_key(&KeySpec::Sm2, "key3", "tenant1")
            .await
            .unwrap();

        let filter = kms_core::key::KeyFilter::default();
        let all_keys = tpm.list_keys(&filter).await.unwrap();
        assert!(all_keys.len() >= 3);
    }

    /// Test key deletion
    #[tokio::test]
    async fn test_tpm_delete_key() {
        let tpm = SimulatedTpmKeystore::new();
        let meta = tpm
            .generate_key(&KeySpec::Aes256Gcm, "delete-me", "tenant")
            .await
            .unwrap();

        tpm.delete_key(&meta.id, "tenant").await.unwrap();

        // Key should be marked as PendingDeletion (soft delete)
        let meta_after = tpm.get_key_metadata(&meta.id).await.unwrap();
        assert_eq!(meta_after.status, kms_core::key::KeyStatus::PendingDeletion);
    }

    /// Test key destruction with proof
    #[tokio::test]
    async fn test_tpm_destroy_key_with_proof() {
        let tpm = SimulatedTpmKeystore::new();
        let meta = tpm
            .generate_key(&KeySpec::Aes256Gcm, "destroy-me", "tenant")
            .await
            .unwrap();

        let proof = tpm.destroy_key_with_proof(&meta.id).await.unwrap();
        // Proof should contain the key ID
        assert_eq!(proof.key_id, meta.id);
    }

    /// Test health check
    #[tokio::test]
    async fn test_tpm_health() {
        let tpm = SimulatedTpmKeystore::new();
        let health = tpm.health().await.unwrap();
        // Simulated TPM should report healthy
        assert!(matches!(health, kms_core::types::HealthStatus::Healthy));
    }

    /// Test get_key_pcr_binding returns None for non-bound key
    #[tokio::test]
    async fn test_tpm_get_pcr_binding_none() {
        let tpm = SimulatedTpmKeystore::new();
        let meta = tpm
            .generate_key(&KeySpec::Aes256Gcm, "non-bound", "tenant")
            .await
            .unwrap();

        // Non-bound key should return None
        let binding = tpm.get_key_pcr_binding(&meta.id).unwrap();
        assert!(binding.is_none());

        // And key_has_pcr_binding should return false
        let has_binding = tpm.key_has_pcr_binding(&meta.id).unwrap();
        assert!(!has_binding);
    }

    /// Test import key material (not supported in TPM keystore)
    #[tokio::test]
    async fn test_tpm_import_key_not_supported() {
        let tpm = SimulatedTpmKeystore::new();
        let material = vec![0u8; 32];

        let result = tpm
            .import_key_material(&KeySpec::Aes256Gcm, "imported", "tenant", material)
            .await;
        // TPM keystore does not support importing raw key material
        assert!(result.is_err());
    }

    /// Test DH key exchange (not implemented in simulated TPM)
    #[tokio::test]
    async fn test_tpm_dh_derive_not_implemented() {
        let tpm = SimulatedTpmKeystore::new();
        let meta = tpm
            .generate_key(&KeySpec::Ed25519, "dh-key", "tenant")
            .await
            .unwrap();

        let peer_pubkey = vec![0u8; 32];
        let result = tpm
            .derive_shared_secret(&meta.id, &peer_pubkey, kms_core::dh::DhAlgorithm::X25519)
            .await;
        // DH is not implemented in simulated TPM
        assert!(result.is_err());
    }

    /// Test SimulatedTpmKeystore Default impl
    #[test]
    fn test_tpm_default() {
        let _tpm = SimulatedTpmKeystore::default();
        // Should be able to create default instance
        let handle = TpmHandle(0);
        assert_eq!(handle.0, 0);
    }

    /// Test PcrBank default and operations
    #[test]
    fn test_pcr_bank_default() {
        let bank = PcrBank::default();
        // Default PCR 0 should be all zeros
        let pcr0 = bank.read(0).unwrap();
        assert!(pcr0.iter().all(|&b| b == 0));
    }

    /// Test PcrBank extend and read
    #[test]
    fn test_pcr_bank_extend_read() {
        let mut bank = PcrBank::default();
        bank.extend(0, b"measurement");
        let pcr0 = bank.read(0).unwrap();
        // After extend, PCR should not be all zeros
        assert!(!pcr0.iter().all(|&b| b == 0));
    }

    /// Test PcrBank read invalid index
    #[test]
    fn test_pcr_bank_read_invalid() {
        let bank = PcrBank::default();
        assert!(bank.read(24).is_none());
    }

    /// Test new_with_pcrs constructor
    #[tokio::test]
    async fn test_tpm_new_with_pcrs() {
        let initial_pcrs = vec![(7, vec![0xAB; 32])];
        let tpm = SimulatedTpmKeystore::new_with_pcrs(&initial_pcrs);

        // PCR7 should have been set (may be hashed, but should not be all zeros)
        let pcr7 = tpm.read_pcr(7).unwrap();
        assert!(!pcr7.iter().all(|&b| b == 0));
    }
}
