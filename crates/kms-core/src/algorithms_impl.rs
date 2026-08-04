//! Concrete implementations of cryptographic algorithm traits
//!
//! This module provides implementations of the Encryptor, Decryptor, Signer, and Verifier
//! traits for supported algorithms (AES-256-GCM, SM4, etc.).

use crate::Error;
use crate::algorithms::{DecryptResult, Decryptor, EncryptResult, Encryptor, SymmetricCrypto};
use crate::key::{Ciphertext, KeySpec};
use rand::Rng;
use ring::aead::{self, BoundKey, LessSafeKey, NonceSequence, SealingKey, UnboundKey};
use ring::error::Unspecified;

/// AES-256-GCM encryptor implementation
pub struct Aes256GcmEncryptor;

impl Aes256GcmEncryptor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Aes256GcmEncryptor {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::Encryptor for Aes256GcmEncryptor {
    fn encrypt(
        &self,
        key_material: &[u8],
        plaintext: &[u8],
        _aad: Option<&[u8]>,
    ) -> crate::EncryptResult {
        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key_material)
            .map_err(|e| Error::EncryptionFailed(format!("invalid AES-256-GCM key: {e}")))?;

        // Generate random starting counter value for unique nonces
        let mut starting_counter_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut starting_counter_bytes);
        let starting_counter = u128::from_be_bytes(starting_counter_bytes);

        struct Counter(u128);
        impl NonceSequence for Counter {
            fn advance(&mut self) -> std::result::Result<aead::Nonce, Unspecified> {
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes.copy_from_slice(&self.0.to_be_bytes()[4..]);
                let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
                self.0 += 1;
                Ok(nonce)
            }
        }

        let counter = Counter(starting_counter);
        let mut sealing_key: SealingKey<Counter> = BoundKey::new(unbound_key, counter);

        let mut in_out = plaintext.to_vec();
        let tag = sealing_key
            .seal_in_place_separate_tag(aead::Aad::empty(), &mut in_out)
            .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

        // Generate a key_id for the Ciphertext - in real usage this would be passed in
        let key_id = uuid::Uuid::new_v4();

        Ok(Ciphertext {
            key_id,
            version: 1,
            format_version: 1,
            nonce: starting_counter.to_be_bytes().to_vec(),
            ciphertext: in_out,
            tag: tag.as_ref().to_vec(),
        })
    }

    fn supported_spec(&self) -> KeySpec {
        KeySpec::Aes256Gcm
    }
}

/// AES-256-GCM decryptor implementation
pub struct Aes256GcmDecryptor;

impl Aes256GcmDecryptor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Aes256GcmDecryptor {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::Decryptor for Aes256GcmDecryptor {
    fn decrypt(
        &self,
        key_material: &[u8],
        ciphertext: &Ciphertext,
        _aad: Option<&[u8]>,
    ) -> crate::DecryptResult {
        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key_material)
            .map_err(|e| Error::DecryptionFailed(format!("invalid AES-256-GCM key: {e}")))?;

        let less_safe_key = LessSafeKey::new(unbound_key);

        // Reconstruct nonce from stored counter bytes
        let mut in_out = ciphertext.ciphertext.to_vec();
        in_out.extend_from_slice(&ciphertext.tag);

        // The nonce stored is the starting counter, we need to reconstruct
        // This is a simplified version - real implementation would need proper counter handling
        let nonce_bytes: [u8; 12] = if ciphertext.nonce.len() >= 12 {
            let mut arr = [0u8; 12];
            arr.copy_from_slice(&ciphertext.nonce[4..16]);
            arr
        } else if ciphertext.nonce.len() == 12 {
            let mut arr = [0u8; 12];
            arr.copy_from_slice(&ciphertext.nonce);
            arr
        } else {
            return Err(Error::DecryptionFailed("invalid nonce length".to_string()));
        };

        less_safe_key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce_bytes),
                aead::Aad::empty(),
                &mut in_out,
            )
            .map_err(|_| Error::DecryptionFailed("decryption failed".to_string()))?
            .to_vec();

        // Remove tag from end
        let plaintext_len = in_out.len() - 16;
        let plaintext = in_out[..plaintext_len].to_vec();

        Ok(plaintext)
    }

    fn supported_spec(&self) -> KeySpec {
        KeySpec::Aes256Gcm
    }
}

/// Combined AES-256-GCM symmetric crypto (encryptor + decryptor)
pub struct Aes256GcmCrypto {
    encryptor: Aes256GcmEncryptor,
    decryptor: Aes256GcmDecryptor,
}

impl Aes256GcmCrypto {
    pub fn new() -> Self {
        Self {
            encryptor: Aes256GcmEncryptor::new(),
            decryptor: Aes256GcmDecryptor::new(),
        }
    }

    pub fn encrypt(&self, key: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> EncryptResult {
        self.encryptor.encrypt(key, plaintext, aad)
    }

    pub fn decrypt(
        &self,
        key: &[u8],
        ciphertext: &Ciphertext,
        aad: Option<&[u8]>,
    ) -> DecryptResult {
        self.decryptor.decrypt(key, ciphertext, aad)
    }
}

impl Default for Aes256GcmCrypto {
    fn default() -> Self {
        Self::new()
    }
}

impl SymmetricCrypto for Aes256GcmCrypto {
    fn encrypt(&self, key: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> EncryptResult {
        self.encryptor.encrypt(key, plaintext, aad)
    }

    fn decrypt(&self, key: &[u8], ciphertext: &Ciphertext, aad: Option<&[u8]>) -> DecryptResult {
        self.decryptor.decrypt(key, ciphertext, aad)
    }

    fn supported_spec(&self) -> KeySpec {
        KeySpec::Aes256Gcm
    }
}

/// SM4-GCM encryptor using gm_crypto
pub struct Sm4GcmEncryptor;

impl Sm4GcmEncryptor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Sm4GcmEncryptor {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::Encryptor for Sm4GcmEncryptor {
    fn encrypt(
        &self,
        key_material: &[u8],
        plaintext: &[u8],
        _aad: Option<&[u8]>,
    ) -> crate::EncryptResult {
        use gm_crypto::sm4::Sm4Cipher;

        let cipher =
            Sm4Cipher::new(key_material).map_err(|e| Error::EncryptionFailed(e.to_string()))?;

        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);

        let (ciphertext, tag) = cipher
            .encrypt_gcm(plaintext, &nonce, &[])
            .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

        let key_id = uuid::Uuid::new_v4();

        Ok(Ciphertext {
            key_id,
            version: 1,
            format_version: 1,
            nonce: nonce.to_vec(),
            ciphertext,
            tag,
        })
    }

    fn supported_spec(&self) -> KeySpec {
        KeySpec::Sm4
    }
}

/// SM4-GCM decryptor using gm_crypto
pub struct Sm4GcmDecryptor;

impl Sm4GcmDecryptor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Sm4GcmDecryptor {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::Decryptor for Sm4GcmDecryptor {
    fn decrypt(
        &self,
        key_material: &[u8],
        ciphertext: &Ciphertext,
        _aad: Option<&[u8]>,
    ) -> crate::DecryptResult {
        use gm_crypto::sm4::Sm4Cipher;

        let cipher =
            Sm4Cipher::new(key_material).map_err(|e| Error::DecryptionFailed(e.to_string()))?;

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&ciphertext.nonce[..12.min(ciphertext.nonce.len())]);

        // decrypt_gcm signature: encrypted_data, nonce, aad, tag
        cipher
            .decrypt_gcm(&ciphertext.ciphertext, &nonce, &[], &ciphertext.tag)
            .map_err(|e| Error::DecryptionFailed(e.to_string()))
    }

    fn supported_spec(&self) -> KeySpec {
        KeySpec::Sm4
    }
}

/// Combined SM4-GCM symmetric crypto
pub struct Sm4GcmCrypto {
    encryptor: Sm4GcmEncryptor,
    decryptor: Sm4GcmDecryptor,
}

impl Sm4GcmCrypto {
    pub fn new() -> Self {
        Self {
            encryptor: Sm4GcmEncryptor::new(),
            decryptor: Sm4GcmDecryptor::new(),
        }
    }

    pub fn encrypt(&self, key: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> EncryptResult {
        self.encryptor.encrypt(key, plaintext, aad)
    }

    pub fn decrypt(
        &self,
        key: &[u8],
        ciphertext: &Ciphertext,
        aad: Option<&[u8]>,
    ) -> DecryptResult {
        self.decryptor.decrypt(key, ciphertext, aad)
    }
}

impl SymmetricCrypto for Sm4GcmCrypto {
    fn encrypt(&self, key: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> EncryptResult {
        self.encryptor.encrypt(key, plaintext, aad)
    }

    fn decrypt(&self, key: &[u8], ciphertext: &Ciphertext, aad: Option<&[u8]>) -> DecryptResult {
        self.decryptor.decrypt(key, ciphertext, aad)
    }

    fn supported_spec(&self) -> KeySpec {
        KeySpec::Sm4
    }
}

impl Default for Sm4GcmCrypto {
    fn default() -> Self {
        Self::new()
    }
}

/// Factory for creating algorithm instances by KeySpec
pub struct AlgorithmFactory;

impl AlgorithmFactory {
    /// Create an encryptor for the given key specification
    pub fn create_encryptor(spec: KeySpec) -> Option<Box<dyn crate::Encryptor>> {
        match spec {
            KeySpec::Aes256Gcm => Some(Box::new(Aes256GcmEncryptor::new())),
            KeySpec::Sm4 => Some(Box::new(Sm4GcmEncryptor::new())),
            _ => None,
        }
    }

    /// Create a decryptor for the given key specification
    pub fn create_decryptor(spec: KeySpec) -> Option<Box<dyn crate::Decryptor>> {
        match spec {
            KeySpec::Aes256Gcm => Some(Box::new(Aes256GcmDecryptor::new())),
            KeySpec::Sm4 => Some(Box::new(Sm4GcmDecryptor::new())),
            _ => None,
        }
    }

    /// Create a symmetric crypto (encryptor + decryptor) for the given key specification
    pub fn create_symmetric_crypto(spec: KeySpec) -> Option<Box<dyn SymmetricCrypto>> {
        match spec {
            KeySpec::Aes256Gcm => Some(Box::new(Aes256GcmCrypto::new())),
            KeySpec::Sm4 => Some(Box::new(Sm4GcmCrypto::new())),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256gcm_encrypt_decrypt() {
        let crypto = Aes256GcmCrypto::new();
        let key = vec![0u8; 32]; // 256-bit key
        let plaintext = b"Hello, AES-256-GCM!";

        let ciphertext = crypto.encrypt(&key, plaintext, None).unwrap();
        assert!(!ciphertext.nonce.is_empty());
        assert!(!ciphertext.ciphertext.is_empty());
        assert!(ciphertext.tag.len() == 16);

        let decrypted = crypto.decrypt(&key, &ciphertext, None).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_sm4_encrypt_decrypt() {
        let crypto = Sm4GcmCrypto::new();
        let key = vec![0u8; 16]; // 128-bit key
        let plaintext = b"Hello, SM4!";

        let ciphertext = crypto.encrypt(&key, plaintext, None).unwrap();
        assert!(!ciphertext.nonce.is_empty());
        assert!(!ciphertext.ciphertext.is_empty());

        let decrypted = crypto.decrypt(&key, &ciphertext, None).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_algorithm_factory_aes() {
        let crypto = AlgorithmFactory::create_symmetric_crypto(KeySpec::Aes256Gcm);
        assert!(crypto.is_some());

        let encryptor = AlgorithmFactory::create_encryptor(KeySpec::Aes256Gcm);
        assert!(encryptor.is_some());
        assert_eq!(encryptor.unwrap().supported_spec(), KeySpec::Aes256Gcm);
    }

    #[test]
    fn test_algorithm_factory_sm4() {
        let crypto = AlgorithmFactory::create_symmetric_crypto(KeySpec::Sm4);
        assert!(crypto.is_some());

        let decryptor = AlgorithmFactory::create_decryptor(KeySpec::Sm4);
        assert!(decryptor.is_some());
        assert_eq!(decryptor.unwrap().supported_spec(), KeySpec::Sm4);
    }

    #[test]
    fn test_algorithm_factory_unsupported() {
        let crypto = AlgorithmFactory::create_symmetric_crypto(KeySpec::Ed25519);
        assert!(crypto.is_none());

        let encryptor = AlgorithmFactory::create_encryptor(KeySpec::Rsa4096);
        assert!(encryptor.is_none());
    }
}
