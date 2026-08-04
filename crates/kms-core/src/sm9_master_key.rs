//! SM9 Master Key Storage with KEK Protection
//!
//! This module provides secure storage for the SM9 KGC (Key Generation Center) master key.
//! The master key is encrypted with a Key Encryption Key (KEK) before persistence.
//!
//! # Architecture
//!
//! ```text
//! +------------------+
//! |   KgcMasterKey  | (in-memory, plaintext)
//! |    (Fr scalar)  |
//! +--------+---------+
//!          |
//!          | encrypt_with_kek()
//!          v
//! +------------------+     +------------------+
//! |  KEK Protected   | --> |      KEK         |
//! |  Master Key     |     | (HSM/TPM/EnvVar) |
//! +------------------+     +------------------+
//!          |
//!          v
//! +------------------+
//! |  PostgreSQL     |
//! |  (persisted)    |
//! +------------------+
//! ```
//!
//! # Security Properties
//!
//! 1. **At Rest**: Master key is never stored in plaintext
//! 2. **KEK Protection**: A separate KEK (stored in HSM/TPM/env var) encrypts the master key
//! 3. **Memory Safety**: Running process keeps master key in memory only; Zeroizing used on drop
//! 4. **Transport**: KEK never leaves secure storage; only encrypted key crosses boundaries
//!
//! # Usage
//!
//! ```rust,ignore
//! // Create store with KEK from environment
//! let store = EnvVarKekStore::new("SM9_KEK");
//! let encrypted = store.encrypt(&master_key_bytes).await?;
//!
//! // Store to PostgreSQL (in kms-keystore crate)
//! repo.store_master_key(&encrypted).await?;
//! ```

use crate::{Error, Result};
use async_trait::async_trait;

/// Store trait for KEK-protected master key storage
///
/// The KEK (Key Encryption Key) is used to encrypt/decrypt the master key
/// before storing to or after loading from the repository.
#[async_trait]
pub trait Sm9MasterKeyStore: Send + Sync {
    /// Encrypt data with KEK
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt data with KEK
    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

// ============================================================================
// KEK Source Implementations
// ============================================================================

/// KEK from environment variable (for development/testing only)
///
/// # Security Warning
/// This implementation is NOT recommended for production use.
/// Environment variables can be leaked through process listing, logs, etc.
pub struct EnvVarKekStore {
    var_name: String,
}

impl EnvVarKekStore {
    /// Create from environment variable name
    pub fn new(var_name: &str) -> Self {
        Self {
            var_name: var_name.to_string(),
        }
    }

    /// Get the KEK bytes from environment
    fn get_kek(&self) -> Result<Vec<u8>> {
        std::env::var(&self.var_name)
            .map_err(|_| Error::MasterKeyError(format!("KEK env var {} not set", self.var_name)))
            .and_then(|s| {
                // Support hex or base64 encoded KEK
                if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
                    // Hex format
                    hex::decode(&s)
                        .map_err(|e| Error::MasterKeyError(format!("invalid hex KEK: {e}")))
                } else {
                    // Assume base64
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD
                        .decode(&s)
                        .map_err(|e| Error::MasterKeyError(format!("invalid base64 KEK: {e}")))
                }
            })
    }
}

#[async_trait]
impl Sm9MasterKeyStore for EnvVarKekStore {
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
        use ring::rand::{SecureRandom, SystemRandom};

        let kek = self.get_kek()?;
        if kek.len() != 32 {
            return Err(Error::MasterKeyError("KEK must be 32 bytes".to_string()));
        }

        let unbound_key = UnboundKey::new(&AES_256_GCM, &kek)
            .map_err(|e| Error::MasterKeyError(e.to_string()))?;
        let key = LessSafeKey::new(unbound_key);

        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes)
            .map_err(|e| Error::MasterKeyError(e.to_string()))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| Error::MasterKeyError(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + in_out.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);

        Ok(result)
    }

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

        if ciphertext.len() < 12 {
            return Err(Error::MasterKeyError("ciphertext too short".to_string()));
        }

        let kek = self.get_kek()?;
        if kek.len() != 32 {
            return Err(Error::MasterKeyError("KEK must be 32 bytes".to_string()));
        }

        let unbound_key = UnboundKey::new(&AES_256_GCM, &kek)
            .map_err(|e| Error::MasterKeyError(e.to_string()))?;
        let key = LessSafeKey::new(unbound_key);

        let nonce_bytes: [u8; 12] = ciphertext[..12]
            .try_into()
            .expect("nonce is 12 bytes (ciphertext.len() >= 12 checked above)");
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = ciphertext[12..].to_vec();

        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| Error::MasterKeyError(e.to_string()))?;

        Ok(plaintext.to_vec())
    }
}

// ============================================================================
// In-Memory Store (for testing)
// ============================================================================

/// In-memory KEK store (for testing only)
pub struct MemoryKekStore {
    kek: [u8; 32],
}

impl MemoryKekStore {
    /// Create with a fixed 32-byte KEK
    pub fn new(kek: [u8; 32]) -> Self {
        Self { kek }
    }
}

#[async_trait]
impl Sm9MasterKeyStore for MemoryKekStore {
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
        use ring::rand::{SecureRandom, SystemRandom};

        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.kek)
            .map_err(|e| Error::MasterKeyError(e.to_string()))?;
        let key = LessSafeKey::new(unbound_key);

        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes)
            .map_err(|e| Error::MasterKeyError(e.to_string()))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| Error::MasterKeyError(e.to_string()))?;

        let mut result = Vec::with_capacity(12 + in_out.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);

        Ok(result)
    }

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

        if ciphertext.len() < 12 {
            return Err(Error::MasterKeyError("ciphertext too short".to_string()));
        }

        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.kek)
            .map_err(|e| Error::MasterKeyError(e.to_string()))?;
        let key = LessSafeKey::new(unbound_key);

        let nonce_bytes: [u8; 12] = ciphertext[..12]
            .try_into()
            .expect("nonce is 12 bytes (ciphertext.len() >= 12 checked above)");
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = ciphertext[12..].to_vec();

        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| Error::MasterKeyError(e.to_string()))?;

        Ok(plaintext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_store_encrypt_decrypt() {
        let store = MemoryKekStore::new([0x42u8; 32]);
        let plaintext = b"test master key data";

        let ciphertext = store.encrypt(plaintext).await.unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);

        let decrypted = store.decrypt(&ciphertext).await.unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[tokio::test]
    async fn test_master_key_store_with_kek() {
        let store = MemoryKekStore::new([0x42u8; 32]);
        let plaintext = vec![0x01, 0x02, 0x03];

        let encrypted = store.encrypt(&plaintext).await.unwrap();
        let decrypted = store.decrypt(&encrypted).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_memory_store_ciphertext_includes_nonce() {
        let store = MemoryKekStore::new([0x42u8; 32]);
        let plaintext = b"test data";
        let ciphertext = store.encrypt(plaintext).await.unwrap();
        // Nonce (12 bytes) + encrypted data + tag (16 bytes for AES-256-GCM)
        assert!(ciphertext.len() > 12 + plaintext.len());
        assert!(ciphertext.len() >= 12 + plaintext.len() + 16);
    }

    #[tokio::test]
    async fn test_memory_store_different_keks_fail() {
        let store1 = MemoryKekStore::new([0x42u8; 32]);
        let store2 = MemoryKekStore::new([0x99u8; 32]);
        let plaintext = b"secret";

        let ciphertext = store1.encrypt(plaintext).await.unwrap();
        // Decrypting with a different KEK should fail
        let result = store2.decrypt(&ciphertext).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_memory_store_decrypt_too_short() {
        let store = MemoryKekStore::new([0x42u8; 32]);
        let short_ct = vec![0u8; 5]; // Less than 12 bytes nonce
        let result = store.decrypt(&short_ct).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[tokio::test]
    async fn test_memory_store_empty_plaintext() {
        let store = MemoryKekStore::new([0x42u8; 32]);
        let plaintext = b"";
        let ciphertext = store.encrypt(plaintext).await.unwrap();
        // Even empty plaintext produces nonce + tag
        assert!(ciphertext.len() >= 12 + 16);
        let decrypted = store.decrypt(&ciphertext).await.unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[tokio::test]
    async fn test_memory_store_large_plaintext() {
        let store = MemoryKekStore::new([0x42u8; 32]);
        let plaintext = vec![0xABu8; 4096];
        let ciphertext = store.encrypt(&plaintext).await.unwrap();
        let decrypted = store.decrypt(&ciphertext).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_memory_store_two_encryptions_differ() {
        // Nonce is random, so two encryptions of the same plaintext should differ
        let store = MemoryKekStore::new([0x42u8; 32]);
        let plaintext = b"same data";
        let ct1 = store.encrypt(plaintext).await.unwrap();
        let ct2 = store.encrypt(plaintext).await.unwrap();
        assert_ne!(ct1, ct2);
        // Both should decrypt to the same plaintext
        assert_eq!(store.decrypt(&ct1).await.unwrap().as_slice(), plaintext);
        assert_eq!(store.decrypt(&ct2).await.unwrap().as_slice(), plaintext);
    }

    // --- EnvVarKekStore ---

    #[tokio::test]
    async fn test_envvar_store_hex_kek() {
        let kek_hex = "4242424242424242424242424242424242424242424242424242424242424242";
        // SAFETY: single-threaded test, no concurrent env access
        unsafe {
            std::env::set_var("TEST_SM9_KEK_HEX", kek_hex);
        }
        let store = EnvVarKekStore::new("TEST_SM9_KEK_HEX");
        let plaintext = b"test data";
        let ciphertext = store.encrypt(plaintext).await.unwrap();
        let decrypted = store.decrypt(&ciphertext).await.unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
        unsafe {
            std::env::remove_var("TEST_SM9_KEK_HEX");
        }
    }

    #[tokio::test]
    async fn test_envvar_store_base64_kek() {
        // 32 bytes base64-encoded
        use base64::Engine;
        let kek = [0x42u8; 32];
        let kek_b64 = base64::engine::general_purpose::STANDARD.encode(kek);
        // SAFETY: single-threaded test, no concurrent env access
        unsafe {
            std::env::set_var("TEST_SM9_KEK_B64", &kek_b64);
        }
        let store = EnvVarKekStore::new("TEST_SM9_KEK_B64");
        let plaintext = b"hello";
        let ciphertext = store.encrypt(plaintext).await.unwrap();
        let decrypted = store.decrypt(&ciphertext).await.unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
        unsafe {
            std::env::remove_var("TEST_SM9_KEK_B64");
        }
    }

    #[tokio::test]
    async fn test_envvar_store_missing_var() {
        let store = EnvVarKekStore::new("NONEXISTENT_KEK_VAR_12345");
        let result = store.encrypt(b"data").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("not set"));
    }

    #[tokio::test]
    async fn test_envvar_store_wrong_length_kek() {
        // 16 bytes hex (too short for 32-byte KEK)
        // SAFETY: single-threaded test, no concurrent env access
        unsafe {
            std::env::set_var("TEST_SM9_KEK_SHORT", "42424242424242424242424242424242");
        }
        let store = EnvVarKekStore::new("TEST_SM9_KEK_SHORT");
        let result = store.encrypt(b"data").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
        unsafe {
            std::env::remove_var("TEST_SM9_KEK_SHORT");
        }
    }
}
