//! Cryptographic algorithm abstractions
//!
//! This module defines traits for cryptographic operations that can be
//! implemented by different algorithms (AES-256-GCM, SM4, SM2, Ed25519, etc.).
//!
//! The trait-based design allows for:
//! - Easy addition of new algorithms
//! - Testing with mock implementations
//! - Registry pattern for algorithm lookup by KeySpec

use crate::Result;
use crate::key::{Ciphertext, KeySpec, Signature};

/// Result type for encryption operations
pub type EncryptResult = Result<Ciphertext>;

/// Result type for decryption operations
pub type DecryptResult = Result<Vec<u8>>;

/// Result type for signing operations
pub type SignResult = Result<Signature>;

/// Result type for verification operations
pub type VerifyResult = Result<bool>;

/// Trait for symmetric encryption algorithms
pub trait Encryptor: Send + Sync {
    /// Encrypt plaintext
    ///
    /// # Arguments
    /// * `key_material` - Raw key bytes
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Additional authenticated data (optional)
    ///
    /// # Returns
    /// Ciphertext containing encrypted data and metadata
    fn encrypt(&self, key_material: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> EncryptResult;

    /// Get the key specification this encryptor supports
    fn supported_spec(&self) -> KeySpec;
}

/// Trait for symmetric decryption algorithms
pub trait Decryptor: Send + Sync {
    /// Decrypt ciphertext
    ///
    /// # Arguments
    /// * `key_material` - Raw key bytes
    /// * `ciphertext` - Encrypted data
    /// * `aad` - Additional authenticated data (optional)
    ///
    /// # Returns
    /// Decrypted plaintext
    fn decrypt(
        &self,
        key_material: &[u8],
        ciphertext: &Ciphertext,
        aad: Option<&[u8]>,
    ) -> DecryptResult;

    /// Get the key specification this decryptor supports
    fn supported_spec(&self) -> KeySpec;
}

/// Trait for asymmetric signing algorithms
pub trait Signer: Send + Sync {
    /// Sign data
    ///
    /// # Arguments
    /// * `key_material` - Private key bytes
    /// * `data` - Data to sign
    ///
    /// # Returns
    /// Signature
    fn sign(&self, key_material: &[u8], data: &[u8]) -> SignResult;

    /// Get the key specification this signer supports
    fn supported_spec(&self) -> KeySpec;
}

/// Trait for asymmetric verification algorithms
pub trait Verifier: Send + Sync {
    /// Verify a signature
    ///
    /// # Arguments
    /// * `key_material` - Public key bytes (or private key for some algs)
    /// * `data` - Original data that was signed
    /// * `signature` - Signature to verify
    ///
    /// # Returns
    /// True if signature is valid
    fn verify(&self, key_material: &[u8], data: &[u8], signature: &Signature) -> VerifyResult;

    /// Get the key specification this verifier supports
    fn supported_spec(&self) -> KeySpec;
}

/// Trait for symmetric encryption/decryption algorithms
pub trait SymmetricCrypto: Send + Sync {
    fn encrypt(&self, key_material: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> EncryptResult;
    fn decrypt(
        &self,
        key_material: &[u8],
        ciphertext: &Ciphertext,
        aad: Option<&[u8]>,
    ) -> DecryptResult;
    fn supported_spec(&self) -> KeySpec;
}

/// Algorithm registry - maps KeySpec to algorithm name for dispatch
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgorithmInfo {
    pub name: &'static str,
    pub is_symmetric: bool,
    pub is_asymmetric: bool,
    pub key_size: usize,
    pub nonce_size: usize,
    pub tag_size: usize,
}

/// Lookup algorithm info by KeySpec
pub fn get_algorithm_info(spec: KeySpec) -> Option<AlgorithmInfo> {
    match spec {
        KeySpec::Aes256Gcm => Some(AlgorithmInfo {
            name: "AES-256-GCM",
            is_symmetric: true,
            is_asymmetric: false,
            key_size: 32,
            nonce_size: 12,
            tag_size: 16,
        }),
        KeySpec::Sm4 => Some(AlgorithmInfo {
            name: "SM4-GCM",
            is_symmetric: true,
            is_asymmetric: false,
            key_size: 16,
            nonce_size: 12,
            tag_size: 16,
        }),
        KeySpec::Sm2 => Some(AlgorithmInfo {
            name: "SM2",
            is_symmetric: false,
            is_asymmetric: true,
            key_size: 32,
            nonce_size: 65, // C1 point
            tag_size: 32,   // C3 SM3 hash
        }),
        KeySpec::Ed25519 => Some(AlgorithmInfo {
            name: "Ed25519",
            is_symmetric: false,
            is_asymmetric: true,
            key_size: 32,
            nonce_size: 0,
            tag_size: 64,
        }),
        KeySpec::EcdsaP256 => Some(AlgorithmInfo {
            name: "ECDSA-P256",
            is_symmetric: false,
            is_asymmetric: true,
            key_size: 32,
            nonce_size: 0,
            tag_size: 64,
        }),
        KeySpec::EcdsaP384 => Some(AlgorithmInfo {
            name: "ECDSA-P384",
            is_symmetric: false,
            is_asymmetric: true,
            key_size: 48,
            nonce_size: 0,
            tag_size: 96,
        }),
        KeySpec::HmacSha256 => Some(AlgorithmInfo {
            name: "HMAC-SHA256",
            is_symmetric: true,
            is_asymmetric: false,
            key_size: 32,
            nonce_size: 0,
            tag_size: 32,
        }),
        _ => None,
    }
}

/// Check if a KeySpec is supported for encryption
pub fn is_encryption_supported(spec: KeySpec) -> bool {
    matches!(spec, KeySpec::Aes256Gcm | KeySpec::Sm4 | KeySpec::Sm2)
}

/// Check if a KeySpec is supported for signing
pub fn is_signing_supported(spec: KeySpec) -> bool {
    matches!(
        spec,
        KeySpec::Ed25519
            | KeySpec::EcdsaP256
            | KeySpec::EcdsaP384
            | KeySpec::Sm2
            | KeySpec::HmacSha256
    )
}

/// Validate key material size for a given KeySpec
pub fn validate_key_size(spec: KeySpec, key_size: usize) -> bool {
    match spec {
        KeySpec::Aes256Gcm | KeySpec::HmacSha256 => key_size == 32,
        KeySpec::Sm4 => key_size == 16,
        KeySpec::Sm2 | KeySpec::Ed25519 | KeySpec::EcdsaP256 => key_size == 32,
        KeySpec::EcdsaP384 => key_size == 48,
        KeySpec::Rsa4096 => key_size >= 512, // PEM-encoded or raw
        _ => false,
    }
}

/// Algorithm registry - stores metadata about supported algorithms
#[derive(Debug, Clone)]
pub struct AlgorithmRegistry {
    algorithms: Vec<(&'static str, AlgorithmInfo)>,
}

impl Default for AlgorithmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmRegistry {
    /// Create a new registry with all built-in algorithms
    pub fn new() -> Self {
        let algorithms = vec![
            (
                "AES-256-GCM",
                get_algorithm_info(KeySpec::Aes256Gcm)
                    .expect("all KeySpec variants have AlgorithmInfo"),
            ),
            (
                "SM4-GCM",
                get_algorithm_info(KeySpec::Sm4).expect("all KeySpec variants have AlgorithmInfo"),
            ),
            (
                "SM2",
                get_algorithm_info(KeySpec::Sm2).expect("all KeySpec variants have AlgorithmInfo"),
            ),
            (
                "Ed25519",
                get_algorithm_info(KeySpec::Ed25519)
                    .expect("all KeySpec variants have AlgorithmInfo"),
            ),
            (
                "ECDSA-P256",
                get_algorithm_info(KeySpec::EcdsaP256)
                    .expect("all KeySpec variants have AlgorithmInfo"),
            ),
            (
                "ECDSA-P384",
                get_algorithm_info(KeySpec::EcdsaP384)
                    .expect("all KeySpec variants have AlgorithmInfo"),
            ),
            (
                "HMAC-SHA256",
                get_algorithm_info(KeySpec::HmacSha256)
                    .expect("all KeySpec variants have AlgorithmInfo"),
            ),
        ];
        Self { algorithms }
    }

    /// Get algorithm info by name
    pub fn get(&self, name: &str) -> Option<&AlgorithmInfo> {
        self.algorithms
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, info)| info)
    }

    /// Get algorithm info by KeySpec
    pub fn get_by_spec(&self, spec: KeySpec) -> Option<AlgorithmInfo> {
        // Find the algorithm in our registry that matches the KeySpec
        let found_name = get_algorithm_info(spec)?.name;
        for (_, info) in &self.algorithms {
            if info.name == found_name {
                return Some(*info);
            }
        }
        None
    }

    /// List all registered algorithm names
    pub fn list_algorithms(&self) -> Vec<&'static str> {
        self.algorithms.iter().map(|(n, _)| *n).collect()
    }

    /// List all symmetric algorithms
    pub fn list_symmetric(&self) -> Vec<&'static str> {
        self.algorithms
            .iter()
            .filter(|(_, info)| info.is_symmetric)
            .map(|(n, _)| *n)
            .collect()
    }

    /// List all asymmetric algorithms
    pub fn list_asymmetric(&self) -> Vec<&'static str> {
        self.algorithms
            .iter()
            .filter(|(_, info)| info.is_asymmetric)
            .map(|(n, _)| *n)
            .collect()
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    #[test]
    fn test_registry_get() {
        let registry = AlgorithmRegistry::new();
        let algo = registry.get("AES-256-GCM").unwrap();
        assert_eq!(algo.name, "AES-256-GCM");
    }

    #[test]
    fn test_registry_list_symmetric() {
        let registry = AlgorithmRegistry::new();
        let symmetric = registry.list_symmetric();
        assert!(symmetric.contains(&"AES-256-GCM"));
        assert!(symmetric.contains(&"SM4-GCM"));
        assert!(!symmetric.contains(&"Ed25519"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_info_aes256gcm() {
        let info = get_algorithm_info(KeySpec::Aes256Gcm).unwrap();
        assert_eq!(info.name, "AES-256-GCM");
        assert!(info.is_symmetric);
        assert!(!info.is_asymmetric);
        assert_eq!(info.key_size, 32);
        assert_eq!(info.nonce_size, 12);
        assert_eq!(info.tag_size, 16);
    }

    #[test]
    fn test_algorithm_info_sm2() {
        let info = get_algorithm_info(KeySpec::Sm2).unwrap();
        assert_eq!(info.name, "SM2");
        assert!(!info.is_symmetric);
        assert!(info.is_asymmetric);
        assert_eq!(info.key_size, 32);
    }

    #[test]
    fn test_algorithm_info_unsupported() {
        assert!(get_algorithm_info(KeySpec::Sm9Signing).is_none());
        assert!(get_algorithm_info(KeySpec::Sm9Encryption).is_none());
        assert!(get_algorithm_info(KeySpec::Rsa4096).is_none());
    }
}
