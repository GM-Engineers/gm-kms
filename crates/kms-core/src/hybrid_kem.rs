//! Hybrid Key Encapsulation Mechanism (KEM) for Post-Quantum Readiness
//!
//! This module provides hybrid KEM structures that combine classical and
//! post-quantum algorithms for quantum-resistant key exchange.
//!
//! ## Security Model
//!
//! Hybrid KEM combines the security of both classical and post-quantum algorithms.
//! The resulting shared secret is secure if either component is secure.
//! This provides defense-in-depth against both classical and quantum attacks.
//!
//! ## Supported Combinations
//!
//! - `HybridP256MlKem768`: ECDH P-256 + ML-KEM-768 (≈AES-192 security)
//! - `HybridP384MlKem1024`: ECDH P-384 + ML-KEM-1024 (≈AES-256 security)
//!
//! ## Implementation Notes
//!
//! When the `ml-kem` crate is available, the actual ML-KEM operations will be used.
//! Currently this module provides type definitions and structure for hybrid KEM readiness.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::key::KeySpec;

/// Hybrid KEM algorithm identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HybridKemVariant {
    /// ECDH P-256 + ML-KEM-768 (≈AES-192 security)
    HybridP256MlKem768,
    /// ECDH P-384 + ML-KEM-1024 (≈AES-256 security)
    HybridP384MlKem1024,
}

impl HybridKemVariant {
    /// Get the classical component KeySpec
    pub fn classical_spec(&self) -> KeySpec {
        match self {
            HybridKemVariant::HybridP256MlKem768 => KeySpec::EcdsaP256,
            HybridKemVariant::HybridP384MlKem1024 => KeySpec::EcdsaP384,
        }
    }

    /// Get the ML-KEM security level (1=AES-128, 3=AES-192, 5=AES-256)
    pub fn ml_kem_level(&self) -> u8 {
        match self {
            HybridKemVariant::HybridP256MlKem768 => 3,
            HybridKemVariant::HybridP384MlKem1024 => 5,
        }
    }

    /// Combined key size in bytes (classical + ML-KEM output)
    pub fn combined_key_size(&self) -> usize {
        match self {
            // ECDH P-256 = 32 bytes, ML-KEM-768 = 32 bytes (shared secret)
            HybridKemVariant::HybridP256MlKem768 => 64,
            // ECDH P-384 = 48 bytes, ML-KEM-1024 = 32 bytes
            HybridKemVariant::HybridP384MlKem1024 => 80,
        }
    }
}

/// Hybrid KEM key pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridKemKeyPair {
    /// Unique key pair identifier
    pub id: Uuid,
    /// Algorithm variant
    pub variant: HybridKemVariant,
    /// Classical EC public key (uncompressed point, 65 bytes for P-256 or 97 bytes for P-384)
    pub classical_public_key: Vec<u8>,
    /// Classical EC private key (scalar)
    #[serde(skip_serializing)]
    pub classical_private_key: Vec<u8>,
    /// ML-KEM public key (1024 or 1564 bytes)
    pub ml_kem_public_key: Vec<u8>,
    /// ML-KEM private key (sk size varies by variant)
    #[serde(skip_serializing)]
    pub ml_kem_private_key: Vec<u8>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Key status
    pub status: HybridKemKeyStatus,
}

/// Hybrid KEM key status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HybridKemKeyStatus {
    /// Key is active and can be used
    Active,
    /// Key has been used for encapsulation
    Used,
    /// Key is obsolete
    Obsolete,
    /// Key has been destroyed
    Destroyed,
}

/// Encapsulated key from hybrid KEM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridKemCiphertext {
    /// Unique encapsulation ID
    pub id: Uuid,
    /// Algorithm variant used
    pub variant: HybridKemVariant,
    /// Classical ECDH ciphertext (ephemeral public key)
    pub classical_ciphertext: Vec<u8>,
    /// ML-KEM ciphertext (768-1564 bytes depending on variant)
    pub ml_kem_ciphertext: Vec<u8>,
    /// Combined shared secret (computed via KDF)
    pub combined_secret: Vec<u8>,
    /// Encapsulation timestamp
    pub encapsulated_at: DateTime<Utc>,
}

impl HybridKemCiphertext {
    /// Create a new hybrid KEM ciphertext
    pub fn new(
        variant: HybridKemVariant,
        classical_ciphertext: Vec<u8>,
        ml_kem_ciphertext: Vec<u8>,
        combined_secret: Vec<u8>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            variant,
            classical_ciphertext,
            ml_kem_ciphertext,
            combined_secret,
            encapsulated_at: Utc::now(),
        }
    }

    /// Get the variant name for algorithm identification
    pub fn algorithm_name(&self) -> &'static str {
        match self.variant {
            HybridKemVariant::HybridP256MlKem768 => "HybridP256-ML-KEM-768",
            HybridKemVariant::HybridP384MlKem1024 => "HybridP384-ML-KEM-1024",
        }
    }
}

/// Hybrid KEM shared secret structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridKemSecret {
    /// Unique secret ID
    pub id: Uuid,
    /// Algorithm variant
    pub variant: HybridKemVariant,
    /// The shared secret bytes (after KDF combination)
    pub secret: Vec<u8>,
    /// Which key pair was used
    pub key_pair_id: Uuid,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Optional context/purpose for the secret
    pub context: Option<String>,
}

impl HybridKemSecret {
    /// Create a new hybrid KEM secret
    pub fn new(
        variant: HybridKemVariant,
        secret: Vec<u8>,
        key_pair_id: Uuid,
        context: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            variant,
            secret,
            key_pair_id,
            created_at: Utc::now(),
            context,
        }
    }
}

impl HybridKemSecret {
    /// Derive a symmetric key from the hybrid KEM secret using KDF
    pub fn derive_symmetric_key(&self, purpose: &[u8], output_len: usize) -> Vec<u8> {
        // Use HMAC-SHA256 as a simple KDF
        use ring::digest::{SHA256, digest};

        let salt = match self.variant {
            HybridKemVariant::HybridP256MlKem768 => b"HybridP256-ML-KEM-768" as &[u8],
            HybridKemVariant::HybridP384MlKem1024 => b"HybridP384-ML-KEM-1024" as &[u8],
        };

        // Combine: salt + secret + purpose
        let mut input = Vec::with_capacity(salt.len() + self.secret.len() + purpose.len());
        input.extend_from_slice(salt);
        input.extend_from_slice(&self.secret);
        input.extend_from_slice(purpose);

        let tag = digest(&SHA256, &input);
        tag.as_ref()[..output_len.min(32)].to_vec()
    }
}

/// Readiness status for post-quantum crypto
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqReadinessStatus {
    /// Hybrid KEM types are defined
    TypesReady,
    /// ML-KEM crate is available and integrated
    MlKemAvailable,
    /// Hybrid operations are implemented
    OperationsReady,
    /// Production ready with external audit
    ProductionReady,
}

/// PQ readiness information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqReadiness {
    /// Current readiness status
    pub status: PqReadinessStatus,
    /// Supported hybrid variants
    pub supported_variants: Vec<HybridKemVariant>,
    /// ML-KEM library version (if available)
    pub ml_kem_version: Option<String>,
    /// Notes about readiness
    pub notes: Vec<String>,
}

impl PqReadiness {
    /// Check current PQ readiness status
    pub fn check() -> Self {
        let mut notes = Vec::new();
        let mut status = PqReadinessStatus::TypesReady;
        let ml_kem_version = None;

        // Type definitions are always available
        notes.push("Hybrid KEM type definitions available".to_string());

        // In a full implementation, we would check for ml-kem crate here
        // For now, mark as types-ready only
        if ml_kem_version.is_some() {
            status = PqReadinessStatus::MlKemAvailable;
            notes.push("ML-KEM crate is available".to_string());
        }

        Self {
            status,
            supported_variants: vec![
                HybridKemVariant::HybridP256MlKem768,
                HybridKemVariant::HybridP384MlKem1024,
            ],
            ml_kem_version,
            notes,
        }
    }

    /// Check if a specific hybrid variant is supported
    pub fn is_variant_supported(&self, variant: HybridKemVariant) -> bool {
        self.supported_variants.contains(&variant)
    }
}

/// Key encapsulation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KemEncapsResult {
    /// The encapsulated ciphertext
    pub ciphertext: HybridKemCiphertext,
    /// The shared secret (should be securely stored/used)
    pub shared_secret: HybridKemSecret,
}

/// Key decapsulation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KemDecapsResult {
    /// The decapsulated shared secret
    pub shared_secret: Vec<u8>,
    /// Whether decapsulation was successful
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_variant_props() {
        let v1 = HybridKemVariant::HybridP256MlKem768;
        assert_eq!(v1.classical_spec(), KeySpec::EcdsaP256);
        assert_eq!(v1.ml_kem_level(), 3);
        assert_eq!(v1.combined_key_size(), 64);

        let v2 = HybridKemVariant::HybridP384MlKem1024;
        assert_eq!(v2.classical_spec(), KeySpec::EcdsaP384);
        assert_eq!(v2.ml_kem_level(), 5);
        assert_eq!(v2.combined_key_size(), 80);
    }

    #[test]
    fn test_pq_readiness_check() {
        let readiness = PqReadiness::check();
        assert_eq!(readiness.status, PqReadinessStatus::TypesReady);
        assert!(readiness.is_variant_supported(HybridKemVariant::HybridP256MlKem768));
        assert!(readiness.is_variant_supported(HybridKemVariant::HybridP384MlKem1024));
    }

    #[test]
    fn test_hybrid_kem_ciphertext() {
        let ct = HybridKemCiphertext::new(
            HybridKemVariant::HybridP256MlKem768,
            vec![0u8; 65],   // classical ciphertext (ephemeral pubkey)
            vec![0u8; 1088], // ML-KEM-768 ciphertext
            vec![0u8; 32],   // combined secret
        );
        assert_eq!(ct.algorithm_name(), "HybridP256-ML-KEM-768");
    }

    /// Test algorithm_name for all variants
    #[test]
    fn test_all_variant_algorithm_names() {
        let v1 = HybridKemVariant::HybridP256MlKem768;
        let ct1 = HybridKemCiphertext::new(v1, vec![0u8; 65], vec![0u8; 1088], vec![0u8; 32]);
        assert_eq!(ct1.algorithm_name(), "HybridP256-ML-KEM-768");

        let v2 = HybridKemVariant::HybridP384MlKem1024;
        let ct2 = HybridKemCiphertext::new(v2, vec![0u8; 97], vec![0u8; 1568], vec![0u8; 40]);
        assert_eq!(ct2.algorithm_name(), "HybridP384-ML-KEM-1024");
    }

    /// Test HybridKemSecret derive_symmetric_key
    #[test]
    fn test_hybrid_kem_secret_derive() {
        let secret = HybridKemSecret::new(
            HybridKemVariant::HybridP256MlKem768,
            vec![0xAA; 32],
            Uuid::new_v4(),
            None,
        );
        let key1 = secret.derive_symmetric_key(b"encryption", 32);
        let key2 = secret.derive_symmetric_key(b"encryption", 32);
        assert_eq!(key1, key2); // deterministic
        assert_eq!(key1.len(), 32);

        let key3 = secret.derive_symmetric_key(b"authentication", 32);
        assert_ne!(key1, key3); // different purpose → different key
    }

    /// Test HybridKemSecret derive with different output lengths
    #[test]
    fn test_hybrid_kem_secret_derive_lengths() {
        let secret = HybridKemSecret::new(
            HybridKemVariant::HybridP256MlKem768,
            vec![0xAA; 32],
            Uuid::new_v4(),
            None,
        );
        // derive_symmetric_key uses SHA-256, max output is 32 bytes
        for len in [16, 24, 32] {
            let key = secret.derive_symmetric_key(b"test", len);
            assert_eq!(key.len(), len);
        }
    }

    /// Test PqReadiness is_variant_supported for all variants
    #[test]
    fn test_pq_readiness_all_variants() {
        let readiness = PqReadiness::check();
        assert!(readiness.is_variant_supported(HybridKemVariant::HybridP256MlKem768));
        assert!(readiness.is_variant_supported(HybridKemVariant::HybridP384MlKem1024));
    }
}
