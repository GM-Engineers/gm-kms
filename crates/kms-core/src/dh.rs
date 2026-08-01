//! Diffie-Hellman Key Exchange types
//!
//! Supports ECDH (P-256, P-384) and X25519 for secure key agreement.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// DH algorithm type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DhAlgorithm {
    /// ECDH with P-256 curve
    EcdsaP256,
    /// ECDH with P-384 curve
    EcdsaP384,
    /// X25519 (Curve25519 ECDH)
    X25519,
    /// SM2 key exchange (国密)
    Sm2Kex,
}

impl DhAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            DhAlgorithm::EcdsaP256 => "ECDH-P256",
            DhAlgorithm::EcdsaP384 => "ECDH-P384",
            DhAlgorithm::X25519 => "X25519",
            DhAlgorithm::Sm2Kex => "SM2-KEX",
        }
    }

    /// Returns the expected public key size in bytes for this algorithm
    pub fn public_key_size(&self) -> usize {
        match self {
            DhAlgorithm::EcdsaP256 => 65, // 1 + 32 + 32 (uncompressed)
            DhAlgorithm::EcdsaP384 => 97, // 1 + 48 + 48 (uncompressed)
            DhAlgorithm::X25519 => 32,
            DhAlgorithm::Sm2Kex => 64, // SM2 public key is 64 bytes
        }
    }

    /// Returns the expected shared secret size in bytes
    pub fn shared_secret_size(&self) -> usize {
        match self {
            DhAlgorithm::EcdsaP256 => 32,
            DhAlgorithm::EcdsaP384 => 48,
            DhAlgorithm::X25519 => 32,
            DhAlgorithm::Sm2Kex => 32,
        }
    }
}

/// DH key pair for key agreement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhKeyPair {
    /// Algorithm used
    pub algorithm: DhAlgorithm,
    /// Our public key (to share with peer)
    pub public_key: Vec<u8>,
    /// Our private key (never share this!)
    #[serde(skip)]
    private_key: Vec<u8>,
}

impl DhKeyPair {
    /// Create a new DH key pair
    pub fn new(algorithm: DhAlgorithm, public_key: Vec<u8>, private_key: Vec<u8>) -> Self {
        Self {
            algorithm,
            public_key,
            private_key,
        }
    }

    /// Get the private key (for internal use only)
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }
}

/// DH key agreement request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhDeriveRequest {
    /// Key ID of our private key
    pub key_id: Uuid,
    /// Algorithm to use
    pub algorithm: DhAlgorithm,
    /// Peer's public key (received from the other party)
    pub peer_public_key: Vec<u8>,
    /// Optional shared info (additional data to bind to the derived key)
    #[serde(default)]
    pub shared_info: Option<Vec<u8>>,
    /// Derive a specific key length (if None, uses algorithm default)
    #[serde(default)]
    pub key_length: Option<usize>,
}

/// DH key agreement response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhDeriveResponse {
    /// The derived shared secret
    pub shared_secret: Vec<u8>,
    /// Key derivation function used
    pub kdf: String,
}

/// ECDH operation result with shared secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSecret {
    /// The shared secret bytes
    pub secret: Vec<u8>,
    /// Key derivation function applied (if any)
    pub kdf: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh_algorithm_as_str() {
        assert_eq!(DhAlgorithm::EcdsaP256.as_str(), "ECDH-P256");
        assert_eq!(DhAlgorithm::EcdsaP384.as_str(), "ECDH-P384");
        assert_eq!(DhAlgorithm::X25519.as_str(), "X25519");
        assert_eq!(DhAlgorithm::Sm2Kex.as_str(), "SM2-KEX");
    }

    #[test]
    fn test_dh_algorithm_public_key_sizes() {
        assert_eq!(DhAlgorithm::EcdsaP256.public_key_size(), 65);
        assert_eq!(DhAlgorithm::EcdsaP384.public_key_size(), 97);
        assert_eq!(DhAlgorithm::X25519.public_key_size(), 32);
        assert_eq!(DhAlgorithm::Sm2Kex.public_key_size(), 64);
    }

    #[test]
    fn test_dh_algorithm_shared_secret_sizes() {
        assert_eq!(DhAlgorithm::EcdsaP256.shared_secret_size(), 32);
        assert_eq!(DhAlgorithm::EcdsaP384.shared_secret_size(), 48);
        assert_eq!(DhAlgorithm::X25519.shared_secret_size(), 32);
        assert_eq!(DhAlgorithm::Sm2Kex.shared_secret_size(), 32);
    }

    #[test]
    fn test_dh_algorithm_serde() {
        let alg = DhAlgorithm::X25519;
        let json = serde_json::to_string(&alg).unwrap();
        assert_eq!(json, "\"x25519\"");
        let de: DhAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(de, alg);
    }

    #[test]
    fn test_dh_algorithm_all_variants_serde() {
        for alg in [
            DhAlgorithm::EcdsaP256,
            DhAlgorithm::EcdsaP384,
            DhAlgorithm::X25519,
            DhAlgorithm::Sm2Kex,
        ] {
            let json = serde_json::to_string(&alg).unwrap();
            let de: DhAlgorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(de, alg);
        }
    }

    #[test]
    fn test_dh_key_pair_new() {
        let pub_key = vec![1u8; 32];
        let priv_key = vec![2u8; 32];
        let pair = DhKeyPair::new(DhAlgorithm::X25519, pub_key.clone(), priv_key.clone());
        assert_eq!(pair.algorithm, DhAlgorithm::X25519);
        assert_eq!(pair.public_key, pub_key);
        assert_eq!(pair.private_key(), &priv_key);
    }

    #[test]
    fn test_dh_key_pair_private_key_skipped_in_serde() {
        let pair = DhKeyPair::new(DhAlgorithm::X25519, vec![1u8; 32], vec![2u8; 32]);
        let json = serde_json::to_string(&pair).unwrap();
        // private_key should not appear in serialized form
        assert!(!json.contains("private_key"));
        // Deserialized pair should have empty private_key
        let de: DhKeyPair = serde_json::from_str(&json).unwrap();
        assert_eq!(de.public_key, vec![1u8; 32]);
        assert!(de.private_key().is_empty());
    }

    #[test]
    fn test_dh_derive_request_serde() {
        let req = DhDeriveRequest {
            key_id: Uuid::new_v4(),
            algorithm: DhAlgorithm::EcdsaP256,
            peer_public_key: vec![3u8; 65],
            shared_info: Some(b"context".to_vec()),
            key_length: Some(32),
        };
        let json = serde_json::to_string(&req).unwrap();
        let de: DhDeriveRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(de.algorithm, DhAlgorithm::EcdsaP256);
        assert_eq!(de.peer_public_key, vec![3u8; 65]);
        assert_eq!(de.shared_info, Some(b"context".to_vec()));
        assert_eq!(de.key_length, Some(32));
    }

    #[test]
    fn test_dh_derive_request_defaults() {
        let json = r#"{"key_id":"00000000-0000-0000-0000-000000000000","algorithm":"x25519","peer_public_key":[]}"#;
        let de: DhDeriveRequest = serde_json::from_str(json).unwrap();
        assert_eq!(de.algorithm, DhAlgorithm::X25519);
        assert!(de.shared_info.is_none());
        assert!(de.key_length.is_none());
    }

    #[test]
    fn test_dh_derive_response_serde() {
        let resp = DhDeriveResponse {
            shared_secret: vec![0xAB; 32],
            kdf: "HKDF-SHA256".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let de: DhDeriveResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(de.shared_secret, vec![0xAB; 32]);
        assert_eq!(de.kdf, "HKDF-SHA256");
    }

    #[test]
    fn test_shared_secret_serde() {
        let ss = SharedSecret {
            secret: vec![0xFF; 32],
            kdf: Some("HKDF-SHA256".to_string()),
        };
        let json = serde_json::to_string(&ss).unwrap();
        let de: SharedSecret = serde_json::from_str(&json).unwrap();
        assert_eq!(de.secret, vec![0xFF; 32]);
        assert_eq!(de.kdf, Some("HKDF-SHA256".to_string()));
    }

    #[test]
    fn test_shared_secret_kdf_none() {
        let ss = SharedSecret {
            secret: vec![0; 16],
            kdf: None,
        };
        let json = serde_json::to_string(&ss).unwrap();
        let de: SharedSecret = serde_json::from_str(&json).unwrap();
        assert!(de.kdf.is_none());
    }
}
