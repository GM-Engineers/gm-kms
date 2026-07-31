//! Key domain types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Key specification - defines the type and parameters of a key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "params")]
pub enum KeySpec {
    /// AES-256-GCM symmetric key
    Aes256Gcm,
    /// RSA-4096 asymmetric key pair
    Rsa4096,
    /// ECDSA with P-256 curve
    EcdsaP256,
    /// ECDSA with P-384 curve
    EcdsaP384,
    /// Ed25519 signature key
    Ed25519,
    /// Ed448 signature key
    Ed448,
    /// HMAC-SHA256 (also used for audit log signing)
    HmacSha256,
    /// SM2 signature key (国密非对称加密)
    Sm2,
    /// SM4 symmetric encryption (国密对称加密, 128-bit)
    Sm4,
    /// SM9 signing key (国密标识密码签名算法)
    Sm9Signing,
    /// SM9 encryption key (国密标识密码加密算法)
    Sm9Encryption,
}

/// Key purpose - defines what a key is used for (for lifecycle management)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    /// Key used for data encryption (DEK)
    DataEncryption,
    /// Key used for key encryption (KEK)
    KeyEncryption,
    /// Key used for signing/verification
    Signing,
    /// Key used for audit log integrity (HMAC)
    AuditSigning,
}

impl KeySpec {
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            KeySpec::Aes256Gcm => "AES-256-GCM",
            KeySpec::Rsa4096 => "RSA-4096",
            KeySpec::EcdsaP256 => "ECDSA-P256",
            KeySpec::EcdsaP384 => "ECDSA-P384",
            KeySpec::Ed25519 => "Ed25519",
            KeySpec::Ed448 => "Ed448",
            KeySpec::HmacSha256 => "HMAC-SHA256",
            KeySpec::Sm2 => "SM2",
            KeySpec::Sm4 => "SM4",
            KeySpec::Sm9Signing => "SM9-Signing",
            KeySpec::Sm9Encryption => "SM9-Encryption",
        }
    }

    pub fn is_asymmetric(&self) -> bool {
        matches!(
            self,
            KeySpec::Rsa4096
                | KeySpec::EcdsaP256
                | KeySpec::EcdsaP384
                | KeySpec::Ed25519
                | KeySpec::Ed448
                | KeySpec::Sm2
                | KeySpec::Sm9Signing
                | KeySpec::Sm9Encryption
        )
    }

    pub fn is_symmetric(&self) -> bool {
        matches!(
            self,
            KeySpec::Aes256Gcm | KeySpec::HmacSha256 | KeySpec::Sm4
        )
    }

    pub fn supports_encryption(&self) -> bool {
        matches!(
            self,
            KeySpec::Aes256Gcm
                | KeySpec::Rsa4096
                | KeySpec::Sm4
                | KeySpec::Sm2
                | KeySpec::Sm9Encryption
        )
    }

    pub fn supports_signing(&self) -> bool {
        matches!(
            self,
            KeySpec::Rsa4096
                | KeySpec::EcdsaP256
                | KeySpec::EcdsaP384
                | KeySpec::Ed25519
                | KeySpec::Ed448
                | KeySpec::Sm2
                | KeySpec::Sm9Signing
        )
    }

    /// Get the default purpose for a key spec
    pub fn default_purpose(&self) -> KeyPurpose {
        match self {
            KeySpec::HmacSha256 => KeyPurpose::AuditSigning,
            KeySpec::Sm2
            | KeySpec::Ed25519
            | KeySpec::Ed448
            | KeySpec::EcdsaP256
            | KeySpec::EcdsaP384
            | KeySpec::Rsa4096
            | KeySpec::Sm9Signing => KeyPurpose::Signing,
            _ => KeyPurpose::DataEncryption,
        }
    }
}

/// Key status - lifecycle state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyStatus {
    /// Key is active and can be used
    Active,
    /// Key is pending deletion (grace period)
    PendingDeletion,
    /// Key is obsolete (replaced by newer version)
    Obsolete,
    /// Key has been destroyed
    Destroyed,
}

impl KeyStatus {
    pub fn can_use(&self) -> bool {
        matches!(self, KeyStatus::Active)
    }

    pub fn can_decrypt(&self) -> bool {
        matches!(
            self,
            KeyStatus::Active | KeyStatus::PendingDeletion | KeyStatus::Obsolete
        )
    }

    pub fn can_rotate(&self) -> bool {
        matches!(self, KeyStatus::Active | KeyStatus::Obsolete)
    }
}

/// Key metadata - information about a key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMeta {
    /// Unique key identifier
    pub id: Uuid,
    /// Tenant ID for multi-tenancy
    pub tenant_id: String,
    /// Human-readable key name
    pub name: String,
    /// Key specification
    pub spec: KeySpec,
    /// Current status
    pub status: KeyStatus,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last rotation timestamp
    pub rotated_at: Option<DateTime<Utc>>,
    /// Current version number
    pub version: u32,
    /// Optional description
    pub description: Option<String>,
    /// Custom metadata (tags, etc.)
    #[serde(default)]
    pub metadata: KeyMetadata,
}

/// Additional key metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeyMetadata {
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub labels: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub max_usage_count: Option<u64>,
    #[serde(default)]
    pub current_usage_count: u64,
    #[serde(default)]
    pub allowed_operations: Vec<String>,
}

/// Full key entity with cryptographic material
pub struct Key {
    /// Key metadata
    pub meta: KeyMeta,
    /// Key material (never log this!)
    #[allow(dead_code)]
    material: zeroize::Zeroizing<Vec<u8>>,
}

impl Key {
    /// Create a new key with the given metadata and material
    pub fn new(meta: KeyMeta, material: Vec<u8>) -> Self {
        Self {
            meta,
            material: zeroize::Zeroizing::new(material),
        }
    }

    /// Get the key material (should be handled carefully)
    pub fn material(&self) -> &[u8] {
        &self.material
    }
}

/// Key filter for listing keys
#[derive(Debug, Clone, Default, Deserialize)]
pub struct KeyFilter {
    pub tenant_id: Option<String>,
    pub status: Option<KeyStatus>,
    pub spec: Option<KeySpec>,
    pub tags: Option<Vec<String>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Ciphertext structure for symmetric encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    /// The key ID used for encryption
    pub key_id: Uuid,
    /// Version of the key used
    pub version: u32,
    /// Ciphertext format version for future compatibility
    /// 0 = legacy format (no version byte)
    /// 1 = current format with explicit structure
    #[serde(default)]
    pub format_version: u8,
    /// Nonce/IV used for encryption
    pub nonce: Vec<u8>,
    /// The encrypted ciphertext
    pub ciphertext: Vec<u8>,
    /// Authentication tag
    pub tag: Vec<u8>,
}

/// Signature structure for asymmetric signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// The key ID used for signing
    pub key_id: Uuid,
    /// Version of the key used
    pub version: u32,
    /// The signature bytes
    pub signature: Vec<u8>,
}

/// Proof of key destruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestructionProof {
    /// The destroyed key ID
    pub key_id: Uuid,
    /// Hash of key material before destruction
    pub material_hash: String,
    /// When the key was destroyed
    pub destroyed_at: DateTime<Utc>,
    /// Hash algorithm used
    pub hash_algorithm: String,
    /// Size of key material in bytes
    pub key_size_bytes: usize,
    /// Whether zeroization was verified
    pub zeroization_verified: bool,
    /// HMAC signature for tamper evidence (optional, added in T-07)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_signature: Option<String>,
}

impl DestructionProof {
    /// Create a new destruction proof
    pub fn new(
        key_id: Uuid,
        material_hash: String,
        key_size_bytes: usize,
        zeroization_verified: bool,
        hmac_signature: Option<String>,
    ) -> Self {
        Self {
            key_id,
            material_hash,
            destroyed_at: Utc::now(),
            hash_algorithm: "SHA256".to_string(),
            key_size_bytes,
            zeroization_verified,
            hmac_signature,
        }
    }
    /// Compute HMAC signature for the destruction proof
    /// Hashes all fields except hmac_signature for deterministic output
    pub fn compute_hmac(&self, key: &[u8]) -> Vec<u8> {
        use ring::hmac::{HMAC_SHA256, Key};
        let signing_key = Key::new(HMAC_SHA256, key);
        // Serialize but exclude hmac_signature field for consistent hashing
        let mut value = serde_json::to_value(self).unwrap_or_default();
        if let Some(obj) = value.as_object_mut() {
            obj.remove("hmac_signature");
        }
        let data = serde_json::to_string(&value).unwrap_or_default();
        ring::hmac::sign(&signing_key, data.as_bytes())
            .as_ref()
            .to_vec()
    }

    /// Verify HMAC signature
    pub fn verify_hmac(&self, key: &[u8]) -> bool {
        if let Some(ref sig) = self.hmac_signature {
            // Compute HMAC over same data as compute_hmac (without hmac_signature)
            let mut value = serde_json::to_value(self).unwrap_or_default();
            if let Some(obj) = value.as_object_mut() {
                obj.remove("hmac_signature");
            }
            let data = serde_json::to_string(&value).unwrap_or_default();

            use ring::hmac::{HMAC_SHA256, Key};
            let signing_key = Key::new(HMAC_SHA256, key);
            let computed = ring::hmac::sign(&signing_key, data.as_bytes())
                .as_ref()
                .to_vec();

            // Decode base64 signature and compare
            if let Ok(decoded_sig) =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig)
            {
                use subtle::ConstantTimeEq;
                computed.ct_eq(&decoded_sig).into()
            } else {
                false
            }
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_spec_purpose() {
        assert_eq!(
            KeySpec::HmacSha256.default_purpose(),
            KeyPurpose::AuditSigning
        );
        assert_eq!(KeySpec::Sm2.default_purpose(), KeyPurpose::Signing);
        assert_eq!(
            KeySpec::Aes256Gcm.default_purpose(),
            KeyPurpose::DataEncryption
        );
    }

    #[test]
    fn test_destruction_proof_hmac() {
        let proof = DestructionProof {
            key_id: Uuid::new_v4(),
            material_hash: "abc123".to_string(),
            destroyed_at: Utc::now(),
            hash_algorithm: "SHA256".to_string(),
            key_size_bytes: 32,
            zeroization_verified: true,
            hmac_signature: None,
        };

        let hmac_key = b"test-hmac-key-32-bytes!!!!!";
        let sig = proof.compute_hmac(hmac_key);
        assert_eq!(sig.len(), 32);

        let mut signed_proof = proof.clone();
        signed_proof.hmac_signature = Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &sig,
        ));
        assert!(signed_proof.verify_hmac(hmac_key));
    }

    /// Test KeySpec algorithm_name
    #[test]
    fn test_key_spec_algorithm_name() {
        assert_eq!(KeySpec::Aes256Gcm.algorithm_name(), "AES-256-GCM");
        assert_eq!(KeySpec::Sm2.algorithm_name(), "SM2");
        assert_eq!(KeySpec::Sm4.algorithm_name(), "SM4");
        assert_eq!(KeySpec::Sm9Signing.algorithm_name(), "SM9-Signing");
        assert_eq!(KeySpec::Ed25519.algorithm_name(), "Ed25519");
        assert_eq!(KeySpec::HmacSha256.algorithm_name(), "HMAC-SHA256");
    }

    /// Test KeySpec is_asymmetric / is_symmetric
    #[test]
    fn test_key_spec_classification() {
        assert!(KeySpec::Aes256Gcm.is_symmetric());
        assert!(!KeySpec::Aes256Gcm.is_asymmetric());

        assert!(KeySpec::Sm2.is_asymmetric());
        assert!(!KeySpec::Sm2.is_symmetric());

        assert!(KeySpec::Ed25519.is_asymmetric());
        assert!(KeySpec::Rsa4096.is_asymmetric());

        assert!(KeySpec::Sm4.is_symmetric());
        assert!(KeySpec::HmacSha256.is_symmetric());
    }

    /// Test KeySpec supports_encryption / supports_signing
    #[test]
    fn test_key_spec_capabilities() {
        assert!(KeySpec::Aes256Gcm.supports_encryption());
        assert!(!KeySpec::Aes256Gcm.supports_signing());

        assert!(KeySpec::Sm2.supports_signing());
        assert!(KeySpec::Ed25519.supports_signing());

        assert!(KeySpec::Sm4.supports_encryption());
        assert!(!KeySpec::Sm4.supports_signing());
    }

    /// Test KeyStatus transitions
    #[test]
    fn test_key_status_can_use() {
        assert!(KeyStatus::Active.can_use());
        assert!(!KeyStatus::Obsolete.can_use());
        assert!(!KeyStatus::PendingDeletion.can_use());
        assert!(!KeyStatus::Destroyed.can_use());
    }

    /// Test KeyStatus can_decrypt
    #[test]
    fn test_key_status_can_decrypt() {
        assert!(KeyStatus::Active.can_decrypt());
        assert!(KeyStatus::Obsolete.can_decrypt()); // Obsolete keys can still decrypt
        assert!(KeyStatus::PendingDeletion.can_decrypt()); // grace period
        assert!(!KeyStatus::Destroyed.can_decrypt());
    }

    /// Test KeyStatus can_rotate
    #[test]
    fn test_key_status_can_rotate() {
        assert!(KeyStatus::Active.can_rotate());
        assert!(KeyStatus::Obsolete.can_rotate()); // Obsolete keys can be rotated
        assert!(!KeyStatus::PendingDeletion.can_rotate());
        assert!(!KeyStatus::Destroyed.can_rotate());
    }

    /// Test Key::new and material access
    #[test]
    fn test_key_new_and_material() {
        let meta = KeyMeta {
            id: Uuid::new_v4(),
            tenant_id: "tenant1".to_string(),
            name: "test-key".to_string(),
            spec: KeySpec::Aes256Gcm,
            status: KeyStatus::Active,
            created_at: Utc::now(),
            rotated_at: None,
            version: 1,
            description: None,
            metadata: KeyMetadata::default(),
        };
        let material = vec![0u8; 32];
        let key = Key::new(meta, material.clone());
        assert_eq!(key.material(), &material);
    }

    /// Test KeyFilter default
    #[test]
    fn test_key_filter_default() {
        let filter = KeyFilter::default();
        assert!(filter.tenant_id.is_none());
        assert!(filter.spec.is_none());
        assert!(filter.status.is_none());
    }

    /// Test DestructionProof verify_hmac with wrong key returns false
    #[test]
    fn test_destruction_proof_wrong_key() {
        let proof = DestructionProof {
            key_id: Uuid::new_v4(),
            material_hash: "abc123".to_string(),
            destroyed_at: Utc::now(),
            hash_algorithm: "SHA256".to_string(),
            key_size_bytes: 32,
            zeroization_verified: true,
            hmac_signature: Some("invalid_signature".to_string()),
        };

        // Wrong key should fail verification
        assert!(!proof.verify_hmac(b"wrong-key-32-bytes-long!!!!!!"));
    }

    /// Test DestructionProof verify_hmac with missing signature
    #[test]
    fn test_destruction_proof_no_signature() {
        let proof = DestructionProof {
            key_id: Uuid::new_v4(),
            material_hash: "abc123".to_string(),
            destroyed_at: Utc::now(),
            hash_algorithm: "SHA256".to_string(),
            key_size_bytes: 32,
            zeroization_verified: true,
            hmac_signature: None,
        };

        // No signature should fail verification
        assert!(!proof.verify_hmac(b"any-key-32-bytes-long!!!!!!!!"));
    }
}
