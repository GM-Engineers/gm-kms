//! The wire types of the SDK.
//!
//! Every type here mirrors a REST DTO of the server (`crates/kms-api/src/rest.rs`).
//! The drift guard in `tests/contract.rs` compares them against the server's
//! own DTOs, so a change on either side that breaks the other fails the build
//! rather than the customer.
//!
//! Binary payloads cross the wire as base64 strings, exactly as the server
//! encodes them. The SDK hides that: the request and response types carry raw
//! bytes and do the encoding themselves.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

/// Serde helper for byte fields that cross the wire as base64 strings.
pub mod base64_bytes {
    use super::{b64, unb64};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize a byte slice as a base64 string.
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&b64(bytes))
    }

    /// Deserialize a base64 string into a byte slice.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let raw = String::deserialize(deserializer)?;
        unb64(&raw).map_err(serde::de::Error::custom)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Keys
// ═══════════════════════════════════════════════════════════════════════════

/// The algorithm of a key.
///
/// The server accepts several spellings of the same algorithm
/// (`"aes-256-gcm"` and `"aes256gcm"`, ...) and answers with the Debug
/// spelling of its internal enum (`"Aes256Gcm"`). [`KeySpec::parse`] accepts
/// all of them, and [`KeySpec::as_str`] returns the canonical spelling the SDK
/// sends.
///
/// A specification this SDK version does not know about is kept verbatim in
/// [`KeySpec::Other`] instead of failing: the server may add algorithms, and
/// an SDK that refused to represent them would break the moment it was used
/// against a newer server.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeySpec {
    /// AES-256-GCM symmetric key.
    Aes256Gcm,
    /// HMAC-SHA256 key.
    HmacSha256,
    /// HMAC-SM3 managed MAC key (国密 SM3 密钥杂凑算法).
    Sm3Hmac,
    /// ECDSA with the P-256 curve.
    EcdsaP256,
    /// ECDSA with the P-384 curve.
    EcdsaP384,
    /// Ed25519 signature key.
    Ed25519,
    /// Ed448 signature key.
    Ed448,
    /// SM4 symmetric key (国密对称加密, 128-bit).
    Sm4,
    /// SM2 asymmetric key (国密非对称).
    Sm2,
    /// SM9 signing key (国密标识密码签名算法).
    Sm9Signing,
    /// SM9 encryption key (国密标识密码加密算法).
    Sm9Encryption,
    /// RSA-4096 asymmetric key.
    Rsa4096,
    /// A specification this SDK version does not know about.
    Other(String),
}

impl KeySpec {
    /// The canonical spelling of the specification, as sent to the server.
    ///
    /// For [`KeySpec::Other`] this is the unknown spelling itself, so that a
    /// value read from the server can be written back unchanged.
    pub fn as_str(&self) -> &str {
        match self {
            KeySpec::Aes256Gcm => "aes-256-gcm",
            KeySpec::HmacSha256 => "hmac-sha256",
            KeySpec::Sm3Hmac => "hmac-sm3",
            KeySpec::EcdsaP256 => "ecdsa-p256",
            KeySpec::EcdsaP384 => "ecdsa-p384",
            KeySpec::Ed25519 => "ed25519",
            KeySpec::Ed448 => "ed448",
            KeySpec::Sm4 => "sm4",
            KeySpec::Sm2 => "sm2",
            KeySpec::Sm9Signing => "sm9-signing",
            KeySpec::Sm9Encryption => "sm9-encryption",
            KeySpec::Rsa4096 => "rsa-4096",
            KeySpec::Other(s) => s.as_str(),
        }
    }

    /// Parse a specification, accepting every spelling the server accepts.
    ///
    /// The server lowercases the value before matching it, and additionally
    /// accepts the Debug spelling it returns in responses. Both are handled
    /// here.
    pub fn parse(value: &str) -> KeySpec {
        match value.to_lowercase().as_str() {
            "aes-256-gcm" | "aes256gcm" => KeySpec::Aes256Gcm,
            "hmac-sha256" | "hmacsha256" => KeySpec::HmacSha256,
            "hmac-sm3" | "sm3-hmac" | "sm3hmac" => KeySpec::Sm3Hmac,
            "ecdsa-p256" | "ecdsap256" => KeySpec::EcdsaP256,
            "ecdsa-p384" | "ecdsap384" => KeySpec::EcdsaP384,
            "ed25519" => KeySpec::Ed25519,
            "ed448" => KeySpec::Ed448,
            "sm4" => KeySpec::Sm4,
            "sm2" => KeySpec::Sm2,
            "sm9-signing" | "sm9signing" => KeySpec::Sm9Signing,
            "sm9-encryption" | "sm9encryption" => KeySpec::Sm9Encryption,
            "rsa-4096" | "rsa4096" => KeySpec::Rsa4096,
            _ => KeySpec::Other(value.to_string()),
        }
    }
}

impl fmt::Display for KeySpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for KeySpec {
    fn from(value: &str) -> Self {
        KeySpec::parse(value)
    }
}

impl From<String> for KeySpec {
    fn from(value: String) -> Self {
        KeySpec::parse(&value)
    }
}

impl Serialize for KeySpec {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for KeySpec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(KeySpec::parse(&raw))
    }
}

/// The metadata of a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Key {
    /// The key's unique identifier.
    pub id: Uuid,
    /// The tenant the key belongs to.
    pub tenant_id: String,
    /// The human-readable name of the key.
    pub name: String,
    /// The algorithm of the key.
    pub spec: KeySpec,
    /// The current status (`"Active"`, `"PendingDeletion"`, ...).
    pub status: String,
    /// The current version; a rotation increments it.
    pub version: u32,
    /// The creation timestamp, RFC 3339.
    pub created_at: String,
}

/// The request to create a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateKeyRequest {
    /// The name of the key, unique within the tenant.
    pub name: String,
    /// The algorithm of the key.
    pub spec: KeySpec,
    /// The tenant to create the key in.
    ///
    /// `None` uses the tenant configured on the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Cryptographic operations
// ═══════════════════════════════════════════════════════════════════════════

/// The request to encrypt data with a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptRequest {
    /// The plaintext to encrypt.
    #[serde(with = "base64_bytes")]
    pub plaintext: Vec<u8>,
    /// Additional authenticated data.
    ///
    /// The AAD is part of what the AEAD authenticates: a ciphertext can only
    /// be decrypted with the same AAD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad: Option<Vec<u8>>,
}

/// The result of an encryption: ciphertext, nonce and authentication tag.
///
/// The three parts belong together — the nonce and the tag are part of the
/// ciphertext, and the key version and format version decide how the AAD is
/// rebuilt. [`EncryptedData`] keeps them together so that they cannot be
/// mixed up between two calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedData {
    /// The ciphertext.
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
    /// The nonce (IV) the ciphertext was produced with.
    #[serde(with = "base64_bytes")]
    pub nonce: Vec<u8>,
    /// The authentication tag.
    #[serde(with = "base64_bytes")]
    pub tag: Vec<u8>,
    /// The key version used.
    pub version: u32,
    /// The ciphertext format version.
    ///
    /// At format 2 the AAD binds `(key_id, tenant_id, version)`. A ciphertext
    /// produced under format 0 or 1 (the legacy, empty-AAD format) must be
    /// decrypted by echoing this value back.
    pub format_version: u8,
}

impl EncryptedData {
    /// The decryption request that decrypts this ciphertext.
    ///
    /// The format version and the key version travel with the ciphertext: at
    /// format 2 the AAD binds them, so dropping them would make the
    /// decryption fail (or, worse, decrypt the wrong version).
    pub fn to_decrypt_request(&self) -> DecryptRequest {
        DecryptRequest {
            ciphertext: self.ciphertext.clone(),
            nonce: self.nonce.clone(),
            tag: self.tag.clone(),
            aad: None,
            format_version: self.format_version,
            version: self.version,
        }
    }
}

/// The request to decrypt a ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptRequest {
    /// The ciphertext to decrypt.
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
    /// The nonce the ciphertext was produced with.
    #[serde(with = "base64_bytes")]
    pub nonce: Vec<u8>,
    /// The authentication tag.
    #[serde(with = "base64_bytes")]
    pub tag: Vec<u8>,
    /// The additional authenticated data used at encryption time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad: Option<Vec<u8>>,
    /// The ciphertext format version.
    ///
    /// Defaults to the current production format (2). A legacy ciphertext
    /// (format 0 or 1) must echo the value that [`Client::encrypt`] returned.
    #[serde(default = "default_format_version")]
    pub format_version: u8,
    /// The key version the ciphertext was produced with.
    ///
    /// Defaults to 1. A ciphertext produced after a key rotation must echo
    /// the version that [`Client::encrypt`] returned.
    #[serde(default = "default_decrypt_version")]
    pub version: u32,
}

fn default_format_version() -> u8 {
    2
}

fn default_decrypt_version() -> u32 {
    1
}

impl Default for DecryptRequest {
    fn default() -> Self {
        DecryptRequest {
            ciphertext: Vec::new(),
            nonce: Vec::new(),
            tag: Vec::new(),
            aad: None,
            format_version: default_format_version(),
            version: default_decrypt_version(),
        }
    }
}

/// The answer of a decryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptResult {
    /// The decrypted plaintext.
    #[serde(with = "base64_bytes")]
    pub plaintext: Vec<u8>,
}

/// The request to sign data with an asymmetric key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequest {
    /// The data to sign.
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
}

/// A signature and the key version that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// The signature bytes.
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
    /// The key version used.
    pub version: u32,
}

/// The request to verify a signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyRequest {
    /// The data that was signed.
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
    /// The signature to verify.
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

/// The answer of a verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResult {
    /// Whether the signature is valid.
    pub valid: bool,
}

/// The request to compute a managed HMAC-SM3 tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HmacRequest {
    /// The data to MAC.
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
    /// Additional authenticated data.
    ///
    /// The AAD is domain-separated into the MAC input; the same AAD must be
    /// supplied when the tag is verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad: Option<Vec<u8>>,
}

/// The request to verify a managed HMAC-SM3 tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HmacVerifyRequest {
    /// The data the MAC was computed over.
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
    /// The MAC tag to verify.
    #[serde(with = "base64_bytes")]
    pub mac: Vec<u8>,
    /// The additional authenticated data used at computation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad: Option<Vec<u8>>,
}

/// A managed HMAC tag and the key version that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacTag {
    /// The MAC bytes.
    #[serde(with = "base64_bytes")]
    pub mac: Vec<u8>,
    /// The key version used.
    pub version: u32,
}

/// The hash algorithms the server supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SM3, the GM standard hash (国密).
    #[serde(rename = "sm3")]
    Sm3,
    /// SHA-256.
    #[serde(rename = "sha256")]
    Sha256,
}

/// The request to compute a hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashRequest {
    /// The data to hash.
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
    /// The algorithm to use.
    pub algorithm: HashAlgorithm,
}

/// The result of a hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashResult {
    /// The hex-encoded digest.
    pub hash: String,
    /// The algorithm that produced it.
    pub algorithm: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// Envelope encryption
// ═══════════════════════════════════════════════════════════════════════════

/// The request to encrypt with a data-encrypting key wrapped by a
/// key-encrypting key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeEncryptRequest {
    /// The plaintext to encrypt.
    #[serde(with = "base64_bytes")]
    pub plaintext: Vec<u8>,
    /// The id of the key-encrypting key.
    pub kek_id: Uuid,
    /// The length of the data-encrypting key in bytes (32 for AES-256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dek_length: Option<usize>,
    /// The tenant to act in; `None` uses the client's tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

/// The result of an envelope encryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeEncrypted {
    /// The data-encrypting key, wrapped with the key-encrypting key.
    #[serde(with = "base64_bytes")]
    pub wrapped_dek: Vec<u8>,
    /// The nonce the data-encrypting key was wrapped with.
    #[serde(with = "base64_bytes")]
    pub dek_nonce: Vec<u8>,
    /// The ciphertext.
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
    /// The nonce the ciphertext was produced with.
    #[serde(with = "base64_bytes")]
    pub data_nonce: Vec<u8>,
    /// The authentication tag.
    #[serde(with = "base64_bytes")]
    pub tag: Vec<u8>,
    /// The version of the key-encrypting key.
    pub kek_version: u32,
}

/// The request to decrypt an envelope-encrypted payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeDecryptRequest {
    /// The wrapped data-encrypting key.
    #[serde(with = "base64_bytes")]
    pub wrapped_dek: Vec<u8>,
    /// The nonce the data-encrypting key was wrapped with.
    #[serde(with = "base64_bytes")]
    pub dek_nonce: Vec<u8>,
    /// The ciphertext.
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
    /// The nonce the ciphertext was produced with.
    #[serde(with = "base64_bytes")]
    pub data_nonce: Vec<u8>,
    /// The authentication tag.
    #[serde(with = "base64_bytes")]
    pub tag: Vec<u8>,
    /// The id of the key-encrypting key.
    pub kek_id: Uuid,
    /// The version of the key-encrypting key used at encryption time.
    pub kek_version: u32,
    /// The tenant to act in; `None` uses the client's tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

/// The request to re-wrap a data-encrypting key under a newer version of the
/// key-encrypting key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeRewrapRequest {
    /// The wrapped data-encrypting key.
    #[serde(with = "base64_bytes")]
    pub wrapped_dek: Vec<u8>,
    /// The nonce the data-encrypting key was wrapped with.
    #[serde(with = "base64_bytes")]
    pub dek_nonce: Vec<u8>,
    /// The id of the key-encrypting key.
    pub kek_id: Uuid,
    /// The version of the key-encrypting key used at encryption time.
    pub old_kek_version: u32,
    /// The tenant to act in; `None` uses the client's tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

/// The result of a re-wrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeRewrapped {
    /// The re-wrapped data-encrypting key.
    #[serde(with = "base64_bytes")]
    pub wrapped_dek: Vec<u8>,
    /// The new nonce.
    #[serde(with = "base64_bytes")]
    pub dek_nonce: Vec<u8>,
    /// The current version of the key-encrypting key.
    pub kek_version: u32,
    /// The version the data-encrypting key was wrapped with before.
    pub old_kek_version: u32,
}

// ═══════════════════════════════════════════════════════════════════════════
// Key import and export
// ═══════════════════════════════════════════════════════════════════════════

/// The request to import an externally generated key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportKeyRequest {
    /// The name of the key, unique within the tenant.
    pub name: String,
    /// The algorithm of the imported key.
    pub spec: KeySpec,
    /// The format of the imported key: `"pkcs8"`, `"jwk"` or `"raw"`.
    pub format: String,
    /// The key material, wrapped with a transport key.
    #[serde(with = "base64_bytes")]
    pub wrapped_key: Vec<u8>,
    /// The transport key, encrypted with the KMS's public key.
    #[serde(with = "base64_bytes")]
    pub encrypted_transport_key: Vec<u8>,
    /// The SHA-256 fingerprint of the source key.
    pub source_fingerprint: String,
    /// The tenant to import into; `None` uses the client's tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

/// The result of a key import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportKeyResult {
    /// The id of the imported key.
    pub id: String,
    /// The algorithm of the imported key.
    pub spec: String,
    /// Whether the key was imported (always true for an import).
    pub imported: bool,
    /// The source fingerprint, for the audit trail.
    pub source_fingerprint: String,
}

/// The request to export a key.
///
/// The export is always a *wrapped* export: the material is encrypted with a
/// transport key that is itself encrypted with `target_public_key`, so the
/// plaintext never leaves the KMS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportKeyRequest {
    /// The id of the key to export.
    #[serde(skip)]
    pub key_id: Uuid,
    /// The system the material is exported to; recorded in the audit log.
    pub target_system: String,
    /// The base64-encoded public key of the target system.
    pub target_public_key: String,
    /// The purpose of the export (`"migration"`, `"backup"`, ...).
    pub purpose: String,
    /// The id of the approved `KeyExport` approval request.
    ///
    /// The export is refused without it (403).
    #[serde(default)]
    pub approval_id: Option<String>,
    /// How the transport key is protected: `"rsa-oaep"` (default) or `"sm2"`.
    #[serde(default)]
    pub protection_scheme: Option<String>,
    /// The version to export; `None` exports the current version.
    #[serde(default)]
    pub version: Option<u32>,
    /// The tenant to act in; `None` uses the client's tenant.
    ///
    /// The tenant travels as a query parameter, not in the body.
    #[serde(skip)]
    pub tenant_id: Option<String>,
}

/// The result of a key export: the wrapped material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportKeyResult {
    /// The key material, wrapped with the transport key.
    #[serde(with = "base64_bytes")]
    pub wrapped_key: Vec<u8>,
    /// The transport key, encrypted with the target system's public key.
    #[serde(with = "base64_bytes")]
    pub encrypted_transport_key: Vec<u8>,
    /// The SHA-256 fingerprint of the key.
    pub key_fingerprint: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// Approvals
// ═══════════════════════════════════════════════════════════════════════════

/// The operations that can require an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOperation {
    /// Deleting a key.
    KeyDelete,
    /// Exporting a key.
    KeyExport,
    /// Rotating a key.
    KeyRotate,
    /// Changing a policy.
    PolicyChange,
    /// Creating a high-value key.
    HighValueKeyCreate,
    /// Reading the audit log.
    AuditAccess,
    /// Changing the MFA configuration.
    MfaChange,
    /// Changing a tenant administrator.
    TenantAdmin,
}

impl ApprovalOperation {
    /// The spelling the server expects.
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalOperation::KeyDelete => "key_delete",
            ApprovalOperation::KeyExport => "key_export",
            ApprovalOperation::KeyRotate => "key_rotate",
            ApprovalOperation::PolicyChange => "policy_change",
            ApprovalOperation::HighValueKeyCreate => "high_value_key_create",
            ApprovalOperation::AuditAccess => "audit_access",
            ApprovalOperation::MfaChange => "mfa_change",
            ApprovalOperation::TenantAdmin => "tenant_admin",
        }
    }
}

impl fmt::Display for ApprovalOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The status of an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Waiting for approval.
    Pending,
    /// Approved.
    Approved,
    /// Rejected.
    Rejected,
    /// Cancelled by the requestor.
    Cancelled,
    /// Expired.
    Expired,
    /// Activated in an emergency.
    EmergencyActivated,
    /// The emergency activation expired.
    EmergencyExpired,
}

/// The authority level of an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalLevel {
    /// No approval required.
    None,
    /// One approver.
    Single,
    /// Two approvers.
    Double,
    /// Three approvers.
    Triple,
    /// A manager.
    Manager,
    /// An administrator.
    Admin,
}

/// The request to raise an approval request.
///
/// The requestor is **not** part of this request: the server derives it from
/// the authenticated API key, and a body-supplied requestor would be ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateApprovalRequest {
    /// The operation the approval is for.
    pub operation: ApprovalOperation,
    /// The resource the approval is bound to.
    pub resource_id: String,
    /// Why the approval is needed.
    #[serde(default)]
    pub justification: Option<String>,
    /// The tenant to act in; `None` uses the client's tenant.
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// The request to approve an approval request.
///
/// The approver's identity and authority come from the API key, so this body
/// carries nothing but the comment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproveRequest {
    /// An optional comment, recorded in the audit trail.
    #[serde(default)]
    pub comment: Option<String>,
}

/// The request to reject an approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectRequest {
    /// Why the request was rejected.
    pub reason: String,
}

/// An approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    /// The id of the request.
    pub id: String,
    /// The operation the approval is for.
    pub operation: String,
    /// The resource the approval is bound to.
    pub resource_id: String,
    /// The type of the bound resource.
    pub resource_type: String,
    /// The tenant the request belongs to.
    pub tenant_id: String,
    /// The authenticated key that raised the request.
    pub requestor_id: String,
    /// Why the approval was needed.
    #[serde(default)]
    pub justification: Option<String>,
    /// The current status.
    pub status: ApprovalStatus,
    /// The authority level the operation requires.
    pub required_level: ApprovalLevel,
    /// The authority level reached so far.
    pub current_level: ApprovalLevel,
    /// How many approvals the request has.
    pub approvals_count: usize,
    /// How many rejections the request has.
    pub rejections_count: usize,
    /// The creation timestamp, RFC 3339.
    pub created_at: String,
    /// The deadline, RFC 3339. An expired request authorizes nothing.
    pub expires_at: String,
    /// The completion timestamp, RFC 3339.
    #[serde(default)]
    pub completed_at: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Policies
// ═══════════════════════════════════════════════════════════════════════════

/// The effect of a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyEffect {
    /// Grants access. Serialized as `"allow"`, the spelling the server expects.
    #[serde(rename = "allow", alias = "Allow")]
    Allow,
    /// Denies access. Serialized as `"deny"`, the spelling the server expects.
    #[serde(rename = "deny", alias = "Deny")]
    Deny,
}

/// The request to create a PBAC policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatePolicyRequest {
    /// The name of the policy.
    pub name: String,
    /// Whether the policy grants or denies.
    pub effect: PolicyEffect,
    /// The condition expression, as a JSON document.
    pub condition: serde_json::Value,
    /// The resource patterns the policy applies to.
    pub resources: Vec<String>,
    /// The subject patterns the policy applies to.
    pub subjects: Vec<String>,
    /// The tenant the policy is restricted to.
    ///
    /// `None` means the policy is not tenant-scoped and applies to every
    /// tenant. A value restricts it to that tenant; a glob pattern is
    /// accepted, so `tenant-*` covers a family of tenants.
    #[serde(default)]
    pub tenant: Option<String>,
    /// Whether the policy is active.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// A PBAC policy.
///
/// `effect` keeps the server's spelling (`"Allow"` / `"Deny"`) so that a
/// policy read from the server can be written back unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// The id of the policy.
    pub id: String,
    /// The name of the policy.
    pub name: String,
    /// Whether the policy grants or denies.
    pub effect: String,
    /// The condition expression, as a JSON document.
    pub condition: serde_json::Value,
    /// The resource patterns the policy applies to.
    pub resources: Vec<String>,
    /// The subject patterns the policy applies to.
    pub subjects: Vec<String>,
    /// The tenant the policy is restricted to, if any.
    #[serde(default)]
    pub tenant: Option<String>,
    /// Whether the policy is active.
    pub enabled: bool,
}

// ═══════════════════════════════════════════════════════════════════════════
// Health
// ═══════════════════════════════════════════════════════════════════════════

/// The health of the individual components.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// The health of the keystore.
    pub keystore: String,
    /// The health of the audit log.
    pub audit: String,
}

/// The health of the KMS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    /// The overall status (`"ok"`, `"degraded"`, `"error"`).
    pub status: String,
    /// The version of the server.
    pub version: String,
    /// The health of the individual components.
    pub components: ComponentHealth,
}

// ═══════════════════════════════════════════════════════════════════════════
// SM9 (国密标识密码)
// ═══════════════════════════════════════════════════════════════════════════

/// The request to sign data with the SM9 identity-based scheme.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sm9SignRequest {
    /// The identity of the signer.
    pub identity: String,
    /// The data to sign.
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
}

/// The request to verify an SM9 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sm9VerifyRequest {
    /// The identity of the signer.
    pub identity: String,
    /// The data that was signed.
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
    /// The first component of the signature.
    #[serde(with = "base64_bytes")]
    pub w: Vec<u8>,
    /// The second component of the signature, hex-encoded.
    pub h: String,
    /// The third component of the signature.
    #[serde(with = "base64_bytes")]
    pub s: Vec<u8>,
}

/// The result of an SM9 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sm9Signature {
    /// The first component of the signature.
    #[serde(with = "base64_bytes")]
    pub w: Vec<u8>,
    /// The second component of the signature, hex-encoded by the server.
    pub h: String,
    /// The third component of the signature.
    #[serde(with = "base64_bytes")]
    pub s: Vec<u8>,
}

/// The request to encrypt data for an SM9 identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sm9EncryptRequest {
    /// The identity of the recipient.
    pub identity: String,
    /// The plaintext to encrypt.
    #[serde(with = "base64_bytes")]
    pub plaintext: Vec<u8>,
}

/// The request to decrypt an SM9 ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sm9DecryptRequest {
    /// The identity of the recipient.
    pub identity: String,
    /// The first component of the ciphertext.
    #[serde(with = "base64_bytes")]
    pub c1: Vec<u8>,
    /// The second component of the ciphertext.
    #[serde(with = "base64_bytes")]
    pub c2: Vec<u8>,
    /// The third component of the ciphertext, hex-encoded.
    pub c3: String,
}

/// The result of an SM9 encryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sm9Ciphertext {
    /// The first component of the ciphertext.
    #[serde(with = "base64_bytes")]
    pub c1: Vec<u8>,
    /// The second component of the ciphertext.
    #[serde(with = "base64_bytes")]
    pub c2: Vec<u8>,
    /// The third component of the ciphertext, hex-encoded by the server.
    pub c3: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// Key derivation
// ═══════════════════════════════════════════════════════════════════════════

/// The request to derive a shared secret with a Diffie-Hellman key exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhDeriveRequest {
    /// The id of the private key to derive with.
    pub key_id: Uuid,
    /// The algorithm: `"ECDH-P256"`, `"ECDH-P384"`, `"X25519"` or `"SM2-KEX"`.
    pub algorithm: String,
    /// The peer's public key.
    #[serde(with = "base64_bytes")]
    pub peer_public_key: Vec<u8>,
    /// The tenant to act in; `None` uses the client's tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

/// The result of a key derivation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedSecret {
    /// The derived shared secret.
    #[serde(with = "base64_bytes")]
    pub shared_secret: Vec<u8>,
    /// The key derivation function that was used.
    pub kdf: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// Internals
// ═══════════════════════════════════════════════════════════════════════════

/// Encode a byte slice the way the server expects it.
pub(crate) fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decode a base64 field the way the server sends it.
pub(crate) fn unb64(value: &str) -> crate::Result<Vec<u8>> {
    Ok(STANDARD.decode(value)?)
}
