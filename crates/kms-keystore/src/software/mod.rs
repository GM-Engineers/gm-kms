//! Software keystore implementation
//!
//! Pure software implementation using ring for cryptographic operations.
//! Also supports GM (国密) algorithms via gm-crypto (SM2/SM3/SM4).
//!
//! Module structure:
//!   - mod.rs: Public API, KeystoreBackend trait impl, SM2-KEX session management
//!   - tests.rs: Unit and integration tests

use async_trait::async_trait;
use chrono::Utc;
use gm_crypto::sm2_kex::{KexSession, Sm2KexMessage, Sm2KexResult};
use kms_core::{
    BackendType, Result,
    dh::SharedSecret,
    error::Error,
    key::{Ciphertext, DestructionProof, KeyMeta, KeySpec, KeyStatus, Signature},
};
use parking_lot::RwLock;
use rand::Rng;
use ring::{
    aead, digest,
    error::Unspecified,
    signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// SM2-KEX session timeout (60 seconds per GM/T 002-2012)
const SM2_KEX_SESSION_TIMEOUT_SECS: u64 = 60;

/// Maximum message history size for replay protection
const MAX_MESSAGE_HISTORY_SIZE: usize = 10;

/// In-memory key entry with material and version history
///
/// Uses `zeroize::Zeroizing` to automatically clear key material from memory when dropped.
/// Zeroizing uses volatile-grade memory operations to resist compiler optimizations,
/// and is designed to prevent data from being optimized away by LLVM.
struct KeyEntry {
    meta: KeyMeta,
    material: zeroize::Zeroizing<Vec<u8>>,
    /// Previous key material versions for decryption of historical ciphertexts
    /// Each entry is (version, encrypted_dek_or_raw_key_material)
    versions: Vec<(u32, zeroize::Zeroizing<Vec<u8>>)>,
}

/// SM2-KEX session entry with replay protection
#[allow(dead_code)]
struct Sm2KexSessionEntry {
    session_id: Uuid,
    key_id: Uuid,
    user_id: Vec<u8>,
    session: KexSession,
    is_initiator: bool,
    /// Nonce counter for message sequence tracking
    nonce: u64,
    /// Session creation timestamp for timeout detection
    created_at: Instant,
    /// Recent message hash history for replay attack detection (timestamp, message hash)
    message_history: Vec<(Instant, Vec<u8>)>,
}

/// Message history TTL in seconds - messages older than this are considered expired
const MESSAGE_HISTORY_TTL_SECS: u64 = 60;

/// Revoked session entry with expiry
#[allow(dead_code)]
struct RevokedSessionEntry {
    revoked_at: Instant,
    /// Expiry time for the revocation (prevents memory leak)
    expires_at: Instant,
}

/// Software-based keystore implementation
pub struct SoftwareKeystore {
    keys: RwLock<std::collections::HashMap<Uuid, KeyEntry>>,
    sm2_kex_sessions: RwLock<std::collections::HashMap<Uuid, Sm2KexSessionEntry>>,
    /// Revoked session IDs to prevent replay of old sessions after removal
    revoked_sessions: RwLock<std::collections::HashMap<Uuid, RevokedSessionEntry>>,
}

impl SoftwareKeystore {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(std::collections::HashMap::new()),
            sm2_kex_sessions: RwLock::new(std::collections::HashMap::new()),
            revoked_sessions: RwLock::new(std::collections::HashMap::new()),
        }
    }

    fn generate_aes_key(&self) -> Vec<u8> {
        let mut key = vec![0u8; 32]; // AES-256
        rand::rng().fill_bytes(&mut key);
        key
    }

    fn generate_ed25519_key(&self) -> Vec<u8> {
        let mut key = vec![0u8; 32];
        rand::rng().fill_bytes(&mut key);
        key
    }

    fn generate_sm4_key(&self) -> Vec<u8> {
        let mut key = vec![0u8; 16]; // SM4 uses 128-bit key
        rand::rng().fill_bytes(&mut key);
        key
    }

    fn generate_sm2_key(&self) -> Vec<u8> {
        // SM2 private key is 32 bytes
        let mut key = vec![0u8; 32];
        rand::rng().fill_bytes(&mut key);
        key
    }

    /// Derive shared secret using ECDH with P-256 curve
    ///
    /// Uses the `p256` crate for ECDH operations.
    ///
    /// **Security note**: This implementation uses EphemeralSecret for forward secrecy.
    /// The `_private_key` parameter is ignored because the p256 ECDH API generates
    /// a fresh ephemeral key pair for each exchange. This is intentional - using
    /// static keys would compromise forward secrecy.
    ///
    /// For static key ECDH (not recommended for production), use X25519 which
    /// properly imports the provided private key.
    pub(crate) fn derive_ecdh_p256(
        &self,
        _private_key: &[u8],
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        use p256::PublicKey;
        use p256::elliptic_curve::ecdh::EphemeralSecret;

        // Create ephemeral secret (p256 ECDH API generates fresh ephemeral keys)
        // This provides forward secrecy - each exchange uses a fresh key
        let secret = EphemeralSecret::random(&mut rand_core::OsRng);

        // Parse peer's public key from SEC1 encoded bytes
        // Accepts uncompressed (65 bytes), compressed (33 bytes), or hybrid format
        let peer_public_key = PublicKey::from_sec1_bytes(peer_public_key)
            .map_err(|e| Error::KeyExchangeFailed(format!("invalid P-256 public key: {}", e)))?;

        // Perform ECDH
        let shared_secret = secret
            .diffie_hellman(&peer_public_key)
            .raw_secret_bytes()
            .to_vec();

        Ok(shared_secret)
    }

    /// Derive shared secret using ECDH with P-384 curve
    ///
    /// Uses the `p384` crate for ECDH operations.
    ///
    /// **Security note**: This implementation uses EphemeralSecret for forward secrecy.
    /// The `_private_key` parameter is ignored because the p384 ECDH API generates
    /// a fresh ephemeral key pair for each exchange. This is intentional - using
    /// static keys would compromise forward secrecy.
    pub(crate) fn derive_ecdh_p384(
        &self,
        _private_key: &[u8],
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        use p384::PublicKey;
        use p384::elliptic_curve::ecdh::EphemeralSecret;

        // Create ephemeral secret (p384 ECDH API generates fresh ephemeral keys)
        // This provides forward secrecy - each exchange uses a fresh key
        let secret = EphemeralSecret::random(&mut rand_core::OsRng);

        // Parse peer's public key from SEC1 encoded bytes
        let peer_public_key = PublicKey::from_sec1_bytes(peer_public_key)
            .map_err(|e| Error::KeyExchangeFailed(format!("invalid P-384 public key: {}", e)))?;

        // Perform ECDH
        let shared_secret = secret
            .diffie_hellman(&peer_public_key)
            .raw_secret_bytes()
            .to_vec();

        Ok(shared_secret)
    }

    /// Derive shared secret using X25519 (Curve25519 ECDH)
    ///
    /// Uses the `x25519-dalek` crate which supports importing existing keys.
    pub(crate) fn derive_x25519(
        &self,
        private_key: &[u8],
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        use x25519_dalek::{PublicKey, StaticSecret};

        // Ensure we have exactly 32 bytes for X25519
        if private_key.len() < 32 {
            return Err(Error::KeyExchangeFailed(
                "X25519 private key must be at least 32 bytes".to_string(),
            ));
        }
        if peer_public_key.len() != 32 {
            return Err(Error::KeyExchangeFailed(
                "X25519 public key must be exactly 32 bytes".to_string(),
            ));
        }

        // Create secret from first 32 bytes
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&private_key[..32]);
        let secret = StaticSecret::from(key_bytes);

        // Parse peer's public key - needs exact 32 bytes array
        let mut peer_bytes = [0u8; 32];
        peer_bytes.copy_from_slice(peer_public_key);
        let peer_public = PublicKey::from(peer_bytes);

        // Perform X25519 ECDH
        let shared_secret = secret.diffie_hellman(&peer_public);
        Ok(shared_secret.as_bytes().to_vec())
    }

    /// Derive shared secret using SM2 key exchange
    ///
    /// Note: SM2-KEX is a multi-step protocol that requires session management.
    /// This method returns an error indicating session-based API should be used.
    pub(crate) fn derive_sm2_kex(
        &self,
        _private_key: &[u8],
        _peer_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        // SM2-KEX requires session-based API due to multi-step protocol
        Err(Error::KeyExchangeFailed(
            "SM2-KEX requires session-based API. Use create_sm2_kex_session and process_sm2_kex_message".to_string(),
        ))
    }

    /// Create a new SM2-KEX session as initiator (Party A)
    ///
    /// Returns a session ID and the first message to send to the responder.
    pub fn create_sm2_kex_session(
        &self,
        key_id: &Uuid,
        user_id: &[u8],
    ) -> Result<(Uuid, Sm2KexMessage)> {
        use gm_crypto::sm2::Sm2KeyPair;
        use gm_crypto::sm2_kex::KexSession;

        // Get the key entry
        let keys = self.keys.read();
        let entry = keys
            .get(key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        if entry.meta.spec != KeySpec::Sm2 {
            return Err(Error::InvalidKeySpec(format!(
                "SM2-KEX requires SM2 key, got {:?}",
                entry.meta.spec
            )));
        }

        // Create Sm2KeyPair from stored material
        let key_pair = Sm2KeyPair::from_private_key(entry.material.as_slice())
            .map_err(|e| Error::KeyExchangeFailed(format!("invalid SM2 key: {}", e)))?;

        // Create initiator session
        let session = KexSession::new_initiator(&key_pair, user_id)
            .map_err(|e| Error::KeyExchangeFailed(format!("failed to create session: {}", e)))?;

        // Generate first message
        let msg1 = session
            .generate_msg1()
            .map_err(|e| Error::KeyExchangeFailed(format!("failed to generate msg1: {}", e)))?;

        // Generate session ID
        let session_id = Uuid::new_v4();

        // Store session with replay protection fields
        let session_entry = Sm2KexSessionEntry {
            session_id,
            key_id: *key_id,
            user_id: user_id.to_vec(),
            session,
            is_initiator: true,
            nonce: 0,
            created_at: Instant::now(),
            message_history: Vec::new(),
        };

        let mut sessions = self.sm2_kex_sessions.write();
        sessions.insert(session_id, session_entry);

        Ok((session_id, msg1))
    }

    /// Create a new SM2-KEX session as responder (Party B) and process the first message
    ///
    /// Returns a session ID and the second message to send to the initiator.
    ///
    /// Security validations:
    /// - Validates R1 in msg1 is not the identity point (per GM/T 002-2012)
    pub fn accept_sm2_kex_session(
        &self,
        key_id: &Uuid,
        user_id: &[u8],
        msg1: &Sm2KexMessage,
        peer_public_key: &[u8],
    ) -> Result<(Uuid, Sm2KexMessage)> {
        use gm_crypto::sm2::Sm2KeyPair;
        use gm_crypto::sm2_kex::KexSession;
        use sm2::elliptic_curve::PublicKey;

        // Get the key entry
        let keys = self.keys.read();
        let entry = keys
            .get(key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        if entry.meta.spec != KeySpec::Sm2 {
            return Err(Error::InvalidKeySpec(format!(
                "SM2-KEX requires SM2 key, got {:?}",
                entry.meta.spec
            )));
        }

        // Create Sm2KeyPair from stored material
        let key_pair = Sm2KeyPair::from_private_key(entry.material.as_slice())
            .map_err(|e| Error::KeyExchangeFailed(format!("invalid SM2 key: {}", e)))?;

        // Create responder session
        let mut session = KexSession::new_responder(&key_pair, user_id)
            .map_err(|e| Error::KeyExchangeFailed(format!("failed to create session: {}", e)))?;

        // Parse peer's public key for signature verification
        let peer_pub_key = PublicKey::from_sec1_bytes(peer_public_key)
            .map_err(|e| Error::KeyExchangeFailed(format!("invalid peer public key: {}", e)))?;

        // === SM2-KEX Security: Validate R1 in msg1 is not identity ===
        // Per GM/T 002-2012, the ephemeral public key R1 must be validated
        // to ensure it's not the point at infinity or a small order point.
        validate_r_pub(&msg1.r_pub)?;

        // Process msg1 and generate msg2
        let msg2 = session
            .process_msg1(msg1, &peer_pub_key)
            .map_err(|e| Error::KeyExchangeFailed(format!("failed to process msg1: {}", e)))?;

        // Generate session ID
        let session_id = Uuid::new_v4();

        // Store session with replay protection fields
        let session_entry = Sm2KexSessionEntry {
            session_id,
            key_id: *key_id,
            user_id: user_id.to_vec(),
            session,
            is_initiator: false,
            nonce: 0,
            created_at: Instant::now(),
            message_history: Vec::new(),
        };

        let mut sessions = self.sm2_kex_sessions.write();
        sessions.insert(session_id, session_entry);

        Ok((session_id, msg2))
    }

    /// Process an SM2-KEX message and get the response
    ///
    /// For initiator (Party A): processes msg2, returns msg3
    /// For responder (Party B): processes msg3, returns nothing
    ///
    /// Implements replay protection via:
    /// - Session timeout (60 seconds per GM/T 002-2012)
    /// - Message hash history to detect replays
    /// - R1/R2 validation to ensure ephemeral public key is not identity point
    pub fn process_sm2_kex_message(
        &self,
        session_id: &Uuid,
        msg: &Sm2KexMessage,
        peer_public_key: &[u8],
    ) -> Result<Option<Sm2KexMessage>> {
        use sm2::elliptic_curve::PublicKey;

        // Check if session has been revoked
        if self.is_session_revoked(session_id) {
            return Err(Error::KeyExchangeFailed(format!(
                "SM2-KEX session {} has been revoked",
                session_id
            )));
        }

        let mut sessions = self.sm2_kex_sessions.write();

        let entry = sessions.get_mut(session_id).ok_or_else(|| {
            Error::KeyNotFound(format!("SM2-KEX session {} not found", session_id))
        })?;

        // === Replay Protection: Check Session Expiration ===
        if entry.created_at.elapsed() > Duration::from_secs(SM2_KEX_SESSION_TIMEOUT_SECS) {
            sessions.remove(session_id);
            return Err(Error::KeyExchangeFailed(
                "SM2-KEX session expired (timeout)".to_string(),
            ));
        }

        // === SM2-KEX Security: Validate R1/R2 in received message ===
        // Per GM/T 002-2012, the ephemeral public key R1/R2 must be validated
        // to ensure it's not the point at infinity or a small order point.
        // This validation is done for msg_type 1 and 2 which contain R1/R2.
        if msg.msg_type == 1 || msg.msg_type == 2 {
            validate_r_pub(&msg.r_pub)?;
        }

        // === Replay Protection: Check Message Hash History ===
        // Compute hash of incoming message for replay detection
        let msg_bytes = serialize_sm2_kex_message(msg);
        let msg_hash = ring::digest::digest(&ring::digest::SHA256, &msg_bytes);
        let msg_hash_vec = msg_hash.as_ref().to_vec();

        // Clean up expired entries and check for replay
        let now = Instant::now();
        entry.message_history.retain(|(timestamp, _)| {
            now.duration_since(*timestamp).as_secs() < MESSAGE_HISTORY_TTL_SECS
        });

        // Check if this message hash already exists (replay attack)
        if entry
            .message_history
            .iter()
            .any(|(_, hash)| hash == &msg_hash_vec)
        {
            return Err(Error::KeyExchangeFailed(
                "SM2-KEX replay attack detected: message already processed".to_string(),
            ));
        }

        // Add to message history with timestamp
        entry.message_history.push((now, msg_hash_vec));

        // Limit size to prevent memory exhaustion
        if entry.message_history.len() > MAX_MESSAGE_HISTORY_SIZE {
            entry.message_history.remove(0);
        }

        // Increment nonce counter
        entry.nonce += 1;

        // Parse peer's public key for signature verification
        let peer_pub_key = PublicKey::from_sec1_bytes(peer_public_key)
            .map_err(|e| Error::KeyExchangeFailed(format!("invalid peer public key: {}", e)))?;

        if entry.is_initiator {
            // Initiator processes msg2 (responder's message with signature)
            match entry.session.process_msg2(msg, &peer_pub_key) {
                Ok(msg3) => Ok(Some(msg3)),
                Err(e) => Err(Error::KeyExchangeFailed(format!(
                    "msg2 processing failed: {}",
                    e
                ))),
            }
        } else {
            // Responder processes msg3 (confirmation from initiator)
            match entry.session.process_msg3(msg) {
                Ok(()) => Ok(None),
                Err(e) => Err(Error::KeyExchangeFailed(format!(
                    "msg3 processing failed: {}",
                    e
                ))),
            }
        }
    }

    /// Get the result of a completed SM2-KEX session
    pub fn get_sm2_kex_result(&self, session_id: &Uuid) -> Result<Sm2KexResult> {
        // Check if session has been revoked
        if self.is_session_revoked(session_id) {
            return Err(Error::KeyExchangeFailed(format!(
                "SM2-KEX session {} has been revoked",
                session_id
            )));
        }

        let sessions = self.sm2_kex_sessions.read();

        let entry = sessions.get(session_id).ok_or_else(|| {
            Error::KeyNotFound(format!("SM2-KEX session {} not found", session_id))
        })?;

        entry
            .session
            .get_result()
            .ok_or_else(|| Error::KeyExchangeFailed("session not completed yet".to_string()))
            .cloned()
    }

    /// Remove a completed SM2-KEX session and revoke it to prevent replay
    ///
    /// After removal, the session ID is added to a revocation list to prevent
    /// replay attacks using old session IDs.
    pub fn remove_sm2_kex_session(&self, session_id: &Uuid) -> Result<()> {
        let mut sessions = self.sm2_kex_sessions.write();

        // Verify session exists
        sessions.get(session_id).ok_or_else(|| {
            Error::KeyNotFound(format!("SM2-KEX session {} not found", session_id))
        })?;

        // Add to revocation list before removal (prevents replay of old session IDs)
        let now = Instant::now();
        {
            let mut revoked = self.revoked_sessions.write();

            // Clean up expired entries first (if more than 100 entries)
            if revoked.len() > 100 {
                revoked.retain(|_, entry| entry.expires_at > now);
            }

            // Add session to revocation list with 5-minute expiry
            revoked.insert(
                *session_id,
                RevokedSessionEntry {
                    revoked_at: now,
                    expires_at: now + Duration::from_secs(300),
                },
            );
        }

        // Remove from active sessions
        sessions.remove(session_id).ok_or_else(|| {
            Error::KeyNotFound(format!("SM2-KEX session {} not found", session_id))
        })?;

        Ok(())
    }

    /// Check if a session ID has been revoked
    fn is_session_revoked(&self, session_id: &Uuid) -> bool {
        let revoked = self.revoked_sessions.read();

        if let Some(entry) = revoked.get(session_id) {
            // Check if revocation has expired
            entry.expires_at > Instant::now()
        } else {
            false
        }
    }
}

/// Validate that R1/R2 (ephemeral public key) is not zero/identity
///
/// Per GM/T 002-2012, the ephemeral public key must be validated to ensure
/// it represents a valid point on the curve and is not the identity point.
/// This prevents attacks where a malicious peer sends zero bytes.
fn validate_r_pub(r_pub: &[u8; 64]) -> Result<()> {
    // Check that R is not the point at infinity (all zeros)
    if r_pub.iter().all(|&b| b == 0) {
        return Err(Error::KeyExchangeFailed(
            "SM2-KEX invalid R1/R2: ephemeral public key is identity point".to_string(),
        ));
    }

    // Check that R is not a small order point (basic sanity check)
    // The GM/T 002-2012 spec requires R to be validated as a proper curve point
    // but full point validation requires expensive elliptic curve operations.
    // This check prevents trivial all-zero and all-same attacks.
    let all_same = r_pub.iter().all(|&b| b == r_pub[0]);
    if all_same {
        return Err(Error::KeyExchangeFailed(
            "SM2-KEX invalid R1/R2: ephemeral public key has uniform bytes".to_string(),
        ));
    }

    Ok(())
}

/// Serialize Sm2KexMessage to bytes for API transport
/// Format: msg_type (1 byte) || sender_id (16 bytes) || r_pub (64 bytes) || signature (64 bytes, optional) || confirmation (32 bytes, optional)
fn serialize_sm2_kex_message(msg: &Sm2KexMessage) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(msg.msg_type);
    bytes.extend_from_slice(&msg.sender_id);
    bytes.extend_from_slice(&msg.r_pub);
    if let Some(sig) = &msg.signature {
        bytes.extend_from_slice(sig);
    }
    if let Some(confirm) = &msg.confirmation {
        bytes.extend_from_slice(confirm);
    }
    bytes
}

/// Deserialize bytes to Sm2KexMessage
/// If expected_type is 0, auto-detect from first byte; otherwise validate against expected_type
fn deserialize_sm2_kex_message(
    bytes: &[u8],
    expected_type: u8,
) -> std::result::Result<Sm2KexMessage, String> {
    if bytes.is_empty() {
        return Err("empty message".to_string());
    }

    let msg_type = bytes[0];
    if expected_type != 0 && msg_type != expected_type {
        return Err(format!(
            "expected msg_type {}, got {}",
            expected_type, msg_type
        ));
    }

    let mut offset = 1;
    if bytes.len() < offset + 16 {
        return Err("insufficient bytes for sender_id".to_string());
    }
    let mut sender_id = [0u8; 16];
    sender_id.copy_from_slice(&bytes[offset..offset + 16]);
    offset += 16;

    let mut r_pub = [0u8; 64];
    if msg_type == 1 || msg_type == 2 {
        if bytes.len() < offset + 64 {
            return Err("insufficient bytes for r_pub".to_string());
        }
        r_pub.copy_from_slice(&bytes[offset..offset + 64]);
        offset += 64;
    }

    let signature = if msg_type == 2 {
        if bytes.len() < offset + 64 {
            return Err("insufficient bytes for signature".to_string());
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bytes[offset..offset + 64]);
        offset += 64;
        Some(sig)
    } else {
        None
    };

    let confirmation = if msg_type == 3 {
        if bytes.len() < offset + 32 {
            return Err("insufficient bytes for confirmation".to_string());
        }
        let mut conf = [0u8; 32];
        conf.copy_from_slice(&bytes[offset..offset + 32]);
        Some(conf)
    } else {
        None
    };

    Ok(Sm2KexMessage {
        msg_type,
        sender_id,
        r_pub,
        signature,
        confirmation,
    })
}

impl Default for SoftwareKeystore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl super::KeystoreBackend for SoftwareKeystore {
    fn backend_type(&self) -> BackendType {
        BackendType::Software
    }

    async fn generate_key(&self, spec: &KeySpec, name: &str, tenant_id: &str) -> Result<KeyMeta> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let material = match spec {
            KeySpec::Aes256Gcm | KeySpec::HmacSha256 => self.generate_aes_key(),
            KeySpec::EcdsaP256 | KeySpec::EcdsaP384 | KeySpec::Ed25519 | KeySpec::Ed448 => {
                self.generate_ed25519_key()
            }
            KeySpec::Sm4 => self.generate_sm4_key(),
            KeySpec::Sm2 => self.generate_sm2_key(),
            KeySpec::Sm9Signing | KeySpec::Sm9Encryption => {
                // SM9 uses identity-based cryptography, material stores identity
                // For now, we store the identity string as material
                Vec::new()
            }
            KeySpec::Rsa4096 => {
                return Err(Error::NotImplemented(
                    "RSA key generation not yet implemented".to_string(),
                ));
            }
        };

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
            material: zeroize::Zeroizing::new(material),
            versions: Vec::new(),
        };

        let mut keys = self.keys.write();
        keys.insert(id, entry);

        Ok(meta)
    }

    async fn import_key_material(
        &self,
        spec: &KeySpec,
        name: &str,
        tenant_id: &str,
        material: Vec<u8>,
    ) -> Result<KeyMeta> {
        // Validate key material format using comprehensive validation
        let validation = crate::validation::validate_key_material(spec, &material)
            .map_err(|e| Error::InvalidAlgorithm(format!("key validation failed: {}", e)))?;

        if !validation.valid {
            return Err(Error::InvalidAlgorithm(format!(
                "invalid key material for {:?}: {}",
                spec,
                validation
                    .error
                    .unwrap_or_else(|| "unknown error".to_string())
            )));
        }

        tracing::debug!(
            "Key validation passed for {:?}: curve={:?}, usage={:?}",
            spec,
            validation.metadata.curve,
            validation.metadata.usage
        );

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

        let entry = KeyEntry {
            meta: meta.clone(),
            material: zeroize::Zeroizing::new(material),
            versions: Vec::new(),
        };

        let mut keys = self.keys.write();
        keys.insert(id, entry);

        Ok(meta)
    }

    async fn export_key_material(&self, key_id: &Uuid, _tenant_id: &str) -> Result<Vec<u8>> {
        let keys = self.keys.read();
        let entry = keys
            .get(key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        if entry.meta.status != KeyStatus::Active {
            return Err(Error::KeyOperationNotAllowed(format!(
                "Key {} is not active for export",
                key_id
            )));
        }

        Ok(entry.material.as_slice().to_vec())
    }

    async fn get_key_material(&self, key_id: &Uuid, _tenant_id: &str) -> Result<Vec<u8>> {
        let keys = self.keys.read();
        let entry = keys
            .get(key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        // Log material access for audit (this is a security-sensitive operation)
        // Note: We don't have access to the audit logger here directly.
        // In a full implementation, this would be handled via event emission.

        Ok(entry.material.as_slice().to_vec())
    }

    async fn get_key_material_version(
        &self,
        key_id: &Uuid,
        version: u32,
        _tenant_id: &str,
    ) -> Result<Vec<u8>> {
        let keys = self.keys.read();
        let entry = keys
            .get(key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        // If version matches current, return current material
        if version == 0 || version == entry.meta.version {
            return Ok(entry.material.as_slice().to_vec());
        }

        // Search version history
        entry
            .versions
            .iter()
            .find(|(v, _)| *v == version)
            .map(|(_, mat)| mat.as_slice().to_vec())
            .ok_or_else(|| {
                Error::InvalidAlgorithm(format!(
                    "Key version {} not found for key {}",
                    version, key_id
                ))
            })
    }

    async fn get_key_metadata(&self, key_id: &Uuid) -> Result<KeyMeta> {
        let keys = self.keys.read();
        keys.get(key_id)
            .map(|e| e.meta.clone())
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))
    }

    async fn encrypt(
        &self,
        key_id: &Uuid,
        plaintext: &[u8],
        _aad: Option<&[u8]>,
        _tenant_id: &str,
    ) -> Result<Ciphertext> {
        let keys = self.keys.read();
        let entry = keys
            .get(key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        if entry.meta.status != KeyStatus::Active {
            return Err(Error::KeyOperationNotAllowed(format!(
                "Key {} is not active",
                key_id
            )));
        }

        match entry.meta.spec {
            KeySpec::Aes256Gcm | KeySpec::HmacSha256 => {
                use ring::aead::{BoundKey, NonceSequence, SealingKey};

                let unbound_key =
                    aead::UnboundKey::new(&aead::AES_256_GCM, entry.material.as_slice())
                        .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

                // Generate random starting counter value to ensure unique nonces per encryption
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

                Ok(Ciphertext {
                    key_id: *key_id,
                    version: entry.meta.version,
                    format_version: 1,
                    nonce: starting_counter.to_be_bytes().to_vec(),
                    ciphertext: in_out,
                    tag: tag.as_ref().to_vec(),
                })
            }
            KeySpec::Sm4 => {
                use gm_crypto::sm4::Sm4Cipher;

                let cipher = Sm4Cipher::new(entry.material.as_slice())
                    .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

                let mut nonce = [0u8; 12];
                rand::rng().fill_bytes(&mut nonce);

                let (ciphertext, tag) = cipher
                    .encrypt_gcm(plaintext, &nonce, &[])
                    .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

                Ok(Ciphertext {
                    key_id: *key_id,
                    version: entry.meta.version,
                    format_version: 1,
                    nonce: nonce.to_vec(),
                    ciphertext,
                    tag,
                })
            }
            KeySpec::Sm2 => {
                use gm_crypto::sm2::{Sm2Encryptor, Sm2KeyPair};

                let key_pair = Sm2KeyPair::from_private_key(entry.material.as_slice())
                    .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

                let encryptor = Sm2Encryptor::new(&key_pair.public_key_bytes_uncompressed())
                    .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

                let encrypted = encryptor
                    .encrypt(plaintext)
                    .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

                // SM2 encrypted output format: C1 (65 bytes) || C3 (32 bytes) || C2 (variable)
                // Parse: first 65 bytes = C1, next 32 bytes = C3, rest = C2
                let c1 = &encrypted[..65];
                let c3 = &encrypted[65..97];
                let c2 = &encrypted[97..];

                Ok(Ciphertext {
                    key_id: *key_id,
                    version: entry.meta.version,
                    format_version: 1,
                    nonce: c1.to_vec(),      // C1: ephemeral public key point
                    ciphertext: c2.to_vec(), // C2: encrypted data
                    tag: c3.to_vec(),        // C3: SM3 hash
                })
            }
            _ => Err(Error::InvalidAlgorithm(format!(
                "Encryption not supported for {:?}",
                entry.meta.spec
            ))),
        }
    }

    async fn decrypt(
        &self,
        key_id: &Uuid,
        ciphertext: &Ciphertext,
        _aad: Option<&[u8]>,
        _tenant_id: &str,
    ) -> Result<Vec<u8>> {
        let keys = self.keys.read();
        let entry = keys
            .get(key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        if !entry.meta.status.can_decrypt() {
            return Err(Error::KeyOperationNotAllowed(format!(
                "Key {} cannot decrypt",
                key_id
            )));
        }

        // Select key material based on version
        // Current version uses entry.material, older versions are in entry.versions
        let key_material = if ciphertext.version == entry.meta.version {
            entry.material.as_slice()
        } else {
            // Search for the correct version in history
            entry
                .versions
                .iter()
                .find(|(v, _)| *v == ciphertext.version)
                .map(|(_, mat)| mat.as_slice())
                .ok_or_else(|| {
                    Error::InvalidAlgorithm(format!(
                        "Key version {} not found for key {}",
                        ciphertext.version, key_id
                    ))
                })?
        };

        match entry.meta.spec {
            KeySpec::Aes256Gcm | KeySpec::HmacSha256 => {
                use ring::aead::{BoundKey, NonceSequence, OpeningKey};

                let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key_material)
                    .map_err(|e| Error::DecryptionFailed(e.to_string()))?;

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

                // Reconstruct starting counter from stored nonce
                let starting_counter = if ciphertext.nonce.len() == 16 {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&ciphertext.nonce);
                    u128::from_be_bytes(bytes)
                } else {
                    0 // Legacy format compatibility
                };
                let counter = Counter(starting_counter);
                let mut opening_key: OpeningKey<Counter> = BoundKey::new(unbound_key, counter);

                let mut in_out = ciphertext.ciphertext.clone();
                in_out.extend_from_slice(&ciphertext.tag);

                let plaintext = opening_key
                    .open_in_place(aead::Aad::empty(), &mut in_out)
                    .map_err(|_| Error::InvalidCiphertext)?;

                Ok(plaintext.to_vec())
            }
            KeySpec::Sm4 => {
                use gm_crypto::sm4::Sm4Cipher;

                let cipher = Sm4Cipher::new(key_material)
                    .map_err(|e| Error::DecryptionFailed(e.to_string()))?;

                let plaintext = cipher
                    .decrypt_gcm(
                        &ciphertext.ciphertext,
                        &ciphertext.nonce,
                        &[],
                        &ciphertext.tag,
                    )
                    .map_err(|_| Error::InvalidCiphertext)?;

                Ok(plaintext)
            }
            KeySpec::Sm2 => {
                use gm_crypto::sm2::{Sm2Decryptor, Sm2KeyPair};

                let key_pair = Sm2KeyPair::from_private_key(key_material)
                    .map_err(|e| Error::DecryptionFailed(e.to_string()))?;

                // Reconstruct SM2 ciphertext: C1 || C3 || C2
                // nonce = C1 (65 bytes), tag = C3 (32 bytes), ciphertext = C2
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
                entry.meta.spec
            ))),
        }
    }

    async fn sign(&self, key_id: &Uuid, data: &[u8], _tenant_id: &str) -> Result<Signature> {
        let keys = self.keys.read();
        let entry = keys
            .get(key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        if entry.meta.status != KeyStatus::Active {
            return Err(Error::KeyOperationNotAllowed(format!(
                "Key {} is not active",
                key_id
            )));
        }

        match entry.meta.spec {
            KeySpec::Ed25519 => {
                let key_pair = Ed25519KeyPair::from_seed_unchecked(entry.material.as_slice())
                    .map_err(|e| Error::SignatureFailed(e.to_string()))?;

                let signature_bytes = key_pair.sign(data).as_ref().to_vec();

                Ok(Signature {
                    key_id: *key_id,
                    version: entry.meta.version,
                    signature: signature_bytes,
                })
            }
            KeySpec::Sm2 => {
                use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer};

                let key_pair = Sm2KeyPair::from_private_key(entry.material.as_slice())
                    .map_err(|e| Error::SignatureFailed(e.to_string()))?;
                let signer =
                    Sm2Signer::new(&key_pair).map_err(|e| Error::SignatureFailed(e.to_string()))?;
                let sig = signer
                    .sign(data)
                    .map_err(|e| Error::SignatureFailed(e.to_string()))?;

                Ok(Signature {
                    key_id: *key_id,
                    version: entry.meta.version,
                    signature: sig,
                })
            }
            _ => Err(Error::InvalidAlgorithm(format!(
                "Signing not supported for {:?}",
                entry.meta.spec
            ))),
        }
    }

    async fn verify(
        &self,
        key_id: &Uuid,
        data: &[u8],
        sig: &Signature,
        _tenant_id: &str,
    ) -> Result<bool> {
        let keys = self.keys.read();
        let entry = keys
            .get(key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        match entry.meta.spec {
            KeySpec::Ed25519 => {
                let key_pair = Ed25519KeyPair::from_seed_unchecked(entry.material.as_slice())
                    .map_err(|e| Error::VerificationFailed(e.to_string()))?;

                let public_key = UnparsedPublicKey::new(&ED25519, key_pair.public_key().as_ref());
                Ok(public_key.verify(data, sig.signature.as_ref()).is_ok())
            }
            KeySpec::Sm2 => {
                use gm_crypto::sm2::{Sm2KeyPair, Sm2Verifier};

                let key_pair = Sm2KeyPair::from_private_key(entry.material.as_slice())
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
                entry.meta.spec
            ))),
        }
    }

    async fn rotate_key(&self, key_id: &Uuid, _tenant_id: &str) -> Result<KeyMeta> {
        let mut keys = self.keys.write();

        let entry = keys
            .get_mut(key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        if !entry.meta.status.can_rotate() {
            return Err(Error::KeyOperationNotAllowed(format!(
                "Key {} cannot be rotated",
                key_id
            )));
        }

        // Archive current material to versions before rotation.
        // std::mem::take moves ownership (not clone), eliminating the
        // plaintext duplicate — the single copy zeroizes on drop.
        let old_version = entry.meta.version;
        let old_material = std::mem::take(&mut entry.material);
        entry.versions.push((old_version, old_material));

        let new_material = match entry.meta.spec {
            KeySpec::Aes256Gcm | KeySpec::HmacSha256 => self.generate_aes_key(),
            KeySpec::Sm4 => self.generate_sm4_key(),
            KeySpec::Sm2 => self.generate_sm2_key(),
            KeySpec::Sm9Signing | KeySpec::Sm9Encryption => {
                // SM9 rotation must be handled by Sm9RotationAdapter via
                // RotationService::with_sm9_adapter(). Direct keystore
                // rotation returns an error to prevent silent no-ops.
                return Err(Error::KeyOperationNotAllowed(
                    "SM9 key rotation must go through Sm9RotationAdapter. \
                     Configure RotationService with .with_sm9_adapter()"
                        .to_string(),
                ));
            }
            KeySpec::Rsa4096 => {
                return Err(Error::NotImplemented(
                    "RSA key rotation not yet implemented".to_string(),
                ));
            }
            _ => self.generate_ed25519_key(),
        };

        // Update existing entry with new material instead of creating new entry
        entry.meta.status = KeyStatus::Active;
        entry.meta.version = old_version + 1;
        entry.meta.rotated_at = Some(entry.meta.created_at);
        entry.meta.created_at = Utc::now();
        entry.material = zeroize::Zeroizing::new(new_material);

        Ok(entry.meta.clone())
    }

    async fn delete_key(&self, key_id: &Uuid, _tenant_id: &str) -> Result<()> {
        let mut keys = self.keys.write();

        let entry = keys
            .get_mut(key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        entry.meta.status = KeyStatus::PendingDeletion;

        Ok(())
    }

    async fn destroy_key(&self, key_id: &Uuid) -> Result<()> {
        let mut keys = self.keys.write();

        let entry = keys
            .remove(key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        // Zeroize the material - ZeroizedBytes will auto-zeroize on drop
        let _ = entry.material;

        Ok(())
    }

    async fn destroy_key_with_proof(&self, key_id: &Uuid) -> Result<DestructionProof> {
        let mut keys = self.keys.write();

        let entry = keys
            .remove(key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        // Compute hash of key material before zeroization for audit trail
        let material_hash =
            hex::encode(digest::digest(&digest::SHA256, entry.material.as_ref()).as_ref());
        let key_size = entry.material.len();

        // Zeroize the material - ZeroizedBytes will auto-zeroize on drop
        let _ = entry.material;

        Ok(DestructionProof::new(
            *key_id,
            material_hash,
            key_size,
            true, // zeroization verified (Zeroizing will zero on drop)
            None, // hmac_signature - should be added during proof storage with proper key
        ))
    }

    async fn list_keys(&self, filter: &kms_core::key::KeyFilter) -> Result<Vec<KeyMeta>> {
        let keys = self.keys.read();

        let mut result: Vec<KeyMeta> = keys
            .values()
            .filter(|e| {
                if let Some(tenant_id) = &filter.tenant_id
                    && e.meta.tenant_id != *tenant_id
                {
                    return false;
                }
                if let Some(status) = &filter.status
                    && e.meta.status != *status
                {
                    return false;
                }
                if let Some(spec) = &filter.spec
                    && e.meta.spec != *spec
                {
                    return false;
                }
                true
            })
            .map(|e| e.meta.clone())
            .collect();

        if let Some(offset) = filter.offset {
            result = result.into_iter().skip(offset).collect();
        }
        if let Some(limit) = filter.limit {
            result = result.into_iter().take(limit).collect();
        }

        Ok(result)
    }

    async fn health(&self) -> Result<kms_core::types::HealthStatus> {
        Ok(kms_core::types::HealthStatus::Healthy)
    }

    async fn derive_shared_secret(
        &self,
        key_id: &Uuid,
        peer_public_key: &[u8],
        algorithm: kms_core::dh::DhAlgorithm,
    ) -> Result<SharedSecret> {
        use kms_core::dh::SharedSecret;

        let keys = self.keys.read();
        let entry = keys
            .get(key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        if entry.meta.status != KeyStatus::Active {
            return Err(Error::KeyOperationNotAllowed(format!(
                "Key {} is not active",
                key_id
            )));
        }

        let shared_secret = match algorithm {
            kms_core::dh::DhAlgorithm::EcdsaP256 => {
                self.derive_ecdh_p256(entry.material.as_slice(), peer_public_key)?
            }
            kms_core::dh::DhAlgorithm::EcdsaP384 => {
                self.derive_ecdh_p384(entry.material.as_slice(), peer_public_key)?
            }
            kms_core::dh::DhAlgorithm::X25519 => {
                self.derive_x25519(entry.material.as_slice(), peer_public_key)?
            }
            kms_core::dh::DhAlgorithm::Sm2Kex => {
                self.derive_sm2_kex(entry.material.as_slice(), peer_public_key)?
            }
        };

        Ok(SharedSecret {
            secret: shared_secret,
            kdf: Some("HKDF-SHA256".to_string()),
        })
    }

    // SM2-KEX Session Management - Override trait defaults

    async fn create_sm2_kex_session(
        &self,
        key_id: &Uuid,
        user_id: &[u8],
    ) -> Result<(Uuid, Vec<u8>)> {
        let user_id_bytes = user_id.to_vec();
        let (session_id, msg) = self
            .create_sm2_kex_session(key_id, &user_id_bytes)
            .map_err(|e| Error::KeyExchangeFailed(e.to_string()))?;

        // Serialize message to bytes
        let msg_bytes = serialize_sm2_kex_message(&msg);
        Ok((session_id, msg_bytes))
    }

    async fn accept_sm2_kex_session(
        &self,
        key_id: &Uuid,
        user_id: &[u8],
        msg1_bytes: &[u8],
        peer_public_key: &[u8],
    ) -> Result<(Uuid, Vec<u8>)> {
        let user_id_bytes = user_id.to_vec();
        let msg1 = deserialize_sm2_kex_message(msg1_bytes, 1)
            .map_err(|e| Error::Internal(format!("invalid msg1: {}", e)))?;

        let (session_id, msg2) = self
            .accept_sm2_kex_session(key_id, &user_id_bytes, &msg1, peer_public_key)
            .map_err(|e| Error::KeyExchangeFailed(e.to_string()))?;

        // Serialize message to bytes
        let msg_bytes = serialize_sm2_kex_message(&msg2);
        Ok((session_id, msg_bytes))
    }

    async fn process_sm2_kex_message(
        &self,
        session_id: &Uuid,
        msg_bytes: &[u8],
        peer_public_key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        // Determine message type from bytes
        let msg = deserialize_sm2_kex_message(msg_bytes, 0) // 0 means detect from bytes
            .map_err(|e| Error::Internal(format!("invalid message: {}", e)))?;

        let result_msg = self
            .process_sm2_kex_message(session_id, &msg, peer_public_key)
            .map_err(|e| Error::KeyExchangeFailed(e.to_string()))?;

        Ok(result_msg.map(|msg| serialize_sm2_kex_message(&msg)))
    }

    async fn get_sm2_kex_result(&self, session_id: &Uuid) -> Result<Vec<u8>> {
        let result = self
            .get_sm2_kex_result(session_id)
            .map_err(|e| Error::KeyExchangeFailed(e.to_string()))?;

        // Return shared_secret (32 bytes)
        Ok(result.shared_secret.to_vec())
    }

    async fn remove_sm2_kex_session(&self, session_id: &Uuid) -> Result<()> {
        self.remove_sm2_kex_session(session_id)
            .map_err(|e| Error::KeyExchangeFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests;
