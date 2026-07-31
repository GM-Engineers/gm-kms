//! KeystoreBackend trait - abstraction for key storage backends

use async_trait::async_trait;
use kms_core::{
    BackendType, Result,
    dh::{DhAlgorithm, SharedSecret},
    key::{Ciphertext, KeyMeta, KeySpec, Signature},
};
use uuid::Uuid;

/// Key filter for listing keys (re-export from kms_core)
pub use kms_core::key::KeyFilter;

/// Health status for a backend (re-export from kms_core)
pub use kms_core::types::HealthStatus;

/// Trait for key storage backends
/// Implement this trait to add support for different storage backends (Software, HSM, TPM)
#[async_trait]
pub trait KeystoreBackend: Send + Sync {
    /// Get the backend type
    fn backend_type(&self) -> BackendType;

    /// Generate a new key with the given specification
    async fn generate_key(&self, spec: &KeySpec, name: &str, tenant_id: &str) -> Result<KeyMeta>;

    /// Get metadata for a key (does not return key material)
    async fn get_key_metadata(&self, key_id: &Uuid) -> Result<KeyMeta>;

    /// Encrypt data using a key
    async fn encrypt(
        &self,
        key_id: &Uuid,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        tenant_id: &str,
    ) -> Result<Ciphertext>;

    /// Decrypt data using a key
    async fn decrypt(
        &self,
        key_id: &Uuid,
        ciphertext: &Ciphertext,
        aad: Option<&[u8]>,
        tenant_id: &str,
    ) -> Result<Vec<u8>>;

    /// Sign data using a key
    async fn sign(&self, key_id: &Uuid, data: &[u8], tenant_id: &str) -> Result<Signature>;

    /// Verify a signature
    async fn verify(
        &self,
        key_id: &Uuid,
        data: &[u8],
        signature: &Signature,
        tenant_id: &str,
    ) -> Result<bool>;

    /// Rotate a key - creates a new version
    async fn rotate_key(&self, key_id: &Uuid, tenant_id: &str) -> Result<KeyMeta>;

    /// Mark a key for deletion (soft delete)
    async fn delete_key(&self, key_id: &Uuid, tenant_id: &str) -> Result<()>;

    /// Permanently destroy a key (hard delete)
    async fn destroy_key(&self, key_id: &Uuid) -> Result<()>;

    /// Permanently destroy a key and return proof of destruction
    ///
    /// Returns a DestructionProof with cryptographic evidence of the destruction,
    /// including a hash of the key material for audit verification.
    async fn destroy_key_with_proof(&self, key_id: &Uuid) -> Result<kms_core::DestructionProof>;

    /// List keys with optional filtering
    async fn list_keys(&self, filter: &KeyFilter) -> Result<Vec<KeyMeta>>;

    /// Check backend health
    async fn health(&self) -> Result<HealthStatus>;

    /// Import raw key material into the backend
    /// The key material should already be unwrapped (decrypted from transport key)
    /// and in the raw bytes format for the algorithm
    async fn import_key_material(
        &self,
        spec: &KeySpec,
        name: &str,
        tenant_id: &str,
        material: Vec<u8>,
    ) -> Result<KeyMeta>;

    /// Export raw key material from the backend
    /// Returns the raw key bytes (caller handles transport key wrapping)
    async fn export_key_material(&self, key_id: &Uuid, tenant_id: &str) -> Result<Vec<u8>>;

    /// Get raw key material for internal use (e.g., KEK for envelope encryption)
    /// Unlike export_key_material, this does not check export policy
    async fn get_key_material(&self, key_id: &Uuid, tenant_id: &str) -> Result<Vec<u8>>;

    /// Get raw key material for a specific key version (for DEK rewrapping after KEK rotation).
    ///
    /// Returns the key material at the given version. If version is 0 or matches
    /// the current version, returns the current material. For older versions,
    /// searches the version history.
    async fn get_key_material_version(
        &self,
        key_id: &Uuid,
        version: u32,
        tenant_id: &str,
    ) -> Result<Vec<u8>> {
        // Default: delegate to current version (backends without version history)
        let _ = version;
        self.get_key_material(key_id, tenant_id).await
    }

    /// Derive a shared secret using Diffie-Hellman key exchange
    ///
    /// Uses our private key (identified by key_id) and peer's public key
    /// to compute a shared secret. Supports ECDH-P256, ECDH-P384, X25519, and SM2-KEX.
    async fn derive_shared_secret(
        &self,
        key_id: &Uuid,
        peer_public_key: &[u8],
        algorithm: DhAlgorithm,
    ) -> Result<SharedSecret>;

    // SM2-KEX Session Management Methods
    // Note: These require session state, unlike single-shot DH methods

    /// Create a new SM2-KEX session as initiator (Party A)
    ///
    /// Returns session ID and the first message to send to responder.
    async fn create_sm2_kex_session(
        &self,
        _key_id: &Uuid,
        _user_id: &[u8],
    ) -> Result<(Uuid, Vec<u8>)> {
        // Returns (session_id, msg1_bytes) or error
        Err(kms_core::Error::NotImplemented(
            "SM2-KEX session requires software backend".to_string(),
        ))
    }

    /// Accept an SM2-KEX session as responder (Party B), processing the first message
    ///
    /// Returns session ID and the second message to send to initiator.
    async fn accept_sm2_kex_session(
        &self,
        _key_id: &Uuid,
        _user_id: &[u8],
        _msg1: &[u8],
        _peer_public_key: &[u8],
    ) -> Result<(Uuid, Vec<u8>)> {
        // Returns (session_id, msg2_bytes) or error
        Err(kms_core::Error::NotImplemented(
            "SM2-KEX session requires software backend".to_string(),
        ))
    }

    /// Process an SM2-KEX message and get the response
    ///
    /// For initiator (Party A): processes msg2, returns msg3
    /// For responder (Party B): processes msg3, returns empty
    async fn process_sm2_kex_message(
        &self,
        _session_id: &Uuid,
        _msg: &[u8],
        _peer_public_key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        // Returns Some(msg_bytes) for next message, or None if exchange complete
        Err(kms_core::Error::NotImplemented(
            "SM2-KEX session requires software backend".to_string(),
        ))
    }

    /// Get the result of a completed SM2-KEX session
    async fn get_sm2_kex_result(&self, _session_id: &Uuid) -> Result<Vec<u8>> {
        // Returns the 32-byte shared secret
        Err(kms_core::Error::NotImplemented(
            "SM2-KEX session requires software backend".to_string(),
        ))
    }

    /// Remove a completed SM2-KEX session
    async fn remove_sm2_kex_session(&self, _session_id: &Uuid) -> Result<()> {
        Err(kms_core::Error::NotImplemented(
            "SM2-KEX session requires software backend".to_string(),
        ))
    }
}
