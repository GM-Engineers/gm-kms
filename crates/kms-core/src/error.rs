//! Error types for KMS

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("key version not found: {0}")]
    KeyVersionNotFound(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("invalid key spec: {0}")]
    InvalidKeySpec(String),

    #[error("invalid algorithm: {0}")]
    InvalidAlgorithm(String),

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("signature failed: {0}")]
    SignatureFailed(String),

    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("key exchange failed: {0}")]
    KeyExchangeFailed(String),

    #[error("policy not found: {0}")]
    PolicyNotFound(String),

    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("policy evaluation failed: {0}")]
    PolicyEvaluationFailed(String),

    #[error("keystore error: {0}")]
    KeystoreError(String),

    #[error("backend unavailable: {0}")]
    BackendUnavailable(String),

    #[error("invalid ciphertext")]
    InvalidCiphertext,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("key operation not allowed: {0}")]
    KeyOperationNotAllowed(String),

    #[error("key already exists: {0}")]
    KeyAlreadyExists(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("not implemented: {0}")]
    NotImplemented(String),

    // TPM-specific errors
    #[error("TPM error: {0}")]
    TpmError(String),

    #[error("TPM session error: {0}")]
    TpmSessionError(String),

    #[error("TPM authorization failed: {0}")]
    TpmAuthFailed(String),

    #[error("TPM PCR mismatch: expected {expected:?}, got {actual:?}")]
    TpmPcrMismatch { expected: Vec<u8>, actual: Vec<u8> },

    #[error("TPM NV index not found: {0}")]
    TpmNvIndexNotFound(u32),

    #[error("TPM NV write failed: {0}")]
    TpmNvWriteFailed(String),

    // SM9 Master Key specific errors
    #[error("master key error: {0}")]
    MasterKeyError(String),

    #[error("master key not found")]
    MasterKeyNotFound,

    #[error("master key corrupted")]
    MasterKeyCorrupted,
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_key_not_found() {
        let e = Error::KeyNotFound("abc-123".to_string());
        assert_eq!(e.to_string(), "key not found: abc-123");
    }

    #[test]
    fn test_error_display_key_version_not_found() {
        let e = Error::KeyVersionNotFound("v2".to_string());
        assert_eq!(e.to_string(), "key version not found: v2");
    }

    #[test]
    fn test_error_display_permission_denied() {
        let e = Error::PermissionDenied("admin only".to_string());
        assert_eq!(e.to_string(), "permission denied: admin only");
    }

    #[test]
    fn test_error_display_invalid_key_spec() {
        let e = Error::InvalidKeySpec("bad spec".to_string());
        assert_eq!(e.to_string(), "invalid key spec: bad spec");
    }

    #[test]
    fn test_error_display_encryption_failed() {
        let e = Error::EncryptionFailed("aes error".to_string());
        assert_eq!(e.to_string(), "encryption failed: aes error");
    }

    #[test]
    fn test_error_display_decryption_failed() {
        let e = Error::DecryptionFailed("tag mismatch".to_string());
        assert_eq!(e.to_string(), "decryption failed: tag mismatch");
    }

    #[test]
    fn test_error_display_invalid_ciphertext() {
        let e = Error::InvalidCiphertext;
        assert_eq!(e.to_string(), "invalid ciphertext");
    }

    #[test]
    fn test_error_display_invalid_signature() {
        let e = Error::InvalidSignature;
        assert_eq!(e.to_string(), "invalid signature");
    }

    #[test]
    fn test_error_display_not_implemented() {
        let e = Error::NotImplemented("tpm2-tss feature required".to_string());
        assert_eq!(e.to_string(), "not implemented: tpm2-tss feature required");
    }

    #[test]
    fn test_error_display_tpm_pcr_mismatch() {
        let e = Error::TpmPcrMismatch {
            expected: vec![0x00, 0x01],
            actual: vec![0x00, 0x02],
        };
        let msg = e.to_string();
        assert!(msg.contains("expected"));
        assert!(msg.contains("[0, 1]"));
        assert!(msg.contains("[0, 2]"));
    }

    #[test]
    fn test_error_display_tpm_nv_index_not_found() {
        let e = Error::TpmNvIndexNotFound(0x01_00_00_00);
        assert_eq!(e.to_string(), "TPM NV index not found: 16777216");
    }

    #[test]
    fn test_error_display_master_key_not_found() {
        let e = Error::MasterKeyNotFound;
        assert_eq!(e.to_string(), "master key not found");
    }

    #[test]
    fn test_error_display_master_key_corrupted() {
        let e = Error::MasterKeyCorrupted;
        assert_eq!(e.to_string(), "master key corrupted");
    }

    #[test]
    fn test_error_display_backend_unavailable() {
        let e = Error::BackendUnavailable("redis down".to_string());
        assert_eq!(e.to_string(), "backend unavailable: redis down");
    }

    #[test]
    fn test_error_display_key_already_exists() {
        let e = Error::KeyAlreadyExists("dup-id".to_string());
        assert_eq!(e.to_string(), "key already exists: dup-id");
    }

    #[test]
    fn test_result_type_alias() {
        fn ok_func() -> Result<i32> {
            Ok(42)
        }
        fn err_func() -> Result<i32> {
            Err(Error::Internal("boom".to_string()))
        }
        assert_eq!(ok_func().unwrap(), 42);
        assert!(err_func().is_err());
    }

    #[test]
    fn test_error_debug_format() {
        let e = Error::TpmAuthFailed("bad password".to_string());
        let debug = format!("{:?}", e);
        assert!(debug.contains("TpmAuthFailed"));
        assert!(debug.contains("bad password"));
    }
}
