//! Service layer error types
//!
//! Provides centralized error mapping between core errors and API errors.

use kms_core::Error;
use std::fmt;

/// Service layer errors that map to API errors
#[derive(Debug)]
pub enum ServiceError {
    /// Key not found
    KeyNotFound(String),
    /// Operation not allowed on key
    KeyOperationNotAllowed(String),
    /// Invalid ciphertext
    InvalidCiphertext,
    /// Invalid algorithm for operation
    InvalidAlgorithm(String),
    /// Quota exceeded
    QuotaExceeded {
        resource: String,
        current: i64,
        limit: i64,
    },
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Invalid specification string
    InvalidSpec(String),
    /// Validation error
    ValidationError(String),
    /// Encryption failed
    EncryptionFailed(String),
    /// Decryption failed
    DecryptionFailed(String),
    /// Signature failed
    SignatureFailed(String),
    /// Internal error
    Internal(String),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceError::KeyNotFound(id) => write!(f, "key not found: {}", id),
            ServiceError::KeyOperationNotAllowed(msg) => write!(f, "{}", msg),
            ServiceError::InvalidCiphertext => write!(f, "invalid ciphertext"),
            ServiceError::InvalidAlgorithm(msg) => write!(f, "invalid algorithm: {}", msg),
            ServiceError::QuotaExceeded {
                resource,
                current,
                limit,
            } => {
                write!(f, "quota exceeded for {}: {}/{}", resource, current, limit)
            }
            ServiceError::RateLimitExceeded => write!(f, "rate limit exceeded"),
            ServiceError::InvalidSpec(spec) => write!(f, "invalid spec: {}", spec),
            ServiceError::ValidationError(msg) => write!(f, "validation error: {}", msg),
            ServiceError::EncryptionFailed(msg) => write!(f, "encryption failed: {}", msg),
            ServiceError::DecryptionFailed(msg) => write!(f, "decryption failed: {}", msg),
            ServiceError::SignatureFailed(msg) => write!(f, "signature failed: {}", msg),
            ServiceError::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<Error> for ServiceError {
    fn from(e: Error) -> Self {
        match e {
            Error::KeyNotFound(id) => ServiceError::KeyNotFound(id),
            Error::KeyVersionNotFound(id) => ServiceError::KeyNotFound(id),
            Error::KeyOperationNotAllowed(msg) => ServiceError::KeyOperationNotAllowed(msg),
            Error::InvalidCiphertext => ServiceError::InvalidCiphertext,
            Error::InvalidAlgorithm(msg) => ServiceError::InvalidAlgorithm(msg),
            Error::EncryptionFailed(msg) => ServiceError::EncryptionFailed(msg),
            Error::DecryptionFailed(msg) => ServiceError::DecryptionFailed(msg),
            Error::SignatureFailed(msg) => ServiceError::SignatureFailed(msg),
            Error::VerificationFailed(msg) => ServiceError::SignatureFailed(msg), // reusing variant
            Error::InvalidKeySpec(spec) => ServiceError::InvalidSpec(spec),
            Error::NotImplemented(msg) => ServiceError::Internal(msg),
            Error::Internal(msg) => ServiceError::Internal(msg),
            _ => ServiceError::Internal(e.to_string()),
        }
    }
}
