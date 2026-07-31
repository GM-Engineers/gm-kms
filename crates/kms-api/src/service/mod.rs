//! Service layer for KMS business logic
//!
//! Provides service layer abstractions that isolate business logic from HTTP/gRPC handlers.
//!
//! # Architecture
//!
//! ```text
//! REST Handler  ──┐
//! gRPC Handler  ──┼──► Service Layer ──► KeystoreBackend
//!                 │
//!          Audit/Quota/Metrics
//! ```
//!
//! # Services
//!
//! - [`KeyService`] - Key lifecycle management (create, rotate, delete)
//! - [`CryptoService`] - Cryptographic operations (encrypt, decrypt, sign, verify)
//! - [`EnvelopeService`] - Envelope encryption (DEK/KEK两层加密)
//!
//! # Error Handling
//!
//! Services return [`ServiceError`] which is mapped to [`ApiError`](crate::error::ApiError)
//! by handlers.

pub mod crypto_service;
pub mod envelope_service;
pub mod error;
pub mod key_format;
pub mod key_service;

#[cfg(test)]
mod fail_secure_tests;

pub use crypto_service::CryptoService;
pub use envelope_service::{EnvelopeEncryptResponse, EnvelopeService, RewrapDekResponse};
pub use error::ServiceError;
pub use key_format::{KeyFormatError, KeyFormatParser};
pub use key_service::{ExportedKey, KeyService};

use crate::ApiError;

/// Extension trait for converting ServiceError to ApiError
pub trait IntoApiError {
    fn into_api_error(self) -> ApiError;
}

impl IntoApiError for ServiceError {
    fn into_api_error(self) -> ApiError {
        match self {
            ServiceError::KeyNotFound(id) => ApiError::KeyNotFound(id),
            ServiceError::KeyOperationNotAllowed(msg) => ApiError::Forbidden(msg),
            ServiceError::InvalidCiphertext => {
                ApiError::InvalidRequest("invalid ciphertext".to_string())
            }
            ServiceError::InvalidAlgorithm(msg) => ApiError::InvalidRequest(msg),
            ServiceError::QuotaExceeded {
                resource,
                current,
                limit,
            } => ApiError::QuotaExceeded {
                resource,
                current: current as u64,
                limit: limit as u64,
            },
            ServiceError::RateLimitExceeded => {
                ApiError::Forbidden("rate limit exceeded".to_string())
            }
            ServiceError::InvalidSpec(spec) => {
                ApiError::InvalidRequest(format!("invalid spec: {}", spec))
            }
            ServiceError::ValidationError(msg) => ApiError::InvalidRequest(msg),
            ServiceError::EncryptionFailed(msg) => ApiError::Internal(msg),
            ServiceError::DecryptionFailed(msg) => ApiError::Internal(msg),
            ServiceError::SignatureFailed(msg) => ApiError::Internal(msg),
            ServiceError::Internal(msg) => ApiError::Internal(msg),
        }
    }
}
