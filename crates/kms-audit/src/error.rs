//! kms-audit error types

use thiserror::Error;

/// Errors that can occur in audit logging operations.
#[derive(Error, Debug)]
pub enum AuditError {
    /// File I/O error (read/write/create/fsync).
    #[error("audit I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization or deserialization error.
    #[error("audit serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Invalid file path or directory.
    #[error("invalid audit path: {path}")]
    InvalidPath {
        path: String,
        #[source]
        source: Option<std::io::Error>,
    },

    /// Hash chain verification failed — possible tampering.
    #[error("hash chain verification failed at entry {index}: {reason}")]
    ChainVerificationFailed { index: usize, reason: String },

    /// Configuration error (missing required field, invalid value).
    #[error("audit configuration error: {0}")]
    Config(String),

    /// Network error (S3 upload, TSA request, etc.).
    #[error("audit network error: {0}")]
    Network(String),

    /// Permission denied or file already read-only.
    #[error("audit permission error: {0}")]
    PermissionDenied(String),

    /// TSA timestamp request failed.
    #[error("TSA timestamp failed: {0}")]
    TsaFailed(String),

    /// Catch-all for errors that don't fit other categories.
    #[error("audit internal error: {0}")]
    Internal(String),
}

/// Convenience type alias for audit results.
pub type AuditResult<T> = Result<T, AuditError>;