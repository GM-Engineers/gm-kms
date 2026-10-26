//! The error type of the SDK.

use thiserror::Error;

/// The result type of every fallible SDK call.
pub type Result<T> = std::result::Result<T, KmsError>;

/// Everything that can go wrong while talking to the KMS.
#[derive(Debug, Error)]
pub enum KmsError {
    /// The server URL could not be used.
    #[error("invalid server URL: {0}")]
    InvalidUrl(String),

    /// The request never produced a response (DNS, TCP, TLS, timeout).
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// The payload could not be encoded or decoded.
    #[error("payload error: {0}")]
    Payload(#[from] serde_json::Error),

    /// A base64 field could not be decoded.
    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// The KMS answered with a non-2xx status.
    ///
    /// `message` is the `error` field of the server's JSON body
    /// (`{"error": "..."}`), or the raw body when the server did not answer
    /// with JSON.
    #[error(
        "the KMS returned HTTP {status}: {message}{}",
        .retry_after
            .map(|s| format!(" (retry after {s}s)"))
            .unwrap_or_default()
    )]
    Api {
        /// The HTTP status code.
        status: u16,
        /// The server's error message.
        message: String,
        /// The `Retry-After` header, in seconds, when the server sent one.
        retry_after: Option<u64>,
    },
}

impl KmsError {
    /// The HTTP status code, when the failure came from the server.
    pub fn status(&self) -> Option<u16> {
        match self {
            KmsError::Api { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// The server's error message, when the failure came from the server.
    pub fn message(&self) -> Option<&str> {
        match self {
            KmsError::Api { message, .. } => Some(message),
            _ => None,
        }
    }

    /// Whether the server answered 403.
    ///
    /// A 403 means the caller is not authorized — the request was well-formed
    /// but the approval or policy gate refused it. A 400, in contrast, means
    /// the request itself was malformed.
    pub fn is_forbidden(&self) -> bool {
        self.status() == Some(403)
    }

    /// Whether the server answered 404.
    pub fn is_not_found(&self) -> bool {
        self.status() == Some(404)
    }

    /// Whether the server answered 401 or 403.
    pub fn is_unauthorized(&self) -> bool {
        matches!(self.status(), Some(401 | 403))
    }

    /// Whether the server answered 429.
    pub fn is_rate_limited(&self) -> bool {
        self.status() == Some(429)
    }
}
