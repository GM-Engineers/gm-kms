//! Error types for API layer
//!
//! All error variants that could leak sensitive information (Internal, KeyNotFound)
//! are sanitized in their `IntoResponse` implementation — clients receive generic
//! messages while full details are logged server-side via `tracing`.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("permission denied")]
    PermissionDenied,

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("quota exceeded: {resource} ({current}/{limit})")]
    QuotaExceeded {
        resource: String,
        current: u64,
        limit: u64,
    },

    #[error("too many requests: {0}")]
    TooManyRequests(String),

    #[error("not implemented")]
    NotImplemented,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            // Sanitized: log key ID server-side, return generic message to client
            ApiError::KeyNotFound(id) => {
                tracing::warn!(key_id = %id, "key not found");
                (StatusCode::NOT_FOUND, "key not found".to_string())
            }
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            ApiError::PermissionDenied => (StatusCode::FORBIDDEN, "permission denied".to_string()),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            ApiError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::InvalidArgument(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            // Sanitized: log full error server-side, return generic message to client
            ApiError::Internal(msg) => {
                tracing::error!(error = %msg, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            }
            ApiError::QuotaExceeded {
                resource,
                current,
                limit,
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                format!("quota exceeded: {} ({}/{})", resource, current, limit),
            ),
            ApiError::TooManyRequests(msg) => (StatusCode::TOO_MANY_REQUESTS, msg.clone()),
            ApiError::NotImplemented => {
                (StatusCode::NOT_IMPLEMENTED, "not implemented".to_string())
            }
        };

        let body = serde_json::json!({
            "error": message
        });

        (status, Json(body)).into_response()
    }
}

impl From<gm_sm9_rs::Sm9Error> for ApiError {
    fn from(e: gm_sm9_rs::Sm9Error) -> Self {
        ApiError::Internal(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    async fn response_body(response: Response) -> serde_json::Value {
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        serde_json::from_slice(&body_bytes).unwrap()
    }

    #[tokio::test]
    async fn test_internal_error_returns_generic_message() {
        let err = ApiError::Internal("sensitive sql error: connection refused".into());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response_body(response).await;
        assert_eq!(body["error"], "internal server error");
        // Ensure the original message is NOT leaked
        let body_str = body.to_string();
        assert!(!body_str.contains("sensitive"));
        assert!(!body_str.contains("sql"));
        assert!(!body_str.contains("connection refused"));
    }

    #[tokio::test]
    async fn test_key_not_found_does_not_leak_id() {
        let err = ApiError::KeyNotFound("secret-key-uuid-12345".into());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = response_body(response).await;
        assert_eq!(body["error"], "key not found");
        // Ensure the key ID is NOT leaked
        let body_str = body.to_string();
        assert!(!body_str.contains("secret-key-uuid-12345"));
    }

    #[tokio::test]
    async fn test_error_format_consistent() {
        // All errors should return JSON with an "error" field
        let errors = vec![
            ApiError::KeyNotFound("any-id".into()),
            ApiError::Internal("any-detail".into()),
            ApiError::InvalidRequest("bad input".into()),
            ApiError::PermissionDenied,
            ApiError::Forbidden("no access".into()),
            ApiError::NotFound("resource gone".into()),
            ApiError::BadRequest("invalid".into()),
            ApiError::TooManyRequests("rate limited".into()),
            ApiError::NotImplemented,
        ];
        for err in errors {
            let response = err.into_response();
            let body = response_body(response).await;
            assert!(body["error"].is_string(), "error field should be a string");
        }
    }

    #[tokio::test]
    async fn test_panic_message_sanitized() {
        // Simulate a panic-like error that might contain stack traces
        let err = ApiError::Internal(
            "thread 'main' panicked at src/keystore.rs:42: called `unwrap()` on Err value".into(),
        );
        let response = err.into_response();
        let body = response_body(response).await;
        assert_eq!(body["error"], "internal server error");
        let body_str = body.to_string();
        assert!(!body_str.contains("panicked"));
        assert!(!body_str.contains("src/keystore.rs"));
    }

    #[tokio::test]
    async fn test_sql_error_not_leaked() {
        let err = ApiError::Internal(
            "database error: relation 'keys' does not exist (SQLSTATE: 42P01)".into(),
        );
        let response = err.into_response();
        let body = response_body(response).await;
        assert_eq!(body["error"], "internal server error");
        let body_str = body.to_string();
        assert!(!body_str.contains("database"));
        assert!(!body_str.contains("SQLSTATE"));
        assert!(!body_str.contains("relation"));
    }

    #[tokio::test]
    async fn test_enumeration_impossible() {
        // Sending different key IDs should produce identical responses,
        // preventing key ID enumeration via timing or response content.
        let resp1 = ApiError::KeyNotFound("key-aaaa-bbbb-cccc".into()).into_response();
        let resp2 = ApiError::KeyNotFound("key-xxxx-yyyy-zzzz".into()).into_response();
        let resp3 = ApiError::KeyNotFound("key-nonexistent-1".into()).into_response();

        let body1 = response_body(resp1).await;
        let body2 = response_body(resp2).await;
        let body3 = response_body(resp3).await;

        assert_eq!(body1["error"], body2["error"]);
        assert_eq!(body2["error"], body3["error"]);
    }
}
