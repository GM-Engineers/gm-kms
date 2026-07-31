//! Distributed tracing utilities for KMS
//!
//! Provides trace ID extraction for request tracing across services.

use axum::http::HeaderMap;

/// X-Request-ID header name
pub const TRACE_ID_HEADER: &str = "x-request-id";

/// Header name for trace context propagation
pub const TRACE_PARENT_HEADER: &str = "x-trace-parent";

/// Extract trace ID from request headers
pub fn extract_trace_id(headers: &HeaderMap) -> Option<String> {
    // Try X-Request-ID first
    if let Some(trace_id) = headers.get(TRACE_ID_HEADER) {
        return trace_id.to_str().ok().map(|s| s.to_string());
    }

    // Try X-Trace-Parent if present (W3C trace context format)
    if let Some(trace_parent) = headers.get(TRACE_PARENT_HEADER)
        && let Ok(s) = trace_parent.to_str()
        && let Some(trace_id) = parse_w3c_trace_parent(s)
    {
        return Some(trace_id);
    }

    None
}

fn parse_w3c_trace_parent(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() >= 2 {
        // Return the trace-id portion
        Some(parts[1].to_string())
    } else {
        None
    }
}

/// Generate a new trace ID
pub fn generate_trace_id() -> String {
    uuid::Uuid::new_v4().to_string()[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};

    #[test]
    fn test_generate_trace_id() {
        let id = generate_trace_id();
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn test_parse_w3c_trace_parent() {
        let parent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        let trace_id = parse_w3c_trace_parent(parent);
        assert_eq!(
            trace_id,
            Some("0af7651916cd43dd8448eb211c80319c".to_string())
        );
    }

    #[test]
    fn test_extract_trace_id_from_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            TRACE_ID_HEADER.parse::<HeaderName>().unwrap(),
            HeaderValue::from_static("test-trace-123"),
        );
        assert_eq!(
            extract_trace_id(&headers),
            Some("test-trace-123".to_string())
        );
    }
}
