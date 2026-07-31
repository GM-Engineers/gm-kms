//! HTTP security headers middleware for the KMS REST API.
//!
//! Applies DJCP Level 3 required security headers to all API responses.

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};

/// Security headers applied to every response
const SECURITY_HEADERS: &[(&str, &str)] = &[
    (
        "strict-transport-security",
        "max-age=31536000; includeSubDomains",
    ),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    (
        "content-security-policy",
        "default-src 'none'; frame-ancestors 'none'",
    ),
    ("cache-control", "no-store, no-cache, must-revalidate"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
];

/// Axum middleware that adds security headers to every response
pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in SECURITY_HEADERS {
        if !headers.contains_key(*name)
            && let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            )
        {
            headers.insert(n, v);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, http::Request, routing::get};
    use tower::ServiceExt;

    async fn test_app() -> Router {
        Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(security_headers_middleware))
    }

    #[tokio::test]
    async fn test_security_headers_present_on_response() {
        let app = test_app().await;
        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let headers = response.headers();
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(
            headers.get("referrer-policy").unwrap(),
            "strict-origin-when-cross-origin"
        );
        assert!(headers.contains_key("strict-transport-security"));
        assert!(headers.contains_key("content-security-policy"));
        assert!(headers.contains_key("cache-control"));
    }

    #[tokio::test]
    async fn test_hsts_max_age() {
        let app = test_app().await;
        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let hsts = response
            .headers()
            .get("strict-transport-security")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(hsts.contains("max-age=31536000"));
        assert!(hsts.contains("includeSubDomains"));
    }

    #[tokio::test]
    async fn test_cache_control_prevents_caching() {
        let app = test_app().await;
        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let cache_control = response
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cache_control.contains("no-store"));
        assert!(cache_control.contains("no-cache"));
        assert!(cache_control.contains("must-revalidate"));
    }

    #[tokio::test]
    async fn test_security_headers_do_not_overwrite_existing() {
        // If a handler sets its own Cache-Control, the middleware should not overwrite it
        async fn custom_cache() -> ([(HeaderName, HeaderValue); 1], &'static str) {
            (
                [(
                    HeaderName::from_static("cache-control"),
                    HeaderValue::from_static("public, max-age=3600"),
                )],
                "cached",
            )
        }

        let app = Router::new()
            .route("/cached", get(custom_cache))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/cached")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let cache_control = response
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap();
        // Should preserve the handler's value, not the middleware default
        assert_eq!(cache_control, "public, max-age=3600");
    }
}
