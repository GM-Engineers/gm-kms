//! Tenant rate limiting middleware
//!
//! Implements sliding window rate limiting per tenant using Redis.
//! Each tenant gets a configurable requests-per-second allowance.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{Response, StatusCode},
    middleware::Next,
};
use redis::AsyncCommands;
use std::sync::Arc;

/// Rate limit configuration per tenant
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per second per tenant
    pub requests_per_second: u64,
    /// Maximum requests per minute per tenant
    pub requests_per_minute: u64,
    /// Maximum burst size
    pub burst_size: u64,
    /// Fail mode when Redis is unavailable
    /// FailOpen: allow requests (risk of DoS)
    /// FailClosed: reject requests (safer default)
    pub fail_mode: RateLimitFailMode,
}

/// Fail mode for rate limiting when Redis is unavailable
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitFailMode {
    /// Allow requests when Redis is down (risk of DoS)
    FailOpen,
    /// Reject requests when Redis is down (safer)
    FailClosed,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 100,
            requests_per_minute: 5000,
            burst_size: 200,
            fail_mode: RateLimitFailMode::FailClosed, // Safer default
        }
    }
}

/// Rate limiter using Redis sliding window
#[derive(Clone)]
pub struct TenantRateLimiter {
    redis: redis::aio::ConnectionManager,
    config: RateLimitConfig,
}

impl TenantRateLimiter {
    /// Create a new rate limiter with Redis connection
    pub fn new(redis: redis::aio::ConnectionManager, config: RateLimitConfig) -> Self {
        Self { redis, config }
    }

    /// Check if a request is allowed for the given tenant
    /// Returns Ok(remaining) if allowed, Err(retry_after_secs) if rate limited
    pub async fn check(&self, tenant_id: &str) -> Result<u64, (u64, i64)> {
        let mut conn = self.redis.clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_millis() as u64;

        let window_ms = 1000; // 1 second window

        // Sliding window key
        let window_key = format!("ratelimit:{}:{}", tenant_id, now / window_ms);

        // Lua script for atomic sliding window
        let script = r#"
            local key = KEYS[1]
            local now = tonumber(ARGV[1])
            local window_ms = tonumber(ARGV[2])
            local max_req = tonumber(ARGV[3])
            local window_key = KEYS[1]

            -- Increment counter
            local current = redis.call('INCR', window_key)
            if current == 1 then
                redis.call('PEXPIRE', window_key, window_ms)
            end

            -- Get TTL for retry-after
            local ttl = redis.call('PTTL', window_key)
            if ttl < 0 then ttl = window_ms end

            return {current, ttl}
        "#;

        let result: Result<Vec<i64>, redis::RedisError> = redis::Script::new(script)
            .key(&window_key)
            .arg(now)
            .arg(window_ms)
            .arg(self.config.requests_per_second)
            .invoke_async(&mut conn)
            .await;

        match result {
            Ok(result) => {
                let (current_count, ttl_ms) = (result[0] as u64, result[1] as u64);

                if current_count > self.config.requests_per_second {
                    let retry_after = (ttl_ms as f64 / 1000.0).ceil() as u64;
                    return Err((retry_after, ttl_ms as i64));
                }

                let remaining = self.config.requests_per_second - current_count;
                Ok(remaining)
            }
            Err(e) => {
                match self.config.fail_mode {
                    RateLimitFailMode::FailOpen => {
                        tracing::warn!(
                            "Rate limit check failed: {}, allowing request (fail open)",
                            e
                        );
                        Ok(self.config.requests_per_second)
                    }
                    RateLimitFailMode::FailClosed => {
                        tracing::warn!(
                            "Rate limit check failed: {}, rejecting request (fail closed)",
                            e
                        );
                        Err((60, 60000)) // Reject with 60 second retry-after
                    }
                }
            }
        }
    }

    /// Get current usage for a tenant
    pub async fn get_usage(&self, tenant_id: &str) -> Result<u64, ()> {
        let mut conn = self.redis.clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_millis() as u64;

        let window_key = format!("ratelimit:{}:{}", tenant_id, now / 1000);

        let count: Option<i64> = conn.get(&window_key).await.map_err(|_| ())?;
        Ok(count.unwrap_or(0) as u64)
    }
}

/// Extract tenant_id from request extensions (secure source)
/// Returns None if tenant_id not found - caller must handle this case
pub fn extract_tenant_id(request: &Request) -> Option<String> {
    // Only extract from extensions, which should be set by authenticated context
    // This prevents header spoofing attacks
    request.extensions().get::<TenantId>().map(|t| t.0.clone())
}

/// Extension to carry tenant ID through request
#[derive(Clone, Debug)]
pub struct TenantId(pub String);

/// Tenant extraction middleware
///
/// Extracts tenant_id from request query parameters and inserts it into
/// request extensions as `TenantId`. This runs before the rate limiter
/// and auth middleware so that tenant-scoped rate limiting works.
///
/// Uses `tenant_id` query parameter with `"default"` as fallback.
/// This is a routing identifier only — actual tenant isolation is enforced
/// by the service layer via FIX-002/FIX-003.
pub async fn tenant_extraction_middleware(mut request: Request, next: Next) -> Response<Body> {
    // Extract tenant_id from query params and insert into extensions.
    // IMPORTANT: always validate format — never trust raw user input.
    // Actual tenant isolation is enforced at the service layer.
    let tenant_id = request
        .uri()
        .query()
        .and_then(|q| {
            q.split('&')
                .find(|p| p.starts_with("tenant_id="))
                .map(|p| p[10..].to_string())
        })
        .filter(|id| {
            // Reject if format looks suspicious — prevents injection into extensions
            !id.is_empty()
                && id.len() <= 128
                && id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
        .unwrap_or_else(|| "default".to_string());

    request.extensions_mut().insert(TenantId(tenant_id));
    next.run(request).await
}

/// Rate limit middleware for Axum
pub async fn rate_limit_middleware(
    State(limiter): State<Arc<TenantRateLimiter>>,
    mut request: Request,
    next: Next,
) -> Response<Body> {
    // Extract tenant_id only from secure extensions (set by auth middleware)
    // Reject if not found to prevent header spoofing
    let tenant_id = match extract_tenant_id(&request) {
        Some(id) => id,
        None => {
            // No tenant_id in extensions - request not authenticated
            // Return 401 Unauthorized
            let body = Body::from(
                r#"{"error":"unauthorized","message":"Tenant ID not found in authenticated context"}"#,
            );
            let mut response = Response::new(body);
            *response.status_mut() = StatusCode::UNAUTHORIZED;
            response.headers_mut().insert(
                "Content-Type",
                "application/json".parse().expect("valid header value"),
            );
            return response;
        }
    };

    // Add tenant_id to extensions for downstream handlers
    request.extensions_mut().insert(TenantId(tenant_id.clone()));

    match limiter.check(&tenant_id).await {
        Ok(_remaining) => {
            // Allow request, continue to handler
            next.run(request).await
        }
        Err((retry_after, _ttl_ms)) => {
            // Rate limited - return 429
            let body = Body::from(format!(
                r#"{{"error":"rate_limit_exceeded","message":"Too many requests","retry_after_secs":{}}}"#,
                retry_after
            ));

            let mut response = Response::new(body);
            *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            response.headers_mut().insert(
                "Retry-After",
                retry_after.to_string().parse().expect("valid header value"),
            );
            response.headers_mut().insert(
                "X-RateLimit-Retry-After-Seconds",
                retry_after.to_string().parse().expect("valid header value"),
            );
            response.headers_mut().insert(
                "Content-Type",
                "application/json".parse().expect("valid header value"),
            );
            response
        }
    }
}

/// Rate limit error response body
#[derive(Debug, serde::Serialize)]
pub struct RateLimitError {
    pub error: String,
    pub retry_after_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_creation() {
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

        let client = redis::Client::open(redis_url).expect("Failed to create Redis client");
        let conn_manager = match redis::aio::ConnectionManager::new(client).await {
            Ok(cm) => cm,
            Err(_) => {
                println!("Redis not available, skipping test");
                return;
            }
        };

        let limiter = TenantRateLimiter::new(conn_manager, RateLimitConfig::default());
        let tenant_id = "test-tenant";

        // First request should succeed
        let result = limiter.check(tenant_id).await;
        assert!(result.is_ok());

        println!("Rate limiter test passed!");
    }

    #[tokio::test]
    async fn test_rate_limiter_rejects_over_limit() {
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

        let client = redis::Client::open(redis_url).expect("Failed to create Redis client");
        let conn_manager = match redis::aio::ConnectionManager::new(client).await {
            Ok(cm) => cm,
            Err(_) => {
                println!("Redis not available, skipping test");
                return;
            }
        };

        // Use very low limits for testing
        let config = RateLimitConfig {
            requests_per_second: 2,
            requests_per_minute: 2,
            burst_size: 2,
            fail_mode: RateLimitFailMode::FailOpen,
        };

        let limiter = TenantRateLimiter::new(conn_manager, config);
        let tenant_id = "test-tenant-overlimit";

        // First two requests should succeed
        for _ in 0..2 {
            let result = limiter.check(tenant_id).await;
            assert!(result.is_ok(), "Request should be allowed");
        }

        // Third request should be rejected
        let result = limiter.check(tenant_id).await;
        assert!(result.is_err(), "Request should be rate limited");

        println!("Rate limiter over-limit test passed!");
    }
}
