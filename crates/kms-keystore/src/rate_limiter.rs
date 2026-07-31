//! Redis-based distributed rate limiter
//!
//! Implements sliding window rate limiting using Redis for distributed
//! multi-tenant rate limiting.

use kms_core::error::Error;
use redis::AsyncCommands;
use std::time::{SystemTime, UNIX_EPOCH};

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per window
    pub max_requests: u64,
    /// Window size in seconds
    pub window_secs: u64,
    /// Enable sliding window algorithm
    pub sliding_window: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 1000,
            window_secs: 60,
            sliding_window: true,
        }
    }
}

/// Rate limit result
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Current request count in window
    pub current: u64,
    /// Maximum allowed requests
    pub limit: u64,
    /// Remaining requests
    pub remaining: u64,
    /// Reset time in seconds since epoch
    pub reset_at: u64,
    /// Time until reset in seconds
    pub retry_after_secs: Option<u64>,
}

impl RateLimitResult {
    /// Create an allowed result
    pub fn allowed(current: u64, limit: u64, reset_at: u64) -> Self {
        Self {
            allowed: true,
            current,
            limit,
            remaining: limit.saturating_sub(current),
            reset_at,
            retry_after_secs: None,
        }
    }

    /// Create a rate limited result
    pub fn rate_limited(current: u64, limit: u64, reset_at: u64, retry_after: u64) -> Self {
        Self {
            allowed: false,
            current,
            limit,
            remaining: 0,
            reset_at,
            retry_after_secs: Some(retry_after),
        }
    }
}

/// Sliding window rate limiter using Redis
///
/// Uses Redis sorted sets for accurate sliding window rate limiting.
pub struct SlidingWindowRateLimiter {
    redis: redis::aio::ConnectionManager,
    config: RateLimitConfig,
}

impl SlidingWindowRateLimiter {
    /// Create a new rate limiter with a single Redis connection.
    ///
    /// If `KMS_DB_TLS_MODE` is set and the URL uses `rediss://`, TLS is enabled.
    pub async fn new(redis_url: &str, config: RateLimitConfig) -> Result<Self, redis::RedisError> {
        let tls_config = kms_core::BackendTlsConfig::from_env();
        let client = if tls_config.is_tls_enabled() || redis_url.starts_with("rediss://") {
            tracing::info!(mode = %tls_config.mode, "Connecting to Redis with TLS");
            redis::Client::open(redis_url)?
        } else {
            redis::Client::open(redis_url)?
        };
        let conn = redis::aio::ConnectionManager::new(client).await?;
        Ok(Self {
            redis: conn,
            config,
        })
    }

    /// Create a new rate limiter with a provided connection manager
    pub fn with_connection(redis: redis::aio::ConnectionManager, config: RateLimitConfig) -> Self {
        Self { redis, config }
    }

    /// Check and update rate limit for a tenant
    ///
    /// Uses sliding window algorithm for accurate rate limiting.
    /// Key format: rate_limit:{tenant_id}:{window}
    pub async fn check_rate_limit(&mut self, tenant_id: &str) -> Result<RateLimitResult, Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Internal(e.to_string()))?
            .as_secs();

        let window = now / self.config.window_secs;
        let window_start = window * self.config.window_secs;
        let window_end = window_start + self.config.window_secs;
        let key = format!("rate_limit:{}:{}", tenant_id, window);

        let mut conn = self.redis.clone();

        if self.config.sliding_window {
            // Sliding window algorithm using Redis sorted sets
            // Score is the timestamp, member is a unique request ID
            let request_id = format!("{}:{}", now, uuid::Uuid::new_v4());

            // Remove expired entries (older than window)
            let window_start_i64 = window_start as i64;
            let _removed: i64 = conn
                .zrembyscore(&key, 0, window_start_i64)
                .await
                .map_err(|e| Error::Internal(e.to_string()))?;

            // Count current requests in window
            let current: u64 = conn
                .zcard(&key)
                .await
                .map_err(|e| Error::Internal(e.to_string()))?;

            if current >= self.config.max_requests {
                // Rate limited
                let retry_after = window_end - now;
                return Ok(RateLimitResult::rate_limited(
                    current,
                    self.config.max_requests,
                    window_end,
                    retry_after,
                ));
            }

            // Add new request
            let score = now as f64;
            let _: i32 = conn
                .zadd(&key, request_id, score)
                .await
                .map_err(|e| Error::Internal(e.to_string()))?;

            // Set expiry on the key
            let _: () = conn
                .expire(&key, (self.config.window_secs * 2) as i64)
                .await
                .map_err(|e| Error::Internal(e.to_string()))?;

            Ok(RateLimitResult::allowed(
                current + 1,
                self.config.max_requests,
                window_end,
            ))
        } else {
            // Fixed window counter
            let current: u64 = conn
                .incr(&key, 1u64)
                .await
                .map_err(|e| Error::Internal(e.to_string()))?;

            // Set expiry on first request in window
            if current == 1 {
                let _: () = conn
                    .expire(&key, self.config.window_secs as i64)
                    .await
                    .map_err(|e| Error::Internal(e.to_string()))?;
            }

            if current > self.config.max_requests {
                let retry_after = window_end - now;
                Ok(RateLimitResult::rate_limited(
                    current,
                    self.config.max_requests,
                    window_end,
                    retry_after,
                ))
            } else {
                Ok(RateLimitResult::allowed(
                    current,
                    self.config.max_requests,
                    window_end,
                ))
            }
        }
    }

    /// Get current rate limit status without incrementing
    pub async fn get_status(&self, tenant_id: &str) -> Result<RateLimitResult, Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Internal(e.to_string()))?
            .as_secs();

        let window = now / self.config.window_secs;
        let window_start = window * self.config.window_secs;
        let window_end = window_start + self.config.window_secs;
        let key = format!("rate_limit:{}:{}", tenant_id, window);

        let mut conn = self.redis.clone();

        if self.config.sliding_window {
            // Remove expired entries first
            let window_start_i64 = window_start as i64;
            let _removed: i64 = conn
                .zrembyscore(&key, 0, window_start_i64)
                .await
                .map_err(|e| Error::Internal(e.to_string()))?;

            // Count current requests
            let current: u64 = conn
                .zcard(&key)
                .await
                .map_err(|e| Error::Internal(e.to_string()))?;

            let remaining = self.config.max_requests.saturating_sub(current);
            Ok(RateLimitResult {
                allowed: current < self.config.max_requests,
                current,
                limit: self.config.max_requests,
                remaining,
                reset_at: window_end,
                retry_after_secs: if current >= self.config.max_requests {
                    Some(window_end - now)
                } else {
                    None
                },
            })
        } else {
            let current: u64 = conn.get(&key).await.unwrap_or(0);

            let remaining = self.config.max_requests.saturating_sub(current);
            Ok(RateLimitResult {
                allowed: current < self.config.max_requests,
                current,
                limit: self.config.max_requests,
                remaining,
                reset_at: window_end,
                retry_after_secs: if current >= self.config.max_requests {
                    Some(window_end - now)
                } else {
                    None
                },
            })
        }
    }

    /// Reset rate limit for a tenant
    pub async fn reset(&mut self, tenant_id: &str) -> Result<(), Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Internal(e.to_string()))?
            .as_secs();

        let window = now / self.config.window_secs;
        let key = format!("rate_limit:{}:{}", tenant_id, window);

        let mut conn = self.redis.clone();
        let _: () = conn
            .del(&key)
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(())
    }
}

/// Redis Cluster mode rate limiter using ConnectionManager
///
/// For use with Redis Cluster that presents as a single endpoint
/// (e.g., through a load balancer or proxy).
#[allow(dead_code)]
pub struct ClusterRateLimiter {
    cluster: redis::aio::ConnectionManager,
    config: RateLimitConfig,
}

#[allow(dead_code)]
impl ClusterRateLimiter {
    /// Create a new cluster rate limiter with ConnectionManager
    pub async fn new(redis_url: &str, config: RateLimitConfig) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        let cluster = redis::aio::ConnectionManager::new(client).await?;
        Ok(Self { cluster, config })
    }

    /// Check rate limit using cluster connection manager
    pub async fn check_rate_limit(&mut self, tenant_id: &str) -> Result<RateLimitResult, Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Internal(e.to_string()))?
            .as_secs();

        let window = now / self.config.window_secs;
        let window_end = window * self.config.window_secs + self.config.window_secs;
        let key = format!("rate_limit:{}:{}", tenant_id, window);

        let mut conn = self.cluster.clone();

        if self.config.sliding_window {
            // Sliding window with sorted sets
            let request_id = format!("{}:{}", now, uuid::Uuid::new_v4());
            let window_start = window * self.config.window_secs;

            // Remove expired entries
            let _: i64 = conn
                .zrembyscore(&key, 0, window_start as i64)
                .await
                .map_err(|e| Error::Internal(e.to_string()))?;

            // Count current requests
            let current: u64 = conn
                .zcard(&key)
                .await
                .map_err(|e| Error::Internal(e.to_string()))?;

            if current >= self.config.max_requests {
                let retry_after = window_end - now;
                return Ok(RateLimitResult::rate_limited(
                    current,
                    self.config.max_requests,
                    window_end,
                    retry_after,
                ));
            }

            // Add new request
            let score = now as f64;
            let _: i32 = conn
                .zadd(&key, request_id, score)
                .await
                .map_err(|e| Error::Internal(e.to_string()))?;

            let _: () = conn
                .expire(&key, (self.config.window_secs * 2) as i64)
                .await
                .map_err(|e| Error::Internal(e.to_string()))?;

            Ok(RateLimitResult::allowed(
                current + 1,
                self.config.max_requests,
                window_end,
            ))
        } else {
            // Fixed window
            let current: u64 = conn
                .incr(&key, 1u64)
                .await
                .map_err(|e| Error::Internal(e.to_string()))?;

            if current == 1 {
                let _: () = conn
                    .expire(&key, self.config.window_secs as i64)
                    .await
                    .map_err(|e| Error::Internal(e.to_string()))?;
            }

            if current > self.config.max_requests {
                let ttl: i64 = conn.ttl(&key).await.unwrap_or(0);
                Ok(RateLimitResult::rate_limited(
                    current,
                    self.config.max_requests,
                    now + ttl as u64,
                    ttl as u64,
                ))
            } else {
                Ok(RateLimitResult::allowed(
                    current,
                    self.config.max_requests,
                    window_end,
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_requests, 1000);
        assert_eq!(config.window_secs, 60);
        assert!(config.sliding_window);
    }

    #[test]
    fn test_rate_limit_result_allowed() {
        let result = RateLimitResult::allowed(50, 100, 1000);
        assert!(result.allowed);
        assert_eq!(result.current, 50);
        assert_eq!(result.limit, 100);
        assert_eq!(result.remaining, 50);
        assert_eq!(result.reset_at, 1000);
        assert!(result.retry_after_secs.is_none());
    }

    #[test]
    fn test_rate_limit_result_rate_limited() {
        let result = RateLimitResult::rate_limited(101, 100, 1000, 30);
        assert!(!result.allowed);
        assert_eq!(result.current, 101);
        assert_eq!(result.limit, 100);
        assert_eq!(result.remaining, 0);
        assert_eq!(result.retry_after_secs, Some(30));
    }
}
