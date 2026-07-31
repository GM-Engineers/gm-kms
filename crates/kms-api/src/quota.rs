//! Tenant quota tracking
//!
//! Tracks per-tenant resource usage including key counts and operation counts.
//! Uses Redis for distributed quota tracking.

use redis::AsyncCommands;

/// Quota configuration per tenant tier
#[derive(Debug, Clone)]
pub struct QuotaConfig {
    /// Maximum keys per tenant
    pub max_keys: u64,
    /// Maximum requests per minute
    pub max_requests_per_minute: u64,
    /// Maximum requests per day
    pub max_requests_per_day: u64,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            max_keys: 1000,
            max_requests_per_minute: 5000,
            max_requests_per_day: 1000000,
        }
    }
}

/// Default quota per tenant (can be overridden per tenant)
pub const DEFAULT_QUOTA: QuotaConfig = QuotaConfig {
    max_keys: 1000,
    max_requests_per_minute: 5000,
    max_requests_per_day: 1000000,
};

/// Quota usage for a tenant
#[derive(Debug, Clone)]
pub struct QuotaUsage {
    pub tenant_id: String,
    pub key_count: u64,
    pub requests_this_minute: u64,
    pub requests_today: u64,
}

/// Tenant quota tracker using Redis
#[derive(Clone)]
pub struct TenantQuotaTracker {
    redis: redis::aio::ConnectionManager,
    config: QuotaConfig,
}

impl TenantQuotaTracker {
    /// Create a new quota tracker
    pub fn new(redis: redis::aio::ConnectionManager, config: QuotaConfig) -> Self {
        Self { redis, config }
    }

    /// Check if tenant can create a new key
    pub async fn can_create_key(&self, tenant_id: &str) -> Result<bool, QuotaExceeded> {
        let mut conn = self.redis.clone();
        let key = format!("quota:{}:keys", tenant_id);

        let current: u64 = conn.get(&key).await.unwrap_or(0);

        if current >= self.config.max_keys {
            return Err(QuotaExceeded {
                resource: "keys".to_string(),
                current,
                limit: self.config.max_keys,
            });
        }

        Ok(true)
    }

    /// Increment key count for tenant
    pub async fn increment_key_count(&self, tenant_id: &str) -> Result<u64, ()> {
        let mut conn = self.redis.clone();
        let key = format!("quota:{}:keys", tenant_id);

        let new_count: u64 = conn.incr(&key, 1).await.map_err(|_| ())?;

        // Set TTL of 30 days for key count
        let _: () = conn.expire(&key, 60 * 60 * 24 * 30).await.map_err(|_| ())?;

        Ok(new_count)
    }

    /// Decrement key count for tenant (when key is deleted)
    pub async fn decrement_key_count(&self, tenant_id: &str) -> Result<u64, ()> {
        let mut conn = self.redis.clone();
        let key = format!("quota:{}:keys", tenant_id);

        let new_count: u64 = conn.decr(&key, 1).await.map_err(|_| ())?;

        // Ensure it doesn't go negative
        if new_count > self.config.max_keys {
            let _: () = conn.set::<_, _, ()>(&key, 0).await.map_err(|_| ())?;
            return Ok(0);
        }

        Ok(new_count)
    }

    /// Record an API request for rate accounting
    pub async fn record_request(&self, tenant_id: &str) -> Result<(), QuotaExceeded> {
        let mut conn = self.redis.clone();

        // Track requests this minute
        let minute_key = format!(
            "quota:{}:req:minute:{}",
            tenant_id,
            chrono::Utc::now().format("%Y%m%d%H%M")
        );
        let minute_count: u64 = match conn.incr(&minute_key, 1).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to increment minute counter: {}", e);
                return Ok(()); // Fail gracefully
            }
        };
        let _: Result<(), _> = conn.expire(&minute_key, 120).await; // 2 min TTL

        if minute_count > self.config.max_requests_per_minute {
            return Err(QuotaExceeded {
                resource: "requests_per_minute".to_string(),
                current: minute_count,
                limit: self.config.max_requests_per_minute,
            });
        }

        // Track requests today
        let day_key = format!(
            "quota:{}:req:day:{}",
            tenant_id,
            chrono::Utc::now().format("%Y%m%d")
        );
        let day_count: u64 = match conn.incr(&day_key, 1).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to increment day counter: {}", e);
                return Ok(()); // Fail gracefully
            }
        };
        let _: Result<(), _> = conn.expire(&day_key, 86400).await; // 24 hour TTL

        if day_count > self.config.max_requests_per_day {
            return Err(QuotaExceeded {
                resource: "requests_per_day".to_string(),
                current: day_count,
                limit: self.config.max_requests_per_day,
            });
        }

        Ok(())
    }

    /// Get current quota usage for a tenant
    pub async fn get_usage(&self, tenant_id: &str) -> Result<QuotaUsage, ()> {
        let mut conn = self.redis.clone();

        // Get key count
        let key_key = format!("quota:{}:keys", tenant_id);
        let key_count: u64 = conn.get(&key_key).await.unwrap_or(0);

        // Get requests this minute
        let minute_key = format!(
            "quota:{}:req:minute:{}",
            tenant_id,
            chrono::Utc::now().format("%Y%m%d%H%M")
        );
        let requests_this_minute: u64 = conn.get(&minute_key).await.unwrap_or(0);

        // Get requests today
        let day_key = format!(
            "quota:{}:req:day:{}",
            tenant_id,
            chrono::Utc::now().format("%Y%m%d")
        );
        let requests_today: u64 = conn.get(&day_key).await.unwrap_or(0);

        Ok(QuotaUsage {
            tenant_id: tenant_id.to_string(),
            key_count,
            requests_this_minute,
            requests_today,
        })
    }

    /// Get the quota config
    pub fn get_config(&self) -> &QuotaConfig {
        &self.config
    }
}

/// Quota exceeded error
#[derive(Debug, Clone)]
pub struct QuotaExceeded {
    pub resource: String,
    pub current: u64,
    pub limit: u64,
}

impl std::fmt::Display for QuotaExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "quota exceeded: {} ({}/{})",
            self.resource, self.current, self.limit
        )
    }
}

impl std::error::Error for QuotaExceeded {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires isolated Redis or cleanup between runs
    async fn test_quota_tracker_basic() {
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

        let config = QuotaConfig {
            max_keys: 100,
            max_requests_per_minute: 1000,
            max_requests_per_day: 100000,
        };

        let tracker = TenantQuotaTracker::new(conn_manager, config);
        let tenant_id = "test-tenant-quota-unique"; // Use unique tenant to avoid conflicts

        // Check initial state
        let can_create = tracker.can_create_key(tenant_id).await;
        assert!(can_create.is_ok());

        // Increment key count
        let count = tracker.increment_key_count(tenant_id).await;
        assert!(count.is_ok());
        assert_eq!(count.unwrap(), 1);

        // Record request
        let result = tracker.record_request(tenant_id).await;
        assert!(result.is_ok());

        // Get usage
        let usage = tracker.get_usage(tenant_id).await;
        assert!(usage.is_ok());
        let usage = usage.unwrap();
        assert_eq!(usage.key_count, 1);
        assert_eq!(usage.requests_this_minute, 1);

        println!("Quota tracker test passed!");
    }

    #[tokio::test]
    #[ignore] // Requires isolated Redis or cleanup between runs
    async fn test_quota_exceeded() {
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

        // Use very low limits
        let config = QuotaConfig {
            max_keys: 2,
            max_requests_per_minute: 2,
            max_requests_per_day: 100000,
        };

        let tracker = TenantQuotaTracker::new(conn_manager, config);
        let tenant_id = "test-tenant-exceeded-unique"; // Use unique tenant

        // First two requests should succeed
        assert!(tracker.can_create_key(tenant_id).await.is_ok());
        let _ = tracker.increment_key_count(tenant_id).await;
        assert!(tracker.can_create_key(tenant_id).await.is_ok());
        let _ = tracker.increment_key_count(tenant_id).await;

        // Third should fail
        assert!(tracker.can_create_key(tenant_id).await.is_err());

        println!("Quota exceeded test passed!");
    }
}
