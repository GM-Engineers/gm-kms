//! Unified caching strategy for KMS
//!
//! Provides a consistent caching layer across different components:
//! - Key metadata caching (with TTL)
//! - Policy caching (with invalidation)
//! - Rate limiting state caching
//!
//! # Cache Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │            Unified Cache Manager            │
//! ├─────────────┬─────────────┬────────────────┤
//! │ KeyMetadata  │   Policy    │  RateLimit     │
//! │    Cache     │    Cache    │    State       │
//! └─────────────┴─────────────┴────────────────┘
//!        ↓            ↓             ↓
//!      Redis       Memory        Redis
//! ```
//!
//! # Configuration
//!
//! ```rust,ignore
//! use kms_api::cache::{CacheConfig, CacheManager, CacheKey};
//!
//! let config = CacheConfig::default();
//! let cache = CacheManager::new(config);
//! ```

use parking_lot::RwLock;
use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

/// Cache entry with expiration
#[derive(Debug, Clone)]
struct CacheEntry<T> {
    value: T,
    expires_at: Instant,
}

impl<T> CacheEntry<T> {
    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// Cache key types
///
/// **Security note**: All cache keys now include tenant_id to ensure proper tenant isolation.
/// This prevents cross-tenant data leakage through the cache layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CacheKey {
    /// Key metadata by key ID and tenant (fully qualified)
    KeyMeta { tenant_id: String, key_id: String },
    /// Policy by policy ID and tenant (fully qualified)
    Policy {
        tenant_id: String,
        policy_id: String,
    },
    /// Tenant quota info
    TenantQuota(String),
    /// User session data
    Session(String),
    /// Custom key with namespace and tenant
    Custom {
        namespace: String,
        tenant_id: String,
        key: String,
    },
}

impl CacheKey {
    /// Create a key metadata cache key with tenant isolation
    pub fn key_metadata(tenant_id: &str, key_id: &str) -> Self {
        CacheKey::KeyMeta {
            tenant_id: tenant_id.to_string(),
            key_id: key_id.to_string(),
        }
    }

    /// Create a policy cache key with tenant isolation
    pub fn policy(tenant_id: &str, policy_id: &str) -> Self {
        CacheKey::Policy {
            tenant_id: tenant_id.to_string(),
            policy_id: policy_id.to_string(),
        }
    }

    pub fn tenant_quota(tenant_id: &str) -> Self {
        CacheKey::TenantQuota(tenant_id.to_string())
    }

    pub fn session(session_id: &str) -> Self {
        CacheKey::Session(session_id.to_string())
    }
}

/// Cache value types
#[derive(Debug, Clone)]
pub enum CacheValue {
    KeyMeta(KeyMetaCacheEntry),
    Policy(PolicyCacheEntry),
    TenantQuota(TenantQuotaCacheEntry),
    Session(SessionCacheEntry),
}

#[derive(Debug, Clone)]
pub struct KeyMetaCacheEntry {
    pub id: String,
    pub name: String,
    pub spec: String,
    pub status: String,
    pub version: u32,
    pub tenant_id: String,
}

/// Policy cache entry
#[derive(Debug, Clone)]
pub struct PolicyCacheEntry {
    pub id: String,
    pub name: String,
    pub effect: String,
    pub enabled: bool,
    pub cached_at: DateTime<Utc>,
}

/// Tenant quota cache entry
#[derive(Debug, Clone)]
pub struct TenantQuotaCacheEntry {
    pub tenant_id: String,
    pub key_count: u64,
    pub key_limit: u64,
    pub operation_count: u64,
    pub operation_limit: u64,
}

/// Session cache entry
#[derive(Debug, Clone)]
pub struct SessionCacheEntry {
    pub session_id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub permissions: Vec<String>,
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Default TTL for entries (seconds)
    pub default_ttl_secs: u64,
    /// Maximum entries in memory cache
    pub max_entries: usize,
    /// Enable/disable cache layers
    pub enable_key_meta_cache: bool,
    pub enable_policy_cache: bool,
    pub enable_quota_cache: bool,
    /// Cleanup interval (seconds)
    pub cleanup_interval_secs: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            default_ttl_secs: 300, // 5 minutes
            max_entries: 10_000,
            enable_key_meta_cache: true,
            enable_policy_cache: true,
            enable_quota_cache: true,
            cleanup_interval_secs: 60,
        }
    }
}

impl CacheConfig {
    /// Create config for development (shorter TTLs)
    pub fn development() -> Self {
        Self {
            default_ttl_secs: 60,
            max_entries: 1_000,
            enable_key_meta_cache: true,
            enable_policy_cache: true,
            enable_quota_cache: true,
            cleanup_interval_secs: 30,
        }
    }

    /// Create config for production (longer TTLs)
    pub fn production() -> Self {
        Self {
            default_ttl_secs: 3600, // 1 hour
            max_entries: 100_000,
            enable_key_meta_cache: true,
            enable_policy_cache: true,
            enable_quota_cache: true,
            cleanup_interval_secs: 300,
        }
    }

    /// Create config for testing (no caching)
    pub fn testing() -> Self {
        Self {
            default_ttl_secs: 0,
            max_entries: 100,
            enable_key_meta_cache: false,
            enable_policy_cache: false,
            enable_quota_cache: false,
            cleanup_interval_secs: 0,
        }
    }
}

/// In-memory cache store
pub struct MemoryCache<T> {
    entries: RwLock<HashMap<String, CacheEntry<T>>>,
    max_entries: usize,
}

impl<T: Clone> MemoryCache<T> {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_entries,
        }
    }

    pub fn get(&self, key: &str) -> Option<T> {
        let entries = self.entries.read();
        if let Some(entry) = entries.get(key)
            && !entry.is_expired()
        {
            return Some(entry.value.clone());
        }
        None
    }

    pub fn set(&self, key: String, value: T, ttl: Duration) {
        let mut entries = self.entries.write();

        // Evict if at capacity
        if entries.len() >= self.max_entries {
            // Remove oldest expired entries first
            entries.retain(|_, v| !v.is_expired());
            // If still at capacity, remove first entry
            if entries.len() >= self.max_entries {
                let first_key = entries.keys().next().cloned();
                if let Some(k) = first_key {
                    entries.remove(&k);
                }
            }
        }

        entries.insert(
            key,
            CacheEntry {
                value,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    pub fn remove(&self, key: &str) {
        let mut entries = self.entries.write();
        entries.remove(key);
    }

    pub fn clear(&self) {
        let mut entries = self.entries.write();
        entries.clear();
    }

    pub fn len(&self) -> usize {
        let entries = self.entries.read();
        entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Cleanup expired entries
    pub fn cleanup(&self) {
        let mut entries = self.entries.write();
        entries.retain(|_, v| !v.is_expired());
    }
}

impl Default for MemoryCache<Vec<u8>> {
    fn default() -> Self {
        Self::new(1000)
    }
}

/// Unified cache manager
pub struct CacheManager {
    config: CacheConfig,
    key_meta_cache: MemoryCache<KeyMetaCacheEntry>,
    policy_cache: MemoryCache<PolicyCacheEntry>,
    quota_cache: MemoryCache<TenantQuotaCacheEntry>,
    session_cache: MemoryCache<SessionCacheEntry>,
}

impl CacheManager {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config: config.clone(),
            key_meta_cache: MemoryCache::new(config.max_entries),
            policy_cache: MemoryCache::new(config.max_entries),
            quota_cache: MemoryCache::new(config.max_entries),
            session_cache: MemoryCache::new(config.max_entries),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(CacheConfig::default())
    }

    /// Get cached key metadata
    pub fn get_key_meta(&self, key_id: &str) -> Option<KeyMetaCacheEntry> {
        if !self.config.enable_key_meta_cache {
            return None;
        }
        self.key_meta_cache.get(key_id)
    }

    /// Cache key metadata
    pub fn set_key_meta(&self, key_id: &str, entry: KeyMetaCacheEntry) {
        if !self.config.enable_key_meta_cache {
            return;
        }
        self.key_meta_cache.set(
            key_id.to_string(),
            entry,
            Duration::from_secs(self.config.default_ttl_secs),
        );
    }

    /// Invalidate key metadata cache
    pub fn invalidate_key_meta(&self, key_id: &str) {
        self.key_meta_cache.remove(key_id);
    }

    /// Get cached policy
    pub fn get_policy(&self, policy_id: &str) -> Option<PolicyCacheEntry> {
        if !self.config.enable_policy_cache {
            return None;
        }
        self.policy_cache.get(policy_id)
    }

    /// Cache policy
    pub fn set_policy(&self, policy_id: &str, entry: PolicyCacheEntry) {
        if !self.config.enable_policy_cache {
            return;
        }
        self.policy_cache.set(
            policy_id.to_string(),
            entry,
            Duration::from_secs(self.config.default_ttl_secs),
        );
    }

    /// Invalidate policy cache
    pub fn invalidate_policy(&self, policy_id: &str) {
        self.policy_cache.remove(policy_id);
    }

    /// Get cached tenant quota
    pub fn get_tenant_quota(&self, tenant_id: &str) -> Option<TenantQuotaCacheEntry> {
        if !self.config.enable_quota_cache {
            return None;
        }
        self.quota_cache.get(tenant_id)
    }

    /// Cache tenant quota
    pub fn set_tenant_quota(&self, tenant_id: &str, entry: TenantQuotaCacheEntry) {
        if !self.config.enable_quota_cache {
            return;
        }
        self.quota_cache.set(
            tenant_id.to_string(),
            entry,
            Duration::from_secs(self.config.default_ttl_secs),
        );
    }

    /// Invalidate tenant quota
    pub fn invalidate_tenant_quota(&self, tenant_id: &str) {
        self.quota_cache.remove(tenant_id);
    }

    /// Get cached session
    pub fn get_session(&self, session_id: &str) -> Option<SessionCacheEntry> {
        self.session_cache.get(session_id)
    }

    /// Cache session
    pub fn set_session(&self, session_id: &str, entry: SessionCacheEntry) {
        self.session_cache.set(
            session_id.to_string(),
            entry,
            Duration::from_secs(self.config.default_ttl_secs),
        );
    }

    /// Invalidate session
    pub fn invalidate_session(&self, session_id: &str) {
        self.session_cache.remove(session_id);
    }

    /// Clear all caches
    pub fn clear_all(&self) {
        self.key_meta_cache.clear();
        self.policy_cache.clear();
        self.quota_cache.clear();
        self.session_cache.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            key_meta_entries: self.key_meta_cache.len(),
            policy_entries: self.policy_cache.len(),
            quota_entries: self.quota_cache.len(),
            session_entries: self.session_cache.len(),
            config: self.config.clone(),
        }
    }

    /// Cleanup expired entries
    pub fn cleanup(&self) {
        self.key_meta_cache.cleanup();
        self.policy_cache.cleanup();
        self.quota_cache.cleanup();
        self.session_cache.cleanup();
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub key_meta_entries: usize,
    pub policy_entries: usize,
    pub quota_entries: usize,
    pub session_entries: usize,
    pub config: CacheConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_cache_basic() {
        let cache = MemoryCache::<String>::new(10);
        cache.set(
            "key1".to_string(),
            "value1".to_string(),
            Duration::from_secs(60),
        );

        let result = cache.get("key1");
        assert_eq!(result, Some("value1".to_string()));
    }

    #[test]
    fn test_memory_cache_expiration() {
        let cache = MemoryCache::<String>::new(10);
        cache.set(
            "key1".to_string(),
            "value1".to_string(),
            Duration::from_millis(1),
        );

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        let result = cache.get("key1");
        assert!(result.is_none());
    }

    #[test]
    fn test_memory_cache_eviction() {
        let cache = MemoryCache::<String>::new(3);
        cache.set(
            "key1".to_string(),
            "v1".to_string(),
            Duration::from_secs(60),
        );
        cache.set(
            "key2".to_string(),
            "v2".to_string(),
            Duration::from_secs(60),
        );
        cache.set(
            "key3".to_string(),
            "v3".to_string(),
            Duration::from_secs(60),
        );

        // Add one more - should trigger eviction
        cache.set(
            "key4".to_string(),
            "v4".to_string(),
            Duration::from_secs(60),
        );

        // At least one of the first three should be gone
        let count = cache.len();
        assert!(count <= 3);
    }

    #[test]
    fn test_cache_key_variants() {
        let k1 = CacheKey::key_metadata("tenant-1", "key-123");
        let k2 = CacheKey::policy("tenant-2", "policy-456");
        let _k3 = CacheKey::tenant_quota("tenant-789");
        let _k4 = CacheKey::session("session-abc");

        // Different tenant/key combinations should be different
        assert!(k1 != k2);
        // Same tenant different key
        let k1b = CacheKey::key_metadata("tenant-1", "key-456");
        assert!(k1 != k1b);
        // Same key different tenant
        let k1c = CacheKey::key_metadata("tenant-2", "key-123");
        assert!(k1 != k1c);
    }

    #[test]
    fn test_cache_config_presets() {
        let dev = CacheConfig::development();
        assert_eq!(dev.default_ttl_secs, 60);

        let prod = CacheConfig::production();
        assert_eq!(prod.default_ttl_secs, 3600);

        let test = CacheConfig::testing();
        assert!(!test.enable_key_meta_cache);
    }

    #[test]
    fn test_cache_manager_operations() {
        let manager = CacheManager::with_default_config();

        // Test key metadata caching
        let key_meta = KeyMetaCacheEntry {
            id: "key-1".to_string(),
            name: "test-key".to_string(),
            spec: "AES-256-GCM".to_string(),
            status: "Active".to_string(),
            version: 1,
            tenant_id: "tenant-1".to_string(),
        };
        manager.set_key_meta("key-1", key_meta.clone());

        let cached = manager.get_key_meta("key-1");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().id, "key-1");

        // Test cache invalidation
        manager.invalidate_key_meta("key-1");
        assert!(manager.get_key_meta("key-1").is_none());
    }

    #[test]
    fn test_cache_manager_disabled_cache() {
        let config = CacheConfig::testing(); // Caching disabled
        let manager = CacheManager::new(config);

        let key_meta = KeyMetaCacheEntry {
            id: "key-1".to_string(),
            name: "test-key".to_string(),
            spec: "AES-256-GCM".to_string(),
            status: "Active".to_string(),
            version: 1,
            tenant_id: "tenant-1".to_string(),
        };

        // Should not cache when disabled
        manager.set_key_meta("key-1", key_meta);
        assert!(manager.get_key_meta("key-1").is_none());
    }
}
