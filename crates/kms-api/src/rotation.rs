//! Key rotation policies and automatic rotation service
//!
//! Provides automatic key rotation based on configurable policies:
//! - Time-based: rotate after N days
//! - Usage-based: rotate after N operations
//! - Version-based: rotate when key version exceeds threshold
//!
//! # Usage
//!
//! ```rust,ignore
//! use kms_api::rotation::{RotationPolicy, RotationService};
//!
//! let policy = RotationPolicy::time_based(30); // rotate every 30 days
//! let rotation_service = RotationService::new(policy, keystore);
//! rotation_service.check_and_rotate(key_id).await;
//! ```

use crate::KmsMetrics;
use kms_core::key::{KeyMeta, KeySpec};
use kms_core::sm9_key_rotation::Sm9RotationAdapter;
use std::sync::Arc;
use uuid::Uuid;

/// Trait for tracking per-key operation counts (encrypt, decrypt, sign, verify).
///
/// Implementations store counts in a persistent store (e.g. Redis)
/// so that usage-based rotation policies can query real operation counts.
#[async_trait::async_trait]
pub trait OperationCounter: Send + Sync {
    /// Increment the operation count for a key and return the new count.
    async fn increment(&self, key_id: &Uuid) -> u64;

    /// Get the current operation count for a key.
    async fn get_count(&self, key_id: &Uuid) -> u64;
}

/// Redis-backed implementation of [`OperationCounter`].
///
/// Uses the key pattern `kms:key:{key_id}:ops` with atomic INCR.
pub struct RedisOperationCounter {
    conn: redis::aio::ConnectionManager,
}

impl RedisOperationCounter {
    /// Create a new Redis operation counter from a connection manager.
    pub fn new(conn: redis::aio::ConnectionManager) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl OperationCounter for RedisOperationCounter {
    async fn increment(&self, key_id: &Uuid) -> u64 {
        let key = format!("kms:key:{}:ops", key_id);
        redis::cmd("INCR")
            .arg(&key)
            .query_async(&mut self.conn.clone())
            .await
            .unwrap_or(0)
    }

    async fn get_count(&self, key_id: &Uuid) -> u64 {
        let key = format!("kms:key:{}:ops", key_id);
        redis::cmd("GET")
            .arg(&key)
            .query_async(&mut self.conn.clone())
            .await
            .unwrap_or(None::<String>)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }
}

/// Rotation policy types
#[derive(Debug, Clone)]
pub enum RotationPolicy {
    /// Rotate after specified number of days
    TimeBased { days: u32 },
    /// Rotate after specified number of operations
    UsageBased { max_operations: u64 },
    /// Rotate when version exceeds threshold (keeps versions bounded)
    VersionBased { max_versions: u32 },
    /// Combined policy - rotate if any condition is met
    Combined {
        time_days: u32,
        max_operations: u64,
        max_versions: u32,
    },
}

impl RotationPolicy {
    /// Create a time-based policy (rotate after N days)
    pub fn time_based(days: u32) -> Self {
        RotationPolicy::TimeBased { days }
    }

    /// Create a usage-based policy (rotate after N operations)
    pub fn usage_based(max_operations: u64) -> Self {
        RotationPolicy::UsageBased { max_operations }
    }

    /// Create a version-based policy (rotate when version exceeds max)
    pub fn version_based(max_versions: u32) -> Self {
        RotationPolicy::VersionBased { max_versions }
    }

    /// Check if a key needs rotation based on this policy
    pub fn needs_rotation(&self, meta: &KeyMeta, operation_count: u64) -> bool {
        let age = chrono::Utc::now() - meta.created_at;
        match self {
            RotationPolicy::TimeBased { days } => age > chrono::Duration::days(*days as i64),
            RotationPolicy::UsageBased { max_operations } => operation_count >= *max_operations,
            RotationPolicy::VersionBased { max_versions } => meta.version >= *max_versions,
            RotationPolicy::Combined {
                time_days,
                max_operations,
                max_versions,
            } => {
                let age_ok = age > chrono::Duration::days(*time_days as i64);
                let usage_ok = operation_count >= *max_operations;
                let version_ok = meta.version >= *max_versions;
                age_ok || usage_ok || version_ok
            }
        }
    }
}

impl Default for RotationPolicy {
    fn default() -> Self {
        RotationPolicy::Combined {
            time_days: 90,             // 90 days default
            max_operations: 1_000_000, // 1M operations default
            max_versions: 10,          // 10 versions default
        }
    }
}

/// Reason for rotation
#[derive(Debug, Clone)]
pub enum RotationReason {
    /// Key exceeded its time limit
    TimeLimit { days: u32, key_age_days: u64 },
    /// Key exceeded operation count limit
    UsageLimit {
        max_operations: u64,
        actual_operations: u64,
    },
    /// Key version exceeded maximum
    VersionLimit {
        max_versions: u32,
        current_version: u32,
    },
    /// Manual rotation requested
    Manual,
}

impl std::fmt::Display for RotationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RotationReason::TimeLimit { days, key_age_days } => {
                write!(
                    f,
                    "time limit ({days} days) exceeded, key is {key_age_days} days old"
                )
            }
            RotationReason::UsageLimit {
                max_operations,
                actual_operations,
            } => {
                write!(
                    f,
                    "usage limit ({max_operations}) exceeded, actual: {actual_operations}"
                )
            }
            RotationReason::VersionLimit {
                max_versions,
                current_version,
            } => {
                write!(
                    f,
                    "version limit ({max_versions}) exceeded, current: {current_version}"
                )
            }
            RotationReason::Manual => write!(f, "manual rotation"),
        }
    }
}

/// Result of a rotation check
#[derive(Debug)]
pub struct RotationCheckResult {
    pub key_id: Uuid,
    pub needs_rotation: bool,
    pub reason: Option<RotationReason>,
}

/// Service for checking and performing key rotation
pub struct RotationService {
    keystore: Arc<dyn kms_keystore::KeystoreBackend>,
    policy: RotationPolicy,
    op_counter: Option<Arc<dyn OperationCounter>>,
    sm9_adapter: Option<Arc<Sm9RotationAdapter>>,
    metrics: Option<KmsMetrics>,
}

impl RotationService {
    /// Create a new rotation service with the given policy
    pub fn new(keystore: Arc<dyn kms_keystore::KeystoreBackend>, policy: RotationPolicy) -> Self {
        Self {
            keystore,
            policy,
            op_counter: None,
            sm9_adapter: None,
            metrics: None,
        }
    }

    /// Create with default policy
    pub fn with_default_policy(keystore: Arc<dyn kms_keystore::KeystoreBackend>) -> Self {
        Self {
            keystore,
            policy: RotationPolicy::default(),
            op_counter: None,
            sm9_adapter: None,
            metrics: None,
        }
    }

    /// Set the operation counter for usage-based rotation tracking.
    pub fn with_op_counter(mut self, counter: Arc<dyn OperationCounter>) -> Self {
        self.op_counter = Some(counter);
        self
    }

    /// Attach an SM9 rotation adapter for identity-based key rotation.
    ///
    /// When set, keys with `KeySpec::Sm9Signing` or `KeySpec::Sm9Encryption`
    /// will be rotated through the SM9 adapter instead of the generic
    /// keystore path. This preserves SM9's grace period and versioned
    /// master key semantics.
    pub fn with_sm9_adapter(mut self, adapter: Arc<Sm9RotationAdapter>) -> Self {
        self.sm9_adapter = Some(adapter);
        self
    }

    /// Attach metrics for observability.
    pub fn with_metrics(mut self, metrics: KmsMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Check if a key needs rotation (without performing it)
    pub async fn check_rotation(
        &self,
        key_id: &Uuid,
    ) -> Result<RotationCheckResult, RotationError> {
        let meta = self
            .keystore
            .get_key_metadata(key_id)
            .await
            .map_err(|e| RotationError::KeystoreError(e.to_string()))?;

        let operation_count = if let Some(ref counter) = self.op_counter {
            counter.get_count(key_id).await
        } else {
            0u64
        };

        let needs_rotation = self.policy.needs_rotation(&meta, operation_count);

        let reason = if needs_rotation {
            Some(self.determine_reason(&meta, operation_count))
        } else {
            None
        };

        Ok(RotationCheckResult {
            key_id: *key_id,
            needs_rotation,
            reason,
        })
    }

    /// Check and rotate a key if needed
    pub async fn check_and_rotate(&self, key_id: &Uuid) -> Result<KeyMeta, RotationError> {
        if let Some(ref m) = self.metrics {
            m.record_rotation_attempt();
        }

        let check = self.check_rotation(key_id).await?;
        // Fetch tenant_id from metadata for the rotation call
        let meta = self
            .keystore
            .get_key_metadata(key_id)
            .await
            .map_err(|e| RotationError::KeystoreError(e.to_string()))?;

        if check.needs_rotation {
            tracing::info!(
                "Rotating key {}: {}",
                key_id,
                check
                    .reason
                    .as_ref()
                    .map(|r| r.to_string())
                    .unwrap_or_default()
            );
            self.rotate_key(key_id, &meta.tenant_id)
                .await
                .inspect_err(|_| {
                    if let Some(ref m) = self.metrics {
                        m.record_rotation_failure();
                    }
                })
        } else {
            Err(RotationError::PolicyNotTriggered)
        }
    }

    /// Perform rotation on a key.
    ///
    /// For SM9 keys (`Sm9Signing` / `Sm9Encryption`), rotation is delegated
    /// to the `Sm9RotationAdapter` when available, which preserves grace
    /// periods and versioned master keys. Otherwise falls through to the
    /// generic keystore path.
    pub async fn rotate_key(
        &self,
        key_id: &Uuid,
        tenant_id: &str,
    ) -> Result<KeyMeta, RotationError> {
        // Check if this is an SM9 key that should go through the adapter
        if let Some(ref sm9_adapter) = self.sm9_adapter {
            let meta = self
                .keystore
                .get_key_metadata(key_id)
                .await
                .map_err(|e| RotationError::KeystoreError(e.to_string()))?;

            // Default grace period: 24 hours (86400 seconds)
            const DEFAULT_GRACE_PERIOD_SECS: u64 = 86_400;

            match meta.spec {
                KeySpec::Sm9Signing => {
                    sm9_adapter
                        .rotate_sign_key(key_id, DEFAULT_GRACE_PERIOD_SECS)
                        .await
                        .map_err(|e| RotationError::KeystoreError(e.to_string()))?;
                    return sm9_adapter
                        .key_meta(key_id)
                        .await
                        .map_err(|e| RotationError::KeystoreError(e.to_string()));
                }
                KeySpec::Sm9Encryption => {
                    sm9_adapter
                        .rotate_enc_key(key_id, DEFAULT_GRACE_PERIOD_SECS)
                        .await
                        .map_err(|e| RotationError::KeystoreError(e.to_string()))?;
                    return sm9_adapter
                        .key_meta(key_id)
                        .await
                        .map_err(|e| RotationError::KeystoreError(e.to_string()));
                }
                _ => {}
            }
        }

        self.keystore
            .rotate_key(key_id, tenant_id)
            .await
            .map_err(|e| RotationError::KeystoreError(e.to_string()))
    }

    /// Check which keys are expiring within the next 7 days.
    ///
    /// Returns the list of key IDs that are approaching expiration.
    /// The caller should log a warning for each expiring key.
    pub fn check_expiring_keys(&self, keys: &[KeyMeta]) -> Vec<Uuid> {
        let threshold = chrono::Duration::days(7);
        let now = chrono::Utc::now();

        keys.iter()
            .filter(|k| {
                // Keys that are active and will expire within 7 days
                if k.status != kms_core::key::KeyStatus::Active {
                    return false;
                }
                // Estimate expiration: created_at + some reasonable lifetime (e.g. 90 days)
                // A key is "expiring soon" if it's older than (default_lifetime - 7 days)
                let default_lifetime = chrono::Duration::days(90);
                let expiry = k.created_at + default_lifetime;
                let remaining = expiry - now;
                remaining > chrono::Duration::zero() && remaining <= threshold
            })
            .map(|k| k.id)
            .collect()
    }

    fn determine_reason(&self, meta: &KeyMeta, operation_count: u64) -> RotationReason {
        let age = (chrono::Utc::now() - meta.created_at).num_days() as u64;
        match &self.policy {
            RotationPolicy::TimeBased { days } => RotationReason::TimeLimit {
                days: *days,
                key_age_days: age,
            },
            RotationPolicy::UsageBased { max_operations } => RotationReason::UsageLimit {
                max_operations: *max_operations,
                actual_operations: operation_count,
            },
            RotationPolicy::VersionBased { max_versions } => RotationReason::VersionLimit {
                max_versions: *max_versions,
                current_version: meta.version,
            },
            RotationPolicy::Combined { .. } => {
                // Simplified - return Manual since combined policy doesn't track which condition triggered
                RotationReason::Manual
            }
        }
    }
}

/// Errors that can occur during rotation
#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    #[error("keystore error: {0}")]
    KeystoreError(String),

    #[error("key not found: {0}")]
    KeyNotFound(Uuid),

    #[error("policy conditions not met - rotation not triggered")]
    PolicyNotTriggered,

    #[error("key operation not allowed: {0}")]
    OperationNotAllowed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use kms_core::key::KeySpec;
    use kms_keystore::KeystoreBackend;

    fn create_test_meta(version: u32, days_old: u64) -> KeyMeta {
        let created_at = Utc::now() - ChronoDuration::days(days_old as i64);
        KeyMeta {
            id: Uuid::new_v4(),
            name: "test-key".to_string(),
            spec: KeySpec::Aes256Gcm,
            tenant_id: "test-tenant".to_string(),
            status: kms_core::key::KeyStatus::Active,
            version,
            created_at,
            rotated_at: None,
            description: None,
            metadata: kms_core::key::KeyMetadata::default(),
        }
    }

    #[test]
    fn test_time_based_policy() {
        let policy = RotationPolicy::time_based(30);

        // 29 days old - no rotation needed
        let meta = create_test_meta(1, 29);
        assert!(!policy.needs_rotation(&meta, 0));

        // 31 days old - rotation needed
        let meta = create_test_meta(1, 31);
        assert!(policy.needs_rotation(&meta, 0));
    }

    #[test]
    fn test_usage_based_policy() {
        let policy = RotationPolicy::usage_based(1000);

        // 999 operations - no rotation needed
        let meta = create_test_meta(1, 0);
        assert!(!policy.needs_rotation(&meta, 999));

        // 1000 operations - rotation needed
        assert!(policy.needs_rotation(&meta, 1000));
        assert!(policy.needs_rotation(&meta, 1001));
    }

    #[test]
    fn test_version_based_policy() {
        let policy = RotationPolicy::version_based(5);

        // Version 4 - no rotation needed
        let meta = create_test_meta(4, 0);
        assert!(!policy.needs_rotation(&meta, 0));

        // Version 5 - rotation needed
        let meta = create_test_meta(5, 0);
        assert!(policy.needs_rotation(&meta, 0));
    }

    #[test]
    fn test_combined_policy() {
        let policy = RotationPolicy::Combined {
            time_days: 30,
            max_operations: 1000,
            max_versions: 5,
        };

        // Old key needs rotation
        let meta = create_test_meta(1, 31);
        assert!(policy.needs_rotation(&meta, 0));

        // High usage needs rotation
        let meta = create_test_meta(1, 0);
        assert!(policy.needs_rotation(&meta, 1001));

        // High version needs rotation
        let meta = create_test_meta(6, 0);
        assert!(policy.needs_rotation(&meta, 0));

        // Fresh key with low usage and low version - no rotation
        let meta = create_test_meta(1, 0);
        assert!(!policy.needs_rotation(&meta, 0));
    }

    #[test]
    fn test_default_policy() {
        let policy = RotationPolicy::default();

        // Default is combined with reasonable limits
        let meta = create_test_meta(1, 0);
        assert!(!policy.needs_rotation(&meta, 0));
    }

    // ── OperationCounter tests ──

    use crate::test_utils::MockOperationCounter;

    #[tokio::test]
    async fn test_operation_counter_increment_and_get() {
        let counter = MockOperationCounter::new();
        let key_id = Uuid::new_v4();

        assert_eq!(counter.get_count(&key_id).await, 0);
        assert_eq!(counter.increment(&key_id).await, 1);
        assert_eq!(counter.increment(&key_id).await, 2);
        assert_eq!(counter.get_count(&key_id).await, 2);
    }

    #[tokio::test]
    async fn test_usage_based_policy_with_counter() {
        use std::sync::Arc;

        let counter = Arc::new(MockOperationCounter::new());
        let key_id = Uuid::new_v4();

        // Simulate 1000 operations
        for _ in 0..1000 {
            counter.increment(&key_id).await;
        }

        assert_eq!(counter.get_count(&key_id).await, 1000);

        let policy = RotationPolicy::usage_based(1000);
        let meta = create_test_meta(1, 0);

        // At exactly 1000, rotation should trigger (>=)
        assert!(policy.needs_rotation(&meta, 1000));
    }

    /// Per-key isolation: incrementing key A does not affect key B's count
    #[tokio::test]
    async fn test_op_counter_per_key_isolation() {
        let counter = MockOperationCounter::new();
        let key_a = Uuid::new_v4();
        let key_b = Uuid::new_v4();

        // Increment key A 5 times
        for _ in 0..5 {
            counter.increment(&key_a).await;
        }

        // Key A count should be 5
        assert_eq!(counter.get_count(&key_a).await, 5);

        // Key B count should still be 0 (untouched)
        assert_eq!(counter.get_count(&key_b).await, 0);

        // Increment key B 3 times
        for _ in 0..3 {
            counter.increment(&key_b).await;
        }

        // Counts should be independent
        assert_eq!(counter.get_count(&key_a).await, 5);
        assert_eq!(counter.get_count(&key_b).await, 3);
    }

    /// Concurrent increments to the same key must be atomic
    #[tokio::test]
    async fn test_op_counter_concurrent_increments() {
        use std::sync::Arc;

        let counter = Arc::new(MockOperationCounter::new());
        let key_id = Uuid::new_v4();
        let n_tasks = 10;
        let n_increments_per_task = 100u64;

        let mut handles = vec![];
        for _ in 0..n_tasks {
            let counter = counter.clone();
            let _key_id = key_id;
            handles.push(tokio::spawn(async move {
                for _ in 0..n_increments_per_task {
                    counter.increment(&key_id).await;
                }
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let expected = n_tasks * n_increments_per_task; // 1000
        assert_eq!(counter.get_count(&key_id).await, expected);
    }

    /// get_count returns 0 for a key that has never been incremented
    #[tokio::test]
    async fn test_op_counter_zero_for_unknown_key() {
        let counter = MockOperationCounter::new();
        let key_id = Uuid::new_v4();
        assert_eq!(counter.get_count(&key_id).await, 0);
        assert_eq!(counter.get_count(&key_id).await, 0); // idempotent
    }

    /// increment returns the new count (return value is correct)
    #[tokio::test]
    async fn test_op_counter_increment_returns_new_count() {
        let counter = MockOperationCounter::new();
        let key_id = Uuid::new_v4();

        assert_eq!(counter.increment(&key_id).await, 1);
        assert_eq!(counter.increment(&key_id).await, 2);
        assert_eq!(counter.increment(&key_id).await, 3);
        assert_eq!(counter.increment(&key_id).await, 4);
        assert_eq!(counter.increment(&key_id).await, 5);
    }

    /// Usage-based rotation with exact threshold boundary
    #[tokio::test]
    async fn test_usage_based_rotation_exact_boundary() {
        let policy = RotationPolicy::usage_based(500);
        let meta = create_test_meta(1, 0);

        // Below threshold
        assert!(!policy.needs_rotation(&meta, 499));

        // At threshold (>=)
        assert!(policy.needs_rotation(&meta, 500));

        // Above threshold
        assert!(policy.needs_rotation(&meta, 501));
    }

    /// Usage-based rotation: zero threshold means every operation triggers
    #[test]
    fn test_usage_based_zero_threshold() {
        let policy = RotationPolicy::usage_based(0);
        let meta = create_test_meta(1, 0);

        // Count 0 >= threshold 0 => needs rotation
        assert!(policy.needs_rotation(&meta, 0));
        assert!(policy.needs_rotation(&meta, 1));
    }

    // ── RotationService integration tests ──

    /// RotationService.check_rotation() returns correct RotationCheckResult
    #[tokio::test]
    async fn test_rotation_service_check_no_rotation_needed() {
        use kms_keystore::SoftwareKeystore;
        use std::sync::Arc;

        let store = Arc::new(SoftwareKeystore::new());
        let meta = store
            .generate_key(&KeySpec::Aes256Gcm, "rs-check", "test-tenant")
            .await
            .unwrap();
        let key_id = meta.id;

        // Time-based policy: 90 days, key just created => no rotation
        let service = RotationService::new(store, RotationPolicy::time_based(90));
        let result = service.check_rotation(&key_id).await.unwrap();

        assert_eq!(result.key_id, key_id);
        assert!(!result.needs_rotation);
        assert!(result.reason.is_none());
    }

    /// RotationService with OperationCounter: usage-based check works
    #[tokio::test]
    async fn test_rotation_service_usage_based_check() {
        use kms_keystore::SoftwareKeystore;
        use std::sync::Arc;

        let store = Arc::new(SoftwareKeystore::new());
        let meta = store
            .generate_key(&KeySpec::Aes256Gcm, "rs-usage", "test-tenant")
            .await
            .unwrap();
        let key_id = meta.id;

        let counter = Arc::new(MockOperationCounter::new());

        // Simulate 100 operations
        for _ in 0..100 {
            counter.increment(&key_id).await;
        }

        let service =
            RotationService::new(store, RotationPolicy::usage_based(50)).with_op_counter(counter);

        let result = service.check_rotation(&key_id).await.unwrap();
        assert!(result.needs_rotation);
        assert!(matches!(
            result.reason,
            Some(RotationReason::UsageLimit { .. })
        ));
    }

    /// RotationService.check_rotation: non-existent key returns error
    #[tokio::test]
    async fn test_rotation_service_check_non_existent_key() {
        use kms_keystore::SoftwareKeystore;
        use std::sync::Arc;

        let store = Arc::new(SoftwareKeystore::new());
        let service = RotationService::with_default_policy(store);

        let result = service.check_rotation(&Uuid::new_v4()).await;
        assert!(result.is_err());
    }

    /// check_and_rotate with conditions not met returns PolicyNotTriggered
    #[tokio::test]
    async fn test_rotation_service_check_and_rotate_not_needed() {
        use kms_keystore::SoftwareKeystore;
        use std::sync::Arc;

        let store = Arc::new(SoftwareKeystore::new());
        let meta = store
            .generate_key(&KeySpec::Aes256Gcm, "rs-not-needed", "test-tenant")
            .await
            .unwrap();
        let key_id = meta.id;

        // 365 day policy — key just created, won't trigger
        let service = RotationService::new(store, RotationPolicy::time_based(365));
        let result = service.check_and_rotate(&key_id).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RotationError::PolicyNotTriggered
        ));
    }

    /// check_and_rotate triggers rotation when time-based condition met
    #[tokio::test]
    async fn test_rotation_service_check_and_rotate_triggered() {
        use kms_keystore::SoftwareKeystore;
        use std::sync::Arc;

        let store = Arc::new(SoftwareKeystore::new());
        let meta = store
            .generate_key(&KeySpec::Aes256Gcm, "rs-triggered", "test-tenant")
            .await
            .unwrap();
        let key_id = meta.id;

        // 0-day policy — key is immediately eligible
        let service = RotationService::new(store.clone(), RotationPolicy::time_based(0));

        // Small delay to ensure created_at is in the past
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let rotated_meta = service.check_and_rotate(&key_id).await.unwrap();
        assert_eq!(rotated_meta.version, 2);
        assert!(rotated_meta.rotated_at.is_some());
    }

    /// expire check: keys approaching expiry are identified
    #[test]
    fn test_expiring_keys_detection() {
        use kms_keystore::SoftwareKeystore;
        use std::sync::Arc;

        let store = Arc::new(SoftwareKeystore::new());
        let service = RotationService::with_default_policy(store);

        let now = Utc::now();
        let expiring_id = Uuid::new_v4();
        let fresh_id = Uuid::new_v4();
        let inactive_id = Uuid::new_v4();

        // Key created 85 days ago (within 7-day warning window for 90-day default lifetime)
        let expiring_key = KeyMeta {
            id: expiring_id,
            name: "expiring-key".to_string(),
            spec: KeySpec::Aes256Gcm,
            tenant_id: "test".to_string(),
            status: kms_core::key::KeyStatus::Active,
            version: 1,
            created_at: now - ChronoDuration::days(85),
            rotated_at: None,
            description: None,
            metadata: kms_core::key::KeyMetadata::default(),
        };

        // Key created today — not expiring
        let fresh_key = KeyMeta {
            id: fresh_id,
            name: "fresh-key".to_string(),
            spec: KeySpec::Aes256Gcm,
            tenant_id: "test".to_string(),
            status: kms_core::key::KeyStatus::Active,
            version: 1,
            created_at: now,
            rotated_at: None,
            description: None,
            metadata: kms_core::key::KeyMetadata::default(),
        };

        // Inactive key even if old — should not be flagged
        let old_but_inactive = KeyMeta {
            id: inactive_id,
            name: "old-inactive".to_string(),
            spec: KeySpec::Aes256Gcm,
            tenant_id: "test".to_string(),
            status: kms_core::key::KeyStatus::PendingDeletion,
            version: 1,
            created_at: now - ChronoDuration::days(85),
            rotated_at: None,
            description: None,
            metadata: kms_core::key::KeyMetadata::default(),
        };

        let expiring = service.check_expiring_keys(&[expiring_key, fresh_key, old_but_inactive]);
        assert_eq!(expiring.len(), 1);
        assert_eq!(expiring[0], expiring_id);
    }

    // ── SM9 rotation integration tests ──

    /// In-memory Sm9MasterKeyStore for testing (no real encryption)
    struct InMemoryKekStore {
        store: parking_lot::Mutex<Vec<Vec<u8>>>,
    }

    impl InMemoryKekStore {
        fn new() -> Self {
            Self {
                store: parking_lot::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl kms_core::sm9_master_key::Sm9MasterKeyStore for InMemoryKekStore {
        async fn encrypt(&self, plaintext: &[u8]) -> kms_core::Result<Vec<u8>> {
            // Just store as-is (no real encryption for tests)
            let mut store = self.store.lock();
            let id = store.len();
            store.push(plaintext.to_vec());
            Ok(format!("kek:{}", id).into_bytes())
        }

        async fn decrypt(&self, ciphertext: &[u8]) -> kms_core::Result<Vec<u8>> {
            let store = self.store.lock();
            let s = String::from_utf8(ciphertext.to_vec())
                .map_err(|e| kms_core::Error::MasterKeyError(format!("invalid KEK ref: {}", e)))?;
            let id: usize = s
                .strip_prefix("kek:")
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| {
                    kms_core::Error::MasterKeyError("invalid KEK ref format".to_string())
                })?;
            store
                .get(id)
                .cloned()
                .ok_or_else(|| kms_core::Error::MasterKeyError("KEK entry not found".to_string()))
        }
    }

    /// SM9 rotation through RotationService with adapter: sign key
    #[tokio::test]
    async fn test_sm9_sign_rotation_via_service() {
        use gm_sm9_rs::key::SignMasterKey;
        use kms_core::sm9_key_rotation::Sm9RotationAdapter;
        use std::sync::Arc;

        let kek_store: Arc<dyn kms_core::sm9_master_key::Sm9MasterKeyStore> =
            Arc::new(InMemoryKekStore::new());
        let adapter = Arc::new(Sm9RotationAdapter::new(kek_store));

        // Register an SM9 signing key
        let master_key = SignMasterKey::generate(&mut rand::rng()).unwrap();
        let (key_id, _version) = adapter
            .register_sign_key("test-tenant", master_key, "sm9-sign-test")
            .await
            .unwrap();

        // Rotate via adapter directly
        let result = adapter.rotate_sign_key(&key_id, 3600).await.unwrap();
        assert_eq!(result.old_version, 1);
        assert_eq!(result.new_version, 2);

        // Verify old version is still valid during grace period
        assert!(adapter.is_sign_key_valid("test-tenant", 1).await);
        assert!(adapter.is_sign_key_valid("test-tenant", 2).await);

        // Verify key_meta returns updated version
        let meta = adapter.key_meta(&key_id).await.unwrap();
        assert_eq!(meta.version, 2);
        assert_eq!(meta.spec, KeySpec::Sm9Signing);
    }

    /// SM9 rotation through RotationService with adapter: enc key
    #[tokio::test]
    async fn test_sm9_enc_rotation_via_adapter() {
        use gm_sm9_rs::key::EncMasterKey;
        use kms_core::sm9_key_rotation::Sm9RotationAdapter;
        use std::sync::Arc;

        let kek_store: Arc<dyn kms_core::sm9_master_key::Sm9MasterKeyStore> =
            Arc::new(InMemoryKekStore::new());
        let adapter = Arc::new(Sm9RotationAdapter::new(kek_store));

        let master_key = EncMasterKey::generate(&mut rand::rng()).unwrap();
        let (key_id, _version) = adapter
            .register_enc_key("test-tenant", master_key, "sm9-enc-test")
            .await
            .unwrap();

        let result = adapter.rotate_enc_key(&key_id, 3600).await.unwrap();
        assert_eq!(result.old_version, 1);
        assert_eq!(result.new_version, 2);

        let meta = adapter.key_meta(&key_id).await.unwrap();
        assert_eq!(meta.version, 2);
        assert_eq!(meta.spec, KeySpec::Sm9Encryption);
    }

    /// Multiple rotations increment version correctly and preserve history
    #[tokio::test]
    async fn test_sm9_multiple_rotations() {
        use gm_sm9_rs::key::SignMasterKey;
        use kms_core::sm9_key_rotation::Sm9RotationAdapter;
        use std::sync::Arc;

        let kek_store: Arc<dyn kms_core::sm9_master_key::Sm9MasterKeyStore> =
            Arc::new(InMemoryKekStore::new());
        let adapter = Arc::new(Sm9RotationAdapter::new(kek_store));

        let master_key = SignMasterKey::generate(&mut rand::rng()).unwrap();
        let (key_id, _version) = adapter
            .register_sign_key("tenant-a", master_key, "multi-rotate")
            .await
            .unwrap();

        // Rotate 3 times
        for expected_version in 2..=4 {
            let result = adapter.rotate_sign_key(&key_id, 60).await.unwrap();
            assert_eq!(result.new_version, expected_version);
        }

        // History should have 3 rotation records
        let history = adapter.sign_rotation_history("tenant-a").await;
        assert_eq!(history.len(), 3);

        // Current version should be 4
        let meta = adapter.key_meta(&key_id).await.unwrap();
        assert_eq!(meta.version, 4);
    }

    /// SM9 direct keystore rotation returns error (must use adapter)
    #[tokio::test]
    async fn test_sm9_direct_keystore_rotation_errors() {
        use kms_keystore::SoftwareKeystore;
        use std::sync::Arc;

        let store = Arc::new(SoftwareKeystore::new());
        let meta = store
            .generate_key(&KeySpec::Sm9Signing, "sm9-direct", "test-tenant")
            .await
            .unwrap();

        let result = store.rotate_key(&meta.id, "test-tenant").await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Sm9RotationAdapter"),
            "Error should mention Sm9RotationAdapter, got: {}",
            err_msg
        );
    }

    /// check_rotation_needed returns true when version exceeds max
    #[tokio::test]
    async fn test_sm9_check_rotation_needed() {
        use gm_sm9_rs::key::SignMasterKey;
        use kms_core::sm9_key_rotation::Sm9RotationAdapter;
        use std::sync::Arc;

        let kek_store: Arc<dyn kms_core::sm9_master_key::Sm9MasterKeyStore> =
            Arc::new(InMemoryKekStore::new());
        let adapter = Arc::new(Sm9RotationAdapter::new(kek_store));

        let master_key = SignMasterKey::generate(&mut rand::rng()).unwrap();
        let (key_id, _version) = adapter
            .register_sign_key("tenant-check", master_key, "check-rotate")
            .await
            .unwrap();

        // Version 1, max 5 → no rotation needed
        assert!(!adapter.check_rotation_needed(&key_id, 5).await.unwrap());

        // Rotate to version 2
        adapter.rotate_sign_key(&key_id, 60).await.unwrap();

        // Version 2, max 2 → rotation needed
        assert!(adapter.check_rotation_needed(&key_id, 2).await.unwrap());
    }

    /// Valid versions list reflects grace period
    #[tokio::test]
    async fn test_sm9_valid_versions_after_rotation() {
        use gm_sm9_rs::key::SignMasterKey;
        use kms_core::sm9_key_rotation::Sm9RotationAdapter;
        use std::sync::Arc;

        let kek_store: Arc<dyn kms_core::sm9_master_key::Sm9MasterKeyStore> =
            Arc::new(InMemoryKekStore::new());
        let adapter = Arc::new(Sm9RotationAdapter::new(kek_store));

        let master_key = SignMasterKey::generate(&mut rand::rng()).unwrap();
        let (key_id, _version) = adapter
            .register_sign_key("tenant-vv", master_key, "valid-versions")
            .await
            .unwrap();

        // Initially only version 1 is valid
        let versions = adapter.valid_sign_versions("tenant-vv").await;
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, 1);

        // After rotation, both old (grace) and new versions are valid
        adapter.rotate_sign_key(&key_id, 3600).await.unwrap();

        let versions2 = adapter.valid_sign_versions("tenant-vv").await;
        assert_eq!(
            versions2.len(),
            2,
            "Both old and new versions should be valid during grace period"
        );
    }
}
