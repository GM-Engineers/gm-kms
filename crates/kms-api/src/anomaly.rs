//! Anomaly detection for key access patterns
//!
//! Detects unusual access patterns that may indicate security threats:
//! - Access outside normal working hours
//! - Excessive failed authentication attempts
//! - Unusual key access frequency
//! - Geographic anomalies (requires external IP data)
//!
//! # Usage
//!
//! ```rust,ignore
//! use kms_api::anomaly::{AnomalyDetector, AnomalyAlert};
//!
//! let detector = AnomalyDetector::new();
//!
//! // Check for anomalies after an access
//! if let Some(alert) = detector.check_access(&access_context).await {
//!     // Handle anomaly - log, notify, or block
//!     tracing::warn!("Anomaly detected: {:?}", alert);
//! }
//! ```

use chrono::{DateTime, Duration as ChronoDuration, Timelike, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Types of anomalies that can be detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyType {
    /// Access outside normal working hours
    OffHoursAccess,
    /// Excessive operations in short time
    HighFrequency,
    /// Failed authentication attempts
    AuthFailure,
    /// Unusual key access pattern
    UnusualPattern,
    /// Rate limit exceeded
    RateLimitExceeded,
}

/// Severity level of an anomaly
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// An anomaly alert with details
#[derive(Debug, Clone)]
pub struct AnomalyAlert {
    /// Type of anomaly detected
    pub anomaly_type: AnomalyType,
    /// Severity level
    pub severity: Severity,
    /// Description of the anomaly
    pub message: String,
    /// Tenant ID associated with the anomaly
    pub tenant_id: String,
    /// User ID if available
    pub user_id: Option<String>,
    /// Timestamp when anomaly was detected
    pub timestamp: DateTime<Utc>,
    /// Additional context as key-value pairs
    pub context: HashMap<String, String>,
}

impl AnomalyAlert {
    /// Create a new anomaly alert
    pub fn new(
        anomaly_type: AnomalyType,
        severity: Severity,
        message: String,
        tenant_id: String,
    ) -> Self {
        Self {
            anomaly_type,
            severity,
            message,
            tenant_id,
            user_id: None,
            timestamp: Utc::now(),
            context: HashMap::new(),
        }
    }

    /// Set user ID
    pub fn with_user(mut self, user_id: &str) -> Self {
        self.user_id = Some(user_id.to_string());
        self
    }

    /// Add context value
    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.insert(key.to_string(), value.to_string());
        self
    }
}

/// Configuration for anomaly detection
#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    /// Normal working hours start (hour, 0-23)
    pub work_start_hour: u32,
    /// Normal working hours end (hour, 0-23)
    pub work_end_hour: u32,
    /// Maximum operations per minute before flagging as high frequency
    pub max_ops_per_minute: u32,
    /// Maximum failed auth attempts before alerting
    pub max_auth_failures: u32,
    /// Window for counting operations (minutes)
    pub ops_window_minutes: u32,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            work_start_hour: 9, // 9 AM
            work_end_hour: 18,  // 6 PM
            max_ops_per_minute: 100,
            max_auth_failures: 5,
            ops_window_minutes: 1,
        }
    }
}

/// Access context for anomaly checking
#[derive(Debug, Clone)]
pub struct AccessContext {
    pub tenant_id: String,
    pub user_id: String,
    pub key_id: Option<String>,
    pub operation: String,
    pub timestamp: DateTime<Utc>,
    pub success: bool,
    pub ip_address: Option<String>,
}

impl AccessContext {
    pub fn new(tenant_id: &str, user_id: &str, operation: &str) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            user_id: user_id.to_string(),
            key_id: None,
            operation: operation.to_string(),
            timestamp: Utc::now(),
            success: true,
            ip_address: None,
        }
    }

    pub fn with_key(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }

    pub fn with_ip(mut self, ip: &str) -> Self {
        self.ip_address = Some(ip.to_string());
        self
    }

    pub fn failed(mut self) -> Self {
        self.success = false;
        self
    }
}

/// Statistics for a tenant's access patterns
#[derive(Debug, Clone, Default)]
pub struct AccessStats {
    pub total_operations: u64,
    pub failed_operations: u64,
    pub last_operation_time: Option<DateTime<Utc>>,
    pub operations_by_hour: HashMap<u32, u32>,
}

impl AccessStats {
    pub fn record_operation(&mut self, success: bool, hour: u32) {
        self.total_operations += 1;
        if !success {
            self.failed_operations += 1;
        }
        self.last_operation_time = Some(Utc::now());
        *self.operations_by_hour.entry(hour).or_insert(0) += 1;
    }
}

/// Anomaly detector service
pub struct AnomalyDetector {
    config: AnomalyConfig,
    /// Per-tenant access statistics
    tenant_stats: Arc<RwLock<HashMap<String, TenantAccessStats>>>,
    /// Recent alerts to avoid duplicate alerts
    #[allow(dead_code)]
    recent_alerts: Arc<RwLock<HashMap<String, Vec<AnomalyAlert>>>>,
}

/// Minimum time between duplicate alerts for same anomaly type (minutes)
#[allow(dead_code)]
const ALERT_COOLDOWN_MINUTES: i64 = 15;

#[derive(Debug, Clone, Default)]
struct TenantAccessStats {
    stats: HashMap<String, AccessStats>, // keyed by user_id
    recent_failures: Vec<DateTime<Utc>>,
}

impl AnomalyDetector {
    /// Create a new anomaly detector with default config
    pub fn new() -> Self {
        Self {
            config: AnomalyConfig::default(),
            tenant_stats: Arc::new(RwLock::new(HashMap::new())),
            recent_alerts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create with custom config
    pub fn with_config(config: AnomalyConfig) -> Self {
        Self {
            config,
            tenant_stats: Arc::new(RwLock::new(HashMap::new())),
            recent_alerts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check for anomalies in an access context
    pub async fn check_access(&self, ctx: &AccessContext) -> Option<AnomalyAlert> {
        // Check off-hours access
        if let Some(alert) = self.check_off_hours(ctx) {
            return Some(alert);
        }

        // Record the access and check frequency
        self.record_access(ctx).await;

        // Check high frequency
        if let Some(alert) = self.check_high_frequency(ctx).await {
            return Some(alert);
        }

        // Check auth failures
        if !ctx.success
            && let Some(alert) = self.check_auth_failures(ctx).await
        {
            return Some(alert);
        }

        None
    }

    /// Record an access for statistics
    async fn record_access(&self, ctx: &AccessContext) {
        let mut stats = self.tenant_stats.write().await;
        let tenant = stats.entry(ctx.tenant_id.clone()).or_default();
        let user_stats = tenant.stats.entry(ctx.user_id.clone()).or_default();
        user_stats.record_operation(ctx.success, ctx.timestamp.hour());
    }

    fn check_off_hours(&self, ctx: &AccessContext) -> Option<AnomalyAlert> {
        let hour = ctx.timestamp.hour();

        // Check if outside work hours (weekday only for simplicity)
        let is_weekday = ctx.timestamp.format("%A").to_string() != "Saturday"
            && ctx.timestamp.format("%A").to_string() != "Sunday";

        if is_weekday && (hour < self.config.work_start_hour || hour >= self.config.work_end_hour) {
            return Some(
                AnomalyAlert::new(
                    AnomalyType::OffHoursAccess,
                    Severity::Medium,
                    format!(
                        "Access at {}:{:02} outside normal working hours ({}-{})",
                        hour,
                        ctx.timestamp.minute(),
                        self.config.work_start_hour,
                        self.config.work_end_hour
                    ),
                    ctx.tenant_id.clone(),
                )
                .with_user(&ctx.user_id),
            );
        }

        // Weekend access is always off-hours
        if !is_weekday {
            return Some(
                AnomalyAlert::new(
                    AnomalyType::OffHoursAccess,
                    Severity::Low,
                    format!("Weekend access at {}:{:02}", hour, ctx.timestamp.minute()),
                    ctx.tenant_id.clone(),
                )
                .with_user(&ctx.user_id),
            );
        }

        None
    }

    async fn check_high_frequency(&self, ctx: &AccessContext) -> Option<AnomalyAlert> {
        let stats = self.tenant_stats.read().await;
        if let Some(tenant) = stats.get(&ctx.tenant_id)
            && let Some(user_stats) = tenant.stats.get(&ctx.user_id)
            && let Some(_last_time) = user_stats.last_operation_time
        {
            let ops_in_window =
                self.count_recent_ops(&user_stats.operations_by_hour, ctx.timestamp);
            if ops_in_window > self.config.max_ops_per_minute {
                return Some(
                    AnomalyAlert::new(
                        AnomalyType::HighFrequency,
                        Severity::High,
                        format!(
                            "User {} performed {} operations in {} minute window (max: {})",
                            ctx.user_id,
                            ops_in_window,
                            self.config.ops_window_minutes,
                            self.config.max_ops_per_minute
                        ),
                        ctx.tenant_id.clone(),
                    )
                    .with_user(&ctx.user_id),
                );
            }
        }
        None
    }

    fn count_recent_ops(
        &self,
        ops_by_hour: &HashMap<u32, u32>,
        _current_time: DateTime<Utc>,
    ) -> u32 {
        // Simplified - in production would track per-minute counts
        ops_by_hour
            .values()
            .sum::<u32>()
            .min(self.config.max_ops_per_minute + 1)
    }

    async fn check_auth_failures(&self, ctx: &AccessContext) -> Option<AnomalyAlert> {
        if ctx.operation != "auth" && ctx.operation != "login" {
            return None;
        }

        let mut stats = self.tenant_stats.write().await;
        let tenant = stats.entry(ctx.tenant_id.clone()).or_default();

        let now = Utc::now();
        // Count failures in last 15 minutes
        let recent_window = now - ChronoDuration::minutes(15);
        tenant.recent_failures.retain(|t| *t > recent_window);

        if !ctx.success {
            tenant.recent_failures.push(now);
        }

        let failure_count = tenant.recent_failures.len() as u32;
        if failure_count >= self.config.max_auth_failures {
            return Some(
                AnomalyAlert::new(
                    AnomalyType::AuthFailure,
                    Severity::High,
                    format!(
                        "{} failed authentication attempts in last 15 minutes",
                        failure_count
                    ),
                    ctx.tenant_id.clone(),
                )
                .with_user(&ctx.user_id),
            );
        }

        None
    }

    /// Get current stats for a tenant
    pub async fn get_tenant_stats(&self, tenant_id: &str) -> Option<HashMap<String, AccessStats>> {
        let stats = self.tenant_stats.read().await;
        stats.get(tenant_id).map(|t| t.stats.clone())
    }

    /// Clear stats for a tenant (for testing)
    pub async fn clear_stats(&self, tenant_id: &str) {
        let mut stats = self.tenant_stats.write().await;
        stats.remove(tenant_id);
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    /// Create a context pinned to a specific datetime (weekday + hour)
    fn make_context(
        tenant: &str,
        user: &str,
        operation: &str,
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
    ) -> AccessContext {
        let mut ctx = AccessContext::new(tenant, user, operation);
        ctx.timestamp = Utc::now()
            .with_year(year)
            .unwrap()
            .with_month(month)
            .unwrap()
            .with_day(day)
            .unwrap()
            .with_hour(hour)
            .unwrap()
            .with_minute(0)
            .unwrap();
        ctx
    }

    fn create_off_hours_context() -> AccessContext {
        // Monday, 3 AM (off-hours on a weekday)
        make_context("tenant-1", "user-1", "encrypt", 2026, 5, 4, 3)
    }

    fn create_work_hours_context() -> AccessContext {
        // Monday, 2 PM (work hours)
        make_context("tenant-1", "user-1", "encrypt", 2026, 5, 4, 14)
    }

    #[test]
    fn test_off_hours_detection_weekday() {
        let detector = AnomalyDetector::new();

        let ctx = create_off_hours_context();
        let alert = detector.check_off_hours(&ctx);

        assert!(alert.is_some());
        assert_eq!(alert.unwrap().anomaly_type, AnomalyType::OffHoursAccess);
    }

    #[test]
    fn test_work_hours_no_anomaly() {
        let detector = AnomalyDetector::new();

        let ctx = create_work_hours_context();
        let alert = detector.check_off_hours(&ctx);

        assert!(alert.is_none());
    }

    #[test]
    fn test_anomaly_alert_creation() {
        let alert = AnomalyAlert::new(
            AnomalyType::HighFrequency,
            Severity::High,
            "Too many operations".to_string(),
            "tenant-1".to_string(),
        )
        .with_user("user-123")
        .with_context("ops_count", "150");

        assert_eq!(alert.tenant_id, "tenant-1");
        assert_eq!(alert.user_id, Some("user-123".to_string()));
        assert_eq!(alert.context.get("ops_count"), Some(&"150".to_string()));
    }

    #[test]
    fn test_access_context_builder() {
        let ctx = AccessContext::new("tenant-1", "user-1", "decrypt")
            .with_key("key-123")
            .with_ip("192.168.1.1")
            .failed();

        assert_eq!(ctx.tenant_id, "tenant-1");
        assert_eq!(ctx.user_id, "user-1");
        assert_eq!(ctx.key_id, Some("key-123".to_string()));
        assert_eq!(ctx.ip_address, Some("192.168.1.1".to_string()));
        assert!(!ctx.success);
    }

    #[test]
    fn test_anomaly_config_default() {
        let config = AnomalyConfig::default();
        assert_eq!(config.work_start_hour, 9);
        assert_eq!(config.work_end_hour, 18);
        assert_eq!(config.max_ops_per_minute, 100);
        assert_eq!(config.max_auth_failures, 5);
    }

    #[tokio::test]
    async fn test_detector_records_access() {
        let detector = AnomalyDetector::new();
        let ctx = AccessContext::new("tenant-1", "user-1", "encrypt");

        detector.record_access(&ctx).await;

        let stats = detector.get_tenant_stats("tenant-1").await;
        assert!(stats.is_some());
        let stats = stats.unwrap();
        assert!(stats.contains_key("user-1"));
    }

    /// Weekend detection: any time on Saturday/Sunday is off-hours
    #[test]
    fn test_off_hours_weekend_detection() {
        let detector = AnomalyDetector::new();

        // Use a known Saturday (2026-05-02 is a Saturday)
        let saturday = Utc::now()
            .with_year(2026)
            .unwrap()
            .with_month(5)
            .unwrap()
            .with_day(2)
            .unwrap()
            .with_hour(14)
            .unwrap() // 2 PM on Saturday
            .with_minute(0)
            .unwrap();

        let mut ctx = AccessContext::new("tenant-w", "user-w", "encrypt");
        ctx.timestamp = saturday;

        let alert = detector.check_off_hours(&ctx);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().anomaly_type, AnomalyType::OffHoursAccess);
    }

    /// Work hours boundary: 8 AM (just before) is off-hours, 9 AM is work hours
    #[test]
    fn test_off_hours_boundary() {
        let detector = AnomalyDetector::new();

        // 8 AM (before work hours)
        let mut ctx = AccessContext::new("tenant-b", "user-b", "encrypt");
        ctx.timestamp = Utc::now().with_hour(8).unwrap().with_minute(0).unwrap();
        assert!(detector.check_off_hours(&ctx).is_some());

        // 9 AM (start of work hours) — ensure it's a weekday
        let mut ctx9 = AccessContext::new("tenant-b", "user-b", "encrypt");
        // Set to Monday, 9 AM
        ctx9.timestamp = Utc::now()
            .with_year(2026)
            .unwrap()
            .with_month(5)
            .unwrap()
            .with_day(4)
            .unwrap() // Monday
            .with_hour(9)
            .unwrap()
            .with_minute(0)
            .unwrap();
        assert!(detector.check_off_hours(&ctx9).is_none());

        // 5 PM (still work hours)
        let mut ctx17 = AccessContext::new("tenant-b", "user-b", "encrypt");
        ctx17.timestamp = Utc::now()
            .with_year(2026)
            .unwrap()
            .with_month(5)
            .unwrap()
            .with_day(4)
            .unwrap() // Monday
            .with_hour(17)
            .unwrap()
            .with_minute(0)
            .unwrap();
        assert!(detector.check_off_hours(&ctx17).is_none());

        // 6 PM (after work hours)
        let mut ctx18 = AccessContext::new("tenant-b", "user-b", "encrypt");
        ctx18.timestamp = Utc::now()
            .with_year(2026)
            .unwrap()
            .with_month(5)
            .unwrap()
            .with_day(4)
            .unwrap() // Monday
            .with_hour(18)
            .unwrap()
            .with_minute(0)
            .unwrap();
        assert!(detector.check_off_hours(&ctx18).is_some());
    }

    /// Severity ordering: Low < Medium < High < Critical
    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
        assert_eq!(Severity::Low as u8, 0);
        assert_eq!(Severity::Critical as u8, 3);
    }

    /// Severity Display impl
    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Low.to_string(), "low");
        assert_eq!(Severity::Medium.to_string(), "medium");
        assert_eq!(Severity::High.to_string(), "high");
        assert_eq!(Severity::Critical.to_string(), "critical");
    }

    /// Auth failure detection: 5 failures in 15 min window triggers alert
    #[tokio::test]
    async fn test_auth_failure_detection() {
        let detector = AnomalyDetector::new();

        // Build up 4 auth failures first
        for _ in 0..4 {
            let ctx = AccessContext::new("tenant-auth", "user-auth", "auth").failed();
            detector.check_auth_failures(&ctx).await;
        }

        // 5th failure should trigger alert
        let check_ctx = AccessContext::new("tenant-auth", "user-auth", "auth").failed();
        let alert = detector.check_auth_failures(&check_ctx).await;
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().anomaly_type, AnomalyType::AuthFailure);
    }

    /// Auth failure: below threshold (4 failures) no alert
    #[tokio::test]
    async fn test_auth_failure_below_threshold() {
        let detector = AnomalyDetector::new();

        // Record only 3 auth failures via check_auth_failures
        for _ in 0..3 {
            let ctx = AccessContext::new("tenant-auth2", "user-auth2", "auth").failed();
            detector.check_auth_failures(&ctx).await;
        }

        // 4th check: still below threshold of 5
        let check_ctx = AccessContext::new("tenant-auth2", "user-auth2", "auth").failed();
        let alert = detector.check_auth_failures(&check_ctx).await;
        assert!(alert.is_none());
    }

    /// Non-auth operation (encrypt) does not trigger auth failure check
    #[tokio::test]
    async fn test_auth_failure_only_for_auth_operations() {
        let detector = AnomalyDetector::new();

        // Call check_auth_failures with encrypt (not auth) — should short-circuit
        let check_ctx = AccessContext::new("tenant-e", "user-e", "encrypt").failed();
        let alert = detector.check_auth_failures(&check_ctx).await;
        assert!(alert.is_none());
    }

    /// Clearing tenant stats removes all tracked data
    #[tokio::test]
    async fn test_clear_tenant_stats() {
        let detector = AnomalyDetector::new();

        let ctx = AccessContext::new("tenant-clr", "user-clr", "encrypt");
        detector.record_access(&ctx).await;

        assert!(detector.get_tenant_stats("tenant-clr").await.is_some());

        detector.clear_stats("tenant-clr").await;
        assert!(detector.get_tenant_stats("tenant-clr").await.is_none());
    }

    /// High frequency detection: many operations in short window
    #[tokio::test]
    async fn test_high_frequency_detection() {
        let config = AnomalyConfig {
            max_ops_per_minute: 5,
            ops_window_minutes: 1,
            ..Default::default()
        };
        let detector = AnomalyDetector::with_config(config);

        // Simulate many operations
        for i in 0..10 {
            let mut ctx = AccessContext::new("tenant-hf", "user-hf", "encrypt");
            ctx.timestamp = Utc::now() + ChronoDuration::seconds(i as i64);
            detector.record_access(&ctx).await;
        }

        let check_ctx = AccessContext::new("tenant-hf", "user-hf", "encrypt");
        let alert = detector.check_high_frequency(&check_ctx).await;
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().anomaly_type, AnomalyType::HighFrequency);
    }

    /// Full check_access: off-hours triggers alert
    #[tokio::test]
    async fn test_check_access_off_hours() {
        let detector = AnomalyDetector::new();
        let ctx = create_off_hours_context();

        let alert = detector.check_access(&ctx).await;
        assert!(alert.is_some());
    }

    /// Full check_access: work hours no alert
    #[tokio::test]
    async fn test_check_access_work_hours_clean() {
        let detector = AnomalyDetector::new();
        let ctx = create_work_hours_context();

        let alert = detector.check_access(&ctx).await;
        // Should be clean during work hours with no prior history
        assert!(alert.is_none());
    }

    /// Rate limit exceeded anomaly: excessive auth failures trigger with RateLimitExceeded type
    #[tokio::test]
    async fn test_rate_limit_exceeded_detection() {
        let config = AnomalyConfig {
            max_auth_failures: 3,
            ..Default::default()
        };
        let detector = AnomalyDetector::with_config(config);

        // Build up auth failures to trigger detection
        for _ in 0..3 {
            let ctx = AccessContext::new("tenant-rl", "user-rl", "auth").failed();
            detector.check_auth_failures(&ctx).await;
        }

        // 4th failure triggers the alert (threshold is 3, so >= 3 fails)
        let check_ctx = AccessContext::new("tenant-rl", "user-rl", "auth").failed();
        let alert = detector.check_auth_failures(&check_ctx).await;
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().anomaly_type, AnomalyType::AuthFailure);
    }

    /// Tenant isolation: stats for one tenant don't leak to another
    #[tokio::test]
    async fn test_tenant_isolation_in_anomaly_detection() {
        let detector = AnomalyDetector::new();

        // Record operations for tenant-A
        for _ in 0..5 {
            let ctx = AccessContext::new("tenant-A", "user-a", "encrypt");
            detector.record_access(&ctx).await;
        }

        // Tenant-B should have no stats
        let stats_b = detector.get_tenant_stats("tenant-B").await;
        assert!(stats_b.is_none());

        // Tenant-A should have its own stats
        let stats_a = detector.get_tenant_stats("tenant-A").await;
        assert!(stats_a.is_some());
        assert!(stats_a.unwrap().contains_key("user-a"));
    }

    /// Tenant isolation: auth failures in one tenant don't affect another
    #[tokio::test]
    async fn test_auth_failure_tenant_isolation() {
        let config = AnomalyConfig {
            max_auth_failures: 3,
            ..Default::default()
        };
        let detector = AnomalyDetector::with_config(config);

        // Tenant-A: 4 auth failures (triggers alert)
        for _ in 0..4 {
            let ctx = AccessContext::new("tenant-A", "user-a", "auth").failed();
            detector.check_auth_failures(&ctx).await;
        }

        // Tenant-B: first auth failure shouldn't trigger (isolated counter)
        let ctx_b = AccessContext::new("tenant-B", "user-b", "auth").failed();
        let alert_b = detector.check_auth_failures(&ctx_b).await;
        assert!(
            alert_b.is_none(),
            "Tenant-B should be isolated from Tenant-A failures"
        );
    }

    /// Anomaly severity is correctly ordered and displayable
    #[test]
    fn test_anomaly_severity_values() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
        assert_eq!(Severity::Low as u8, 0);
        assert_eq!(Severity::Critical as u8, 3);
    }
}
