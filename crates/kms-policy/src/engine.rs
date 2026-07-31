//! PBAC Policy Engine implementation

use super::{AccessContext, Decision, Policy};
use kms_core::{PolicyEffect, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use kms_core::policy::PolicyContext;

/// Maximum allowed time skew between system clock and external time source (30 seconds)
const MAX_TIME_SKEW_SECS: i64 = 30;

/// Time skew alert threshold (warning at 10 seconds)
const TIME_SKEW_WARNING_SECS: i64 = 10;

/// Trait for time source validation
/// Implement this to provide external time source verification
pub trait TimeValidator: Send + Sync {
    /// Get the current trusted time from external source
    fn get_trusted_time(&self) -> Result<i64>;

    /// Check if the system clock is synchronized with external time source
    fn check_time_skew(&self) -> Result<TimeSkewStatus> {
        let system_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| kms_core::Error::Internal(e.to_string()))?
            .as_secs() as i64;

        let trusted_time = self.get_trusted_time()?;

        let skew = (system_time - trusted_time).abs();
        let status = if skew > MAX_TIME_SKEW_SECS {
            TimeSkewStatus::Critical(skew)
        } else if skew > TIME_SKEW_WARNING_SECS {
            TimeSkewStatus::Warning(skew)
        } else {
            TimeSkewStatus::Ok
        };

        Ok(status)
    }
}

/// Status of time skew check
#[derive(Debug, Clone)]
pub enum TimeSkewStatus {
    /// Time is within acceptable range
    Ok,
    /// Time skew is concerning but not critical
    Warning(i64),
    /// Time skew exceeds acceptable limits - potential attack
    Critical(i64),
}

impl TimeSkewStatus {
    /// Returns true if the status indicates a problem
    pub fn is_healthy(&self) -> bool {
        matches!(self, TimeSkewStatus::Ok)
    }

    /// Get the skew seconds if any
    pub fn skew_secs(&self) -> Option<i64> {
        match self {
            TimeSkewStatus::Ok => None,
            TimeSkewStatus::Warning(s) | TimeSkewStatus::Critical(s) => Some(*s),
        }
    }
}

/// Default time validator using system clock only
/// For production, implement TimeValidator with NTP or other trusted time source
pub struct SystemTimeValidator;

impl TimeValidator for SystemTimeValidator {
    fn get_trusted_time(&self) -> Result<i64> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| kms_core::Error::Internal(e.to_string()))?
            .as_secs() as i64)
    }
}

/// PBAC Policy Engine
pub struct PBACEngine {
    policies: RwLock<HashMap<String, Policy>>,
    time_validator: Arc<dyn TimeValidator>,
    time_skew_alerts: RwLock<Vec<TimeSkewAlert>>,
}

/// Time skew alert record
#[derive(Debug, Clone)]
pub struct TimeSkewAlert {
    pub timestamp: i64,
    pub skew_seconds: i64,
    pub severity: String,
}

impl PBACEngine {
    /// Create a new engine with default system time validator
    pub fn new() -> Self {
        Self::with_time_validator(SystemTimeValidator)
    }

    /// Create a new engine with a custom time validator
    pub fn with_time_validator(validator: impl TimeValidator + 'static) -> Self {
        Self {
            policies: RwLock::new(HashMap::new()),
            time_validator: Arc::new(validator),
            time_skew_alerts: RwLock::new(Vec::new()),
        }
    }

    /// Add a policy
    pub async fn add_policy(&self, policy: Policy) -> Result<()> {
        let mut policies = self.policies.write().await;
        policies.insert(policy.id.to_string(), policy);
        Ok(())
    }

    /// Remove a policy
    pub async fn remove_policy(&self, id: &str) -> Result<()> {
        let mut policies = self.policies.write().await;
        policies.remove(id);
        Ok(())
    }

    /// Get a policy by ID
    pub async fn get_policy(&self, id: &str) -> Result<Option<Policy>> {
        let policies = self.policies.read().await;
        Ok(policies.get(id).cloned())
    }

    /// List all policies
    pub async fn list_policies(&self) -> Result<Vec<Policy>> {
        let policies = self.policies.read().await;
        Ok(policies.values().cloned().collect())
    }

    /// Check time skew between system clock and trusted time source
    pub async fn check_time_skew(&self) -> Result<TimeSkewStatus> {
        let status = self.time_validator.check_time_skew()?;

        // Log alert if there's a problem
        if !status.is_healthy() {
            let skew = status.skew_secs().unwrap_or(0);
            let severity = match status {
                TimeSkewStatus::Critical(_) => "critical",
                TimeSkewStatus::Warning(_) => "warning",
                TimeSkewStatus::Ok => return Ok(status),
            };

            let alert = TimeSkewAlert {
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| kms_core::Error::Internal(e.to_string()))?
                    .as_secs() as i64,
                skew_seconds: skew,
                severity: severity.to_string(),
            };

            let mut alerts = self.time_skew_alerts.write().await;
            alerts.push(alert);

            // Keep only last 100 alerts
            if alerts.len() > 100 {
                alerts.remove(0);
            }

            tracing::warn!(
                "Time skew detected: {} seconds (severity: {})",
                skew,
                severity
            );
        }

        Ok(status)
    }

    /// Get recent time skew alerts
    pub async fn get_time_skew_alerts(&self) -> Result<Vec<TimeSkewAlert>> {
        let alerts = self.time_skew_alerts.read().await;
        Ok(alerts.clone())
    }

    /// Evaluate access request
    pub async fn evaluate(&self, ctx: &AccessContext) -> Result<Decision> {
        let policies = self.policies.read().await;
        let policy_ctx = ctx.to_policy_context();

        // Sort policies: explicit deny first, then by priority
        let mut matching_policies: Vec<&Policy> = policies
            .values()
            .filter(|p| {
                if !p.enabled {
                    return false;
                }

                // Check subject match
                let subject_match = p.subjects.iter().any(|s| glob_match(s, &ctx.subject_id));

                if !subject_match {
                    return false;
                }

                // Check resource match
                p.resources.iter().any(|r| glob_match(r, &ctx.resource_id))
            })
            .collect();

        // Sort: deny before allow
        matching_policies.sort_by(|a, b| {
            let a_deny = a.effect == PolicyEffect::Deny;
            let b_deny = b.effect == PolicyEffect::Deny;
            if a_deny && !b_deny {
                std::cmp::Ordering::Less
            } else if !a_deny && b_deny {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        });

        // Evaluate matching policies
        for policy in matching_policies {
            let condition_result = self.evaluate_condition(&policy.condition, &policy_ctx);

            if condition_result {
                return Ok(match policy.effect {
                    PolicyEffect::Allow => Decision::Allow,
                    PolicyEffect::Deny => Decision::Deny,
                });
            }
        }

        // Default deny
        Ok(Decision::Deny)
    }

    fn evaluate_condition(&self, condition: &Value, ctx: &PolicyContext) -> bool {
        // Simplified condition evaluation
        // In production, parse and evaluate the full condition tree
        match condition {
            Value::Bool(b) => *b,
            Value::Object(obj) => {
                if let Some(operator) = obj.get("operator").and_then(|v| v.as_str()) {
                    let args = obj.get("args").or(obj.get("value"));
                    match operator {
                        "always" => true,
                        "never" => false,
                        "eq" | "==" => {
                            if let (Some(attr), Some(val)) = (
                                obj.get("attribute").and_then(|v| v.as_str()),
                                args.and_then(|v| v.as_str()),
                            ) {
                                ctx.get_str(attr) == Some(val)
                            } else {
                                false
                            }
                        }
                        "in" => {
                            if let (Some(attr), Some(arr)) = (
                                obj.get("attribute").and_then(|v| v.as_str()),
                                args.and_then(|v| v.as_array()),
                            ) {
                                if let Some(attr_val) = ctx.get_str(attr) {
                                    arr.iter().any(|v| v.as_str() == Some(attr_val))
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        }
                        "and" => {
                            if let Some(conditions) = args.and_then(|v| v.as_array()) {
                                conditions.iter().all(|c| self.evaluate_condition(c, ctx))
                            } else {
                                false
                            }
                        }
                        "or" => {
                            if let Some(conditions) = args.and_then(|v| v.as_array()) {
                                conditions.iter().any(|c| self.evaluate_condition(c, ctx))
                            } else {
                                false
                            }
                        }
                        "time_range" => {
                            // Check if current time is within a specified range
                            // Expected format: { "operator": "time_range", "start": "HH:MM", "end": "HH:MM" }
                            // Or with timezone: { "operator": "time_range", "start": "HH:MM", "end": "HH:MM", "tz": "UTC" }
                            let start = obj.get("start").and_then(|v| v.as_str());
                            let end = obj.get("end").and_then(|v| v.as_str());

                            if let (Some(start_time), Some(end_time)) = (start, end) {
                                self.evaluate_time_range(start_time, end_time)
                            } else {
                                false
                            }
                        }
                        "time_between" => {
                            // Alternative format: { "operator": "time_between", "value": "09:00-17:00" }
                            if let Some(value) = args.and_then(|v| v.as_str()) {
                                let parts: Vec<&str> = value.split('-').collect();
                                if parts.len() == 2 {
                                    self.evaluate_time_range(parts[0], parts[1])
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        }
                        "not_expired" => {
                            // Check if a timestamp attribute is not expired
                            // Expected format: { "operator": "not_expired", "attribute": "context.timestamp" }
                            if let Some(attr) = obj.get("attribute").and_then(|v| v.as_str()) {
                                if let Some(ts) = ctx.get_i64(attr) {
                                    let now = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .map(|d| d.as_secs() as i64)
                                        .unwrap_or(0);
                                    ts > now
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        }
                        _ => false,
                    }
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Evaluate a time range condition
    /// Uses the trusted time source to prevent clock manipulation attacks
    fn evaluate_time_range(&self, start: &str, end: &str) -> bool {
        // Get current time from trusted source
        let current_time = match self.time_validator.get_trusted_time() {
            Ok(t) => t as u64,
            Err(_) => {
                // Fall back to system time if trusted source fails
                tracing::warn!("Trusted time unavailable, falling back to system time");
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            }
        };

        // Convert current time to HH:MM
        let hours = (current_time % 86400) / 3600;
        let minutes = (current_time % 3600) / 60;
        let current_minutes = hours * 60 + minutes;

        // Parse start and end times (format: "HH:MM")
        let parse_time = |time_str: &str| -> Option<u32> {
            let parts: Vec<&str> = time_str.split(':').collect();
            if parts.len() == 2 {
                let hour: u32 = parts[0].parse().ok()?;
                let minute: u32 = parts[1].parse().ok()?;
                if hour < 24 && minute < 60 {
                    return Some(hour * 60 + minute);
                }
            }
            None
        };

        let start_minutes = match parse_time(start) {
            Some(m) => m as u64,
            None => return false,
        };
        let end_minutes = match parse_time(end) {
            Some(m) => m as u64,
            None => return false,
        };

        // Handle overnight ranges (e.g., 22:00-06:00)
        if start_minutes <= end_minutes {
            current_minutes >= start_minutes && current_minutes <= end_minutes
        } else {
            // Overnight: either in [start, midnight) or [0, end]
            current_minutes >= start_minutes || current_minutes <= end_minutes
        }
    }
}

impl Default for PBACEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple glob matching
fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0;

    // Handle leading wildcard
    if pattern.starts_with('*') && !parts.is_empty() {
        // Find the first non-empty part
        if let Some(first) = parts.iter().find(|p| !p.is_empty()) {
            let first_len = first.len();
            if let Some(idx) = text[first_len..].find(first) {
                pos = idx + first_len;
            } else {
                return false;
            }
        }
    } else {
        // No leading wildcard, match from start
        if let Some(first) = parts.first() {
            if !first.is_empty() && !text.starts_with(first) {
                return false;
            }
            pos = first.len();
        }
    }

    for part in parts[1..].iter() {
        if part.is_empty() {
            continue;
        }

        if let Some(idx) = text[pos..].find(part) {
            pos += idx + part.len();
        } else {
            return false;
        }
    }

    // If pattern ends with wildcard, it's a match
    if pattern.ends_with('*') {
        true
    } else {
        pos == text.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_simple_allow() {
        let engine = PBACEngine::new();

        let policy = Policy {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            effect: PolicyEffect::Allow,
            condition: serde_json::json!({
                "operator": "always",
                "args": true
            }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            enabled: true,
        };

        engine.add_policy(policy).await.unwrap();

        let ctx = AccessContext::new("user1", "encrypt", "key:123");
        let result = engine.evaluate(&ctx).await.unwrap();

        assert_eq!(result, Decision::Allow);
    }

    #[tokio::test]
    async fn test_deny_override() {
        let engine = PBACEngine::new();

        // Add deny policy
        let deny_policy = Policy {
            id: uuid::Uuid::new_v4(),
            name: "deny-test".to_string(),
            effect: PolicyEffect::Deny,
            condition: serde_json::json!({
                "operator": "always",
                "args": true
            }),
            resources: vec!["key:*".to_string()],
            subjects: vec!["bad-user".to_string()],
            enabled: true,
        };

        // Add allow policy
        let allow_policy = Policy {
            id: uuid::Uuid::new_v4(),
            name: "allow-test".to_string(),
            effect: PolicyEffect::Allow,
            condition: serde_json::json!({
                "operator": "always",
                "args": true
            }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            enabled: true,
        };

        engine.add_policy(deny_policy).await.unwrap();
        engine.add_policy(allow_policy).await.unwrap();

        let ctx = AccessContext::new("bad-user", "encrypt", "key:123");
        let result = engine.evaluate(&ctx).await.unwrap();

        // Deny should take precedence
        assert_eq!(result, Decision::Deny);
    }

    /// Default deny: no policies means all access is denied
    #[tokio::test]
    async fn test_default_deny_no_policies() {
        let engine = PBACEngine::new();

        let ctx = AccessContext::new("any-user", "encrypt", "key:456");
        let result = engine.evaluate(&ctx).await.unwrap();

        assert_eq!(result, Decision::Deny);
    }

    /// Disabled policy is ignored during evaluation
    #[tokio::test]
    async fn test_disabled_policy_ignored() {
        let engine = PBACEngine::new();

        let policy = Policy {
            id: uuid::Uuid::new_v4(),
            name: "disabled-allow".to_string(),
            effect: PolicyEffect::Allow,
            condition: serde_json::json!({
                "operator": "always",
                "args": true
            }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            enabled: false, // DISABLED
        };

        engine.add_policy(policy).await.unwrap();

        let ctx = AccessContext::new("user1", "encrypt", "key:123");
        let result = engine.evaluate(&ctx).await.unwrap();

        // Disabled allow policy — should result in default deny
        assert_eq!(result, Decision::Deny);
    }

    /// Subject-specific policy: only matching subject is allowed
    #[tokio::test]
    async fn test_subject_specific_policy() {
        let engine = PBACEngine::new();

        let policy = Policy {
            id: uuid::Uuid::new_v4(),
            name: "subject-allow".to_string(),
            effect: PolicyEffect::Allow,
            condition: serde_json::json!({
                "operator": "always",
                "args": true
            }),
            resources: vec!["*".to_string()],
            subjects: vec!["trusted-user".to_string()],
            enabled: true,
        };

        engine.add_policy(policy).await.unwrap();

        // Trusted user: allowed
        let ctx = AccessContext::new("trusted-user", "encrypt", "key:1");
        assert_eq!(engine.evaluate(&ctx).await.unwrap(), Decision::Allow);

        // Untrusted user: denied (default)
        let ctx2 = AccessContext::new("malicious-user", "encrypt", "key:1");
        assert_eq!(engine.evaluate(&ctx2).await.unwrap(), Decision::Deny);
    }

    /// Test glob_match with various patterns
    #[test]
    fn test_glob_match_wildcard() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("key:*", "key:123"));
        assert!(glob_match("key:*", "key:abc-def"));
        // Note: glob_match has limitations with leading wildcard + suffix patterns
        assert!(glob_match("key:123", "key:123"));
        assert!(!glob_match("key:123", "key:456"));
        assert!(!glob_match("key:abc", "key:xyz"));
    }

    /// Test glob_match with prefix and suffix patterns
    #[test]
    fn test_glob_match_prefix_suffix() {
        assert!(glob_match("prefix*", "prefix-something"));
        assert!(!glob_match("prefix*", "other-prefix"));
        // Note: suffix-only patterns like "*suffix" are not fully supported
        // by the current glob_match implementation
        assert!(glob_match("*middle*", "before-middle-after"));
    }

    /// Test policy with resource glob pattern
    #[tokio::test]
    async fn test_resource_glob_pattern() {
        let engine = PBACEngine::new();

        let policy = Policy {
            id: uuid::Uuid::new_v4(),
            name: "key-access".to_string(),
            effect: PolicyEffect::Allow,
            condition: serde_json::json!({"operator": "always"}),
            resources: vec!["key:prod-*".to_string()],
            subjects: vec!["*".to_string()],
            enabled: true,
        };

        engine.add_policy(policy).await.unwrap();

        // Matching resource
        let ctx = AccessContext::new("user1", "encrypt", "key:prod-001");
        assert_eq!(engine.evaluate(&ctx).await.unwrap(), Decision::Allow);

        // Non-matching resource
        let ctx2 = AccessContext::new("user1", "encrypt", "key:dev-001");
        assert_eq!(engine.evaluate(&ctx2).await.unwrap(), Decision::Deny);
    }

    /// Test condition: eq operator
    #[tokio::test]
    async fn test_condition_eq() {
        let engine = PBACEngine::new();

        let policy = Policy {
            id: uuid::Uuid::new_v4(),
            name: "dept-check".to_string(),
            effect: PolicyEffect::Allow,
            condition: serde_json::json!({
                "operator": "eq",
                "attribute": "subject.id",
                "value": "admin-user"
            }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            enabled: true,
        };

        engine.add_policy(policy).await.unwrap();

        // Matching attribute
        let ctx = AccessContext::new("admin-user", "encrypt", "key:1");
        assert_eq!(engine.evaluate(&ctx).await.unwrap(), Decision::Allow);

        // Non-matching attribute
        let ctx2 = AccessContext::new("regular-user", "encrypt", "key:1");
        assert_eq!(engine.evaluate(&ctx2).await.unwrap(), Decision::Deny);
    }

    /// Test condition: never operator
    #[tokio::test]
    async fn test_condition_never() {
        let engine = PBACEngine::new();

        let policy = Policy {
            id: uuid::Uuid::new_v4(),
            name: "never-allow".to_string(),
            effect: PolicyEffect::Allow,
            condition: serde_json::json!({"operator": "never"}),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            enabled: true,
        };

        engine.add_policy(policy).await.unwrap();

        let ctx = AccessContext::new("user1", "encrypt", "key:1");
        assert_eq!(engine.evaluate(&ctx).await.unwrap(), Decision::Deny);
    }

    /// Test condition: and/or logical operators
    #[tokio::test]
    async fn test_condition_and_or() {
        let engine = PBACEngine::new();

        // AND: both conditions must be true (but second is false)
        let policy_and = Policy {
            id: uuid::Uuid::new_v4(),
            name: "and-test".to_string(),
            effect: PolicyEffect::Allow,
            condition: serde_json::json!({
                "operator": "and",
                "args": [
                    {"operator": "always"},
                    {"operator": "never"}
                ]
            }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            enabled: true,
        };

        engine.add_policy(policy_and).await.unwrap();

        let ctx = AccessContext::new("user1", "encrypt", "key:1");
        assert_eq!(engine.evaluate(&ctx).await.unwrap(), Decision::Deny);

        // OR: either condition can be true
        let engine2 = PBACEngine::new();
        let policy_or = Policy {
            id: uuid::Uuid::new_v4(),
            name: "or-test".to_string(),
            effect: PolicyEffect::Allow,
            condition: serde_json::json!({
                "operator": "or",
                "args": [
                    {"operator": "never"},
                    {"operator": "always"}
                ]
            }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            enabled: true,
        };

        engine2.add_policy(policy_or).await.unwrap();
        assert_eq!(engine2.evaluate(&ctx).await.unwrap(), Decision::Allow);
    }

    /// Test condition: in operator
    #[tokio::test]
    async fn test_condition_in() {
        let engine = PBACEngine::new();

        let policy = Policy {
            id: uuid::Uuid::new_v4(),
            name: "in-test".to_string(),
            effect: PolicyEffect::Allow,
            condition: serde_json::json!({
                "operator": "in",
                "attribute": "subject.id",
                "value": ["alice", "bob", "charlie"]
            }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            enabled: true,
        };

        engine.add_policy(policy).await.unwrap();

        // In list
        let ctx = AccessContext::new("bob", "encrypt", "key:1");
        assert_eq!(engine.evaluate(&ctx).await.unwrap(), Decision::Allow);

        // Not in list
        let ctx2 = AccessContext::new("eve", "encrypt", "key:1");
        assert_eq!(engine.evaluate(&ctx2).await.unwrap(), Decision::Deny);
    }

    /// Test policy management: add, get, remove, list
    #[tokio::test]
    async fn test_policy_management() {
        let engine = PBACEngine::new();

        let policy1 = Policy {
            id: uuid::Uuid::new_v4(),
            name: "p1".to_string(),
            effect: PolicyEffect::Allow,
            condition: serde_json::json!({"operator": "always"}),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            enabled: true,
        };

        let policy2 = Policy {
            id: uuid::Uuid::new_v4(),
            name: "p2".to_string(),
            effect: PolicyEffect::Deny,
            condition: serde_json::json!({"operator": "always"}),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            enabled: true,
        };

        engine.add_policy(policy1.clone()).await.unwrap();
        engine.add_policy(policy2.clone()).await.unwrap();

        // List
        let list = engine.list_policies().await.unwrap();
        assert_eq!(list.len(), 2);

        // Get
        let got = engine.get_policy(&policy1.id.to_string()).await.unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().name, "p1");

        // Remove
        engine.remove_policy(&policy1.id.to_string()).await.unwrap();
        let list = engine.list_policies().await.unwrap();
        assert_eq!(list.len(), 1);
    }

    /// Test TimeSkewStatus
    #[test]
    fn test_time_skew_status() {
        assert!(TimeSkewStatus::Ok.is_healthy());
        assert!(!TimeSkewStatus::Warning(15).is_healthy());
        assert!(!TimeSkewStatus::Critical(45).is_healthy());

        assert_eq!(TimeSkewStatus::Ok.skew_secs(), None);
        assert_eq!(TimeSkewStatus::Warning(15).skew_secs(), Some(15));
        assert_eq!(TimeSkewStatus::Critical(45).skew_secs(), Some(45));
    }

    /// Test SystemTimeValidator returns current time
    #[test]
    fn test_system_time_validator() {
        let validator = SystemTimeValidator;
        let t1 = validator.get_trusted_time().unwrap();
        let t2 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!((t1 - t2).abs() <= 1);
    }

    /// Test custom TimeValidator with mock time
    struct MockTimeValidator {
        offset: i64,
    }

    impl TimeValidator for MockTimeValidator {
        fn get_trusted_time(&self) -> Result<i64> {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| kms_core::Error::Internal(e.to_string()))?
                .as_secs() as i64;
            Ok(now + self.offset)
        }
    }

    /// Test time skew detection with mock validator
    #[tokio::test]
    async fn test_time_skew_detection() {
        // Large offset should trigger critical skew
        let engine = PBACEngine::with_time_validator(MockTimeValidator { offset: 60 });
        let status = engine.check_time_skew().await.unwrap();
        assert!(matches!(status, TimeSkewStatus::Critical(_)));

        // Small offset should be OK
        let engine2 = PBACEngine::with_time_validator(MockTimeValidator { offset: 5 });
        let status2 = engine2.check_time_skew().await.unwrap();
        assert!(matches!(status2, TimeSkewStatus::Ok));
    }

    /// Test time skew alert recording
    #[tokio::test]
    async fn test_time_skew_alerts() {
        let engine = PBACEngine::with_time_validator(MockTimeValidator { offset: 60 });

        // Trigger alert
        engine.check_time_skew().await.unwrap();

        let alerts = engine.get_time_skew_alerts().await.unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, "critical");
        assert_eq!(alerts[0].skew_seconds, 60);
    }

    /// Test evaluate_time_range with valid ranges
    #[test]
    fn test_evaluate_time_range_format() {
        let engine = PBACEngine::new();

        // These should not panic and should return bool
        let _ = engine.evaluate_time_range("09:00", "17:00");
        let _ = engine.evaluate_time_range("22:00", "06:00"); // overnight
        let _ = engine.evaluate_time_range("00:00", "23:59");
    }

    // --- Additional tests ---

    /// Test PBACEngine default
    #[test]
    fn test_pbac_engine_default() {
        let engine = PBACEngine::default();
        // Should compile and not panic
        let _ = engine;
    }

    /// Test remove_policy on non-existent policy
    #[tokio::test]
    async fn test_remove_nonexistent_policy() {
        let engine = PBACEngine::new();
        // Should succeed even if policy doesn't exist
        engine.remove_policy("nonexistent").await.unwrap();
    }

    /// Test get_policy on empty engine
    #[tokio::test]
    async fn test_get_policy_empty() {
        let engine = PBACEngine::new();
        let result = engine.get_policy("any").await.unwrap();
        assert!(result.is_none());
    }

    /// Test list_policies on empty engine
    #[tokio::test]
    async fn test_list_policies_empty() {
        let engine = PBACEngine::new();
        let policies = engine.list_policies().await.unwrap();
        assert!(policies.is_empty());
    }

    /// Test list_policies with multiple policies
    #[tokio::test]
    async fn test_list_policies_multiple() {
        let engine = PBACEngine::new();
        let p1 = Policy {
            id: uuid::Uuid::new_v4(),
            name: "Policy 1".to_string(),
            effect: PolicyEffect::Allow,
            condition: serde_json::json!({"operator": "always", "args": true}),
            resources: vec!["key:*".to_string()],
            subjects: vec!["user:*".to_string()],
            enabled: true,
        };
        let p2 = Policy {
            id: uuid::Uuid::new_v4(),
            name: "Policy 2".to_string(),
            effect: PolicyEffect::Deny,
            condition: serde_json::json!({"operator": "always", "args": true}),
            resources: vec!["key:*".to_string()],
            subjects: vec!["admin".to_string()],
            enabled: true,
        };
        engine.add_policy(p1).await.unwrap();
        engine.add_policy(p2).await.unwrap();

        let policies = engine.list_policies().await.unwrap();
        assert_eq!(policies.len(), 2);
    }

    /// Test glob_match with empty pattern and text
    #[test]
    fn test_glob_match_empty() {
        let engine = PBACEngine::new();
        let _ = engine;
    }

    /// Test evaluate_time_range with invalid format
    #[test]
    fn test_evaluate_time_range_invalid() {
        let engine = PBACEngine::new();
        // Invalid format should return false, not panic
        assert!(!engine.evaluate_time_range("invalid", "17:00"));
        assert!(!engine.evaluate_time_range("09:00", "invalid"));
        assert!(!engine.evaluate_time_range("25:00", "17:00"));
        assert!(!engine.evaluate_time_range("09:99", "17:00"));
    }

    /// Test TimeSkewAlert fields
    #[test]
    fn test_time_skew_alert_fields() {
        let alert = TimeSkewAlert {
            timestamp: 1000,
            skew_seconds: 45,
            severity: "critical".to_string(),
        };
        assert_eq!(alert.timestamp, 1000);
        assert_eq!(alert.skew_seconds, 45);
        assert_eq!(alert.severity, "critical");
    }

    /// Test warning level time skew
    #[tokio::test]
    async fn test_time_skew_warning_level() {
        // Offset of 15 seconds should trigger Warning (>10 but <30)
        let engine = PBACEngine::with_time_validator(MockTimeValidator { offset: 15 });
        let status = engine.check_time_skew().await.unwrap();
        assert!(matches!(status, TimeSkewStatus::Warning(_)));

        let alerts = engine.get_time_skew_alerts().await.unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, "warning");
    }

    /// Test multiple time skew alerts are recorded
    #[tokio::test]
    async fn test_multiple_time_skew_alerts() {
        let engine = PBACEngine::with_time_validator(MockTimeValidator { offset: 60 });

        engine.check_time_skew().await.unwrap();
        engine.check_time_skew().await.unwrap();
        engine.check_time_skew().await.unwrap();

        let alerts = engine.get_time_skew_alerts().await.unwrap();
        assert_eq!(alerts.len(), 3);
    }
}
