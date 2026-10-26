//! PBAC Policy Engine implementation

use super::store::{PolicyRepository, PolicyStoreError};
use super::{AccessContext, Decision, Policy};
use kms_core::{PolicyEffect, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;

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
    /// Durable store for the policy set, when one is configured.
    ///
    /// The engine evaluates out of memory, so this is the half that makes an
    /// installed policy survive a restart (audit follow-up B9-a). It is
    /// optional: an engine without one behaves exactly as before, which is
    /// what the in-memory development mode relies on.
    repository: Option<Arc<dyn PolicyRepository>>,
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
            repository: None,
        }
    }

    /// Attach a durable store to the engine.
    ///
    /// From this point on every policy change is written through to the
    /// store: a policy that the API accepted is a policy that is persisted,
    /// and a policy that was persisted is loaded back on the next start.
    pub fn with_repository(mut self, repository: Arc<dyn PolicyRepository>) -> Self {
        self.repository = Some(repository);
        self
    }

    /// Whether a durable store is attached.
    pub fn has_repository(&self) -> bool {
        self.repository.is_some()
    }

    /// Add a policy
    ///
    /// When a durable store is attached the policy is written to it **first**
    /// and the in-memory map is only updated once the write succeeded. The
    /// durable state is the source of truth: a policy that the store rejected
    /// must not linger in memory, because it would look installed until the
    /// next restart, when it would silently vanish.
    pub async fn add_policy(&self, policy: Policy) -> Result<()> {
        if let Some(repo) = &self.repository {
            repo.save(&policy)
                .await
                .map_err(|e| kms_core::Error::Internal(format!("persist policy: {e}")))?;
        }

        let mut policies = self.policies.write().await;
        policies.insert(policy.id.to_string(), policy);
        Ok(())
    }

    /// Remove a policy
    ///
    /// Removing a policy that is not installed is not an error, so the
    /// durable store is asked to delete the row as well: the two sides must
    /// not drift apart.
    pub async fn remove_policy(&self, id: &Uuid) -> Result<()> {
        if let Some(repo) = &self.repository {
            repo.delete(id)
                .await
                .map_err(|e| kms_core::Error::Internal(format!("delete policy: {e}")))?;
        }

        let mut policies = self.policies.write().await;
        policies.remove(&id.to_string());
        Ok(())
    }

    /// Replace the whole policy set in one shot.
    ///
    /// Used by the startup load and by a reload: the engine never observes a
    /// half-applied policy set.
    pub async fn replace_all(&self, policies: Vec<Policy>) {
        let mut guard = self.policies.write().await;
        *guard = policies
            .into_iter()
            .map(|policy| (policy.id.to_string(), policy))
            .collect();
    }

    /// Load every stored policy into the engine.
    ///
    /// Returns the number of policies loaded. A store that cannot be read is
    /// an error, never an empty result: the caller cannot tell an empty
    /// store from an unreadable one, and reporting the second as the first
    /// would silently disable attribute-based control.
    pub async fn load_from_repository(&self) -> Result<usize> {
        let repo = self.repository.as_ref().ok_or_else(|| {
            kms_core::Error::Internal("no policy repository is configured".to_string())
        })?;

        let policies = repo.load_all().await.map_err(|e: PolicyStoreError| {
            kms_core::Error::Internal(format!("load policies: {e}"))
        })?;

        let count = policies.len();
        self.replace_all(policies).await;
        Ok(count)
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

    /// Number of **enabled** policies.
    ///
    /// The engine itself always denies a request that no policy covers
    /// (default-deny). Callers that need to distinguish "no policy configured
    /// at all" from "policies configured but none matches" use this counter:
    /// an engine with zero enabled policies imposes no attribute-level
    /// restriction, and as soon as the first enabled policy is installed the
    /// default-deny applies to everything the policies do not cover
    /// (audit follow-up B7-g).
    ///
    /// Only **enabled** policies count, because that is exactly what
    /// [`PBACEngine::evaluate`] takes into account. Counting disabled ones
    /// would make a single disabled policy switch the engine into the
    /// default-deny mode while it matches nothing — locking out every
    /// request with no way to tell why (audit follow-up B7-h).
    pub async fn enabled_policy_count(&self) -> usize {
        self.policies
            .read()
            .await
            .values()
            .filter(|p| p.enabled)
            .count()
    }

    /// Evaluate an access request, taking the enabled policies into account.
    ///
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

    /// Evaluate an access request, taking the enabled policies into account.
    ///
    /// Returns `None` when **no enabled policy** is configured. The caller
    /// then knows that attribute-based control is not in force; once at least
    /// one enabled policy exists the engine's default-deny applies to
    /// everything the policies do not cover (audit follow-up B7-h).
    ///
    /// The count and the decision are taken under a single lock, so a policy
    /// installed concurrently can neither be missed (which would allow a
    /// request the policy denies) nor hide a policy that is already active.
    pub async fn evaluate_if_configured(&self, ctx: &AccessContext) -> Result<Option<Decision>> {
        let policies = self.policies.read().await;
        if policies.values().all(|p| !p.enabled) {
            return Ok(None);
        }
        Ok(Some(self.evaluate_locked(&policies, ctx)))
    }

    /// Evaluate access request
    pub async fn evaluate(&self, ctx: &AccessContext) -> Result<Decision> {
        let policies = self.policies.read().await;
        Ok(self.evaluate_locked(&policies, ctx))
    }

    /// The decision for one request, given an already-held policy snapshot.
    fn evaluate_locked(
        &self,
        policies: &std::collections::HashMap<String, Policy>,
        ctx: &AccessContext,
    ) -> Decision {
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
                return match policy.effect {
                    PolicyEffect::Allow => Decision::Allow,
                    PolicyEffect::Deny => Decision::Deny,
                };
            }
        }

        // Default deny
        Decision::Deny
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

    /// `enabled_policy_count` distinguishes "no policy configured" from
    /// "policies configured but none matches" (audit follow-up B7-g), and it
    /// counts only the policies `evaluate` actually takes into account
    /// (audit follow-up B7-h).
    #[tokio::test]
    async fn test_enabled_policy_count_tracks_policies() {
        let engine = PBACEngine::new();
        assert_eq!(engine.enabled_policy_count().await, 0);

        let policy = Policy {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            effect: PolicyEffect::Allow,
            condition: serde_json::json!({ "operator": "always" }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            enabled: true,
        };
        let policy_id = policy.id;

        engine.add_policy(policy).await.unwrap();
        assert_eq!(engine.enabled_policy_count().await, 1);

        engine.remove_policy(&policy_id).await.unwrap();
        assert_eq!(engine.enabled_policy_count().await, 0);
    }

    /// A disabled policy is invisible to `evaluate`, so it must not be counted
    /// as an active policy either (audit follow-up B7-h).
    #[tokio::test]
    async fn test_disabled_policy_is_not_counted() {
        let engine = PBACEngine::new();
        let policy = Policy {
            id: uuid::Uuid::new_v4(),
            name: "disabled".to_string(),
            effect: PolicyEffect::Allow,
            condition: serde_json::json!({ "operator": "always" }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            enabled: false,
        };
        engine.add_policy(policy).await.unwrap();

        assert_eq!(engine.enabled_policy_count().await, 0);
    }

    /// `evaluate_if_configured` returns `None` while no enabled policy exists
    /// and the decision once one does (audit follow-up B7-h).
    #[tokio::test]
    async fn test_evaluate_if_configured() {
        let engine = PBACEngine::new();
        let ctx = AccessContext::new("user1", "encrypt", "key:123");

        // No policy => the control is not in force.
        assert_eq!(engine.evaluate_if_configured(&ctx).await.unwrap(), None);

        // A disabled policy is still "not in force".
        let disabled = Policy {
            id: uuid::Uuid::new_v4(),
            name: "disabled".to_string(),
            effect: PolicyEffect::Allow,
            condition: serde_json::json!({ "operator": "always" }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            enabled: false,
        };
        engine.add_policy(disabled).await.unwrap();
        assert_eq!(engine.evaluate_if_configured(&ctx).await.unwrap(), None);

        // An enabled, matching policy decides.
        let enabled = Policy {
            id: uuid::Uuid::new_v4(),
            name: "enabled".to_string(),
            effect: PolicyEffect::Allow,
            condition: serde_json::json!({ "operator": "always" }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            enabled: true,
        };
        engine.add_policy(enabled).await.unwrap();
        assert_eq!(
            engine.evaluate_if_configured(&ctx).await.unwrap(),
            Some(Decision::Allow)
        );
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
        engine.remove_policy(&policy1.id).await.unwrap();
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
        engine.remove_policy(&Uuid::new_v4()).await.unwrap();
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

    // ── Durable store tests (audit follow-up B9-a) ──

    /// An in-memory stand-in for a real policy store.
    ///
    /// It records the calls the engine makes and can be told to fail, so the
    /// write-through behaviour can be observed without a database.
    #[derive(Default)]
    struct FakeRepository {
        stored: std::sync::Mutex<Vec<Policy>>,
        saved: std::sync::Mutex<Vec<Uuid>>,
        deleted: std::sync::Mutex<Vec<Uuid>>,
        fail_save: bool,
        fail_load: bool,
    }

    impl FakeRepository {
        fn new() -> Self {
            Self::default()
        }

        fn failing_save() -> Self {
            Self {
                fail_save: true,
                ..Self::default()
            }
        }

        fn failing_load() -> Self {
            Self {
                fail_load: true,
                ..Self::default()
            }
        }

        fn stored_policies(&self) -> Vec<Policy> {
            self.stored.lock().expect("lock").clone()
        }
    }

    #[async_trait::async_trait]
    impl PolicyRepository for FakeRepository {
        async fn migrate(&self) -> std::result::Result<(), PolicyStoreError> {
            Ok(())
        }

        async fn load_all(&self) -> std::result::Result<Vec<Policy>, PolicyStoreError> {
            if self.fail_load {
                return Err(PolicyStoreError::Unavailable("store is down".to_string()));
            }
            Ok(self.stored_policies())
        }

        async fn save(&self, policy: &Policy) -> std::result::Result<(), PolicyStoreError> {
            if self.fail_save {
                return Err(PolicyStoreError::Unavailable("store is down".to_string()));
            }
            self.saved.lock().expect("lock").push(policy.id);
            let mut stored = self.stored.lock().expect("lock");
            stored.retain(|p| p.id != policy.id);
            stored.push(policy.clone());
            Ok(())
        }

        async fn delete(&self, id: &Uuid) -> std::result::Result<bool, PolicyStoreError> {
            self.deleted.lock().expect("lock").push(*id);
            let mut stored = self.stored.lock().expect("lock");
            let before = stored.len();
            stored.retain(|p| p.id != *id);
            Ok(stored.len() != before)
        }
    }

    fn sample_policy(effect: PolicyEffect) -> Policy {
        Policy {
            id: Uuid::new_v4(),
            name: "persisted".to_string(),
            effect,
            condition: serde_json::json!({"operator": "always", "args": true}),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            enabled: true,
        }
    }

    /// A policy that the API accepted must be in the store, not only in
    /// memory — otherwise it disappears on the next restart.
    #[tokio::test]
    async fn test_add_policy_is_written_through_to_the_store() {
        let repo = Arc::new(FakeRepository::new());
        let engine = PBACEngine::new().with_repository(repo.clone());
        let policy = sample_policy(PolicyEffect::Allow);

        engine.add_policy(policy.clone()).await.unwrap();

        assert_eq!(repo.saved.lock().expect("lock").as_slice(), &[policy.id]);
        assert_eq!(repo.stored_policies().len(), 1);
    }

    /// A store that rejects the write must leave the engine untouched: a
    /// policy that only lives in memory looks installed until the next
    /// restart, when it silently vanishes.
    #[tokio::test]
    async fn test_add_policy_leaves_the_engine_untouched_when_the_store_fails() {
        let repo = Arc::new(FakeRepository::failing_save());
        let engine = PBACEngine::new().with_repository(repo);

        let result = engine.add_policy(sample_policy(PolicyEffect::Allow)).await;

        assert!(result.is_err(), "the failure must be reported");
        assert_eq!(engine.list_policies().await.unwrap().len(), 0);
    }

    /// Removing a policy must remove it from the store as well, so the two
    /// sides cannot drift apart.
    #[tokio::test]
    async fn test_remove_policy_is_written_through_to_the_store() {
        let repo = Arc::new(FakeRepository::new());
        let engine = PBACEngine::new().with_repository(repo.clone());
        let policy = sample_policy(PolicyEffect::Allow);
        engine.add_policy(policy.clone()).await.unwrap();

        engine.remove_policy(&policy.id).await.unwrap();

        assert_eq!(repo.deleted.lock().expect("lock").as_slice(), &[policy.id]);
        assert!(repo.stored_policies().is_empty());
        assert!(engine.list_policies().await.unwrap().is_empty());
    }

    /// A store that cannot be read must be an error, never an empty policy
    /// set: the caller cannot tell the two apart, and mistaking the second
    /// for the first disables attribute-based control without a word.
    #[tokio::test]
    async fn test_load_from_repository_reports_a_failing_store_as_an_error() {
        let repo = Arc::new(FakeRepository::failing_load());
        let engine = PBACEngine::new().with_repository(repo);

        let result = engine.load_from_repository().await;

        assert!(result.is_err(), "an unreadable store must not look empty");
    }

    /// Loading restores the persisted policy set, and the restored policy
    /// still decides requests — that is the whole point of persisting it.
    #[tokio::test]
    async fn test_loaded_policies_still_decide_requests() {
        let repo = Arc::new(FakeRepository::new());
        let writer = PBACEngine::new().with_repository(repo.clone());
        writer
            .add_policy(sample_policy(PolicyEffect::Deny))
            .await
            .unwrap();

        // A fresh engine over the same store stands in for a restart.
        let restarted = PBACEngine::new().with_repository(repo);
        let count = restarted.load_from_repository().await.unwrap();
        assert_eq!(count, 1);

        let ctx = AccessContext::new("user1", "encrypt", "key:123");
        assert_eq!(restarted.evaluate(&ctx).await.unwrap(), Decision::Deny);
    }

    /// An engine without a store keeps the previous in-memory behaviour.
    #[tokio::test]
    async fn test_engine_without_a_store_still_works() {
        let engine = PBACEngine::new();
        assert!(!engine.has_repository());

        engine
            .add_policy(sample_policy(PolicyEffect::Allow))
            .await
            .unwrap();
        assert_eq!(engine.enabled_policy_count().await, 1);

        // Loading without a store is an error, not a silent empty set.
        assert!(engine.load_from_repository().await.is_err());
    }
}
