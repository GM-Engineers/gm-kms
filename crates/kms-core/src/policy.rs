//! Policy types for PBAC
//!
//! ## Architecture: Two-Layer Condition Model
//!
//! This module defines the internal/business-logic layer of the KMS policy system.
//! The condition field uses a typed [`Condition`] enum for compile-time safety.
//!
//! See [`kms_policy`] crate's module documentation for the API layer and the
//! two-layer condition design explanation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Policy effect - allow or deny
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

/// Condition operators for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operator", content = "args")]
pub enum Condition {
    // Basic comparison
    Eq(String, String),
    Neq(String, String),
    Gt(String, i64),
    Gte(String, i64),
    Lt(String, i64),
    Lte(String, i64),

    // String operations
    Contains(String, String),
    StartsWith(String, String),
    EndsWith(String, String),
    Matches(String, String),

    // Collection operations
    In(String, Vec<String>),
    NotIn(String, Vec<String>),

    // Time operations
    Between(String, String, String),
    Outside(String, String, String),

    // Existence
    Exists(String),
    NotExists(String),

    // Logical (used internally)
    And(Vec<Condition>),
    Or(Vec<Condition>),
    Not(Box<Condition>),
}

impl Condition {
    /// Evaluate condition against context
    pub fn evaluate(&self, ctx: &PolicyContext) -> bool {
        match self {
            Condition::Eq(attr, value) => ctx.get_str(attr) == Some(value.as_str()),
            Condition::Neq(attr, value) => ctx.get_str(attr) != Some(value.as_str()),
            Condition::Gt(attr, val) => ctx.get_i64(attr).map(|v| v > *val).unwrap_or(false),
            Condition::Gte(attr, val) => ctx.get_i64(attr).map(|v| v >= *val).unwrap_or(false),
            Condition::Lt(attr, val) => ctx.get_i64(attr).map(|v| v < *val).unwrap_or(false),
            Condition::Lte(attr, val) => ctx.get_i64(attr).map(|v| v <= *val).unwrap_or(false),
            Condition::Contains(attr, val) => {
                ctx.get_str(attr).map(|s| s.contains(val)).unwrap_or(false)
            }
            Condition::StartsWith(attr, val) => ctx
                .get_str(attr)
                .map(|s| s.starts_with(val))
                .unwrap_or(false),
            Condition::EndsWith(attr, val) => {
                ctx.get_str(attr).map(|s| s.ends_with(val)).unwrap_or(false)
            }
            Condition::Matches(attr, pattern) => ctx
                .get_str(attr)
                .map(|s| {
                    regex::Regex::new(pattern)
                        .map(|r| r.is_match(s))
                        .unwrap_or(false)
                })
                .unwrap_or(false),
            Condition::In(attr, values) => ctx
                .get_str(attr)
                .map(|s| values.contains(&s.to_string()))
                .unwrap_or(false),
            Condition::NotIn(attr, values) => ctx
                .get_str(attr)
                .map(|s| !values.contains(&s.to_string()))
                .unwrap_or(false),
            Condition::Between(attr, start, end) => ctx
                .get_str(attr)
                .map(|s| s >= start.as_str() && s <= end.as_str())
                .unwrap_or(false),
            Condition::Outside(attr, start, end) => ctx
                .get_str(attr)
                .map(|s| s < start.as_str() || s > end.as_str())
                .unwrap_or(false),
            Condition::Exists(attr) => ctx.get(attr).is_some(),
            Condition::NotExists(attr) => ctx.get(attr).is_none(),
            Condition::And(conditions) => conditions.iter().all(|c| c.evaluate(ctx)),
            Condition::Or(conditions) => conditions.iter().any(|c| c.evaluate(ctx)),
            Condition::Not(inner) => !inner.evaluate(ctx),
        }
    }
}

/// Policy context for evaluation
#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub attributes: std::collections::HashMap<String, serde_json::Value>,
}

impl PolicyContext {
    pub fn new() -> Self {
        Self {
            attributes: std::collections::HashMap::new(),
        }
    }

    pub fn with_attr(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.attributes.insert(key.to_string(), value.into());
        self
    }

    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.attributes.get(key)
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.attributes.get(key)?.as_str()
    }

    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.attributes.get(key)?.as_i64()
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.attributes.get(key)?.as_bool()
    }

    pub fn get_list(&self, key: &str) -> Option<Vec<&str>> {
        Some(
            self.attributes
                .get(key)?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_str())
                .collect(),
        )
    }
}

impl Default for PolicyContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub effect: PolicyEffect,
    pub condition: Condition,
    pub resources: Vec<String>, // Resource patterns like "key:*", "key:prod-*"
    pub subjects: Vec<String>,  // Subject patterns
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub enabled: bool,
}

impl Policy {
    pub fn new(name: &str, effect: PolicyEffect, condition: Condition) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name.to_string(),
            description: None,
            effect,
            condition,
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            created_at: now,
            updated_at: now,
            enabled: true,
        }
    }

    /// Check if this policy applies to the given context
    pub fn matches(&self, ctx: &PolicyContext) -> bool {
        if !self.enabled {
            return false;
        }

        // Check subject matches
        let subject_matches = self.subjects.iter().any(|s| {
            ctx.get_str("subject.id")
                .map(|id| glob_match(s, id))
                .unwrap_or(false)
        });

        if !subject_matches {
            return false;
        }

        // Check resource matches
        let resource_matches = self.resources.iter().any(|r| {
            ctx.get_str("resource.id")
                .map(|id| glob_match(r, id))
                .unwrap_or(false)
        });

        resource_matches && self.condition.evaluate(ctx)
    }
}

/// Simple glob pattern matching
fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0;

    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            // Empty part means leading/trailing/consecutive * — matches anything
            continue;
        }

        if let Some(idx) = text[pos..].find(part) {
            // For the first non-empty part, it must match at the start if pattern starts with non-*
            if i == 0 && !pattern.starts_with('*') && idx != 0 {
                return false;
            }
            pos += idx + part.len();
        } else {
            return false;
        }
    }

    // If pattern ends with *, it matches any trailing text
    if pattern.ends_with('*') {
        return true;
    }

    pos == text.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- PolicyEffect ---

    #[test]
    fn test_policy_effect_serde() {
        let allow = serde_json::to_string(&PolicyEffect::Allow).unwrap();
        assert_eq!(allow, "\"ALLOW\"");
        let deny = serde_json::to_string(&PolicyEffect::Deny).unwrap();
        assert_eq!(deny, "\"DENY\"");
    }

    #[test]
    fn test_policy_effect_eq() {
        assert_eq!(PolicyEffect::Allow, PolicyEffect::Allow);
        assert_ne!(PolicyEffect::Allow, PolicyEffect::Deny);
    }

    // --- PolicyContext ---

    #[test]
    fn test_policy_context_new() {
        let ctx = PolicyContext::new();
        assert!(ctx.attributes.is_empty());
    }

    #[test]
    fn test_policy_context_with_attr_str() {
        let ctx = PolicyContext::new().with_attr("user", "alice");
        assert_eq!(ctx.get_str("user"), Some("alice"));
    }

    #[test]
    fn test_policy_context_with_attr_i64() {
        let ctx = PolicyContext::new().with_attr("count", 42i64);
        assert_eq!(ctx.get_i64("count"), Some(42));
    }

    #[test]
    fn test_policy_context_with_attr_bool() {
        let ctx = PolicyContext::new().with_attr("admin", true);
        assert_eq!(ctx.get_bool("admin"), Some(true));
    }

    #[test]
    fn test_policy_context_get_missing() {
        let ctx = PolicyContext::new();
        assert!(ctx.get("missing").is_none());
        assert!(ctx.get_str("missing").is_none());
        assert!(ctx.get_i64("missing").is_none());
        assert!(ctx.get_bool("missing").is_none());
        assert!(ctx.get_list("missing").is_none());
    }

    #[test]
    fn test_policy_context_get_list() {
        let ctx = PolicyContext::new().with_attr(
            "roles",
            serde_json::json!(["admin", "operator"]),
        );
        let list = ctx.get_list("roles").unwrap();
        assert_eq!(list, vec!["admin", "operator"]);
    }

    #[test]
    fn test_policy_context_get_list_non_array() {
        let ctx = PolicyContext::new().with_attr("roles", "admin");
        assert!(ctx.get_list("roles").is_none());
    }

    #[test]
    fn test_policy_context_default() {
        let ctx = PolicyContext::default();
        assert!(ctx.attributes.is_empty());
    }

    // --- Condition: Eq / Neq ---

    #[test]
    fn test_condition_eq_match() {
        let ctx = PolicyContext::new().with_attr("role", "admin");
        let cond = Condition::Eq("role".into(), "admin".into());
        assert!(cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_eq_no_match() {
        let ctx = PolicyContext::new().with_attr("role", "user");
        let cond = Condition::Eq("role".into(), "admin".into());
        assert!(!cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_eq_missing_attr() {
        let ctx = PolicyContext::new();
        let cond = Condition::Eq("role".into(), "admin".into());
        assert!(!cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_neq() {
        let ctx = PolicyContext::new().with_attr("role", "user");
        let cond = Condition::Neq("role".into(), "admin".into());
        assert!(cond.evaluate(&ctx));
    }

    // --- Condition: numeric ---

    #[test]
    fn test_condition_gt() {
        let ctx = PolicyContext::new().with_attr("count", 10i64);
        assert!(Condition::Gt("count".into(), 5).evaluate(&ctx));
        assert!(!Condition::Gt("count".into(), 10).evaluate(&ctx));
        assert!(!Condition::Gt("count".into(), 15).evaluate(&ctx));
    }

    #[test]
    fn test_condition_gte() {
        let ctx = PolicyContext::new().with_attr("count", 10i64);
        assert!(Condition::Gte("count".into(), 10).evaluate(&ctx));
        assert!(Condition::Gte("count".into(), 5).evaluate(&ctx));
        assert!(!Condition::Gte("count".into(), 11).evaluate(&ctx));
    }

    #[test]
    fn test_condition_lt() {
        let ctx = PolicyContext::new().with_attr("count", 10i64);
        assert!(Condition::Lt("count".into(), 15).evaluate(&ctx));
        assert!(!Condition::Lt("count".into(), 10).evaluate(&ctx));
    }

    #[test]
    fn test_condition_lte() {
        let ctx = PolicyContext::new().with_attr("count", 10i64);
        assert!(Condition::Lte("count".into(), 10).evaluate(&ctx));
        assert!(!Condition::Lte("count".into(), 5).evaluate(&ctx));
    }

    #[test]
    fn test_condition_numeric_missing_attr() {
        let ctx = PolicyContext::new();
        assert!(!Condition::Gt("count".into(), 0).evaluate(&ctx));
    }

    // --- Condition: string ops ---

    #[test]
    fn test_condition_contains() {
        let ctx = PolicyContext::new().with_attr("name", "alice cooper");
        assert!(Condition::Contains("name".into(), "lice".into()).evaluate(&ctx));
        assert!(!Condition::Contains("name".into(), "bob".into()).evaluate(&ctx));
    }

    #[test]
    fn test_condition_starts_with() {
        let ctx = PolicyContext::new().with_attr("name", "alice");
        assert!(Condition::StartsWith("name".into(), "al".into()).evaluate(&ctx));
        assert!(!Condition::StartsWith("name".into(), "bob".into()).evaluate(&ctx));
    }

    #[test]
    fn test_condition_ends_with() {
        let ctx = PolicyContext::new().with_attr("name", "alice");
        assert!(Condition::EndsWith("name".into(), "ice".into()).evaluate(&ctx));
        assert!(!Condition::EndsWith("name".into(), "son".into()).evaluate(&ctx));
    }

    #[test]
    fn test_condition_matches() {
        let ctx = PolicyContext::new().with_attr("email", "alice@example.com");
        assert!(Condition::Matches("email".into(), r".*@example\.com".into()).evaluate(&ctx));
        assert!(!Condition::Matches("email".into(), r".*@evil\.com".into()).evaluate(&ctx));
    }

    #[test]
    fn test_condition_matches_invalid_regex() {
        let ctx = PolicyContext::new().with_attr("email", "alice");
        assert!(!Condition::Matches("email".into(), r"[invalid".into()).evaluate(&ctx));
    }

    // --- Condition: collection ---

    #[test]
    fn test_condition_in() {
        let ctx = PolicyContext::new().with_attr("role", "admin");
        assert!(Condition::In("role".into(), vec!["admin".into(), "root".into()]).evaluate(&ctx));
        assert!(!Condition::In("role".into(), vec!["user".into(), "guest".into()]).evaluate(&ctx));
    }

    #[test]
    fn test_condition_not_in() {
        let ctx = PolicyContext::new().with_attr("role", "user");
        assert!(Condition::NotIn("role".into(), vec!["admin".into(), "root".into()]).evaluate(&ctx));
        assert!(!Condition::NotIn("role".into(), vec!["user".into(), "guest".into()]).evaluate(&ctx));
    }

    // --- Condition: Between / Outside ---

    #[test]
    fn test_condition_between() {
        let ctx = PolicyContext::new().with_attr("level", "5");
        assert!(Condition::Between("level".into(), "1".into(), "9".into()).evaluate(&ctx));
        assert!(!Condition::Between("level".into(), "6".into(), "9".into()).evaluate(&ctx));
    }

    #[test]
    fn test_condition_outside() {
        let ctx = PolicyContext::new().with_attr("level", "z");
        assert!(Condition::Outside("level".into(), "a".into(), "m".into()).evaluate(&ctx));
        assert!(!Condition::Outside("level".into(), "a".into(), "z".into()).evaluate(&ctx));
    }

    // --- Condition: Exists ---

    #[test]
    fn test_condition_exists() {
        let ctx = PolicyContext::new().with_attr("role", "admin");
        assert!(Condition::Exists("role".into()).evaluate(&ctx));
        assert!(!Condition::Exists("missing".into()).evaluate(&ctx));
    }

    #[test]
    fn test_condition_not_exists() {
        let ctx = PolicyContext::new().with_attr("role", "admin");
        assert!(!Condition::NotExists("role".into()).evaluate(&ctx));
        assert!(Condition::NotExists("missing".into()).evaluate(&ctx));
    }

    // --- Condition: logical ---

    #[test]
    fn test_condition_and_all_true() {
        let ctx = PolicyContext::new()
            .with_attr("role", "admin")
            .with_attr("dept", "eng");
        let cond = Condition::And(vec![
            Condition::Eq("role".into(), "admin".into()),
            Condition::Eq("dept".into(), "eng".into()),
        ]);
        assert!(cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_and_one_false() {
        let ctx = PolicyContext::new()
            .with_attr("role", "admin")
            .with_attr("dept", "sales");
        let cond = Condition::And(vec![
            Condition::Eq("role".into(), "admin".into()),
            Condition::Eq("dept".into(), "eng".into()),
        ]);
        assert!(!cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_or_any_true() {
        let ctx = PolicyContext::new().with_attr("role", "user");
        let cond = Condition::Or(vec![
            Condition::Eq("role".into(), "admin".into()),
            Condition::Eq("role".into(), "user".into()),
        ]);
        assert!(cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_or_all_false() {
        let ctx = PolicyContext::new().with_attr("role", "guest");
        let cond = Condition::Or(vec![
            Condition::Eq("role".into(), "admin".into()),
            Condition::Eq("role".into(), "user".into()),
        ]);
        assert!(!cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_not() {
        let ctx = PolicyContext::new().with_attr("role", "user");
        let cond = Condition::Not(Box::new(Condition::Eq("role".into(), "admin".into())));
        assert!(cond.evaluate(&ctx));
    }

    // --- Policy ---

    #[test]
    fn test_policy_new() {
        let policy = Policy::new("test-policy", PolicyEffect::Allow, Condition::Exists("role".into()));
        assert_eq!(policy.name, "test-policy");
        assert_eq!(policy.effect, PolicyEffect::Allow);
        assert!(policy.enabled);
        assert_eq!(policy.resources, vec!["*".to_string()]);
        assert_eq!(policy.subjects, vec!["*".to_string()]);
        assert!(policy.description.is_none());
    }

    #[test]
    fn test_policy_matches_disabled() {
        let mut policy = Policy::new("p", PolicyEffect::Deny, Condition::Exists("role".into()));
        policy.enabled = false;
        let ctx = PolicyContext::new().with_attr("role", "admin");
        assert!(!policy.matches(&ctx));
    }

    #[test]
    fn test_policy_matches_subject() {
        let mut policy = Policy::new("p", PolicyEffect::Allow, Condition::Exists("role".into()));
        policy.subjects = vec!["alice".to_string()];
        let ctx = PolicyContext::new()
            .with_attr("subject.id", "alice")
            .with_attr("resource.id", "key:123")
            .with_attr("role", "admin");
        assert!(policy.matches(&ctx));
    }

    #[test]
    fn test_policy_matches_subject_no_match() {
        let mut policy = Policy::new("p", PolicyEffect::Allow, Condition::Exists("role".into()));
        policy.subjects = vec!["alice".to_string()];
        let ctx = PolicyContext::new()
            .with_attr("subject.id", "bob")
            .with_attr("resource.id", "key:123")
            .with_attr("role", "admin");
        assert!(!policy.matches(&ctx));
    }

    #[test]
    fn test_policy_matches_resource_glob() {
        let mut policy = Policy::new("p", PolicyEffect::Allow, Condition::Exists("role".into()));
        policy.resources = vec!["key:prod-*".to_string()];
        let ctx = PolicyContext::new()
            .with_attr("subject.id", "alice")
            .with_attr("resource.id", "key:prod-payments")
            .with_attr("role", "admin");
        assert!(policy.matches(&ctx));
    }

    #[test]
    fn test_policy_matches_condition_false() {
        let mut policy = Policy::new("p", PolicyEffect::Allow, Condition::Eq("role".into(), "admin".into()));
        policy.resources = vec!["*".to_string()];
        policy.subjects = vec!["*".to_string()];
        let ctx = PolicyContext::new()
            .with_attr("subject.id", "alice")
            .with_attr("resource.id", "key:123")
            .with_attr("role", "user");
        assert!(!policy.matches(&ctx));
    }

    // --- glob_match ---

    #[test]
    fn test_glob_match_star() {
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("key:123", "key:123"));
        assert!(!glob_match("key:123", "key:456"));
    }

    #[test]
    fn test_glob_match_prefix() {
        assert!(glob_match("key:prod-*", "key:prod-payments"));
        assert!(!glob_match("key:prod-*", "key:dev-test"));
    }

    #[test]
    fn test_glob_match_suffix() {
        assert!(glob_match("*-readonly", "key-readonly"));
        assert!(!glob_match("*-readonly", "key-admin"));
    }
}
