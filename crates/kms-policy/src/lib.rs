//! kms-policy - Policy-Based Access Control engine
//!
//! Provides PBAC policy evaluation with RBAC/ABAC support.
//!
//! ## Architecture: Two-Layer Condition Model
//!
//! This crate uses a two-layer design for conditions:
//!
//! - **API layer** (`kms_policy::Policy`): Stores conditions as `serde_json::Value`
//!   This provides maximum flexibility — clients can send any valid JSON structure,
//!   and the API doesn't need to be updated when new condition operators are added.
//!
//! - **Business logic layer** (`kms_core::Policy` / `kms_core::Condition`): Uses a
//!   typed `Condition` enum for compile-time safety and easier testing within the
//!   KMS core. This is used for internal policy evaluation.
//!
//! The bridge is [`PBACEngine::evaluate_condition()`] in `engine.rs`, which parses
//! `serde_json::Value` at runtime into operator/action pairs. This decoupled design
//! allows the REST API to accept arbitrary JSON conditions while the internal logic
//! uses typed representations.
//!
//! ## Example JSON Condition
//!
//! ```json
//! {
//!   "operator": "and",
//!   "args": [
//!     {"operator": "eq", "attribute": "role", "value": "admin"},
//!     {"operator": "time_range", "start": "09:00", "end": "17:00"}
//!   ]
//! }
//! ```
//!
//! Supported operators: `always`, `never`, `eq`, `ne`, `gt`, `lt`, `in`, `not_in`,
//! `and`, `or`, `time_range`, `not_expired`, `matches`, etc.

pub mod engine;

pub use engine::{PBACEngine, TimeSkewAlert, TimeSkewStatus, TimeValidator};
use kms_core::PolicyEffect;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Policy for storage / REST API layer.
///
/// This type stores the `condition` field as `serde_json::Value` to accept
/// arbitrary JSON from API clients. See module-level documentation for the
/// two-layer condition design.
///
/// For internal policy evaluation with typed conditions, see `kms_core::Policy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub effect: PolicyEffect,
    /// Raw JSON condition from API. Evaluated by [`PBACEngine::evaluate_condition()`].
    /// Format: `{"operator": "...", "attribute": "...", "value": ...}` or
    /// `{"operator": "and", "args": [...]}` for logical combinations.
    pub condition: serde_json::Value,
    pub resources: Vec<String>,
    pub subjects: Vec<String>,
    pub enabled: bool,
}

/// Access decision
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum Decision {
    #[default]
    Deny,
    Allow,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Allow => write!(f, "allow"),
            Decision::Deny => write!(f, "deny"),
        }
    }
}

/// Access context for policy evaluation
#[derive(Debug, Clone)]
pub struct AccessContext {
    subject_id: String,
    subject_type: String,
    subject_roles: Vec<String>,
    subject_attrs: std::collections::HashMap<String, serde_json::Value>,
    resource_id: String,
    resource_type: String,
    action: String,
    environment: std::collections::HashMap<String, serde_json::Value>,
}

impl AccessContext {
    pub fn new(subject_id: &str, action: &str, resource_id: &str) -> Self {
        Self {
            subject_id: subject_id.to_string(),
            subject_type: "user".to_string(),
            subject_roles: vec![],
            subject_attrs: std::collections::HashMap::new(),
            resource_id: resource_id.to_string(),
            resource_type: "key".to_string(),
            action: action.to_string(),
            environment: std::collections::HashMap::new(),
        }
    }

    pub fn with_subject_type(mut self, subject_type: &str) -> Self {
        self.subject_type = subject_type.to_string();
        self
    }

    pub fn with_roles(mut self, roles: Vec<&str>) -> Self {
        self.subject_roles = roles.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_resource_type(mut self, resource_type: &str) -> Self {
        self.resource_type = resource_type.to_string();
        self
    }

    pub fn with_env(mut self, key: &str, value: serde_json::Value) -> Self {
        self.environment.insert(key.to_string(), value);
        self
    }

    pub fn with_attr(mut self, key: &str, value: serde_json::Value) -> Self {
        self.subject_attrs.insert(key.to_string(), value);
        self
    }

    pub fn to_policy_context(&self) -> kms_core::policy::PolicyContext {
        use kms_core::policy::PolicyContext;
        let mut ctx = PolicyContext::new();

        ctx.attributes
            .insert("subject.id".to_string(), serde_json::json!(self.subject_id));
        ctx.attributes.insert(
            "subject.type".to_string(),
            serde_json::json!(self.subject_type),
        );
        ctx.attributes.insert(
            "resource.id".to_string(),
            serde_json::json!(self.resource_id),
        );
        ctx.attributes.insert(
            "resource.type".to_string(),
            serde_json::json!(self.resource_type),
        );
        ctx.attributes
            .insert("action".to_string(), serde_json::json!(self.action));

        if let Ok(roles) = serde_json::to_value(&self.subject_roles) {
            ctx.attributes.insert("subject.roles".to_string(), roles);
        }

        for (k, v) in &self.subject_attrs {
            ctx.attributes.insert(format!("subject.{}", k), v.clone());
        }

        for (k, v) in &self.environment {
            ctx.attributes.insert(format!("env.{}", k), v.clone());
        }

        ctx
    }
}
