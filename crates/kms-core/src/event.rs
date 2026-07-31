//! Event types for audit logging

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Event type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    // Key lifecycle events
    KeyCreated,
    KeyAccessed,
    KeyMaterialAccessed,
    KeyEncrypted,
    KeyDecrypted,
    KeySigned,
    KeyVerified,
    KeyRotated,
    KeyDeleted,
    KeyDestroyed,
    KeyImported,
    KeyExportRequested,
    KeyExported,

    // Policy events
    PolicyCreated,
    PolicyUpdated,
    PolicyDeleted,
    PolicyChanged,
    PolicyEvaluated,

    // Access events
    AccessGranted,
    AccessDenied,

    // System events
    SystemStarted,
    SystemStopped,
    HealthCheck,
    SelfTestPassed,
    SelfTestFailed,

    // Admin events
    AdminLogin,
    AdminLogout,
    ConfigChanged,

    // MFA events
    MfaSetup,
    MfaVerified,
    MfaFailed,
    MfaBackupCodeUsed,

    // API Key events
    ApiKeyCreated,
    ApiKeyRotated,
    ApiKeyRevoked,

    // Rate limit events
    RateLimitTriggered,

    // Session events
    SessionCreated,
    SessionExpired,

    // Backup/Restore events
    BackupCreated,
    BackupRestored,

    // Approval workflow events
    ApprovalRequested,
    ApprovalGranted,
    ApprovalDenied,
}

/// Audit event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unique event identifier
    pub event_id: Uuid,
    /// Event timestamp (UTC)
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: EventType,
    /// Actor (user or service) identifier
    pub actor_id: String,
    /// Actor type (user/service/system)
    pub actor_type: String,
    /// Action performed
    pub action: String,
    /// Resource type
    pub resource_type: String,
    /// Resource identifier
    pub resource_id: Option<String>,
    /// Operation result (success/failure)
    pub result: String,
    /// Additional metadata
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
}

impl Event {
    pub fn new(
        event_type: EventType,
        actor_id: &str,
        actor_type: &str,
        action: &str,
        resource_type: &str,
        resource_id: Option<String>,
        result: &str,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            actor_id: actor_id.to_string(),
            actor_type: actor_type.to_string(),
            action: action.to_string(),
            resource_type: resource_type.to_string(),
            resource_id,
            result: result.to_string(),
            metadata: std::collections::HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: &str, value: serde_json::Value) -> Self {
        self.metadata.insert(key.to_string(), value);
        self
    }
}

impl Event {
    pub fn key_created(key_id: &Uuid, actor_id: &str, spec: &str) -> Self {
        Self::new(
            EventType::KeyCreated,
            actor_id,
            "user",
            "create_key",
            "key",
            Some(key_id.to_string()),
            "success",
        )
        .with_metadata("key_spec", serde_json::json!(spec))
    }

    pub fn key_encrypted(key_id: &Uuid, actor_id: &str, bytes: usize) -> Self {
        Self::new(
            EventType::KeyEncrypted,
            actor_id,
            "user",
            "encrypt",
            "key",
            Some(key_id.to_string()),
            "success",
        )
        .with_metadata("bytes", serde_json::json!(bytes))
    }

    pub fn key_decrypted(key_id: &Uuid, actor_id: &str, bytes: usize) -> Self {
        Self::new(
            EventType::KeyDecrypted,
            actor_id,
            "user",
            "decrypt",
            "key",
            Some(key_id.to_string()),
            "success",
        )
        .with_metadata("bytes", serde_json::json!(bytes))
    }

    pub fn key_signed(key_id: &Uuid, actor_id: &str) -> Self {
        Self::new(
            EventType::KeySigned,
            actor_id,
            "user",
            "sign",
            "key",
            Some(key_id.to_string()),
            "success",
        )
    }

    pub fn key_verified(key_id: &Uuid, actor_id: &str, valid: bool) -> Self {
        Self::new(
            EventType::KeyVerified,
            actor_id,
            "user",
            "verify",
            "key",
            Some(key_id.to_string()),
            if valid { "success" } else { "failure" },
        )
        .with_metadata("valid", serde_json::json!(valid))
    }

    pub fn key_deleted(key_id: &Uuid, actor_id: &str) -> Self {
        Self::new(
            EventType::KeyDeleted,
            actor_id,
            "user",
            "delete_key",
            "key",
            Some(key_id.to_string()),
            "success",
        )
    }

    pub fn key_rotated(key_id: &Uuid, actor_id: &str) -> Self {
        Self::new(
            EventType::KeyRotated,
            actor_id,
            "user",
            "rotate_key",
            "key",
            Some(key_id.to_string()),
            "success",
        )
    }

    pub fn key_imported(key_id: &Uuid, actor_id: &str, format: &str) -> Self {
        Self::new(
            EventType::KeyImported,
            actor_id,
            "user",
            "import_key",
            "key",
            Some(key_id.to_string()),
            "success",
        )
        .with_metadata("key_format", serde_json::json!(format))
    }

    pub fn key_exported(key_id: &Uuid, actor_id: &str, _purpose: &str) -> Self {
        Self::new(
            EventType::KeyExported,
            actor_id,
            "user",
            "export_key",
            "key",
            Some(key_id.to_string()),
            "success",
        )
    }

    pub fn key_material_accessed(key_id: &Uuid, actor_id: &str, operation: &str) -> Self {
        Self::new(
            EventType::KeyMaterialAccessed,
            actor_id,
            "user",
            operation,
            "key",
            Some(key_id.to_string()),
            "success",
        )
    }

    pub fn key_export_requested(key_id: &Uuid, actor_id: &str, format: &str) -> Self {
        Self::new(
            EventType::KeyExportRequested,
            actor_id,
            "user",
            "export_key_request",
            "key",
            Some(key_id.to_string()),
            "success",
        )
        .with_metadata("export_format", serde_json::json!(format))
    }

    pub fn policy_changed(policy_id: &Uuid, actor_id: &str, change_type: &str) -> Self {
        Self::new(
            EventType::PolicyChanged,
            actor_id,
            "user",
            "policy_update",
            "policy",
            Some(policy_id.to_string()),
            "success",
        )
        .with_metadata("change_type", serde_json::json!(change_type))
    }

    pub fn access_denied(actor_id: &str, action: &str, reason: &str) -> Self {
        Self::new(
            EventType::AccessDenied,
            actor_id,
            "user",
            action,
            "policy",
            None,
            "denied",
        )
        .with_metadata("reason", serde_json::json!(reason))
    }

    // MFA events
    pub fn mfa_setup(user_id: &str, method: &str) -> Self {
        Self::new(
            EventType::MfaSetup,
            user_id,
            "user",
            "mfa_setup",
            "mfa",
            None,
            "success",
        )
        .with_metadata("method", serde_json::json!(method))
    }

    pub fn mfa_verified(user_id: &str) -> Self {
        Self::new(
            EventType::MfaVerified,
            user_id,
            "user",
            "mfa_verify",
            "mfa",
            None,
            "success",
        )
    }

    pub fn mfa_failed(user_id: &str, reason: &str) -> Self {
        Self::new(
            EventType::MfaFailed,
            user_id,
            "user",
            "mfa_verify",
            "mfa",
            None,
            "failure",
        )
        .with_metadata("reason", serde_json::json!(reason))
    }

    pub fn mfa_backup_code_used(user_id: &str) -> Self {
        Self::new(
            EventType::MfaBackupCodeUsed,
            user_id,
            "user",
            "mfa_verify_backup",
            "mfa",
            None,
            "success",
        )
    }

    // API Key events
    pub fn api_key_created(key_id: &str, actor_id: &str) -> Self {
        Self::new(
            EventType::ApiKeyCreated,
            actor_id,
            "user",
            "create_api_key",
            "api_key",
            Some(key_id.to_string()),
            "success",
        )
    }

    pub fn api_key_rotated(key_id: &str, actor_id: &str) -> Self {
        Self::new(
            EventType::ApiKeyRotated,
            actor_id,
            "user",
            "rotate_api_key",
            "api_key",
            Some(key_id.to_string()),
            "success",
        )
    }

    pub fn api_key_revoked(key_id: &str, actor_id: &str) -> Self {
        Self::new(
            EventType::ApiKeyRevoked,
            actor_id,
            "user",
            "revoke_api_key",
            "api_key",
            Some(key_id.to_string()),
            "success",
        )
    }

    // Rate limit events
    pub fn rate_limit_triggered(actor_id: &str, tenant_id: &str, limit_type: &str) -> Self {
        Self::new(
            EventType::RateLimitTriggered,
            actor_id,
            "user",
            "rate_limit",
            "rate_limit",
            None,
            "denied",
        )
        .with_metadata("tenant_id", serde_json::json!(tenant_id))
        .with_metadata("limit_type", serde_json::json!(limit_type))
    }

    // Session events
    pub fn session_created(session_id: &Uuid, actor_id: &str) -> Self {
        Self::new(
            EventType::SessionCreated,
            actor_id,
            "user",
            "create_session",
            "session",
            Some(session_id.to_string()),
            "success",
        )
    }

    pub fn session_expired(session_id: &Uuid, actor_id: &str) -> Self {
        Self::new(
            EventType::SessionExpired,
            actor_id,
            "user",
            "session_expired",
            "session",
            Some(session_id.to_string()),
            "success",
        )
    }

    // Backup events
    pub fn backup_created(backup_id: &str, actor_id: &str, key_count: usize) -> Self {
        Self::new(
            EventType::BackupCreated,
            actor_id,
            "user",
            "create_backup",
            "backup",
            Some(backup_id.to_string()),
            "success",
        )
        .with_metadata("key_count", serde_json::json!(key_count))
    }

    pub fn backup_restored(backup_id: &str, actor_id: &str, key_count: usize) -> Self {
        Self::new(
            EventType::BackupRestored,
            actor_id,
            "user",
            "restore_backup",
            "backup",
            Some(backup_id.to_string()),
            "success",
        )
        .with_metadata("key_count", serde_json::json!(key_count))
    }

    // Approval workflow events
    pub fn approval_requested(request_id: &Uuid, actor_id: &str, operation: &str) -> Self {
        Self::new(
            EventType::ApprovalRequested,
            actor_id,
            "user",
            "request_approval",
            "approval",
            Some(request_id.to_string()),
            "pending",
        )
        .with_metadata("operation", serde_json::json!(operation))
    }

    pub fn approval_granted(request_id: &Uuid, approver_id: &str) -> Self {
        Self::new(
            EventType::ApprovalGranted,
            approver_id,
            "user",
            "approve_request",
            "approval",
            Some(request_id.to_string()),
            "success",
        )
    }

    pub fn approval_denied(request_id: &Uuid, approver_id: &str, reason: &str) -> Self {
        Self::new(
            EventType::ApprovalDenied,
            approver_id,
            "user",
            "deny_request",
            "approval",
            Some(request_id.to_string()),
            "denied",
        )
        .with_metadata("reason", serde_json::json!(reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All EventType variants should be constructable via Event::new
    #[test]
    fn test_all_event_types_constructable() {
        let id = Uuid::new_v4();
        let id_str = id.to_string();

        // Key lifecycle
        Event::new(
            EventType::KeyCreated,
            "actor",
            "user",
            "create",
            "key",
            Some(id_str.clone()),
            "success",
        );
        Event::new(
            EventType::KeyAccessed,
            "actor",
            "user",
            "access",
            "key",
            Some(id_str.clone()),
            "success",
        );
        Event::new(
            EventType::KeyMaterialAccessed,
            "actor",
            "user",
            "access",
            "key",
            Some(id_str.clone()),
            "success",
        );
        Event::new(
            EventType::KeyEncrypted,
            "actor",
            "user",
            "encrypt",
            "key",
            Some(id_str.clone()),
            "success",
        );
        Event::new(
            EventType::KeyDecrypted,
            "actor",
            "user",
            "decrypt",
            "key",
            Some(id_str.clone()),
            "success",
        );
        Event::new(
            EventType::KeySigned,
            "actor",
            "user",
            "sign",
            "key",
            Some(id_str.clone()),
            "success",
        );
        Event::new(
            EventType::KeyVerified,
            "actor",
            "user",
            "verify",
            "key",
            Some(id_str.clone()),
            "success",
        );
        Event::new(
            EventType::KeyRotated,
            "actor",
            "user",
            "rotate",
            "key",
            Some(id_str.clone()),
            "success",
        );
        Event::new(
            EventType::KeyDeleted,
            "actor",
            "user",
            "delete",
            "key",
            Some(id_str.clone()),
            "success",
        );
        Event::new(
            EventType::KeyDestroyed,
            "actor",
            "user",
            "destroy",
            "key",
            Some(id_str),
            "success",
        );
    }

    /// Event builder methods produce correct EventType
    #[test]
    fn test_event_builders() {
        let id = Uuid::new_v4();

        let ev = Event::key_created(&id, "user1", "AES-256-GCM");
        assert_eq!(ev.event_type, EventType::KeyCreated);

        let ev = Event::key_encrypted(&id, "user1", 256);
        assert_eq!(ev.event_type, EventType::KeyEncrypted);

        let ev = Event::key_decrypted(&id, "user1", 256);
        assert_eq!(ev.event_type, EventType::KeyDecrypted);

        let ev = Event::key_rotated(&id, "user1");
        assert_eq!(ev.event_type, EventType::KeyRotated);

        let ev = Event::key_deleted(&id, "user1");
        assert_eq!(ev.event_type, EventType::KeyDeleted);

        let ev = Event::new(
            EventType::KeyDestroyed,
            "user1",
            "user",
            "destroy",
            "key",
            Some(id.to_string()),
            "success",
        );
        assert_eq!(ev.event_type, EventType::KeyDestroyed);

        let ev = Event::access_denied("user1", "key_manager", "no_permission");
        assert_eq!(ev.event_type, EventType::AccessDenied);

        let ev = Event::new(
            EventType::AccessGranted,
            "user1",
            "user",
            "access",
            "key",
            Some(id.to_string()),
            "success",
        );
        assert_eq!(ev.event_type, EventType::AccessGranted);
    }

    /// Event serializes to JSON correctly
    #[test]
    fn test_event_json_roundtrip() {
        let id = Uuid::new_v4();
        let event = Event::key_created(&id, "user1", "AES-256-GCM")
            .with_metadata("algorithm", serde_json::json!("AES-256-GCM"));

        let json = serde_json::to_string(&event).unwrap();
        let parsed: Event = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.event_type, EventType::KeyCreated);
        assert_eq!(parsed.actor_id, "user1");
        assert_eq!(parsed.resource_id, Some(id.to_string()));
        assert_eq!(
            parsed.metadata.get("algorithm"),
            Some(&serde_json::json!("AES-256-GCM"))
        );
    }

    /// EventType serializes as SCREAMING_SNAKE_CASE
    #[test]
    fn test_event_type_json_format() {
        let json = serde_json::to_string(&EventType::KeyCreated).unwrap();
        assert_eq!(json, "\"KEY_CREATED\"");

        let json = serde_json::to_string(&EventType::MfaVerified).unwrap();
        assert_eq!(json, "\"MFA_VERIFIED\"");

        let json = serde_json::to_string(&EventType::ApiKeyCreated).unwrap();
        assert_eq!(json, "\"API_KEY_CREATED\"");
    }

    /// Event with metadata preserves key-value pairs
    #[test]
    fn test_event_metadata_accumulates() {
        let id = Uuid::new_v4();
        let event = Event::key_encrypted(&id, "user1", 256)
            .with_metadata("key_spec", serde_json::json!("AES-256-GCM"))
            .with_metadata("ciphertext_len", serde_json::json!(256));

        assert_eq!(event.metadata.len(), 3); // key_encrypted adds "bytes", plus 2 more
        assert_eq!(
            event.metadata.get("key_spec"),
            Some(&serde_json::json!("AES-256-GCM"))
        );
        assert_eq!(
            event.metadata.get("ciphertext_len"),
            Some(&serde_json::json!(256))
        );
        assert_eq!(event.metadata.get("bytes"), Some(&serde_json::json!(256)));
    }

    /// MFA events have correct types
    #[test]
    fn test_mfa_event_builders() {
        let ev = Event::mfa_setup("user1", "totp");
        assert_eq!(ev.event_type, EventType::MfaSetup);

        let ev = Event::mfa_verified("user1");
        assert_eq!(ev.event_type, EventType::MfaVerified);

        let ev = Event::mfa_failed("user1", "bad_code");
        assert_eq!(ev.event_type, EventType::MfaFailed);

        let ev = Event::mfa_backup_code_used("user1");
        assert_eq!(ev.event_type, EventType::MfaBackupCodeUsed);
    }

    /// API key events have correct types
    #[test]
    fn test_api_key_event_builders() {
        let ev = Event::api_key_created("key-1", "admin1");
        assert_eq!(ev.event_type, EventType::ApiKeyCreated);

        let ev = Event::api_key_rotated("key-1", "admin1");
        assert_eq!(ev.event_type, EventType::ApiKeyRotated);

        let ev = Event::api_key_revoked("key-1", "admin1");
        assert_eq!(ev.event_type, EventType::ApiKeyRevoked);
    }

    /// System events constructed via Event::new have correct types
    #[test]
    fn test_system_event_builders() {
        let ev = Event::new(
            EventType::SystemStarted,
            "system",
            "system",
            "start",
            "system",
            None,
            "success",
        );
        assert_eq!(ev.event_type, EventType::SystemStarted);

        let ev = Event::new(
            EventType::SystemStopped,
            "system",
            "system",
            "stop",
            "system",
            None,
            "success",
        );
        assert_eq!(ev.event_type, EventType::SystemStopped);

        let ev = Event::new(
            EventType::HealthCheck,
            "system",
            "system",
            "health_check",
            "system",
            None,
            "success",
        );
        assert_eq!(ev.event_type, EventType::HealthCheck);
    }
}
