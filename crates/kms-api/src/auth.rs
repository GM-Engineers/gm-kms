//! Authentication middleware for KMS API
//!
//! Provides API Key authentication with three-officer separation (三员分立)
//! as required by GB/T 22239-2019 (等保三级).
//!
//! ## Role Separation
//! - **ReadOnly**: List and get key metadata only
//! - **Operator**: Encrypt, decrypt, sign, verify, hash, DH key exchange
//! - **KeyAdmin**: Key lifecycle management (create/delete/rotate/import/export)
//! - **SecurityOfficer**: Policy management, API key management, MFA, approval, audit view
//! - **AuditAdmin**: Audit log viewing and export only
//!
//! No single role possesses all permissions - roles are mutually exclusive.

use axum::{
    extract::{FromRequestParts, Request},
    http::{StatusCode, request::Parts},
    middleware::Next,
    response::Response,
};
use bitflags::bitflags;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use thiserror::Error;

/// Caller identity extracted from API key for audit trail.
/// Injected into request extensions by auth middleware, used via `FromRequestParts`.
#[derive(Debug, Clone)]
pub struct CallerId {
    pub key_id: String,
}

impl CallerId {
    /// Fallback value used when no API key is attached (e.g., health endpoint).
    pub const UNKNOWN: &'static str = "anonymous";
}

impl<S: Send + Sync> FromRequestParts<S> for CallerId {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<CallerId>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}

/// Authentication errors
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("API key not configured: environment variable {0} is not set")]
    ApiKeyNotConfigured(String),

    #[error("configuration error: {0}")]
    Configuration(String),
}

pub type AuthResult<T> = std::result::Result<T, AuthError>;

bitflags! {
    /// Fine-grained permissions for KMS operations.
    ///
    /// Each role maps to a distinct set of these permissions.
    /// Route handlers check for specific Permission bits, not roles.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Permission: u32 {
        /// Key read operations
        const LIST_KEYS   = 1 << 0;
        const GET_KEY     = 1 << 1;

        /// Crypto operations
        const ENCRYPT     = 1 << 2;
        const DECRYPT     = 1 << 3;
        const SIGN        = 1 << 4;
        const VERIFY      = 1 << 5;
        const HASH        = 1 << 6;
        const DH_DERIVE   = 1 << 7;

        /// Key lifecycle management
        const CREATE_KEY  = 1 << 8;
        const DELETE_KEY  = 1 << 9;
        const ROTATE_KEY  = 1 << 10;
        const IMPORT_KEY  = 1 << 11;
        const EXPORT_KEY  = 1 << 12;

        /// Administration
        const MANAGE_POLICY    = 1 << 13;
        const VIEW_AUDIT       = 1 << 14;
        const EXPORT_AUDIT     = 1 << 15;
        const MANAGE_API_KEYS  = 1 << 16;
        const MANAGE_MFA       = 1 << 17;
        const APPROVE_ACTION   = 1 << 18;
    }
}

impl Permission {
    /// Any authenticated key — used for endpoints that all roles can access
    /// (e.g., creating an approval request, checking health via auth endpoint).
    /// A key must at minimum have LIST_KEYS to be considered authenticated.
    pub const AUTHENTICATED: Self = Permission::LIST_KEYS;
}

/// API Key role — determines which set of permissions a key holder has.
///
/// Implements three-officer separation (三员分立):
/// - **System Admin** → `KeyAdmin`: manages keys but cannot approve or audit
/// - **Security Admin** → `SecurityOfficer`: approves, manages policies, but cannot operate keys
/// - **Audit Admin** → `AuditAdmin`: views/export audit logs only
///
/// `ReadOnly` and `Operator` are operational roles with no admin privileges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ApiKeyPermission {
    /// Read-only access (list, get keys)
    ReadOnly = 0,
    /// Crypto operation access (encrypt, decrypt, sign, verify, hash, dh)
    Operator = 1,
    /// Key lifecycle management (create, delete, rotate, import, export)
    KeyAdmin = 2,
    /// Security administration (policy, API keys, MFA, approval, audit view)
    SecurityOfficer = 3,
    /// Audit administration (audit log view and export only)
    AuditAdmin = 4,
}

impl ApiKeyPermission {
    /// Get the Permission bitmask for this role.
    pub fn permissions(&self) -> Permission {
        match self {
            ApiKeyPermission::ReadOnly => Permission::LIST_KEYS | Permission::GET_KEY,
            ApiKeyPermission::Operator => {
                Permission::LIST_KEYS
                    | Permission::GET_KEY
                    | Permission::ENCRYPT
                    | Permission::DECRYPT
                    | Permission::SIGN
                    | Permission::VERIFY
                    | Permission::HASH
                    | Permission::DH_DERIVE
            }
            ApiKeyPermission::KeyAdmin => {
                Permission::LIST_KEYS
                    | Permission::GET_KEY
                    | Permission::ENCRYPT
                    | Permission::DECRYPT
                    | Permission::SIGN
                    | Permission::VERIFY
                    | Permission::HASH
                    | Permission::DH_DERIVE
                    | Permission::CREATE_KEY
                    | Permission::DELETE_KEY
                    | Permission::ROTATE_KEY
                    | Permission::IMPORT_KEY
                    | Permission::EXPORT_KEY
            }
            ApiKeyPermission::SecurityOfficer => {
                Permission::LIST_KEYS
                    | Permission::GET_KEY
                    | Permission::VIEW_AUDIT
                    | Permission::MANAGE_POLICY
                    | Permission::MANAGE_API_KEYS
                    | Permission::MANAGE_MFA
                    | Permission::APPROVE_ACTION
            }
            ApiKeyPermission::AuditAdmin => Permission::VIEW_AUDIT | Permission::EXPORT_AUDIT,
        }
    }

    /// Check if this role satisfies the required permission.
    pub fn satisfies(&self, required: Permission) -> bool {
        self.permissions().contains(required)
    }
}

impl std::fmt::Display for ApiKeyPermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiKeyPermission::ReadOnly => write!(f, "read-only"),
            ApiKeyPermission::Operator => write!(f, "operator"),
            ApiKeyPermission::KeyAdmin => write!(f, "key-admin"),
            ApiKeyPermission::SecurityOfficer => write!(f, "security-officer"),
            ApiKeyPermission::AuditAdmin => write!(f, "audit-admin"),
        }
    }
}

/// API Key with role assignment
#[derive(Debug)]
pub struct ApiKey {
    /// The API key secret (zeroized on Drop)
    pub secret: zeroize::Zeroizing<String>,
    /// Role / permission level for this key
    pub permission: ApiKeyPermission,
    /// When the key was created
    pub created_at: DateTime<Utc>,
    /// When the key expires (None = never expires)
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether the key has been revoked
    pub revoked: bool,
    /// Key ID for rotation tracking
    pub key_id: String,
    /// Failed login attempt counter
    failed_attempts: u32,
    /// When the key was locked due to too many failures
    locked_until: Option<DateTime<Utc>>,
}

impl Clone for ApiKey {
    fn clone(&self) -> Self {
        Self {
            secret: zeroize::Zeroizing::new(self.secret.as_str().to_string()),
            permission: self.permission,
            created_at: self.created_at,
            expires_at: self.expires_at,
            revoked: self.revoked,
            key_id: self.key_id.clone(),
            failed_attempts: self.failed_attempts,
            locked_until: self.locked_until,
        }
    }
}

impl ApiKey {
    /// Create a new API key with the given role
    pub fn new(secret: String, permission: ApiKeyPermission) -> Self {
        Self {
            secret: secret.into(),
            permission,
            created_at: Utc::now(),
            expires_at: None,
            revoked: false,
            key_id: uuid::Uuid::new_v4().to_string(),
            failed_attempts: 0,
            locked_until: None,
        }
    }

    /// Create a read-only API key
    pub fn read_only(secret: String) -> Self {
        Self::new(secret, ApiKeyPermission::ReadOnly)
    }

    /// Create an operator API key (encrypt, decrypt, sign, verify)
    pub fn operator(secret: String) -> Self {
        Self::new(secret, ApiKeyPermission::Operator)
    }

    /// Create a key admin API key (key lifecycle management)
    pub fn key_admin(secret: String) -> Self {
        Self::new(secret, ApiKeyPermission::KeyAdmin)
    }

    /// Create a security officer API key (policy, API keys, MFA, approval)
    pub fn security_officer(secret: String) -> Self {
        Self::new(secret, ApiKeyPermission::SecurityOfficer)
    }

    /// Create an audit admin API key (audit log view and export only)
    pub fn audit_admin(secret: String) -> Self {
        Self::new(secret, ApiKeyPermission::AuditAdmin)
    }

    /// Create a new API key with expiration
    pub fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Create a new API key with a specific key ID
    pub fn with_key_id(mut self, key_id: String) -> Self {
        self.key_id = key_id;
        self
    }

    /// Check if the key is currently valid (not expired and not revoked)
    pub fn is_valid(&self) -> bool {
        !self.revoked && self.expires_at.is_none_or(|exp| Utc::now() < exp)
    }

    /// Check if the key is locked due to too many failed attempts
    pub fn is_locked(&self) -> bool {
        self.locked_until.is_some_and(|until| Utc::now() < until)
    }

    /// Record a failed login attempt
    pub fn record_failed_attempt(&mut self) {
        self.failed_attempts += 1;
    }

    /// Record a successful login (reset failed attempts)
    pub fn record_successful_login(&mut self) {
        self.failed_attempts = 0;
        self.locked_until = None;
    }

    /// Get the current failed attempt count
    pub fn failed_attempts(&self) -> u32 {
        self.failed_attempts
    }

    /// Lock the key for a specified duration
    pub fn lock(&mut self, duration: chrono::Duration) {
        self.locked_until = Some(Utc::now() + duration);
    }
}

/// API Key configuration
pub struct ApiKeyConfig {
    /// Header name for API key
    pub header_name: String,
    /// Valid API keys with their permission levels (Mutex for interior mutability)
    valid_keys: std::sync::Arc<parking_lot::Mutex<Vec<ApiKey>>>,
    /// Maximum failed attempts before lockout
    max_failed_attempts: u32,
    /// Lockout duration
    lockout_duration: chrono::Duration,
    /// Enable brute force protection
    brute_force_protection: bool,
    /// Counter for unknown/invalid API key attempts (anti-enumeration)
    unknown_key_attempts: u32,
    /// Timestamp of the last unknown key attempt (for decay)
    unknown_key_last_attempt: Option<chrono::DateTime<chrono::Utc>>,
}

impl Clone for ApiKeyConfig {
    fn clone(&self) -> Self {
        Self {
            header_name: self.header_name.clone(),
            valid_keys: self.valid_keys.clone(),
            max_failed_attempts: self.max_failed_attempts,
            lockout_duration: self.lockout_duration,
            brute_force_protection: self.brute_force_protection,
            unknown_key_attempts: self.unknown_key_attempts,
            unknown_key_last_attempt: self.unknown_key_last_attempt,
        }
    }
}

impl std::fmt::Debug for ApiKeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyConfig")
            .field("header_name", &self.header_name)
            .field("valid_keys_count", &self.valid_keys.lock().len())
            .field("max_failed_attempts", &self.max_failed_attempts)
            .field("lockout_duration", &self.lockout_duration)
            .field("brute_force_protection", &self.brute_force_protection)
            .finish_non_exhaustive()
    }
}

impl ApiKeyConfig {
    /// Create new config with single API key (read-only by default)
    pub fn new(header_name: &str, api_key: &str) -> Self {
        Self {
            header_name: header_name.to_string(),
            valid_keys: std::sync::Arc::new(parking_lot::Mutex::new(vec![ApiKey::read_only(
                api_key.to_string(),
            )])),
            max_failed_attempts: 5,
            lockout_duration: chrono::Duration::minutes(15),
            brute_force_protection: true,
            unknown_key_attempts: 0,
            unknown_key_last_attempt: None,
        }
    }

    /// Create new config with single API key and specific role
    pub fn with_role(header_name: &str, api_key: &str, role: ApiKeyPermission) -> Self {
        Self {
            header_name: header_name.to_string(),
            valid_keys: std::sync::Arc::new(parking_lot::Mutex::new(vec![ApiKey::new(
                api_key.to_string(),
                role,
            )])),
            max_failed_attempts: 5,
            lockout_duration: chrono::Duration::minutes(15),
            brute_force_protection: true,
            unknown_key_attempts: 0,
            unknown_key_last_attempt: None,
        }
    }

    /// Create from environment variable (requires the environment variable to be set)
    ///
    /// # Errors
    /// Returns `AuthError::ApiKeyNotConfigured` if the environment variable is not set.
    /// Production deployments must set `KMS_API_KEY` to a secure value.
    pub fn from_env(header_name: &str, env_var: &str) -> AuthResult<Self> {
        let api_key = std::env::var(env_var)
            .map_err(|_| AuthError::ApiKeyNotConfigured(env_var.to_string()))?;

        if api_key.is_empty() {
            return Err(AuthError::Configuration(
                "API key cannot be empty".to_string(),
            ));
        }

        if api_key == "dev-api-key" {
            // Block insecure default key unless explicitly in dev mode
            if std::env::var("KMS_DEV_MODE").as_deref() != Ok("1") {
                return Err(AuthError::Configuration(
                    "Insecure default 'dev-api-key' rejected. Set KMS_API_KEY to a secure value, or set KMS_DEV_MODE=1 for development.".to_string(),
                ));
            }
            tracing::warn!(
                "⚠️  DEV MODE: Using insecure 'dev-api-key'. Set {} to a secure value for production.",
                env_var
            );
        }

        // Dev mode: default key gets KeyAdmin role for full development access
        // Production: override via KMS_API_KEY_ROLE env var
        let role = std::env::var("KMS_API_KEY_ROLE")
            .ok()
            .and_then(|r| match r.as_str() {
                "read-only" => Some(ApiKeyPermission::ReadOnly),
                "operator" => Some(ApiKeyPermission::Operator),
                "key-admin" => Some(ApiKeyPermission::KeyAdmin),
                "security-officer" => Some(ApiKeyPermission::SecurityOfficer),
                "audit-admin" => Some(ApiKeyPermission::AuditAdmin),
                _ => None,
            })
            .unwrap_or_else(|| {
                if api_key == "dev-api-key" {
                    // Dev mode default: KeyAdmin for full access (KMS_DEV_MODE=1 required above)
                    ApiKeyPermission::KeyAdmin
                } else {
                    // Production default: Operator (least privilege for single-key setups)
                    ApiKeyPermission::Operator
                }
            });

        Ok(Self::with_role(header_name, &api_key, role))
    }

    /// Create from multiple API keys with roles
    pub fn with_keys(keys: Vec<ApiKey>) -> Self {
        Self {
            header_name: "x-api-key".to_string(),
            valid_keys: std::sync::Arc::new(parking_lot::Mutex::new(keys)),
            max_failed_attempts: 5,
            lockout_duration: chrono::Duration::minutes(15),
            brute_force_protection: true,
            unknown_key_attempts: 0,
            unknown_key_last_attempt: None,
        }
    }

    /// Disable brute force protection (for testing scenarios)
    pub fn disable_brute_force_protection(&mut self) {
        self.brute_force_protection = false;
    }

    /// Validate an API key and return its role
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    /// Only returns permission if the key is valid (not expired, not revoked, not locked).
    pub fn validate(&self, key: &str) -> Option<ApiKeyPermission> {
        let key_bytes = key.as_bytes();
        self.valid_keys
            .lock()
            .iter()
            .find(|k| k.secret.as_bytes().ct_eq(key_bytes).into() && k.is_valid() && !k.is_locked())
            .map(|k| k.permission)
    }

    /// Validate and return both permission and identity (key_id) for audit trail.
    /// Use this when the caller identity must be recorded in audit events.
    pub fn validate_with_identity(&self, key: &str) -> Option<(ApiKeyPermission, String)> {
        let key_bytes = key.as_bytes();
        self.valid_keys
            .lock()
            .iter()
            .find(|k| k.secret.as_bytes().ct_eq(key_bytes).into() && k.is_valid() && !k.is_locked())
            .map(|k| (k.permission, k.key_id.clone()))
    }

    /// Record a failed authentication attempt for a key.
    ///
    /// For known keys: increment the key's failed-attempt counter and lock if threshold reached.
    /// For unknown keys: increment a global counter and apply a progressive delay to thwart
    /// enumeration attacks (P2-4). The delay grows linearly: 50ms × attempts, capped at 2s.
    /// The counter decays every 5 minutes to prevent permanent lockout from transient scans.
    pub async fn record_failed_attempt(&mut self, key: &str) {
        if !self.brute_force_protection {
            return;
        }

        // Decay unknown-key counter if last attempt was > 5 minutes ago
        if let Some(last) = self.unknown_key_last_attempt {
            let elapsed = chrono::Utc::now() - last;
            if elapsed > chrono::Duration::minutes(5) {
                self.unknown_key_attempts = 0;
            }
        }

        let key_bytes = key.as_bytes();
        let mut found = false;
        for k in self.valid_keys.lock().iter_mut() {
            if k.secret.as_bytes().ct_eq(key_bytes).into() {
                k.record_failed_attempt();
                if k.failed_attempts() >= self.max_failed_attempts {
                    k.lock(self.lockout_duration);
                    tracing::warn!(
                        "API key {} locked due to {} failed attempts",
                        k.key_id,
                        k.failed_attempts()
                    );
                }
                found = true;
                break;
            }
        }

        if !found {
            self.unknown_key_attempts += 1;
            self.unknown_key_last_attempt = Some(chrono::Utc::now());
            let delay_ms = (self.unknown_key_attempts as u64 * 50).min(2000);
            tracing::info!(
                unknown_attempts = self.unknown_key_attempts,
                delay_ms,
                "Unknown API key rejected — applying progressive delay"
            );
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
    }

    /// Record a successful authentication (resets failed attempts)
    pub fn record_successful_login(&mut self, key: &str) {
        let key_bytes = key.as_bytes();
        if let Some(k) = self
            .valid_keys
            .lock()
            .iter_mut()
            .find(|k| k.secret.as_bytes().ct_eq(key_bytes).into())
        {
            k.record_successful_login();
        }
    }

    /// Check if a key is locked
    pub fn is_locked(&self, key: &str) -> bool {
        let key_bytes = key.as_bytes();
        self.valid_keys
            .lock()
            .iter()
            .find(|k| k.secret.as_bytes().ct_eq(key_bytes).into())
            .map(|k| k.is_locked())
            .unwrap_or(false)
    }

    /// Check if an API key is valid (any role, not expired, not revoked)
    pub fn is_valid(&self, key: &str) -> bool {
        self.validate(key).is_some()
    }

    /// Check if an API key has the required Permission.
    /// `required` is empty (`Permission::empty()`) to mean "any authenticated key".
    pub fn has_permission(&self, key: &str, required: Permission) -> bool {
        self.validate(key)
            .map(|p| required.is_empty() || p.satisfies(required))
            .unwrap_or(false)
    }

    /// Look up the key_id for a given key (for audit trail).
    /// Returns the key_id even for locked/revoked keys (identity lookup, not auth).
    pub fn lookup_key_id(&self, key: &str) -> Option<String> {
        let key_bytes = key.as_bytes();
        self.valid_keys
            .lock()
            .iter()
            .find(|k| k.secret.as_bytes().ct_eq(key_bytes).into())
            .map(|k| k.key_id.clone())
    }

    /// Add a new API key to the config
    pub fn add_key(&self, key: ApiKey) {
        self.valid_keys.lock().push(key);
    }

    /// Revoke an API key by its key_id
    pub fn revoke_key(&self, key_id: &str) -> bool {
        if let Some(key) = self
            .valid_keys
            .lock()
            .iter_mut()
            .find(|k| k.key_id == key_id)
        {
            key.revoked = true;
            true
        } else {
            false
        }
    }

    /// Lock an API key by its key_id (H-2: MFA-API Key linkage).
    /// Called when MFA failures trigger a lockout to also lock the API key.
    pub fn lock_key_by_id(&self, key_id: &str) {
        if let Some(key) = self
            .valid_keys
            .lock()
            .iter_mut()
            .find(|k| k.key_id == key_id)
        {
            key.lock(self.lockout_duration);
            tracing::warn!(
                key_id = %key_id,
                lockout_duration_secs = self.lockout_duration.num_seconds(),
                "API key locked via MFA failure linkage"
            );
        }
    }

    /// Rotate an API key: revoke old key and add new key with grace period
    ///
    /// The old key remains valid for the duration of `grace_period` to allow
    /// clients to transition to the new key.
    ///
    /// Returns the new key if successful, None if old key not found.
    pub fn rotate_key(
        &self,
        old_key_id: &str,
        new_secret: String,
        new_permission: ApiKeyPermission,
        grace_period: chrono::Duration,
    ) -> Option<ApiKey> {
        {
            let mut guard = self.valid_keys.lock();
            let old_key = guard.iter_mut().find(|k| k.key_id == old_key_id)?;
            old_key.expires_at = Some(Utc::now() + grace_period);
        }

        let new_key =
            ApiKey::new(new_secret, new_permission).with_key_id(format!("{}-rotated", old_key_id));

        self.valid_keys.lock().push(new_key.clone());
        Some(new_key)
    }

    /// List all valid (non-revoked, non-expired) API keys (cloned for Mutex safety)
    pub fn list_valid_keys(&self) -> Vec<ApiKey> {
        self.valid_keys
            .lock()
            .iter()
            .filter(|k| k.is_valid())
            .cloned()
            .collect()
    }

    /// Get key metadata (without secret) by key_id
    pub fn get_key_metadata(&self, key_id: &str) -> Option<ApiKeyMetadata> {
        self.valid_keys
            .lock()
            .iter()
            .find(|k| k.key_id == key_id)
            .map(|k| ApiKeyMetadata {
                key_id: k.key_id.clone(),
                permission: k.permission,
                created_at: k.created_at,
                expires_at: k.expires_at,
                revoked: k.revoked,
                is_valid: k.is_valid(),
            })
    }
}

/// API Key metadata (without the secret)
#[derive(Debug, Clone)]
pub struct ApiKeyMetadata {
    pub key_id: String,
    pub permission: ApiKeyPermission,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    pub is_valid: bool,
}

// ── Middleware ──────────────────────────────────────────────────────────

/// Authentication middleware that checks for a specific Permission.
///
/// This is the primary middleware factory. Use `require_permission()`
/// to create middleware for specific endpoint requirements.
async fn auth_middleware_with_permission(
    request: Request,
    next: Next,
    required: Permission,
) -> Result<Response, StatusCode> {
    let config = request.extensions().get::<Arc<ApiKeyConfig>>().cloned();

    match config {
        Some(config) => {
            let header_name = config.header_name.to_lowercase();
            let api_key = request
                .headers()
                .get(&header_name)
                .and_then(|v| v.to_str().ok());

            match api_key {
                Some(key) => {
                    // Extract identity for audit trail (P2-1 fix)
                    let key_id = config.lookup_key_id(key);
                    if config.has_permission(key, required) {
                        let mut request = request;
                        request.extensions_mut().insert(CallerId {
                            key_id: key_id.unwrap_or_else(|| "unknown".to_string()),
                        });
                        Ok(next.run(request).await)
                    } else {
                        Err(StatusCode::FORBIDDEN)
                    }
                }
                _ => Err(StatusCode::UNAUTHORIZED),
            }
        }
        None => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Default authentication: any authenticated key can access.
/// Uses `Permission::AUTHENTICATED` (LIST_KEYS) as minimum bar.
pub async fn api_key_auth(request: Request, next: Next) -> Result<Response, StatusCode> {
    auth_middleware_with_permission(request, next, Permission::AUTHENTICATED).await
}

/// Require a specific Permission. Creates a middleware function for use with `from_fn`.
///
/// # Example
/// ```text
/// .route_layer(from_fn(move |req, next| {
///     require_permission(Permission::ENCRYPT, req, next)
/// }))
/// ```
pub async fn require_permission(
    required: Permission,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    auth_middleware_with_permission(request, next, required).await
}

/// Evaluate PBAC policy for a REST access request.
///
/// Returns Ok(()) if the policy allows access, or a 403 Forbidden StatusCode.
/// This should be called after authentication/permission middleware succeeds,
/// e.g., right after extracting `CallerId` in a REST handler.
///
/// # Security
///
/// PBAC is ADDITIVE — the role-based permission check must still pass first.
/// PBAC can only FURTHER RESTRICT access, never grant it.
pub async fn check_rest_pbac(
    engine: &kms_policy::PBACEngine,
    subject_id: &str,
    action: &str,
    resource_id: &str,
) -> Result<(), StatusCode> {
    let ctx = kms_policy::AccessContext::new(subject_id, action, resource_id);
    match engine.evaluate(&ctx).await {
        Ok(kms_policy::Decision::Allow) => Ok(()),
        Ok(kms_policy::Decision::Deny) => {
            tracing::warn!(%subject_id, %action, %resource_id, "REST PBAC denied");
            Err(StatusCode::FORBIDDEN)
        }
        Err(e) => {
            tracing::error!(%subject_id, %action, %resource_id, error = %e, "REST PBAC evaluation error");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Permission bitmask tests ──

    #[test]
    fn test_permission_roles_are_mutually_exclusive() {
        // KeyAdmin must NOT have SecurityOfficer permissions
        assert!(
            !ApiKeyPermission::KeyAdmin
                .permissions()
                .contains(Permission::APPROVE_ACTION)
        );
        assert!(
            !ApiKeyPermission::KeyAdmin
                .permissions()
                .contains(Permission::MANAGE_POLICY)
        );
        assert!(
            !ApiKeyPermission::KeyAdmin
                .permissions()
                .contains(Permission::MANAGE_API_KEYS)
        );

        // SecurityOfficer must NOT have KeyAdmin permissions
        assert!(
            !ApiKeyPermission::SecurityOfficer
                .permissions()
                .contains(Permission::CREATE_KEY)
        );
        assert!(
            !ApiKeyPermission::SecurityOfficer
                .permissions()
                .contains(Permission::DELETE_KEY)
        );
        assert!(
            !ApiKeyPermission::SecurityOfficer
                .permissions()
                .contains(Permission::ROTATE_KEY)
        );
        assert!(
            !ApiKeyPermission::SecurityOfficer
                .permissions()
                .contains(Permission::IMPORT_KEY)
        );
        assert!(
            !ApiKeyPermission::SecurityOfficer
                .permissions()
                .contains(Permission::ENCRYPT)
        );

        // AuditAdmin must ONLY have audit permissions
        assert!(
            ApiKeyPermission::AuditAdmin
                .permissions()
                .contains(Permission::VIEW_AUDIT)
        );
        assert!(
            ApiKeyPermission::AuditAdmin
                .permissions()
                .contains(Permission::EXPORT_AUDIT)
        );
        assert!(
            !ApiKeyPermission::AuditAdmin
                .permissions()
                .contains(Permission::LIST_KEYS)
        );
        assert!(
            !ApiKeyPermission::AuditAdmin
                .permissions()
                .contains(Permission::ENCRYPT)
        );
        assert!(
            !ApiKeyPermission::AuditAdmin
                .permissions()
                .contains(Permission::CREATE_KEY)
        );
        assert!(
            !ApiKeyPermission::AuditAdmin
                .permissions()
                .contains(Permission::APPROVE_ACTION)
        );
    }

    #[test]
    fn test_permission_satisfies() {
        // KeyAdmin satisfies key operations
        assert!(ApiKeyPermission::KeyAdmin.satisfies(Permission::LIST_KEYS));
        assert!(ApiKeyPermission::KeyAdmin.satisfies(Permission::ENCRYPT));
        assert!(ApiKeyPermission::KeyAdmin.satisfies(Permission::CREATE_KEY));
        assert!(ApiKeyPermission::KeyAdmin.satisfies(Permission::DELETE_KEY));
        // KeyAdmin does NOT satisfy admin operations
        assert!(!ApiKeyPermission::KeyAdmin.satisfies(Permission::APPROVE_ACTION));
        assert!(!ApiKeyPermission::KeyAdmin.satisfies(Permission::VIEW_AUDIT));

        // SecurityOfficer satisfies admin operations
        assert!(ApiKeyPermission::SecurityOfficer.satisfies(Permission::APPROVE_ACTION));
        assert!(ApiKeyPermission::SecurityOfficer.satisfies(Permission::MANAGE_POLICY));
        assert!(ApiKeyPermission::SecurityOfficer.satisfies(Permission::VIEW_AUDIT));
        // SecurityOfficer does NOT satisfy key operations
        assert!(!ApiKeyPermission::SecurityOfficer.satisfies(Permission::ENCRYPT));
        assert!(!ApiKeyPermission::SecurityOfficer.satisfies(Permission::CREATE_KEY));

        // Operator satisfies crypto operations but not key lifecycle
        assert!(ApiKeyPermission::Operator.satisfies(Permission::ENCRYPT));
        assert!(ApiKeyPermission::Operator.satisfies(Permission::SIGN));
        assert!(!ApiKeyPermission::Operator.satisfies(Permission::CREATE_KEY));
        assert!(!ApiKeyPermission::Operator.satisfies(Permission::DELETE_KEY));

        // ReadOnly satisfies only read
        assert!(ApiKeyPermission::ReadOnly.satisfies(Permission::LIST_KEYS));
        assert!(!ApiKeyPermission::ReadOnly.satisfies(Permission::ENCRYPT));
    }

    #[test]
    fn test_empty_permission_always_satisfied() {
        // empty() means "any authenticated key" — used for open endpoints
        assert!(ApiKeyPermission::ReadOnly.satisfies(Permission::empty()));
        assert!(ApiKeyPermission::AuditAdmin.satisfies(Permission::empty()));
        // But AUTHENTICATED requires at least LIST_KEYS
        assert!(ApiKeyPermission::ReadOnly.satisfies(Permission::AUTHENTICATED));
        assert!(!ApiKeyPermission::AuditAdmin.satisfies(Permission::AUTHENTICATED));
    }

    // ── API Key creation tests ──

    #[test]
    fn test_api_key_creation() {
        let read_key = ApiKey::read_only("secret1".into());
        assert_eq!(read_key.permission, ApiKeyPermission::ReadOnly);

        let op_key = ApiKey::operator("secret2".into());
        assert_eq!(op_key.permission, ApiKeyPermission::Operator);

        let ka_key = ApiKey::key_admin("secret3".into());
        assert_eq!(ka_key.permission, ApiKeyPermission::KeyAdmin);

        let so_key = ApiKey::security_officer("secret4".into());
        assert_eq!(so_key.permission, ApiKeyPermission::SecurityOfficer);

        let aa_key = ApiKey::audit_admin("secret5".into());
        assert_eq!(aa_key.permission, ApiKeyPermission::AuditAdmin);
    }

    #[test]
    fn test_config_validate() {
        let config = ApiKeyConfig::with_keys(vec![
            ApiKey::read_only("read-key".into()),
            ApiKey::operator("op-key".into()),
            ApiKey::key_admin("ka-key".into()),
            ApiKey::security_officer("so-key".into()),
            ApiKey::audit_admin("aa-key".into()),
        ]);

        assert_eq!(
            config.validate("read-key"),
            Some(ApiKeyPermission::ReadOnly)
        );
        assert_eq!(config.validate("op-key"), Some(ApiKeyPermission::Operator));
        assert_eq!(config.validate("ka-key"), Some(ApiKeyPermission::KeyAdmin));
        assert_eq!(
            config.validate("so-key"),
            Some(ApiKeyPermission::SecurityOfficer)
        );
        assert_eq!(
            config.validate("aa-key"),
            Some(ApiKeyPermission::AuditAdmin)
        );
        assert_eq!(config.validate("invalid-key"), None);
    }

    #[test]
    fn test_config_has_permission() {
        let config = ApiKeyConfig::with_keys(vec![
            ApiKey::read_only("read-key".into()),
            ApiKey::operator("op-key".into()),
            ApiKey::key_admin("ka-key".into()),
            ApiKey::security_officer("so-key".into()),
            ApiKey::audit_admin("aa-key".into()),
        ]);

        // ReadOnly key
        assert!(config.has_permission("read-key", Permission::LIST_KEYS));
        assert!(!config.has_permission("read-key", Permission::ENCRYPT));
        assert!(!config.has_permission("read-key", Permission::CREATE_KEY));

        // Operator key
        assert!(config.has_permission("op-key", Permission::LIST_KEYS));
        assert!(config.has_permission("op-key", Permission::ENCRYPT));
        assert!(!config.has_permission("op-key", Permission::CREATE_KEY));

        // KeyAdmin key
        assert!(config.has_permission("ka-key", Permission::ENCRYPT));
        assert!(config.has_permission("ka-key", Permission::CREATE_KEY));
        assert!(!config.has_permission("ka-key", Permission::APPROVE_ACTION));
        assert!(!config.has_permission("ka-key", Permission::VIEW_AUDIT));

        // SecurityOfficer key
        assert!(!config.has_permission("so-key", Permission::ENCRYPT));
        assert!(config.has_permission("so-key", Permission::APPROVE_ACTION));
        assert!(config.has_permission("so-key", Permission::MANAGE_POLICY));

        // AuditAdmin key
        assert!(config.has_permission("aa-key", Permission::VIEW_AUDIT));
        assert!(!config.has_permission("aa-key", Permission::LIST_KEYS));
        assert!(!config.has_permission("aa-key", Permission::ENCRYPT));

        // Empty permission = any authenticated key
        assert!(config.has_permission("read-key", Permission::empty()));
        assert!(config.has_permission("aa-key", Permission::empty()));
    }

    // ── Lifecycle tests ──

    #[test]
    fn test_api_key_with_expiration() {
        let key = ApiKey::operator("test-key".into())
            .with_expiration(Utc::now() + chrono::Duration::hours(1));

        assert!(key.is_valid());
        assert!(key.expires_at.is_some());

        let expired_key = ApiKey::operator("expired-key".into())
            .with_expiration(Utc::now() - chrono::Duration::hours(1));

        assert!(!expired_key.is_valid());
    }

    #[test]
    fn test_api_key_revocation() {
        let config = ApiKeyConfig::with_keys(vec![ApiKey::operator("valid-key".into())]);

        let key_id = config.list_valid_keys()[0].key_id.clone();
        assert!(config.revoke_key(&key_id));
        assert!(!config.is_valid("valid-key"));
    }

    #[test]
    fn test_api_key_rotation_with_grace_period() {
        let config = ApiKeyConfig::with_keys(vec![ApiKey::operator("old-key".into())]);

        let old_key_id = config.list_valid_keys()[0].key_id.clone();

        let new_key = config.rotate_key(
            &old_key_id,
            "new-key".into(),
            ApiKeyPermission::Operator,
            chrono::Duration::hours(1),
        );

        assert!(new_key.is_some());
        assert!(new_key.as_ref().unwrap().permission == ApiKeyPermission::Operator);

        assert!(config.is_valid("old-key"));
        assert!(config.is_valid("new-key"));
    }

    #[test]
    fn test_api_key_rotation_nonexistent_key() {
        let config = ApiKeyConfig::with_keys(vec![ApiKey::operator("existing-key".into())]);

        let result = config.rotate_key(
            "nonexistent-key-id",
            "new-key".into(),
            ApiKeyPermission::Operator,
            chrono::Duration::hours(1),
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_get_key_metadata() {
        let key = ApiKey::operator("test-key".into());
        let key_id = key.key_id.clone();

        let config = ApiKeyConfig::with_keys(vec![key]);

        let metadata = config.get_key_metadata(&key_id);
        assert!(metadata.is_some());
        let meta = metadata.unwrap();
        assert_eq!(meta.key_id, key_id);
        assert_eq!(meta.permission, ApiKeyPermission::Operator);
        assert!(!meta.revoked);
        assert!(meta.is_valid);
    }

    #[test]
    fn test_list_valid_keys() {
        let key1 = ApiKey::read_only("valid1".into());
        let key2 = ApiKey::operator("valid2".into());
        let config = ApiKeyConfig::with_keys(vec![key1, key2]);

        // Add an expired key
        let expired_key = ApiKey::key_admin("expired".into())
            .with_expiration(Utc::now() - chrono::Duration::hours(1));
        config.add_key(expired_key);

        let valid_keys = config.list_valid_keys();
        assert_eq!(valid_keys.len(), 2);
    }

    #[test]
    fn test_no_role_has_all_permissions() {
        // Verify no single role encompasses all permissions
        let all = Permission::all();
        assert_ne!(ApiKeyPermission::ReadOnly.permissions(), all);
        assert_ne!(ApiKeyPermission::Operator.permissions(), all);
        assert_ne!(ApiKeyPermission::KeyAdmin.permissions(), all);
        assert_ne!(ApiKeyPermission::SecurityOfficer.permissions(), all);
        assert_ne!(ApiKeyPermission::AuditAdmin.permissions(), all);
    }

    // ── Security regression tests ──

    /// Brute force protection: key locks after max_failed_attempts (5)
    #[tokio::test]
    async fn test_auth_brute_force_lockout() {
        let mut config = ApiKeyConfig::with_keys(vec![ApiKey::operator("secret-key".into())]);

        // After 5 failed attempts, the key should be locked
        for _ in 0..5 {
            config.record_failed_attempt("secret-key").await;
        }

        assert!(config.is_locked("secret-key"));
        // Locked key must not pass validate()
        assert!(config.validate("secret-key").is_none());
    }

    /// Lockout resets on successful login (before threshold)
    #[tokio::test]
    async fn test_auth_lockout_reset_on_success() {
        let mut config = ApiKeyConfig::with_keys(vec![ApiKey::operator("reset-key".into())]);

        // 4 failed attempts — below threshold
        for _ in 0..4 {
            config.record_failed_attempt("reset-key").await;
        }

        // Successful login resets counter
        config.record_successful_login("reset-key");
        assert!(!config.is_locked("reset-key"));
        assert!(config.validate("reset-key").is_some());

        // 5 more failures should lock again (fresh counter)
        for _ in 0..5 {
            config.record_failed_attempt("reset-key").await;
        }
        assert!(config.is_locked("reset-key"));
    }

    /// Without brute force protection, lockout is disabled
    #[tokio::test]
    async fn test_auth_no_lockout_without_protection() {
        let mut config = ApiKeyConfig::with_keys(vec![ApiKey::operator("unlocked-key".into())]);
        config.disable_brute_force_protection();
        for _ in 0..10 {
            config.record_failed_attempt("unlocked-key").await;
        }
        assert!(!config.is_locked("unlocked-key"));
    }

    /// Expired key is rejected by validate()
    #[test]
    fn test_auth_expired_key_rejected_by_validate() {
        let config = ApiKeyConfig::with_keys(vec![
            ApiKey::operator("expired-key".into())
                .with_expiration(Utc::now() - chrono::Duration::hours(1)),
        ]);

        // Expired key must not validate
        assert!(!config.is_valid("expired-key"));
        assert!(config.validate("expired-key").is_none());
    }

    /// Revoked key is rejected by validate()
    #[test]
    fn test_auth_revoked_key_rejected_by_validate() {
        let config = ApiKeyConfig::with_keys(vec![ApiKey::operator("revoked-key".into())]);

        let key_id = config.list_valid_keys()[0].key_id.clone();
        config.revoke_key(&key_id);

        assert!(!config.is_valid("revoked-key"));
        assert!(config.validate("revoked-key").is_none());
    }

    /// Invalid keys: empty, whitespace, wrong key all return None
    #[test]
    fn test_auth_invalid_keys_return_none() {
        let config = ApiKeyConfig::with_keys(vec![ApiKey::operator("real-key".into())]);

        assert!(config.validate("").is_none());
        assert!(config.validate("   ").is_none());
        assert!(config.validate("wrong-key").is_none());
        assert!(config.validate("real-key\n").is_none());
    }

    /// Rotation grace period: old key still valid within grace period, new key works immediately
    #[test]
    fn test_auth_rotation_grace_period_both_valid() {
        let config = ApiKeyConfig::with_keys(vec![ApiKey::operator("old-secret".into())]);

        let old_key_id = config.list_valid_keys()[0].key_id.clone();

        let result = config.rotate_key(
            &old_key_id,
            "new-secret".into(),
            ApiKeyPermission::Operator,
            chrono::Duration::hours(1),
        );
        assert!(result.is_some());

        // Both keys valid during grace period
        assert!(config.is_valid("old-secret"));
        assert!(config.is_valid("new-secret"));
        assert_eq!(
            config.validate("old-secret"),
            Some(ApiKeyPermission::Operator)
        );
        assert_eq!(
            config.validate("new-secret"),
            Some(ApiKeyPermission::Operator)
        );
    }

    /// Permission boundaries: AuditAdmin has no operational permissions
    #[test]
    fn test_auth_permission_boundaries() {
        let config = ApiKeyConfig::with_keys(vec![
            ApiKey::read_only("ro-key".into()),
            ApiKey::operator("op-key".into()),
            ApiKey::audit_admin("aa-key".into()),
        ]);

        // ReadOnly: can list, cannot encrypt
        assert!(config.has_permission("ro-key", Permission::LIST_KEYS));
        assert!(!config.has_permission("ro-key", Permission::ENCRYPT));
        assert!(!config.has_permission("ro-key", Permission::CREATE_KEY));

        // Operator: can encrypt, cannot manage policies
        assert!(config.has_permission("op-key", Permission::ENCRYPT));
        assert!(!config.has_permission("op-key", Permission::MANAGE_POLICY));
        assert!(!config.has_permission("op-key", Permission::APPROVE_ACTION));

        // AuditAdmin: only audit access
        assert!(config.has_permission("aa-key", Permission::VIEW_AUDIT));
        assert!(!config.has_permission("aa-key", Permission::LIST_KEYS));
        assert!(!config.has_permission("aa-key", Permission::ENCRYPT));
        assert!(!config.has_permission("aa-key", Permission::CREATE_KEY));
    }
}
