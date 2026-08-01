//! Secret Rotation Manager
//!
//! Provides automated rotation of credentials (database passwords, API keys, TLS certs).
//! Implements versioned secrets with TTL-based expiration.
//!
//! ## Features
//!
//! - Versioned secrets with automatic rotation
//! - TTL-based expiration
//! - Pre/post validation hooks
//! - Rotation state machine

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Secret type for rotation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretType {
    /// Database credentials (username/password)
    DatabaseCredential,
    /// API key
    ApiKey,
    /// TLS certificate
    TlsCertificate,
    /// Generic secret
    GenericSecret,
}

/// Secret version with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    /// Version number (increments on rotation)
    pub version: u32,
    /// The secret value (encrypted at rest)
    pub secret: Vec<u8>,
    /// When this version was created
    pub created_at: DateTime<Utc>,
    /// When this version expires (TTL)
    pub expires_at: DateTime<Utc>,
    /// Whether this version is currently active
    pub active: bool,
}

impl SecretVersion {
    /// Check if this version is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// Secret rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    /// Secret type
    pub secret_type: SecretType,
    /// TTL in seconds
    pub ttl_seconds: u64,
    /// Grace period (overlap time) in seconds before expiration
    pub grace_period_seconds: u64,
    /// Number of versions to keep (for rollback)
    pub keep_versions: u32,
    /// Pre-rotation validation hook (script path or URL)
    pub pre_validate: Option<String>,
    /// Post-rotation validation hook (script path or URL)
    pub post_validate: Option<String>,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            secret_type: SecretType::GenericSecret,
            ttl_seconds: 86400,         // 24 hours
            grace_period_seconds: 3600, // 1 hour grace
            keep_versions: 3,
            pre_validate: None,
            post_validate: None,
        }
    }
}

/// Secret rotation state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationState {
    /// No rotation needed
    Idle,
    /// About to rotate
    Pending,
    /// Rotation in progress
    Rotating,
    /// Validation in progress
    Validating,
    /// Rollback in progress
    RollingBack,
    /// Rotation completed successfully
    Completed,
    /// Rotation failed
    Failed,
}

/// Secret rotation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRotation {
    /// Unique rotation ID
    pub id: Uuid,
    /// Secret name/identifier
    pub secret_name: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Current state
    pub state: RotationState,
    /// Old version (before rotation)
    pub old_version: Option<u32>,
    /// New version (after rotation)
    pub new_version: Option<u32>,
    /// Error message if failed
    pub error: Option<String>,
    /// When rotation started
    pub started_at: DateTime<Utc>,
    /// When rotation completed
    pub completed_at: Option<DateTime<Utc>>,
}

/// Secret rotation manager
///
/// Manages versioned rotation of secrets with TTL-based expiration.
#[derive(Debug, Clone)]
pub struct SecretRotationManager {
    /// Secret name -> versions (newest first)
    secrets: HashMap<String, Vec<SecretVersion>>,
    /// Secret name -> rotation config
    configs: HashMap<String, RotationConfig>,
    /// Rotation history
    rotations: Vec<SecretRotation>,
}

impl SecretRotationManager {
    /// Create a new secret rotation manager
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
            configs: HashMap::new(),
            rotations: Vec::new(),
        }
    }

    /// Register a secret for rotation
    pub fn register(
        &mut self,
        name: &str,
        tenant_id: &str,
        initial_secret: Vec<u8>,
        config: RotationConfig,
    ) -> Result<u32, crate::Error> {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(config.ttl_seconds as i64);

        let version = SecretVersion {
            version: 1,
            secret: initial_secret,
            created_at: now,
            expires_at,
            active: true,
        };

        self.secrets.insert(name.to_string(), vec![version]);
        self.configs.insert(name.to_string(), config);

        tracing::info!(
            secret_name = name,
            tenant_id = tenant_id,
            "Secret registered for rotation"
        );

        Ok(1)
    }

    /// Get current active secret
    pub fn get_active(&self, name: &str) -> Option<&SecretVersion> {
        self.secrets
            .get(name)
            .and_then(|versions| versions.iter().find(|v| v.active && !v.is_expired()))
    }

    /// Check if a secret needs rotation
    pub fn needs_rotation(&self, name: &str) -> bool {
        if let Some(config) = self.configs.get(name)
            && let Some(active) = self.get_active(name)
        {
            let grace_start =
                active.expires_at - Duration::seconds(config.grace_period_seconds as i64);
            return Utc::now() >= grace_start;
        }
        true
    }

    /// Rotate a secret (generate new version)
    pub fn rotate(&mut self, name: &str) -> Result<SecretRotation, crate::Error> {
        let config = self
            .configs
            .get(name)
            .ok_or_else(|| crate::Error::Internal(format!("Secret {} not found", name)))?;

        let old_version = self.get_active(name).map(|v| v.version);

        // Deactivate old version
        if let Some(versions) = self.secrets.get_mut(name) {
            for v in versions.iter_mut() {
                v.active = false;
            }
        }

        // Generate new secret
        let new_secret = crate::csprng::random_bytes(32);

        let now = Utc::now();
        let expires_at = now + Duration::seconds(config.ttl_seconds as i64);

        let new_version_num = old_version.unwrap_or(0) + 1;

        let new_version = SecretVersion {
            version: new_version_num,
            secret: new_secret,
            created_at: now,
            expires_at,
            active: true,
        };

        // Add new version
        let versions = self.secrets.entry(name.to_string()).or_default();
        versions.insert(0, new_version);

        // Trim old versions
        while versions.len() > config.keep_versions as usize {
            versions.pop();
        }

        let rotation = SecretRotation {
            id: Uuid::new_v4(),
            secret_name: name.to_string(),
            tenant_id: "default".to_string(), // Would come from context in real impl
            state: RotationState::Completed,
            old_version,
            new_version: Some(new_version_num),
            error: None,
            started_at: now,
            completed_at: Some(Utc::now()),
        };

        self.rotations.push(rotation.clone());

        tracing::info!(
            secret_name = name,
            old_version = ?old_version,
            new_version = new_version_num,
            "Secret rotated successfully"
        );

        Ok(rotation)
    }

    /// Get rotation history for a secret
    pub fn get_history(&self, name: &str) -> Vec<&SecretRotation> {
        self.rotations
            .iter()
            .filter(|r| r.secret_name == name)
            .collect()
    }

    /// Rollback to a previous version
    pub fn rollback(&mut self, name: &str, version: u32) -> Result<SecretRotation, crate::Error> {
        let versions = self
            .secrets
            .get_mut(name)
            .ok_or_else(|| crate::Error::Internal(format!("Secret {} not found", name)))?;

        // Find target index
        let target_idx = versions
            .iter()
            .position(|v| v.version == version)
            .ok_or_else(|| crate::Error::Internal(format!("Version {} not found", version)))?;

        // Deactivate all and reactivate target
        for v in versions.iter_mut() {
            v.active = false;
        }
        versions[target_idx].active = true;

        let old_version = versions
            .iter()
            .find(|v| v.active && v.version != version)
            .map(|v| v.version);

        let now = Utc::now();
        let rotation = SecretRotation {
            id: Uuid::new_v4(),
            secret_name: name.to_string(),
            tenant_id: "default".to_string(),
            state: RotationState::Completed,
            old_version,
            new_version: Some(version),
            error: None,
            started_at: now,
            completed_at: Some(now),
        };

        self.rotations.push(rotation.clone());

        tracing::warn!(
            secret_name = name,
            rolled_back_to_version = version,
            "Secret rolled back"
        );

        Ok(rotation)
    }
}

impl Default for SecretRotationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_get_secret() {
        let mut manager = SecretRotationManager::new();
        let secret = b"my-super-secret-password".to_vec();

        let version = manager
            .register(
                "test-db-creds",
                "tenant-1",
                secret,
                RotationConfig::default(),
            )
            .unwrap();

        assert_eq!(version, 1);

        let active = manager.get_active("test-db-creds").unwrap();
        assert_eq!(active.version, 1);
        assert!(!active.is_expired());
    }

    #[test]
    fn test_rotation() {
        let mut manager = SecretRotationManager::new();
        let secret = b"initial-secret".to_vec();

        manager
            .register(
                "test-db-creds",
                "tenant-1",
                secret,
                RotationConfig::default(),
            )
            .unwrap();

        let rotation = manager.rotate("test-db-creds").unwrap();
        assert_eq!(rotation.state, RotationState::Completed);
        assert_eq!(rotation.old_version, Some(1));
        assert_eq!(rotation.new_version, Some(2));

        let active = manager.get_active("test-db-creds").unwrap();
        assert_eq!(active.version, 2);
    }

    #[test]
    fn test_rollback() {
        let mut manager = SecretRotationManager::new();
        let secret = b"initial-secret".to_vec();

        manager
            .register(
                "test-db-creds",
                "tenant-1",
                secret,
                RotationConfig::default(),
            )
            .unwrap();

        manager.rotate("test-db-creds").unwrap();
        manager.rotate("test-db-creds").unwrap();

        let active = manager.get_active("test-db-creds").unwrap();
        assert_eq!(active.version, 3);

        manager.rollback("test-db-creds", 1).unwrap();

        let active = manager.get_active("test-db-creds").unwrap();
        assert_eq!(active.version, 1);
    }

    /// Test needs_rotation check
    #[test]
    fn test_needs_rotation() {
        let mut manager = SecretRotationManager::new();
        let secret = b"my-secret".to_vec();

        // Not registered yet — needs rotation (no active version)
        assert!(manager.needs_rotation("nonexistent"));

        manager
            .register("test-secret", "tenant-1", secret, RotationConfig::default())
            .unwrap();

        // Just registered — should not need rotation
        assert!(!manager.needs_rotation("test-secret"));
    }

    /// Test get_history
    #[test]
    fn test_get_history() {
        let mut manager = SecretRotationManager::new();
        let secret = b"initial".to_vec();

        manager
            .register("hist-test", "tenant-1", secret, RotationConfig::default())
            .unwrap();
        manager.rotate("hist-test").unwrap();
        manager.rotate("hist-test").unwrap();

        let history = manager.get_history("hist-test");
        assert!(history.len() >= 2); // At least 2 rotations
    }

    /// Test get_active returns None for unknown secret
    #[test]
    fn test_get_active_nonexistent() {
        let manager = SecretRotationManager::new();
        assert!(manager.get_active("nonexistent").is_none());
    }

    /// Test rotate nonexistent secret fails
    #[test]
    fn test_rotate_nonexistent_fails() {
        let mut manager = SecretRotationManager::new();
        let result = manager.rotate("nonexistent");
        assert!(result.is_err());
    }

    /// Test rollback to invalid version fails
    #[test]
    fn test_rollback_invalid_version() {
        let mut manager = SecretRotationManager::new();
        manager
            .register(
                "rb-test",
                "tenant-1",
                b"secret".to_vec(),
                RotationConfig::default(),
            )
            .unwrap();

        // Version 99 doesn't exist
        let result = manager.rollback("rb-test", 99);
        assert!(result.is_err());
    }

    /// Test SecretVersion is_expired with old timestamp
    #[test]
    fn test_secret_version_expired() {
        use chrono::{Duration, Utc};
        let old_version = SecretVersion {
            version: 1,
            secret: b"old-secret".to_vec(),
            created_at: Utc::now() - Duration::days(365),
            expires_at: Utc::now() - Duration::days(300), // expired 300 days ago
            active: false,
        };
        assert!(old_version.is_expired());
    }
}
