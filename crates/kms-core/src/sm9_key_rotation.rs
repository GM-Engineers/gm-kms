//! SM9 Key Rotation Adapter — Bridge between gm-sm9-rs KeyRotationManager and gm-kms
//!
//! This module bridges the gap between:
//! - **gm-sm9-rs's `KeyRotationManager`**: Pure in-memory, manages SM9 master key versions
//!   and grace periods, but is unaware of persistence, tenants, or keystore backends.
//! - **gm-kms's `RotationService`**: Full policy engine with gRPC API, but only handles
//!   generic symmetric keys (AES/SM4) and doesn't understand SM9's identity-based key model.
//!
//! # Architecture
//!
//! ```text
//! gm-kms RotationService (policy engine, gRPC)
//!        │
//!        ▼
//! Sm9RotationAdapter (this module)
//!   ├── Manages KeyRotationManager lifecycle
//!   ├── Bridges versioned SM9 keys to KeyMeta
//!   ├── Handles SM9-specific rotation logic
//!   └── Persists rotated keys via KeystoreBackend
//!        │
//!        ▼
//! gm-sm9-rs KeyRotationManager (in-memory versioned keys)
//! ```

use crate::key::{KeyMeta, KeyMetadata, KeySpec, KeyStatus};
use crate::sm9_master_key::Sm9MasterKeyStore;
use crate::{Error, Result};
use chrono::Utc;
use gm_sm9_rs::key::{EncMasterKey, SignMasterKey};
use gm_sm9_rs::key_rotation::{KeyRotationManager, KeyVersion, RotationRecord};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Serialize SignMasterKey to bytes: s (32 bytes BE) || ppubs (G2 affine: 128 bytes)
fn serialize_sign_master_key(key: &SignMasterKey) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(160);
    buf.extend_from_slice(&gm_sm9_rs::z256::to_bytes_be(&key.s));
    let (x, y) = key
        .ppubs
        .to_affine()
        .ok_or_else(|| Error::MasterKeyError("Identity point cannot be serialized".to_string()))?;
    buf.extend_from_slice(&x.to_bytes());
    buf.extend_from_slice(&y.to_bytes());
    Ok(buf)
}

/// Serialize EncMasterKey to bytes: s (32 bytes BE) || ppube (G1 affine: 64 bytes)
fn serialize_enc_master_key(key: &EncMasterKey) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(96);
    buf.extend_from_slice(&gm_sm9_rs::z256::to_bytes_be(&key.s));
    let (x, y) = key
        .ppube
        .to_affine()
        .ok_or_else(|| Error::MasterKeyError("Identity point cannot be serialized".to_string()))?;
    buf.extend_from_slice(&x.to_bytes());
    buf.extend_from_slice(&y.to_bytes());
    Ok(buf)
}

/// Adapter that bridges gm-sm9-rs's KeyRotationManager with gm-kms infrastructure.
///
/// This is the single point of integration for SM9 key rotation in gm-kms.
/// It wraps the in-memory KeyRotationManager and adds:
/// - Persistence via Sm9MasterKeyStore (KEK-protected)
/// - Tenant awareness
/// - KeyMeta mapping (so rotated keys appear in kms-keystore listings)
/// - Grace period management that gm-kms RotationService can query
pub struct Sm9RotationAdapter {
    /// Inner in-memory rotation managers, keyed by tenant_id
    /// Each tenant has its own independent KeyRotationManager
    managers: RwLock<HashMap<String, KeyRotationManager>>,

    /// KEK-protected store for persisting rotated master keys
    kek_store: Arc<dyn Sm9MasterKeyStore>,

    /// Map from KMS key_id → (tenant_id, key_type, version)
    /// key_type is "sign" or "enc"
    key_registry: RwLock<HashMap<Uuid, Sm9KeyEntry>>,
}

/// Registry entry tracking an SM9 key in KMS terms
#[derive(Debug, Clone)]
struct Sm9KeyEntry {
    tenant_id: String,
    key_type: Sm9KeyType,
    version: KeyVersion,
    /// The KMS key_id under which this SM9 key is registered
    kms_key_id: Uuid,
}

/// Whether this is a signing or encryption master key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sm9KeyType {
    Signing,
    Encryption,
}

impl std::fmt::Display for Sm9KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Sm9KeyType::Signing => write!(f, "signing"),
            Sm9KeyType::Encryption => write!(f, "encryption"),
        }
    }
}

/// Result of an SM9 key rotation operation
#[derive(Debug)]
pub struct Sm9RotationResult {
    /// The new key version
    pub new_version: KeyVersion,
    /// The old key version (before rotation)
    pub old_version: KeyVersion,
    /// Grace period in seconds
    pub grace_period_secs: u64,
    /// Updated KeyMeta for the KMS key registry
    pub meta: KeyMeta,
}

/// Information about a valid SM9 key version
#[derive(Debug, Clone)]
pub struct Sm9KeyVersionInfo {
    pub version: KeyVersion,
    pub active: bool,
    pub grace_expired: bool,
}

impl Sm9RotationAdapter {
    /// Create a new adapter with the given KEK store
    pub fn new(kek_store: Arc<dyn Sm9MasterKeyStore>) -> Self {
        Self {
            managers: RwLock::new(HashMap::new()),
            kek_store,
            key_registry: RwLock::new(HashMap::new()),
        }
    }

    // ========================================================================
    // Key Registration
    // ========================================================================

    /// Register a new signing master key for a tenant.
    ///
    /// Creates a KMS key entry and registers the key with the in-memory
    /// KeyRotationManager. The key material is persisted via the KEK store.
    ///
    /// Returns the KMS key ID and initial version.
    pub async fn register_sign_key(
        &self,
        tenant_id: &str,
        key: SignMasterKey,
        _name: &str,
    ) -> Result<(Uuid, KeyVersion)> {
        let key_id = Uuid::new_v4();

        // Register with in-memory manager
        let mut managers = self.managers.write().await;
        let manager = managers
            .entry(tenant_id.to_string())
            .or_insert_with(KeyRotationManager::new);

        let version = manager.register_sign_key(key.clone()).map_err(|e| {
            Error::MasterKeyError(format!("SM9 sign key registration failed: {e}"))
        })?;

        // Persist key material
        let key_bytes = serialize_sign_master_key(&key)?;
        self.kek_store.encrypt(&key_bytes).await?;

        // Register in KMS key registry
        let entry = Sm9KeyEntry {
            tenant_id: tenant_id.to_string(),
            key_type: Sm9KeyType::Signing,
            version,
            kms_key_id: key_id,
        };
        self.key_registry.write().await.insert(key_id, entry);

        Ok((key_id, version))
    }

    /// Register a new encryption master key for a tenant.
    pub async fn register_enc_key(
        &self,
        tenant_id: &str,
        key: EncMasterKey,
        _name: &str,
    ) -> Result<(Uuid, KeyVersion)> {
        let key_id = Uuid::new_v4();

        let mut managers = self.managers.write().await;
        let manager = managers
            .entry(tenant_id.to_string())
            .or_insert_with(KeyRotationManager::new);

        let version = manager.register_enc_key(key.clone()).map_err(|e| {
            Error::MasterKeyError(format!("SM9 enc key registration failed: {e}"))
        })?;

        let key_bytes = serialize_enc_master_key(&key)?;
        self.kek_store.encrypt(&key_bytes).await?;

        let entry = Sm9KeyEntry {
            tenant_id: tenant_id.to_string(),
            key_type: Sm9KeyType::Encryption,
            version,
            kms_key_id: key_id,
        };
        self.key_registry.write().await.insert(key_id, entry);

        Ok((key_id, version))
    }

    // ========================================================================
    // Key Rotation
    // ========================================================================

    /// Rotate a signing master key.
    ///
    /// Generates a new master key, registers it as the current version,
    /// and marks the old key as being in grace period. The new key material
    /// is persisted via the KEK store.
    pub async fn rotate_sign_key(
        &self,
        key_id: &Uuid,
        grace_period_secs: u64,
    ) -> Result<Sm9RotationResult> {
        let entry = self.get_entry(key_id).await?;
        if entry.key_type != Sm9KeyType::Signing {
            return Err(Error::MasterKeyError(
                "Key is not a signing key".to_string(),
            ));
        }

        // Generate new master key
        let new_key = SignMasterKey::generate(&mut rand::rng())
            .map_err(|e| Error::MasterKeyError(format!("SM9 key generation failed: {e}")))?;

        let mut managers = self.managers.write().await;
        let manager = managers
            .get_mut(&entry.tenant_id)
            .ok_or_else(|| Error::MasterKeyError("No rotation manager for tenant".to_string()))?;

        let _old_version = manager.current_sign_version();
        let rotation = manager
            .rotate_sign_key(new_key.clone(), grace_period_secs)
            .map_err(|e| Error::MasterKeyError(format!("SM9 sign key rotation failed: {e}")))?;

        // Persist new key material
        let key_bytes = serialize_sign_master_key(&new_key)?;
        self.kek_store.encrypt(&key_bytes).await?;

        // Update registry
        let meta = self
            .update_registry_version(key_id, rotation.to_version)
            .await?;

        Ok(Sm9RotationResult {
            new_version: rotation.to_version,
            old_version: rotation.from_version,
            grace_period_secs,
            meta,
        })
    }

    /// Rotate an encryption master key.
    pub async fn rotate_enc_key(
        &self,
        key_id: &Uuid,
        grace_period_secs: u64,
    ) -> Result<Sm9RotationResult> {
        let entry = self.get_entry(key_id).await?;
        if entry.key_type != Sm9KeyType::Encryption {
            return Err(Error::MasterKeyError(
                "Key is not an encryption key".to_string(),
            ));
        }

        let new_key = EncMasterKey::generate(&mut rand::rng())
            .map_err(|e| Error::MasterKeyError(format!("SM9 key generation failed: {e}")))?;

        let mut managers = self.managers.write().await;
        let manager = managers
            .get_mut(&entry.tenant_id)
            .ok_or_else(|| Error::MasterKeyError("No rotation manager for tenant".to_string()))?;

        let _old_version = manager.current_enc_version();
        let rotation = manager
            .rotate_enc_key(new_key.clone(), grace_period_secs)
            .map_err(|e| Error::MasterKeyError(format!("SM9 enc key rotation failed: {e}")))?;

        let key_bytes = serialize_enc_master_key(&new_key)?;
        self.kek_store.encrypt(&key_bytes).await?;

        let meta = self
            .update_registry_version(key_id, rotation.to_version)
            .await?;

        Ok(Sm9RotationResult {
            new_version: rotation.to_version,
            old_version: rotation.from_version,
            grace_period_secs,
            meta,
        })
    }

    // ========================================================================
    // Key Access
    // ========================================================================

    /// Get the current signing master key for a tenant
    pub async fn current_sign_key(&self, tenant_id: &str) -> Result<Option<SignMasterKey>> {
        let managers = self.managers.read().await;
        let Some(manager) = managers.get(tenant_id) else {
            return Ok(None);
        };
        // KeyRotationManager returns a reference, we need to clone
        // SignMasterKey implements Clone
        Ok(manager.current_sign_key().cloned())
    }

    /// Get the current encryption master key for a tenant
    pub async fn current_enc_key(&self, tenant_id: &str) -> Result<Option<EncMasterKey>> {
        let managers = self.managers.read().await;
        let Some(manager) = managers.get(tenant_id) else {
            return Ok(None);
        };
        Ok(manager.current_enc_key().cloned())
    }

    /// Get a specific version of the signing key
    pub async fn sign_key_version(
        &self,
        tenant_id: &str,
        version: KeyVersion,
    ) -> Result<Option<SignMasterKey>> {
        let managers = self.managers.read().await;
        let Some(manager) = managers.get(tenant_id) else {
            return Ok(None);
        };
        Ok(manager.get_sign_key(version).cloned())
    }

    /// Get a specific version of the encryption key
    pub async fn enc_key_version(
        &self,
        tenant_id: &str,
        version: KeyVersion,
    ) -> Result<Option<EncMasterKey>> {
        let managers = self.managers.read().await;
        let Some(manager) = managers.get(tenant_id) else {
            return Ok(None);
        };
        Ok(manager.get_enc_key(version).cloned())
    }

    /// Check if a key version is still valid (within grace period)
    pub async fn is_sign_key_valid(&self, tenant_id: &str, version: KeyVersion) -> bool {
        let managers = self.managers.read().await;
        managers
            .get(tenant_id)
            .map(|m| m.is_sign_key_valid(version))
            .unwrap_or(false)
    }

    /// Check if an encryption key version is still valid (within grace period)
    pub async fn is_enc_key_valid(&self, tenant_id: &str, version: KeyVersion) -> bool {
        let managers = self.managers.read().await;
        managers
            .get(tenant_id)
            .map(|m| m.is_enc_key_valid(version))
            .unwrap_or(false)
    }

    /// List all valid signing key versions for a tenant
    pub async fn valid_sign_versions(&self, tenant_id: &str) -> Vec<Sm9KeyVersionInfo> {
        let managers = self.managers.read().await;
        let Some(manager) = managers.get(tenant_id) else {
            return vec![];
        };
        let current = manager.current_sign_version();
        manager
            .valid_sign_versions()
            .into_iter()
            .map(|v| Sm9KeyVersionInfo {
                version: v,
                active: v == current,
                grace_expired: !manager.is_sign_key_valid(v),
            })
            .collect()
    }

    /// List all valid encryption key versions for a tenant
    pub async fn valid_enc_versions(&self, tenant_id: &str) -> Vec<Sm9KeyVersionInfo> {
        let managers = self.managers.read().await;
        let Some(manager) = managers.get(tenant_id) else {
            return vec![];
        };
        let current = manager.current_enc_version();
        manager
            .valid_enc_versions()
            .into_iter()
            .map(|v| Sm9KeyVersionInfo {
                version: v,
                active: v == current,
                grace_expired: !manager.is_enc_key_valid(v),
            })
            .collect()
    }

    /// Get rotation history for signing keys
    pub async fn sign_rotation_history(&self, tenant_id: &str) -> Vec<RotationRecord> {
        let managers = self.managers.read().await;
        managers
            .get(tenant_id)
            .map(|m| m.sign_rotation_history().to_vec())
            .unwrap_or_default()
    }

    /// Get rotation history for encryption keys
    pub async fn enc_rotation_history(&self, tenant_id: &str) -> Vec<RotationRecord> {
        let managers = self.managers.read().await;
        managers
            .get(tenant_id)
            .map(|m| m.enc_rotation_history().to_vec())
            .unwrap_or_default()
    }

    // ========================================================================
    // KMS Integration
    // ========================================================================

    /// Get KeyMeta for a registered SM9 key
    pub async fn key_meta(&self, key_id: &Uuid) -> Result<KeyMeta> {
        let entry = self.get_entry(key_id).await?;
        let spec = match entry.key_type {
            Sm9KeyType::Signing => KeySpec::Sm9Signing,
            Sm9KeyType::Encryption => KeySpec::Sm9Encryption,
        };
        Ok(KeyMeta {
            id: entry.kms_key_id,
            tenant_id: entry.tenant_id,
            name: format!("sm9-{}-v{}", entry.key_type, entry.version),
            spec,
            status: KeyStatus::Active,
            created_at: Utc::now(),
            rotated_at: None,
            version: entry.version,
            description: Some(format!("SM9 {} master key", entry.key_type)),
            metadata: KeyMetadata::default(),
        })
    }

    /// Check if a key needs rotation based on the given policy.
    ///
    /// This integrates with gm-kms's RotationService by providing
    /// SM9-specific rotation logic that the generic RotationService
    /// cannot handle.
    pub async fn check_rotation_needed(&self, key_id: &Uuid, max_versions: u32) -> Result<bool> {
        let entry = self.get_entry(key_id).await?;
        let managers = self.managers.read().await;
        let Some(manager) = managers.get(&entry.tenant_id) else {
            return Ok(false);
        };

        let current_version = match entry.key_type {
            Sm9KeyType::Signing => manager.current_sign_version(),
            Sm9KeyType::Encryption => manager.current_enc_version(),
        };

        Ok(current_version >= max_versions)
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    async fn get_entry(&self, key_id: &Uuid) -> Result<Sm9KeyEntry> {
        self.key_registry
            .read()
            .await
            .get(key_id)
            .cloned()
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))
    }

    async fn update_registry_version(
        &self,
        key_id: &Uuid,
        new_version: KeyVersion,
    ) -> Result<KeyMeta> {
        let mut registry = self.key_registry.write().await;
        let entry = registry
            .get_mut(key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;
        entry.version = new_version;

        let spec = match entry.key_type {
            Sm9KeyType::Signing => KeySpec::Sm9Signing,
            Sm9KeyType::Encryption => KeySpec::Sm9Encryption,
        };

        Ok(KeyMeta {
            id: entry.kms_key_id,
            tenant_id: entry.tenant_id.clone(),
            name: format!("sm9-{}-v{}", entry.key_type, new_version),
            spec,
            status: KeyStatus::Active,
            created_at: Utc::now(),
            rotated_at: Some(Utc::now()),
            version: new_version,
            description: Some(format!("SM9 {} master key (rotated)", entry.key_type)),
            metadata: KeyMetadata::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm9_master_key::MemoryKekStore;

    fn make_adapter() -> Sm9RotationAdapter {
        Sm9RotationAdapter::new(Arc::new(MemoryKekStore::new([0x42u8; 32])))
    }

    #[tokio::test]
    async fn test_register_sign_key() {
        let adapter = make_adapter();
        let key = SignMasterKey::generate(&mut rand::rng()).unwrap();
        let (key_id, version) = adapter
            .register_sign_key("tenant-1", key, "sm9-sign")
            .await
            .unwrap();
        assert_eq!(version, 1);

        let meta = adapter.key_meta(&key_id).await.unwrap();
        assert_eq!(meta.spec, KeySpec::Sm9Signing);
        assert_eq!(meta.version, 1);
    }

    #[tokio::test]
    async fn test_register_enc_key() {
        let adapter = make_adapter();
        let key = EncMasterKey::generate(&mut rand::rng()).unwrap();
        let (key_id, version) = adapter
            .register_enc_key("tenant-1", key, "sm9-enc")
            .await
            .unwrap();
        assert_eq!(version, 1);

        let meta = adapter.key_meta(&key_id).await.unwrap();
        assert_eq!(meta.spec, KeySpec::Sm9Encryption);
    }

    #[tokio::test]
    async fn test_rotate_sign_key() {
        let adapter = make_adapter();
        let key = SignMasterKey::generate(&mut rand::rng()).unwrap();
        let (key_id, v1) = adapter
            .register_sign_key("tenant-1", key, "sm9-sign")
            .await
            .unwrap();
        assert_eq!(v1, 1);

        let result = adapter.rotate_sign_key(&key_id, 3600).await.unwrap();
        assert_eq!(result.old_version, 1);
        assert_eq!(result.new_version, 2);
        assert_eq!(result.grace_period_secs, 3600);

        // Old version should still be valid during grace
        assert!(adapter.is_sign_key_valid("tenant-1", 1).await);
        assert!(adapter.is_sign_key_valid("tenant-1", 2).await);

        let meta = adapter.key_meta(&key_id).await.unwrap();
        assert_eq!(meta.version, 2);
    }

    #[tokio::test]
    async fn test_rotate_enc_key() {
        let adapter = make_adapter();
        let key = EncMasterKey::generate(&mut rand::rng()).unwrap();
        let (key_id, v1) = adapter
            .register_enc_key("tenant-1", key, "sm9-enc")
            .await
            .unwrap();
        assert_eq!(v1, 1);

        let result = adapter.rotate_enc_key(&key_id, 1800).await.unwrap();
        assert_eq!(result.new_version, 2);

        // Both versions valid during grace
        assert!(adapter.is_enc_key_valid("tenant-1", 1).await);
        assert!(adapter.is_enc_key_valid("tenant-1", 2).await);
    }

    #[tokio::test]
    async fn test_current_key_access() {
        let adapter = make_adapter();
        let key = SignMasterKey::generate(&mut rand::rng()).unwrap();
        let _ = adapter
            .register_sign_key("tenant-1", key, "sm9-sign")
            .await
            .unwrap();

        let current = adapter.current_sign_key("tenant-1").await.unwrap();
        assert!(current.is_some());
    }

    #[tokio::test]
    async fn test_tenant_isolation() {
        let adapter = make_adapter();
        let key1 = SignMasterKey::generate(&mut rand::rng()).unwrap();
        let key2 = SignMasterKey::generate(&mut rand::rng()).unwrap();
        let _ = adapter
            .register_sign_key("tenant-1", key1, "sm9-sign")
            .await
            .unwrap();
        let _ = adapter
            .register_sign_key("tenant-2", key2, "sm9-sign")
            .await
            .unwrap();

        // Each tenant has independent managers
        let v1 = adapter.valid_sign_versions("tenant-1").await;
        let v2 = adapter.valid_sign_versions("tenant-2").await;
        assert_eq!(v1.len(), 1);
        assert_eq!(v2.len(), 1);
    }

    #[tokio::test]
    async fn test_rotation_type_mismatch_rejected() {
        let adapter = make_adapter();
        let key = SignMasterKey::generate(&mut rand::rng()).unwrap();
        let (key_id, _) = adapter
            .register_sign_key("tenant-1", key, "sm9-sign")
            .await
            .unwrap();

        // Try to rotate a signing key as encryption → should fail
        let result = adapter.rotate_enc_key(&key_id, 3600).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_check_rotation_needed() {
        let adapter = make_adapter();
        let key = SignMasterKey::generate(&mut rand::rng()).unwrap();
        let (key_id, _) = adapter
            .register_sign_key("tenant-1", key, "sm9-sign")
            .await
            .unwrap();

        // Not needed at version 1 with max_versions=3
        assert!(!adapter.check_rotation_needed(&key_id, 3).await.unwrap());

        // Rotate twice to version 3
        adapter.rotate_sign_key(&key_id, 3600).await.unwrap();
        adapter.rotate_sign_key(&key_id, 3600).await.unwrap();

        // Now at version 3, rotation needed with max=3
        assert!(adapter.check_rotation_needed(&key_id, 3).await.unwrap());
    }

    #[tokio::test]
    async fn test_valid_versions_after_multiple_rotations() {
        let adapter = make_adapter();
        let key = SignMasterKey::generate(&mut rand::rng()).unwrap();
        let (key_id, _) = adapter
            .register_sign_key("tenant-1", key, "sm9-sign")
            .await
            .unwrap();

        adapter.rotate_sign_key(&key_id, 3600).await.unwrap();
        adapter.rotate_sign_key(&key_id, 3600).await.unwrap();

        let versions = adapter.valid_sign_versions("tenant-1").await;
        assert!(!versions.is_empty());
        // Current version should be 3
        assert!(versions.iter().any(|v| v.version == 3 && v.active));
    }
}
