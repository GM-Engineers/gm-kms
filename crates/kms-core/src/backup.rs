//! Key backup and restore service
//!
//! Provides encrypted key backup with master key protection.
//! Complies with GB/T 39786-2021 requirements for key backup and recovery.
//!
//! ## Security properties
//! - **SM4-GCM encryption**: All backups encrypted with 国密 SM4-GCM (128-bit key)
//! - **SM3-HMAC signing**: Each backup file is signed with SM3-HMAC for tamper detection
//! - **SecureBox master key**: Master key stored in mlock'd memory, zeroized on drop
//! - **Encrypted master key persistence**: Master key exported with passphrase-based encryption
//! - **Owner-only file permissions**: Backup files created with 0o600
//! - **Integrity verification**: SM3 hash of original material verified on restore

use crate::key::KeyMeta;
use crate::memory_protection::SecureBox;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Backup format version (v2: SM4-GCM + SM3-HMAC signing)
const BACKUP_VERSION: u32 = 2;

/// File name (within `backup_path`) holding the passphrase-encrypted backup
/// master key, so backups stay recoverable across process restarts (audit P2-7).
pub const MASTER_KEY_FILE: &str = "master_key.enc";

/// SM4 key size in bytes (128 bits per GM/T 0002-2012)
const SM4_KEY_SIZE: usize = 16;

/// SM4-GCM nonce size in bytes
const SM4_NONCE_SIZE: usize = 12;

/// SM3-HMAC key size in bytes
const HMAC_KEY_SIZE: usize = 32;

// ============================================================================
// KeyBackup — Encrypted key backup entry
// ============================================================================

/// Encrypted key backup entry.
///
/// Contains the key metadata and SM4-GCM encrypted key material.
/// The serialized backup file also includes an SM3-HMAC signature
/// (see [`SignedBackup`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBackup {
    /// Backup format version
    pub version: u32,
    /// Key metadata
    pub key_meta: KeyMeta,
    /// SM4-GCM encrypted key material (ciphertext + 16-byte tag appended)
    pub encrypted_material: Vec<u8>,
    /// 12-byte nonce for SM4-GCM decryption
    pub nonce: Vec<u8>,
    /// SM3 hash of original key material for post-decryption integrity check
    pub material_hash: String,
    /// Backup timestamp
    pub backed_up_at: chrono::DateTime<chrono::Utc>,
    /// Optional backup description
    pub description: Option<String>,
}

/// Signed backup envelope — serialized `KeyBackup` + SM3-HMAC signature.
///
/// The `data` field is a JSON-serialized [`KeyBackup`]. The `signature`
/// is SM3-HMAC(key=hmac_key, msg=data) in hex encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBackup {
    /// JSON-serialized KeyBackup
    pub data: String,
    /// SM3-HMAC signature (hex-encoded)
    pub signature: String,
}

// ============================================================================
// MasterKey — Memory-protected backup master key
// ============================================================================

/// Master key for encrypting backups.
///
/// Key material is stored in a [`SecureBox`] for mlock + zeroize protection.
/// 128-bit SM4 key for GCM encryption + 256-bit HMAC key for signing.
///
/// # Security
/// - Not `Clone`: prevents accidental duplication of key material
/// - `Debug` does not reveal key material
pub struct MasterKey {
    /// Master key identifier
    pub id: Uuid,
    /// SM4 encryption key (16 bytes) + HMAC signing key (32 bytes)
    /// Stored in SecureBox for memory protection
    material: SecureBox,
}

impl MasterKey {
    /// Create a new master key from raw material.
    ///
    /// `material` must be exactly `SM4_KEY_SIZE + HMAC_KEY_SIZE` bytes
    /// (16 bytes SM4 key + 32 bytes HMAC key = 48 bytes total).
    pub fn new(material: &[u8]) -> Result<Self> {
        if material.len() != SM4_KEY_SIZE + HMAC_KEY_SIZE {
            anyhow::bail!(
                "Master key material must be {} bytes ({} SM4 + {} HMAC), got {}",
                SM4_KEY_SIZE + HMAC_KEY_SIZE,
                SM4_KEY_SIZE,
                HMAC_KEY_SIZE,
                material.len()
            );
        }

        let mut sb = SecureBox::new(material.len())?;
        sb.copy_from_slice(material);

        Ok(Self {
            id: Uuid::new_v4(),
            material: sb,
        })
    }

    /// Generate a new random master key using OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let total_size = SM4_KEY_SIZE + HMAC_KEY_SIZE;
        let mut sb = SecureBox::new(total_size)?;
        rand::Rng::fill_bytes(&mut rand::rng(), &mut sb[..]);
        Ok(Self {
            id: Uuid::new_v4(),
            material: sb,
        })
    }

    /// Get the SM4 encryption key portion (first 16 bytes).
    fn sm4_key(&self) -> &[u8] {
        &self.material[..SM4_KEY_SIZE]
    }

    /// Get the HMAC signing key portion (last 32 bytes).
    fn hmac_key(&self) -> &[u8] {
        &self.material[SM4_KEY_SIZE..]
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// EncryptedMasterKey — Passphrase-encrypted master key for persistence
// ============================================================================

/// Encrypted master key for persistent storage.
///
/// The SM4 key + HMAC key are encrypted with a key derived from a passphrase
/// using SM3-based KDF (iterated hashing). The nonce and salt are random.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMasterKey {
    /// Master key identifier
    pub id: Uuid,
    /// SM4-GCM encrypted key material (ciphertext + tag)
    pub encrypted_material: Vec<u8>,
    /// 12-byte nonce for SM4-GCM
    pub nonce: Vec<u8>,
    /// 32-byte salt for KDF
    pub salt: Vec<u8>,
    /// KDF iteration count (recommend >= 100_000)
    pub kdf_iterations: u32,
}

/// Derive a 16-byte SM4 key from a passphrase + salt using SM3 iterated hashing.
fn derive_key_from_passphrase(passphrase: &str, salt: &[u8], iterations: u32) -> Result<SecureBox> {
    let mut key = SecureBox::new(SM4_KEY_SIZE)?;
    let mut buf = Vec::with_capacity(salt.len() + passphrase.len());

    // Initial: hash(salt || passphrase)
    buf.extend_from_slice(salt);
    buf.extend_from_slice(passphrase.as_bytes());
    let mut hash = gm_crypto::sm3::Sm3Hasher::hash(&buf)
        .map_err(|e| anyhow::anyhow!("SM3 KDF failed: {e}"))?;

    // Iterate
    for _ in 1..iterations {
        let mut input = hash.clone();
        input.extend_from_slice(&buf);
        hash = gm_crypto::sm3::Sm3Hasher::hash(&input)
            .map_err(|e| anyhow::anyhow!("SM3 KDF failed: {e}"))?;
    }

    key.copy_from_slice(&hash[..SM4_KEY_SIZE]);
    Ok(key)
}

impl MasterKey {
    /// Export the master key encrypted with a passphrase.
    ///
    /// Uses SM3-based KDF to derive a 128-bit key from the passphrase,
    /// then encrypts the full master key material (SM4 key + HMAC key) with SM4-GCM.
    pub fn export_encrypted(
        &self,
        passphrase: &str,
        kdf_iterations: u32,
    ) -> Result<EncryptedMasterKey> {
        let mut salt = SecureBox::new(32)?;
        rand::Rng::fill_bytes(&mut rand::rng(), &mut salt[..]);

        let derived_key = derive_key_from_passphrase(passphrase, &salt, kdf_iterations)?;

        let mut nonce = [0u8; SM4_NONCE_SIZE];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut nonce);

        let cipher = gm_crypto::sm4::Sm4Cipher::new(&derived_key)
            .map_err(|e| anyhow::anyhow!("Failed to create SM4 cipher for export: {e}"))?;

        let (ciphertext, tag) = cipher
            .encrypt_gcm(&self.material[..], &nonce, &[])
            .map_err(|e| anyhow::anyhow!("Failed to encrypt master key: {e}"))?;

        // Append tag to ciphertext
        let mut encrypted_material = ciphertext;
        encrypted_material.extend_from_slice(&tag);

        Ok(EncryptedMasterKey {
            id: self.id,
            encrypted_material,
            nonce: nonce.to_vec(),
            salt: salt.to_vec(),
            kdf_iterations,
        })
    }

    /// Import a master key from an encrypted export.
    pub fn import_encrypted(encrypted: &EncryptedMasterKey, passphrase: &str) -> Result<Self> {
        let derived_key =
            derive_key_from_passphrase(passphrase, &encrypted.salt, encrypted.kdf_iterations)?;

        let cipher = gm_crypto::sm4::Sm4Cipher::new(&derived_key)
            .map_err(|e| anyhow::anyhow!("Failed to create SM4 cipher for import: {e}"))?;

        // Split ciphertext and tag (tag is last 16 bytes)
        if encrypted.encrypted_material.len() < 16 {
            anyhow::bail!("Encrypted master key too short");
        }
        let split_at = encrypted.encrypted_material.len() - 16;
        let ciphertext = &encrypted.encrypted_material[..split_at];
        let tag = &encrypted.encrypted_material[split_at..];

        // Convert nonce
        let nonce: [u8; 12] = encrypted.nonce[..]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid nonce length"))?;

        let plaintext = cipher
            .decrypt_gcm(ciphertext, &nonce, &[], tag)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt master key: {e}"))?;

        let mut sb = SecureBox::new(plaintext.len())?;
        sb.copy_from_slice(&plaintext);

        Ok(Self {
            id: encrypted.id,
            material: sb,
        })
    }

    /// Persist this master key passphrase-encrypted to `path` (audit P2-7).
    ///
    /// Writes an [`EncryptedMasterKey`] JSON envelope with owner-only (0o600)
    /// permissions, creating the parent directory if needed.
    pub fn save_encrypted(
        &self,
        path: &std::path::Path,
        passphrase: &str,
        kdf_iterations: u32,
    ) -> Result<()> {
        let encrypted = self.export_encrypted(passphrase, kdf_iterations)?;
        let json = serde_json::to_string_pretty(&encrypted)
            .context("Failed to serialize encrypted master key")?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create master key directory")?;
        }
        std::fs::write(path, json).context("Failed to write encrypted master key")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .context("Failed to set master key file permissions")?;
        }
        Ok(())
    }

    /// Load a master key previously saved with [`MasterKey::save_encrypted`].
    ///
    /// The SM4-GCM tag is validated on decrypt, so a wrong passphrase or a
    /// corrupted file yields an error rather than a silently-wrong key.
    pub fn load_encrypted(path: &std::path::Path, passphrase: &str) -> Result<Self> {
        let json =
            std::fs::read_to_string(path).context("Failed to read encrypted master key file")?;
        let encrypted: EncryptedMasterKey =
            serde_json::from_str(&json).context("Failed to parse encrypted master key file")?;
        Self::import_encrypted(&encrypted, passphrase)
    }
}

// ============================================================================
// BackupConfig
// ============================================================================

/// Key backup configuration
#[derive(Debug, Clone)]
pub struct BackupConfig {
    /// Enable encrypted backup
    pub enabled: bool,
    /// Backup storage path
    pub backup_path: String,
    /// Retain number of backups per key
    pub retention_count: u32,
    /// Backup retention days
    pub retention_days: u32,
    /// KDF iterations for master key passphrase encryption
    pub kdf_iterations: u32,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backup_path: "/var/kms/backup".to_string(),
            retention_count: 3,
            retention_days: 365,
            kdf_iterations: 100_000,
        }
    }
}

// ============================================================================
// KeyBackupService
// ============================================================================

/// Key backup service providing encrypted backup and restore.
///
/// Uses SM4-GCM for encryption and SM3-HMAC for file integrity signing.
pub struct KeyBackupService {
    config: BackupConfig,
    master_key: MasterKey,
    /// In-memory backup registry (in production, use database)
    backup_registry: parking_lot::RwLock<Vec<BackupRecord>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct BackupRecord {
    key_id: Uuid,
    backup_id: Uuid,
    backed_up_at: chrono::DateTime<chrono::Utc>,
    material_hash: String,
}

impl KeyBackupService {
    /// Create a new backup service with the given master key.
    pub fn new(config: BackupConfig, master_key: MasterKey) -> Self {
        Self {
            config,
            master_key,
            backup_registry: parking_lot::RwLock::new(Vec::new()),
        }
    }

    /// Create a new backup service with a randomly generated master key.
    pub fn with_random_master_key(config: BackupConfig) -> Result<Self> {
        let master_key = MasterKey::generate()?;
        Ok(Self::new(config, master_key))
    }

    /// Load the backup master key from `backup_path`/[`MASTER_KEY_FILE`],
    /// generating and persisting it on first use (audit P2-7).
    ///
    /// This is the restart-safe replacement for [`KeyBackupService::with_random_master_key`]:
    /// the same master key is reloaded after a process restart, so backups taken
    /// by a previous run remain decryptable. The passphrase encrypts the master key
    /// at rest; a wrong passphrase or corrupted file fails loudly (never a silent
    /// regeneration, which would orphan existing backups). Runs a [`self_check`]
    /// (`MasterKey::self_check`) on the resulting service.
    ///
    /// [`self_check`]: KeyBackupService::self_check
    pub fn load_or_create(config: &BackupConfig, passphrase: &str) -> Result<Self> {
        anyhow::ensure!(
            !passphrase.is_empty(),
            "backup master key passphrase must not be empty"
        );
        let path = std::path::Path::new(&config.backup_path).join(MASTER_KEY_FILE);
        let master_key = if path.exists() {
            MasterKey::load_encrypted(&path, passphrase).with_context(|| {
                format!(
                    "failed to load backup master key from {} (wrong passphrase or corrupted file)",
                    path.display()
                )
            })?
        } else {
            let mk = MasterKey::generate()?;
            mk.save_encrypted(&path, passphrase, config.kdf_iterations)?;
            tracing::info!(
                "Generated and persisted backup master key at {}",
                path.display()
            );
            mk
        };
        let svc = Self::new(config.clone(), master_key);
        svc.self_check()?;
        Ok(svc)
    }

    /// Verify the master key is usable: an SM4-GCM encrypt/decrypt round-trip and
    /// an SM3-HMAC compute both succeed. Called at startup so a corrupted or
    /// wrong-passphrase master key fails fast rather than silently producing
    /// backups that can never be restored (audit P2-7).
    pub fn self_check(&self) -> Result<()> {
        let probe = b"kms-backup-masterkey-self-check";
        let mut nonce = [0u8; SM4_NONCE_SIZE];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut nonce);
        let ct = self.encrypt_with_master(probe, &nonce)?;
        let back = self.decrypt_with_master(&ct, &nonce)?;
        if back != probe {
            anyhow::bail!("backup master key self-check failed: SM4-GCM round-trip mismatch");
        }
        // Computing the HMAC exercises the signing portion of the master key.
        let _ = self.compute_hmac(probe)?;
        Ok(())
    }

    /// Backup a key with SM4-GCM encryption and SM3-HMAC signing.
    ///
    /// Returns the `KeyBackup` metadata. The signed backup file is written
    /// to disk automatically.
    pub fn backup_key(
        &self,
        key_meta: &KeyMeta,
        key_material: &[u8],
        description: Option<String>,
    ) -> Result<KeyBackup> {
        // Generate random nonce for SM4-GCM
        let mut nonce = [0u8; SM4_NONCE_SIZE];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut nonce);

        // Compute SM3 hash of original material for integrity check
        let material_hash = gm_crypto::sm3::Sm3Hasher::hash_hex(key_material)
            .map_err(|e| anyhow::anyhow!("SM3 hash failed: {e}"))?;

        // Encrypt key material with master key using SM4-GCM
        let encrypted_material = self.encrypt_with_master(key_material, &nonce)?;

        let backup = KeyBackup {
            version: BACKUP_VERSION,
            key_meta: key_meta.clone(),
            encrypted_material,
            nonce: nonce.to_vec(),
            material_hash: material_hash.clone(),
            backed_up_at: chrono::Utc::now(),
            description,
        };

        // Register in-memory
        {
            let mut registry = self.backup_registry.write();
            registry.push(BackupRecord {
                key_id: key_meta.id,
                backup_id: Uuid::new_v4(),
                backed_up_at: backup.backed_up_at,
                material_hash: material_hash.clone(),
            });
        }

        // Save signed backup to persistent storage
        self.save_backup(&backup)?;

        tracing::info!("Backed up key {} to backup storage", key_meta.id);
        Ok(backup)
    }

    /// Restore a key from backup with integrity verification.
    pub fn restore_key(&self, backup: &KeyBackup) -> Result<Vec<u8>> {
        // Verify backup version
        if backup.version != BACKUP_VERSION {
            anyhow::bail!(
                "Unsupported backup version: {} (expected {})",
                backup.version,
                BACKUP_VERSION
            );
        }

        // Decrypt key material with SM4-GCM
        let nonce: [u8; 12] = backup.nonce[..]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid nonce length in backup"))?;

        let key_material = self.decrypt_with_master(&backup.encrypted_material, &nonce)?;

        // Verify SM3 integrity hash
        let computed_hash = gm_crypto::sm3::Sm3Hasher::hash_hex(&key_material)
            .map_err(|e| anyhow::anyhow!("SM3 hash failed: {e}"))?;

        if computed_hash != backup.material_hash {
            anyhow::bail!(
                "Key material SM3 integrity check failed for key {}",
                backup.key_meta.id
            );
        }

        tracing::info!("Restored key {} from backup", backup.key_meta.id);
        Ok(key_material)
    }

    /// Verify a backup file on disk (parses JSON, verifies HMAC, checks structure).
    pub fn verify_backup_file(&self, path: &std::path::Path) -> Result<KeyBackup> {
        let file_content =
            std::fs::read_to_string(path).context("Failed to read backup file for verification")?;

        let signed: SignedBackup =
            serde_json::from_str(&file_content).context("Failed to parse signed backup file")?;

        // Verify HMAC signature
        let computed_sig = self.compute_hmac(signed.data.as_bytes())?;
        if computed_sig != signed.signature {
            anyhow::bail!("Backup file HMAC signature verification failed");
        }

        // Parse the inner backup
        let backup: KeyBackup =
            serde_json::from_str(&signed.data).context("Failed to parse backup data")?;

        if backup.version != BACKUP_VERSION {
            anyhow::bail!("Backup version mismatch: {}", backup.version);
        }

        Ok(backup)
    }

    /// Load a backup from a file on disk (verifies HMAC signature, does not decrypt).
    pub fn load_backup_file(&self, path: &std::path::Path) -> Result<KeyBackup> {
        self.verify_backup_file(path)
    }

    /// Load a backup from file and restore the key material.
    pub fn restore_from_file(&self, path: &std::path::Path) -> Result<(KeyBackup, Vec<u8>)> {
        let backup = self.load_backup_file(path)?;
        let material = self.restore_key(&backup)?;
        Ok((backup, material))
    }

    // -- internal methods --

    /// Encrypt plaintext with SM4-GCM using the master key.
    fn encrypt_with_master(&self, plaintext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let cipher = gm_crypto::sm4::Sm4Cipher::new(self.master_key.sm4_key())
            .map_err(|e| anyhow::anyhow!("Failed to create SM4 cipher: {e}"))?;

        let (ciphertext, tag) = cipher
            .encrypt_gcm(plaintext, nonce, &[])
            .map_err(|e| anyhow::anyhow!("SM4-GCM encryption failed: {e}"))?;

        // Append 16-byte GCM tag to ciphertext
        let mut result = ciphertext;
        result.extend_from_slice(&tag);
        Ok(result)
    }

    /// Decrypt ciphertext with SM4-GCM using the master key.
    fn decrypt_with_master(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        if ciphertext.len() < 16 {
            anyhow::bail!("Ciphertext too short for SM4-GCM (need at least 16 bytes for tag)");
        }

        let split_at = ciphertext.len() - 16;
        let ct = &ciphertext[..split_at];
        let tag = &ciphertext[split_at..];

        let cipher = gm_crypto::sm4::Sm4Cipher::new(self.master_key.sm4_key())
            .map_err(|e| anyhow::anyhow!("Failed to create SM4 cipher: {e}"))?;

        cipher
            .decrypt_gcm(ct, nonce, &[], tag)
            .map_err(|e| anyhow::anyhow!("SM4-GCM decryption failed: {e}"))
    }

    /// Compute SM3-HMAC of data using the HMAC signing key.
    fn compute_hmac(&self, data: &[u8]) -> Result<String> {
        let hmac = gm_crypto::sm3::Sm3Hmac::new(self.master_key.hmac_key());
        hmac.compute_hex(data)
            .map_err(|e| anyhow::anyhow!("SM3-HMAC computation failed: {e}"))
    }

    /// Save backup to persistent storage with SM3-HMAC signing.
    fn save_backup(&self, backup: &KeyBackup) -> Result<()> {
        let backup_path = std::path::Path::new(&self.config.backup_path);
        if !backup_path.exists() {
            std::fs::create_dir_all(backup_path).context("Failed to create backup directory")?;
        }

        // Serialize the backup to JSON
        let data = serde_json::to_string(backup).context("Failed to serialize backup")?;

        // Sign with SM3-HMAC
        let signature = self.compute_hmac(data.as_bytes())?;

        let signed = SignedBackup { data, signature };

        let filename = format!(
            "{}-{}.json",
            backup.key_meta.id,
            backup.backed_up_at.timestamp()
        );
        let path = backup_path.join(filename);

        let json =
            serde_json::to_string_pretty(&signed).context("Failed to serialize signed backup")?;

        std::fs::write(&path, json).context("Failed to write backup file")?;

        // Set file permissions to owner-only (0o600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&path) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&path, perms)?;
            }
        }

        Ok(())
    }

    /// Identifier of the backup master key (non-secret; usable to assert that a
    /// reload yielded the same persisted key without exposing material).
    pub fn master_key_id(&self) -> Uuid {
        self.master_key.id
    }

    /// List backups for a key from the in-memory registry.
    pub fn list_backups(&self, key_id: &Uuid) -> Vec<chrono::DateTime<chrono::Utc>> {
        let registry = self.backup_registry.read();
        registry
            .iter()
            .filter(|r| r.key_id == *key_id)
            .map(|r| r.backed_up_at)
            .collect()
    }

    /// Delete old backups beyond retention period.
    pub fn cleanup_old_backups(&self) -> Result<usize> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(self.config.retention_days as i64);
        let mut removed = 0;

        let backup_path = std::path::Path::new(&self.config.backup_path);
        if backup_path.exists() {
            for entry in std::fs::read_dir(backup_path)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json")
                    && let Ok(metadata) = entry.metadata()
                    && let Ok(modified) = metadata.modified()
                {
                    let modified: chrono::DateTime<chrono::Utc> = modified.into();
                    if modified < cutoff {
                        std::fs::remove_file(&path)?;
                        removed += 1;
                    }
                }
            }
        }

        if removed > 0 {
            tracing::info!("Cleaned up {} old backup(s)", removed);
        }
        Ok(removed)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_key_meta() -> KeyMeta {
        KeyMeta {
            id: Uuid::new_v4(),
            tenant_id: "test-tenant".to_string(),
            name: "test-key".to_string(),
            spec: crate::key::KeySpec::Sm4,
            status: crate::key::KeyStatus::Active,
            version: 1,
            created_at: chrono::Utc::now(),
            rotated_at: None,
            description: None,
            metadata: crate::key::KeyMetadata::default(),
        }
    }

    fn create_test_service(temp_dir: &tempfile::TempDir) -> KeyBackupService {
        let config = BackupConfig {
            backup_path: temp_dir.path().to_string_lossy().to_string(),
            ..Default::default()
        };
        KeyBackupService::with_random_master_key(config)
            .expect("Failed to create test backup service")
    }

    // -- MasterKey tests --

    #[test]
    fn test_master_key_generate() {
        let mk = MasterKey::generate().unwrap();
        assert_eq!(mk.sm4_key().len(), SM4_KEY_SIZE);
        assert_eq!(mk.hmac_key().len(), HMAC_KEY_SIZE);
    }

    #[test]
    fn test_master_key_new_invalid_size() {
        let result = MasterKey::new(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_master_key_debug_no_leak() {
        // Generate multiple keys to ensure no key material bytes leak through Debug
        for _ in 0..10 {
            let mk = MasterKey::generate().unwrap();
            let debug_str = format!("{mk:?}");
            assert!(debug_str.contains("MasterKey"));
            // The Debug impl only shows `id` (UUID) and `..` — never raw key bytes.
            // Check that the debug output matches the expected pattern exactly.
            assert!(
                debug_str.starts_with("MasterKey { id:")
                    || debug_str.starts_with("MasterKey { id "),
                "Debug output should start with 'MasterKey {{ id:' but got: {debug_str}"
            );
            assert!(
                debug_str.contains(".."),
                "Debug output should contain '..' (finish_non_exhaustive), got: {debug_str}"
            );
        }
    }

    // -- Backup/restore roundtrip --

    #[test]
    fn test_backup_restore_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let service = create_test_service(&temp_dir);

        let key_meta = create_test_key_meta();
        let key_material = b"super_secret_key_material_32_bytes!!";

        let backup = service.backup_key(&key_meta, key_material, None).unwrap();

        assert_eq!(backup.version, BACKUP_VERSION);
        assert_eq!(backup.key_meta.id, key_meta.id);
        assert!(!backup.encrypted_material.is_empty());
        assert_eq!(backup.nonce.len(), SM4_NONCE_SIZE);

        // Restore
        let restored = service.restore_key(&backup).unwrap();
        assert_eq!(restored, key_material);
    }

    #[test]
    fn test_backup_restore_with_description() {
        let temp_dir = tempfile::tempdir().unwrap();
        let service = create_test_service(&temp_dir);

        let key_meta = create_test_key_meta();
        let desc = "Quarterly backup for compliance".to_string();

        let backup = service
            .backup_key(&key_meta, b"test_key", Some(desc.clone()))
            .unwrap();

        assert_eq!(backup.description, Some(desc));
    }

    #[test]
    fn test_backup_uses_sm4_gcm() {
        let temp_dir = tempfile::tempdir().unwrap();
        let service = create_test_service(&temp_dir);

        let key_meta = create_test_key_meta();
        // Key material must be exactly 16 bytes for SM4 key
        let key_material = b"0123456789abcdef";

        let backup = service.backup_key(&key_meta, key_material, None).unwrap();

        // SM4-GCM produces ciphertext + 16-byte tag
        // Ciphertext should be same length as plaintext, plus tag
        assert_eq!(backup.encrypted_material.len(), key_material.len() + 16);

        // Verify roundtrip
        let restored = service.restore_key(&backup).unwrap();
        assert_eq!(restored, key_material);
    }

    // -- Integrity checks --

    #[test]
    fn test_integrity_check_fails_on_tampered_ciphertext() {
        let temp_dir = tempfile::tempdir().unwrap();
        let service = create_test_service(&temp_dir);

        let key_meta = create_test_key_meta();
        let key_material = b"test_key_16bytes!";

        let backup = service.backup_key(&key_meta, key_material, None).unwrap();

        // Tamper with encrypted material
        let mut tampered = backup.clone();
        tampered.encrypted_material[0] ^= 0xFF;

        let result = service.restore_key(&tampered);
        assert!(
            result.is_err(),
            "Tampered backup should fail decryption/integrity"
        );
    }

    #[test]
    fn test_integrity_check_fails_on_tampered_nonce() {
        let temp_dir = tempfile::tempdir().unwrap();
        let service = create_test_service(&temp_dir);

        let key_meta = create_test_key_meta();
        let backup = service
            .backup_key(&key_meta, b"test_key_16bytes!", None)
            .unwrap();

        let mut tampered = backup.clone();
        tampered.nonce[0] ^= 0xFF;

        let result = service.restore_key(&tampered);
        assert!(result.is_err(), "Tampered nonce should fail decryption");
    }

    #[test]
    fn test_integrity_check_fails_on_tampered_material_hash() {
        let temp_dir = tempfile::tempdir().unwrap();
        let service = create_test_service(&temp_dir);

        let key_meta = create_test_key_meta();
        let key_material = b"test_key_16bytes!";
        let backup = service.backup_key(&key_meta, key_material, None).unwrap();

        // Tamper the hash but not ciphertext — should still fail since
        // the actual decryption won't match
        let mut tampered = backup.clone();
        tampered.material_hash = "00000000000000000000000000000000".to_string();

        let result = service.restore_key(&tampered);
        assert!(
            result.is_err(),
            "Tampered hash should trigger integrity failure"
        );
    }

    // -- Signed backup file tests --

    #[test]
    fn test_signed_backup_file_on_disk() {
        let temp_dir = tempfile::tempdir().unwrap();
        let service = create_test_service(&temp_dir);

        let key_meta = create_test_key_meta();
        let key_material = b"signed_backup_test!";

        let _backup = service.backup_key(&key_meta, key_material, None).unwrap();

        // Find the backup file on disk
        let backup_path = std::path::Path::new(temp_dir.path());
        let files: Vec<_> = std::fs::read_dir(backup_path)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(files.len(), 1, "Should have exactly one backup file");

        let file_path = files[0].path();

        // Verify the file is signed
        let loaded = service.verify_backup_file(&file_path).unwrap();
        assert_eq!(loaded.key_meta.id, key_meta.id);
    }

    #[test]
    fn test_hmac_verification_fails_on_tampered_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let service = create_test_service(&temp_dir);

        let key_meta = create_test_key_meta();
        service
            .backup_key(&key_meta, b"signed_backup_test!", None)
            .unwrap();

        let files: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        let file_path = files[0].path();

        // Tamper with the file content — flip a byte in the data payload
        let mut content = std::fs::read_to_string(&file_path).unwrap();
        // The SignedBackup contains a "data" field with the serialized KeyBackup.
        // We flip a character in the data to invalidate the HMAC.
        content = content.replacen("\\\"version\\\":2", "\\\"version\\\":9", 1);
        std::fs::write(&file_path, &content).unwrap();

        let result = service.verify_backup_file(&file_path);
        assert!(
            result.is_err(),
            "Tampered backup file should fail HMAC verification"
        );
    }

    #[test]
    fn test_restore_from_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let service = create_test_service(&temp_dir);

        let key_meta = create_test_key_meta();
        let key_material = b"restore_file_test!";
        service.backup_key(&key_meta, key_material, None).unwrap();

        let files: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        let file_path = files[0].path();

        let (loaded_backup, restored_material) = service.restore_from_file(&file_path).unwrap();
        assert_eq!(loaded_backup.key_meta.id, key_meta.id);
        assert_eq!(restored_material, key_material);
    }

    // -- Master key export/import --

    #[test]
    fn test_master_key_export_import_roundtrip() {
        let mk = MasterKey::generate().unwrap();
        let passphrase = "correct-horse-battery-staple";

        let encrypted = mk.export_encrypted(passphrase, 10_000).unwrap();
        assert_eq!(encrypted.id, mk.id);
        assert!(!encrypted.encrypted_material.is_empty());
        assert_eq!(encrypted.salt.len(), 32);
        assert_eq!(encrypted.kdf_iterations, 10_000);

        // Import with correct passphrase
        let mk2 = MasterKey::import_encrypted(&encrypted, passphrase).unwrap();
        assert_eq!(mk2.id, mk.id);
        assert_eq!(mk2.sm4_key(), mk.sm4_key());
        assert_eq!(mk2.hmac_key(), mk.hmac_key());
    }

    #[test]
    fn test_master_key_import_wrong_passphrase() {
        let mk = MasterKey::generate().unwrap();
        let encrypted = mk.export_encrypted("correct-passphrase", 1000).unwrap();

        let result = MasterKey::import_encrypted(&encrypted, "wrong-passphrase");
        assert!(result.is_err(), "Wrong passphrase should fail");
    }

    #[test]
    fn test_master_key_import_wrong_salt() {
        let mk = MasterKey::generate().unwrap();
        let passphrase = "test-passphrase";
        let mut encrypted = mk.export_encrypted(passphrase, 1000).unwrap();

        // Tamper salt
        encrypted.salt[0] ^= 0xFF;

        let result = MasterKey::import_encrypted(&encrypted, passphrase);
        assert!(
            result.is_err(),
            "Wrong salt should produce wrong key and fail"
        );
    }

    // -- Master key persistence (audit P2-7) --

    #[test]
    fn test_master_key_save_load_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join(MASTER_KEY_FILE);
        let passphrase = "persist-me";

        let mk = MasterKey::generate().unwrap();
        mk.save_encrypted(&path, passphrase, 1000).unwrap();
        assert!(path.exists(), "master key file should be written");

        let loaded = MasterKey::load_encrypted(&path, passphrase).unwrap();
        assert_eq!(loaded.id, mk.id);
        assert_eq!(loaded.sm4_key(), mk.sm4_key());
        assert_eq!(loaded.hmac_key(), mk.hmac_key());
    }

    #[test]
    fn test_master_key_load_wrong_passphrase_fails() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join(MASTER_KEY_FILE);

        let mk = MasterKey::generate().unwrap();
        mk.save_encrypted(&path, "right", 1000).unwrap();

        let result = MasterKey::load_encrypted(&path, "wrong");
        assert!(
            result.is_err(),
            "loading with a wrong passphrase must fail (GCM tag)"
        );
    }

    /// The core P2-7 scenario: a backup taken by one run must be restorable by a
    /// later run that reloads the SAME persisted master key.
    #[test]
    fn test_backup_survives_restart_via_load_or_create() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = BackupConfig {
            backup_path: temp_dir.path().to_string_lossy().to_string(),
            kdf_iterations: 1000,
            ..Default::default()
        };
        let passphrase = "restart-passphrase";

        // Run 1: creates + persists the master key, then backs up a key.
        let svc1 = KeyBackupService::load_or_create(&config, passphrase).unwrap();
        let key_meta = create_test_key_meta();
        let material = b"persisted-across-restart-material";
        svc1.backup_key(&key_meta, material, None).unwrap();
        let mk1_id = svc1.master_key_id();

        let files: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
            .collect();
        let backup_file = files[0].path();

        // Run 2 (simulated restart): reload from the same directory + passphrase.
        let svc2 = KeyBackupService::load_or_create(&config, passphrase).unwrap();
        assert_eq!(
            svc2.master_key_id(),
            mk1_id,
            "reload must yield the same persisted master key"
        );

        let (_, restored) = svc2.restore_from_file(&backup_file).unwrap();
        assert_eq!(
            restored, material,
            "run 2 must restore a backup created by run 1"
        );
    }

    /// Without persistence (the pre-fix `with_random_master_key`), a second service
    /// gets a fresh random master key and can no longer restore run 1's backup.
    #[test]
    fn test_random_master_key_cannot_restore_prior_backup() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = BackupConfig {
            backup_path: temp_dir.path().to_string_lossy().to_string(),
            ..Default::default()
        };

        let svc1 = KeyBackupService::with_random_master_key(config.clone()).unwrap();
        let key_meta = create_test_key_meta();
        svc1.backup_key(&key_meta, b"orphaned-material", None)
            .unwrap();
        let backup_file = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
            .unwrap();

        let svc2 = KeyBackupService::with_random_master_key(config).unwrap();
        assert!(
            svc2.restore_from_file(&backup_file).is_err(),
            "a fresh random master key must NOT decrypt the previous backup"
        );
    }

    #[test]
    fn test_load_or_create_wrong_passphrase_fails_closed() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = BackupConfig {
            backup_path: temp_dir.path().to_string_lossy().to_string(),
            kdf_iterations: 1000,
            ..Default::default()
        };

        KeyBackupService::load_or_create(&config, "right").unwrap();

        // A second startup with the wrong passphrase must fail loudly rather than
        // silently regenerating a new master key (which would orphan backups).
        let result = KeyBackupService::load_or_create(&config, "wrong");
        assert!(result.is_err(), "wrong passphrase must fail closed");
    }

    #[test]
    fn test_load_or_create_empty_passphrase_rejected() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = BackupConfig {
            backup_path: temp_dir.path().to_string_lossy().to_string(),
            ..Default::default()
        };
        assert!(KeyBackupService::load_or_create(&config, "").is_err());
    }

    // -- Listing & cleanup --

    #[test]
    fn test_list_backups() {
        let temp_dir = tempfile::tempdir().unwrap();
        let service = create_test_service(&temp_dir);

        let key_meta = create_test_key_meta();
        let key_material = b"list_backups_test";

        for _ in 0..3 {
            service.backup_key(&key_meta, key_material, None).unwrap();
        }

        let backups = service.list_backups(&key_meta.id);
        assert_eq!(backups.len(), 3);
    }

    #[test]
    fn test_backup_version() {
        let temp_dir = tempfile::tempdir().unwrap();
        let service = create_test_service(&temp_dir);

        let key_meta = create_test_key_meta();
        let backup = service
            .backup_key(&key_meta, b"version_test_16b!", None)
            .unwrap();

        assert_eq!(backup.version, BACKUP_VERSION);
    }

    #[test]
    fn test_cleanup_old_backups() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = BackupConfig {
            backup_path: temp_dir.path().to_string_lossy().to_string(),
            retention_days: 365, // only cleanup > 365 days
            ..Default::default()
        };
        let service = KeyBackupService::with_random_master_key(config).unwrap();

        let key_meta = create_test_key_meta();
        service
            .backup_key(&key_meta, b"cleanup_test_16b!!", None)
            .unwrap();

        // Nothing should be removed since backup is recent
        let removed = service.cleanup_old_backups().unwrap();
        assert_eq!(removed, 0);
    }
}
