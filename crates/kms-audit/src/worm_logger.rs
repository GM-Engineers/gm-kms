//! WORM-enabled signed audit logger
//!
//! Integrates hash chain signing with WORM-compatible storage
//! for compliance with 等保三级 and 金融行业 requirements.

use super::{AuditEvent, SignedAuditConfig, SignedAuditEntry, WormWriter};
use crate::AuditConfig;
use crate::error::{AuditError, AuditResult};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Configuration for WORM-enabled signed audit logging
#[derive(Debug, Clone)]
pub struct WormSignedAuditConfig {
    /// Signed audit configuration
    pub signed: SignedAuditConfig,
    /// WORM storage configuration
    pub worm_path: PathBuf,
    /// Rotation age in seconds (default: 1 hour)
    pub rotation_age_secs: u64,
    /// PR-4.11 / P2-6: signing-key path is now configurable.
    /// `None` preserves pre-4.11 behavior (sibling file at
    /// `<worm_path>.signing_key`); `Some(p)` stores the key at `p`,
    /// which SHOULD be on a separate filesystem from `worm_path`.
    pub signing_key_path: Option<PathBuf>,
}

/// Default sibling signing-key path (preserved for backward
/// compatibility with pre-PR-4.11 callers).
fn default_signing_key_path(worm_path: &Path) -> PathBuf {
    worm_path.with_extension("signing_key")
}

impl WormSignedAuditConfig {
    /// Create new WORM signed audit config with random signing key
    pub fn new(worm_path: PathBuf, initial_sequence: u64) -> Self {
        let signed_config = SignedAuditConfig::new(AuditConfig::default(), initial_sequence);
        Self {
            signed: signed_config,
            worm_path,
            rotation_age_secs: 3600,
            signing_key_path: None,
        }
    }

    /// Create with existing signing key
    pub fn with_key(worm_path: PathBuf, signing_key: Vec<u8>, initial_sequence: u64) -> Self {
        let signed_config =
            SignedAuditConfig::with_key(AuditConfig::default(), signing_key, initial_sequence);
        Self {
            signed: signed_config,
            worm_path,
            rotation_age_secs: 3600,
            signing_key_path: None,
        }
    }

    /// Create new config, loading signing key from disk if present
    ///
    /// If the signing key file exists, loads it; otherwise generates a new random key.
    /// The key is stored with restrictive permissions (0o600).
    /// Create new config, loading signing key from disk if present
    ///
    /// If the signing key file exists, loads it; otherwise generates a new random key.
    /// The key is stored with restrictive permissions (0o600).
    pub fn load_or_create(worm_path: PathBuf, initial_sequence: u64) -> AuditResult<Self> {
        // PR-4.11 / P2-6: load the signing key from the DEFAULT
        // sibling path. `load_or_create_with_key_path` is the
        // variant for operators who want the key on a separate
        // filesystem. We intentionally do NOT mutate `signing_key_path`
        // here — pre-PR-4.11 callers see byte-identical behavior.
        let key_path = default_signing_key_path(&worm_path);
        let signing_key = load_or_generate_key(&key_path)?;

        let signed_config =
            SignedAuditConfig::with_key(AuditConfig::default(), signing_key, initial_sequence);
        Ok(Self {
            signed: signed_config,
            worm_path,
            rotation_age_secs: 3600,
            signing_key_path: None,
        })
    }

    /// PR-4.11 / P2-6: load-or-create the signing key at a custom
    /// path (separate from `worm_path`). Returns a config whose
    /// `signing_key_path` is set to `key_path`, so subsequent calls
    /// to `effective_signing_key_path()` resolve to the custom
    /// location. Operators SHOULD deploy `key_path` on a different
    /// filesystem / mount / account than `worm_path`.
    pub fn load_or_create_with_key_path(
        worm_path: PathBuf,
        key_path: PathBuf,
        initial_sequence: u64,
    ) -> AuditResult<Self> {
        let signing_key = load_or_generate_key(&key_path)?;

        let signed_config =
            SignedAuditConfig::with_key(AuditConfig::default(), signing_key, initial_sequence);
        Ok(Self {
            signed: signed_config,
            worm_path,
            rotation_age_secs: 3600,
            signing_key_path: Some(key_path),
        })
    }

    /// Set rotation age
    pub fn with_rotation_age_secs(mut self, secs: u64) -> Self {
        self.rotation_age_secs = secs;
        self
    }

    /// PR-4.11 / P2-6: store the HMAC signing key at a custom
    /// path, separate from the WORM storage path. Operators are
    /// STRONGLY advised to deploy the key on a different
    /// filesystem / mount / account than the WORM log, so that
    /// the audit signing material is not co-located with the data
    /// it signs (preserving the integrity guarantee of WORM
    /// append-only storage).
    pub fn with_signing_key_path(mut self, p: PathBuf) -> Self {
        self.signing_key_path = Some(p);
        self
    }

    /// PR-4.11 / P2-6: resolve the effective signing-key path,
    /// honoring the operator-supplied override if set; otherwise
    /// returns the default sibling path. This is the SINGLE
    /// source of truth — every key load/generation call MUST go
    /// through this method.
    pub fn effective_signing_key_path(&self) -> PathBuf {
        self.signing_key_path
            .clone()
            .unwrap_or_else(|| default_signing_key_path(&self.worm_path))
    }
}

/// Load signing key from file or generate a new one if not present
fn load_or_generate_key(key_path: &Path) -> AuditResult<Vec<u8>> {
    if key_path.exists() {
        // Load existing key
        let key_bytes = std::fs::read(key_path)?;
        if key_bytes.len() != 32 {
            return Err(AuditError::Config(format!(
                "Invalid signing key length: expected 32 bytes, got {}",
                key_bytes.len()
            )));
        }
        tracing::info!("Loaded audit signing key from {}", key_path.display());
        Ok(key_bytes)
    } else {
        // Generate new key
        let mut signing_key = vec![0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut signing_key);

        // Ensure parent directory exists
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Write with restrictive permissions (0o600 = owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(key_path, &signing_key)?;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(key_path, perms)?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(key_path, &signing_key)?;
        }

        tracing::info!("Generated new audit signing key at {}", key_path.display());
        Ok(signing_key)
    }
}

/// WORM-enabled signed audit logger
///
/// This logger combines:
/// - HMAC-SHA256 hash chain signing (tamper evidence)
/// - WORM-compatible file storage (immutability)
/// - Automatic file rotation (retention management)
pub struct WormSignedAuditLogger {
    config: WormSignedAuditConfig,
    buffer: Arc<Mutex<Vec<SignedAuditEntry>>>,
    current_sequence: Arc<Mutex<u64>>,
    previous_signature: Arc<Mutex<Option<Vec<u8>>>>,
    worm_writer: Arc<WormWriter>,
}

impl WormSignedAuditLogger {
    /// Create new WORM signed audit logger
    pub fn new(config: WormSignedAuditConfig) -> AuditResult<Self> {
        let worm_writer = WormWriter::new(config.worm_path.clone())?
            .with_rotation_age(std::time::Duration::from_secs(config.rotation_age_secs));

        Ok(Self {
            config,
            buffer: Arc::new(Mutex::new(Vec::new())),
            current_sequence: Arc::new(Mutex::new(0)),
            previous_signature: Arc::new(Mutex::new(None)),
            worm_writer: Arc::new(worm_writer),
        })
    }

    /// Log an audit event with signature and WORM storage
    pub async fn log(&self, event: impl Into<AuditEvent>) {
        let audit_event: AuditEvent = event.into();

        let sequence = {
            let mut seq_guard = self.current_sequence.lock().await;
            let seq = *seq_guard;
            *seq_guard += 1;
            seq
        };

        let prev_sig = {
            let prev_guard = self.previous_signature.lock().await;
            prev_guard.clone()
        };

        let signing_key = &*self.config.signed.signing_key;
        let prev_sig_ref = prev_sig.as_deref();
        let signed_entry =
            SignedAuditEntry::new(audit_event, sequence, signing_key, prev_sig_ref, None);

        // Update previous signature
        {
            let mut prev_guard = self.previous_signature.lock().await;
            *prev_guard = Some(signed_entry.signature.clone());
        }

        // Write to WORM storage immediately
        if let Err(e) = self.worm_writer.append(&signed_entry).await {
            tracing::error!("Failed to write to WORM storage: {}", e);
        }

        // Buffer for potential additional outputs (Kafka, etc.)
        let mut buffer = self.buffer.lock().await;
        buffer.push(signed_entry);

        // Flush if buffer is full
        if buffer.len() >= self.config.signed.base.buffer_size {
            drop(buffer);
            self.flush().await;
        }
    }

    /// Log from an Event
    pub async fn log_event(&self, event: &kms_core::Event) {
        self.log(super::AuditEvent::from(event.clone())).await;
    }

    /// Flush buffer to non-WORM outputs (stdout, Kafka)
    pub async fn flush(&self) {
        let entries = {
            let mut buffer = self.buffer.lock().await;
            buffer.drain(..).collect::<Vec<_>>()
        };

        if entries.is_empty() {
            return;
        }

        // Output to stdout or file (non-WORM output)
        let stdout = std::io::stdout();
        let mut output: Box<dyn std::io::Write> =
            if self.config.signed.base.output_path.to_string_lossy() == "stdout" {
                Box::new(stdout)
            } else {
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.config.signed.base.output_path)
                {
                    Ok(file) => Box::new(file) as Box<dyn std::io::Write>,
                    Err(_) => Box::new(stdout) as Box<dyn std::io::Write>,
                }
            };

        for entry in &entries {
            if let Ok(line) = serde_json::to_string(entry) {
                let _ = writeln!(output, "{line}");
            }
        }
    }

    /// Get the signing key (for verification)
    pub fn signing_key(&self) -> &[u8] {
        &self.config.signed.signing_key
    }

    /// Get WORM writer for direct access
    pub fn worm_writer(&self) -> &Arc<WormWriter> {
        &self.worm_writer
    }

    /// Verify hash chain integrity
    pub async fn verify_chain(
        &self,
        entries: &[SignedAuditEntry],
    ) -> AuditResult<super::VerificationReport> {
        self.worm_writer.verify_chain(entries).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kms_core::EventType;
    use tempfile::tempdir;

    fn create_test_event() -> AuditEvent {
        AuditEvent {
            event_id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            event_type: EventType::KeyCreated,
            actor_id: "test-user".to_string(),
            actor_type: "user".to_string(),
            action: "test".to_string(),
            resource_type: "key".to_string(),
            resource_id: Some("test-key".to_string()),
            result: "success".to_string(),
            metadata: std::collections::HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_worm_signed_logger() -> AuditResult<()> {
        let temp_dir = tempdir()?;
        let path = temp_dir.path().join("audit");

        let config = WormSignedAuditConfig::new(path.clone(), 0);
        let logger = WormSignedAuditLogger::new(config)?;

        // Log several events
        for _ in 0..3 {
            let event = create_test_event();
            logger.log(event).await;
        }

        // Flush and verify
        logger.flush().await;

        // Verify WORM writer state
        let state = logger.worm_writer().get_chain_state().await;
        assert_eq!(state.entry_count(), 3);

        Ok(())
    }

    #[tokio::test]
    async fn test_signing_key_access() -> AuditResult<()> {
        let temp_dir = tempdir()?;
        let path = temp_dir.path().join("audit");

        let signing_key = vec![0u8; 32];
        let config = WormSignedAuditConfig::with_key(path, signing_key.clone(), 0);
        let logger = WormSignedAuditLogger::new(config)?;

        assert_eq!(logger.signing_key(), signing_key.as_slice());

        Ok(())
    }

    // --- Additional tests ---

    /// Test load_or_create generates a new key if not present
    #[test]
    fn test_load_or_create_new_key() -> AuditResult<()> {
        let temp_dir = tempdir()?;
        let worm_path = temp_dir.path().join("audit");
        let key_path = default_signing_key_path(&worm_path);

        assert!(!key_path.exists());

        let config = WormSignedAuditConfig::load_or_create(worm_path.clone(), 0)?;

        // Key file should now exist
        assert!(key_path.exists());
        // Key should be 32 bytes
        assert_eq!(config.signed.signing_key.len(), 32);

        Ok(())
    }

    /// Test load_or_create loads existing key
    #[test]
    fn test_load_or_create_existing_key() -> AuditResult<()> {
        let temp_dir = tempdir()?;
        let worm_path = temp_dir.path().join("audit");
        let _key_path = default_signing_key_path(&worm_path);

        // First call creates
        let config1 = WormSignedAuditConfig::load_or_create(worm_path.clone(), 0)?;
        let key1 = config1.signed.signing_key.clone();

        // Second call should load the same key
        let config2 = WormSignedAuditConfig::load_or_create(worm_path, 0)?;
        assert_eq!(config2.signed.signing_key, key1);

        Ok(())
    }

    /// Test with_rotation_age_secs
    #[test]
    fn test_with_rotation_age_secs() {
        let path = std::path::PathBuf::from("/tmp/test_audit");
        let config = WormSignedAuditConfig::new(path, 0).with_rotation_age_secs(7200);
        assert_eq!(config.rotation_age_secs, 7200);
    }

    /// Test log_event (from kms_core::Event)
    #[tokio::test]
    async fn test_log_event_from_event() -> AuditResult<()> {
        let temp_dir = tempdir()?;
        let path = temp_dir.path().join("audit");

        let config = WormSignedAuditConfig::new(path, 0);
        let logger = WormSignedAuditLogger::new(config)?;

        let event = kms_core::Event::new(
            EventType::KeyCreated,
            "user1",
            "user",
            "create_key",
            "key",
            Some("key-001".to_string()),
            "success",
        );

        logger.log_event(&event).await;
        logger.flush().await;

        let state = logger.worm_writer().get_chain_state().await;
        assert_eq!(state.entry_count(), 1);

        Ok(())
    }

    /// Test multiple log calls and sequence increments
    #[tokio::test]
    async fn test_sequence_increments() -> AuditResult<()> {
        let temp_dir = tempdir()?;
        let path = temp_dir.path().join("audit");

        let config = WormSignedAuditConfig::new(path, 100);
        let logger = WormSignedAuditLogger::new(config)?;

        // Log multiple events
        for i in 0..5 {
            let mut event = create_test_event();
            event.action = format!("action_{i}");
            logger.log(event).await;
        }

        let state = logger.worm_writer().get_chain_state().await;
        assert_eq!(state.entry_count(), 5);

        Ok(())
    }

    /// Test signing_key_path function
    #[test]
    fn test_signing_key_path() {
        let worm_path = std::path::PathBuf::from("/data/audit.log");
        let key_path = default_signing_key_path(&worm_path);
        assert_eq!(
            key_path,
            std::path::PathBuf::from("/data/audit.signing_key")
        );
    }
}

// ============================================================================
// PR-4.11 / P2-6: signing-key isolation tests
// ============================================================================
//
// Pre-PR-4.11, the HMAC signing key file was a sibling of the
// WORM log file. A compromised process could replace both the
// log AND the signing key, defeating the integrity guarantee of
// the hash chain. PR-4.11 introduces an opt-in
// `with_signing_key_path` builder + a `load_or_create_with_key_path`
// factory so operators can deploy the signing key on a separate
// filesystem / mount.

#[cfg(test)]
mod pr411_signing_key_isolation_tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn pr411_default_signing_key_path_is_sibling() {
        // No `with_signing_key_path` call: must fall back to the
        // pre-PR-4.11 sibling path.
        let worm_path = PathBuf::from("/data/audit.log");
        let config = WormSignedAuditConfig::new(worm_path.clone(), 0);
        assert_eq!(
            config.effective_signing_key_path(),
            PathBuf::from("/data/audit.signing_key")
        );
        assert!(config.signing_key_path.is_none());
    }

    #[test]
    fn pr411_with_signing_key_path_overrides() {
        let worm_path = PathBuf::from("/data/audit.log");
        let key_path = PathBuf::from("/secure/keys/audit-hmac.key");
        let config =
            WormSignedAuditConfig::new(worm_path, 0).with_signing_key_path(key_path.clone());
        assert_eq!(config.effective_signing_key_path(), key_path);
        assert_eq!(config.signing_key_path, Some(key_path));
    }

    #[test]
    fn pr411_separate_key_path_creates_file_in_custom_location() -> AuditResult<()> {
        // Real tmp-dir test: WORM dir + key dir are separate.
        let worm_dir = tempdir()?;
        let key_dir = tempdir()?;
        let worm_path = worm_dir.path().join("audit.log");
        let custom_key_path = key_dir.path().join("audit-hmac.key");

        let config =
            WormSignedAuditConfig::load_or_create_with_key_path(worm_path, custom_key_path, 0)?;

        // Key was created at the custom path, NOT the sibling path.
        assert!(config.signing_key_path.is_some());
        assert_eq!(
            config.effective_signing_key_path(),
            key_dir.path().join("audit-hmac.key")
        );
        // Sibling path MUST NOT exist (no leakage).
        assert!(!worm_dir.path().join("audit.signing_key").exists());

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn pr411_signing_key_file_is_0o600_on_unix() -> AuditResult<()> {
        use std::os::unix::fs::PermissionsExt;
        let worm_dir = tempdir()?;
        let key_dir = tempdir()?;
        let worm_path = worm_dir.path().join("audit.log");
        let custom_key_path = key_dir.path().join("audit-hmac.key");

        let _ = WormSignedAuditConfig::load_or_create_with_key_path(
            worm_path,
            custom_key_path.clone(),
            0,
        )?;

        let metadata = std::fs::metadata(&custom_key_path)?;
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "signing-key file must be 0600 on unix (got 0o{mode:o})"
        );

        Ok(())
    }

    #[test]
    fn pr411_existing_key_at_custom_path_is_loaded() -> AuditResult<()> {
        // Pre-write a 32-byte key; load_or_create_with_key_path
        // must load it rather than generate a new one.
        let worm_dir = tempdir()?;
        let key_dir = tempdir()?;
        let worm_path = worm_dir.path().join("audit.log");
        let custom_key_path = key_dir.path().join("audit-hmac.key");

        // Use a deterministic 32-byte sequence so we can assert.
        let expected_key: Vec<u8> = (0u8..32).collect();
        std::fs::write(&custom_key_path, &expected_key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&custom_key_path, std::fs::Permissions::from_mode(0o600))?;
        }

        let config = WormSignedAuditConfig::load_or_create_with_key_path(
            worm_path,
            custom_key_path.clone(),
            0,
        )?;
        // `signed.signing_key` is wrapped in `Zeroizing<Vec<u8>>`
        // for defense-in-depth; dereference it for assertion
        // against our plain `Vec<u8>` expected_key.
        assert_eq!(
            &*config.signed.signing_key,
            &expected_key[..],
            "existing key must be loaded, not regenerated"
        );

        Ok(())
    }

    #[test]
    fn pr411_load_or_create_unchanged_default_behavior() -> AuditResult<()> {
        // Backward compat: pre-PR-4.11 callers using
        // `load_or_create(worm_path, ...)` continue to write
        // the key to the sibling path with signing_key_path=Some(None).
        let worm_dir = tempdir()?;
        let worm_path = worm_dir.path().join("audit.log");
        let sibling_key_path = worm_dir.path().join("audit.signing_key");

        let config = WormSignedAuditConfig::load_or_create(worm_path, 0)?;
        assert!(config.signing_key_path.is_none());
        assert!(sibling_key_path.exists());
        assert_eq!(config.effective_signing_key_path(), sibling_key_path);

        Ok(())
    }
}
