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
}

/// Path to the signing key file (lives alongside WORM storage)
fn signing_key_path(worm_path: &Path) -> PathBuf {
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
        }
    }

    /// Create new config, loading signing key from disk if present
    ///
    /// If the signing key file exists, loads it; otherwise generates a new random key.
    /// The key is stored with restrictive permissions (0o600).
    pub fn load_or_create(worm_path: PathBuf, initial_sequence: u64) -> AuditResult<Self> {
        let key_path = signing_key_path(&worm_path);
        let signing_key = load_or_generate_key(&key_path)?;

        let signed_config =
            SignedAuditConfig::with_key(AuditConfig::default(), signing_key, initial_sequence);
        Ok(Self {
            signed: signed_config,
            worm_path,
            rotation_age_secs: 3600,
        })
    }

    /// Set rotation age
    pub fn with_rotation_age_secs(mut self, secs: u64) -> Self {
        self.rotation_age_secs = secs;
        self
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
        let key_path = signing_key_path(&worm_path);

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
        let _key_path = signing_key_path(&worm_path);

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
        let key_path = signing_key_path(&worm_path);
        assert_eq!(
            key_path,
            std::path::PathBuf::from("/data/audit.signing_key")
        );
    }
}
