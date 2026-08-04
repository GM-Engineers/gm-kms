//! WORM-compatible audit log writer
//!
//! Provides append-only, tamper-evident audit log storage that satisfies
//! compliance requirements (等保三级, 金融行业).
//!
//! Key features:
//! - Append-only writes with fsync for durability
//! - Hash chain for tamper detection
//! - File rotation with minimum age to prevent rapid switching
//! - Optional read-only attribute setting (Unix-only)

use super::SignedAuditEntry;
use crate::error::{AuditError, AuditResult};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;

/// Minimum file age before rotation (prevents rapid rotation on busy systems)
const MIN_ROTATION_AGE_SECS: u64 = 60;

/// WORM-compatible file writer for audit logs
///
/// This writer provides:
/// - Append-only semantics (O_APPEND)
/// - fsync after each write for durability
/// - Hash chain tracking for tamper detection
/// - Automatic file rotation with time-based policies
pub struct WormWriter {
    base_path: PathBuf,
    current_file: Arc<Mutex<Option<File>>>,
    current_path: Arc<Mutex<PathBuf>>,
    hash_chain: Arc<Mutex<HashChainState>>,
    rotation_age: Duration,
    /// Minimum age before rotation
    #[allow(dead_code)]
    min_rotation_age: Duration,
}

impl WormWriter {
    /// Create new WORM writer
    ///
    /// # Arguments
    /// * `base_path` - Directory path for audit files (e.g., `/var/log/kms/audit`)
    ///
    /// # Security Notes
    /// - Directory should have restricted permissions (700 or 750)
    /// - Run as dedicated user, not root
    /// - Consider mounting on immutable filesystem for production
    pub fn new(base_path: PathBuf) -> AuditResult<Self> {
        // Ensure base directory exists with restricted permissions
        Self::ensure_directory(&base_path)?;

        let writer = Self {
            base_path,
            current_file: Arc::new(Mutex::new(None)),
            current_path: Arc::new(Mutex::new(PathBuf::new())),
            hash_chain: Arc::new(Mutex::new(HashChainState::new())),
            rotation_age: Duration::from_secs(3600), // Default: rotate every hour
            min_rotation_age: Duration::from_secs(MIN_ROTATION_AGE_SECS),
        };

        Ok(writer)
    }

    /// Ensure directory exists with restricted permissions
    fn ensure_directory(path: &Path) -> AuditResult<()> {
        if !path.exists() {
            fs::create_dir_all(path)?;
        }

        // Set directory permissions (Unix-only, fails gracefully on Windows)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = fs::metadata(path) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o750); // rwxr-x--- (owner and group read/write/execute)
                fs::set_permissions(path, perms)?;
            }
        }

        Ok(())
    }

    /// Set rotation age (default: 1 hour)
    pub fn with_rotation_age(mut self, age: Duration) -> Self {
        self.rotation_age = age;
        self
    }

    /// Write a signed audit entry
    ///
    /// This method:
    /// 1. Computes the entry hash
    /// 2. Appends to the current file with O_APPEND
    /// 3. Calls fsync for durability
    /// 4. Updates the hash chain
    /// 5. Triggers rotation if needed
    pub async fn append(&self, entry: &SignedAuditEntry) -> AuditResult<()> {
        // Check if rotation is needed before writing
        self.maybe_rotate().await?;

        // Get or open current file
        let mut file_guard = self.current_file.lock().await;
        if file_guard.is_none() {
            let path = self.open_new_file().await?;
            let mut path_guard = self.current_path.lock().await;
            *path_guard = path;
            *file_guard = Some(Self::open_append_only(&path_guard)?);
        }

        let file = file_guard.as_mut().expect("file opened immediately above");

        // Serialize entry
        let json = serde_json::to_vec(entry)?;

        // Compute entry hash for chain
        let entry_hash = Self::compute_entry_hash(entry);

        // Append to file with fsync
        file.write_all(&json)?;
        file.write_all(b"\n")?;
        file.sync_all()?;

        // Update hash chain
        {
            let mut chain = self.hash_chain.lock().await;
            chain.update(entry_hash);
        }

        Ok(())
    }

    /// Write multiple entries in a batch
    pub async fn append_batch(&self, entries: &[SignedAuditEntry]) -> AuditResult<()> {
        for entry in entries {
            self.append(entry).await?;
        }
        Ok(())
    }

    /// Compute SHA-256 hash of an entry (for chain verification)
    fn compute_entry_hash(entry: &SignedAuditEntry) -> [u8; 32] {
        use ring::digest::{SHA256, digest};
        let payload_json = serde_json::to_string(&entry.payload).unwrap_or_default();
        let signing_input = entry.signature.as_slice();
        // Chain: SHA256(payload_bytes || signature_bytes)
        let combined: Vec<u8> = payload_json
            .as_bytes()
            .iter()
            .chain(signing_input.iter())
            .cloned()
            .collect();
        let digest_result = digest(&SHA256, &combined);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(digest_result.as_ref());
        hash
    }

    /// Open file with append-only semantics and set restrictive permissions
    /// atomically via the file descriptor (eliminating the TOCTOU window).
    fn open_append_only(path: &Path) -> AuditResult<File> {
        use std::os::unix::io::AsRawFd;

        let file = OpenOptions::new().create(true).append(true).open(path)?;

        // Set permissions via the file descriptor BEFORE any writes —
        // this avoids the time-of-check-to-time-of-use window between
        // open() and a separate fs::set_permissions() call.
        #[cfg(unix)]
        {
            let fd = file.as_raw_fd();
            // 0o640: owner rw, group r, other none
            // Safety: fchmod is thread-safe and operates on the already-opened fd.
            let rc = unsafe { libc::fchmod(fd, 0o640) };
            if rc != 0 {
                let e = std::io::Error::last_os_error();
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "fchmod failed — file permissions may be more permissive than intended"
                );
            }
        }

        Ok(file)
    }

    /// Open a new audit file with timestamp-based naming
    async fn open_new_file(&self) -> AuditResult<PathBuf> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs();

        let filename = format!("audit-{timestamp}.jsonl");
        let path = self.base_path.join(&filename);

        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;

        // Set file permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o640);
            let _ = file.metadata()?.permissions();
        }

        // Drop file to release mutable reference
        drop(file);

        tracing::info!("Opened new audit file: {}", path.display());
        Ok(path)
    }

    /// Check if rotation is needed and perform it
    async fn maybe_rotate(&self) -> AuditResult<()> {
        let path_guard = self.current_path.lock().await;

        if path_guard.as_os_str().is_empty() {
            return Ok(());
        }

        let current_path = path_guard.as_path();
        if let Ok(metadata) = fs::metadata(current_path)
            && let Ok(modified) = metadata.modified()
        {
            let age = SystemTime::now()
                .duration_since(modified)
                .unwrap_or(Duration::ZERO);

            if age > self.rotation_age {
                drop(path_guard);
                self.rotate().await?;
            }
        }
        Ok(())
    }

    /// Rotate to a new file
    async fn rotate(&self) -> AuditResult<()> {
        tracing::info!("Rotating WORM audit log");

        // Close current file
        {
            let mut file_guard = self.current_file.lock().await;
            if let Some(file) = file_guard.take() {
                // Sync before closing
                let _ = file.sync_all();
            }
        }

        // Mark current file as immutable (read-only)
        let path_guard = self.current_path.lock().await;
        let current_path = path_guard.as_path();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = fs::metadata(current_path) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o440); // r--r----- (read-only)
                let _ = fs::set_permissions(current_path, perms);
            }
        }

        // Reset path to empty
        drop(path_guard);
        let mut path_guard = self.current_path.lock().await;
        *path_guard = PathBuf::new();

        Ok(())
    }

    /// Get current hash chain state (for verification)
    pub async fn get_chain_state(&self) -> HashChainState {
        self.hash_chain.lock().await.clone()
    }

    /// Verify hash chain integrity
    pub async fn verify_chain(
        &self,
        entries: &[SignedAuditEntry],
    ) -> AuditResult<VerificationReport> {
        let mut prev_entry_hash: Option<[u8; 32]> = None;
        let chain = self.hash_chain.lock().await;

        let mut first_invalid: Option<usize> = None;
        let mut error_desc: Option<String> = None;

        for (i, entry) in entries.iter().enumerate() {
            // Verify chain linkage: previous_signature stores the hash of the
            // preceding entry for Merkle-Damgård–style chain integrity.
            if let Some(expected_prev) = prev_entry_hash {
                let entry_prev = entry.previous_signature.as_deref().unwrap_or(&[]);
                if entry_prev != expected_prev.as_slice() {
                    first_invalid = first_invalid.or(Some(i));
                    error_desc = Some(format!(
                        "chain broken at entry {i}: stored previous_signature does not match computed prev_entry_hash"));
                    break;
                }
            }
            prev_entry_hash = Some(Self::compute_entry_hash(entry));
        }

        let mut report = VerificationReport {
            valid: first_invalid.is_none(),
            entries_checked: entries.len(),
            first_invalid_index: first_invalid,
            error: error_desc,
        };

        // Compare with stored state
        if report.valid
            && let Some(expected_count) = chain.entry_count.checked_sub(1)
            && entries.len() as u64 != expected_count
        {
            report.valid = false;
            report.error = Some(format!(
                "Entry count mismatch: expected {}, got {}",
                expected_count,
                entries.len()
            ));
            report.first_invalid_index = Some(0);
        }

        Ok(report)
    }

    /// Read all audit entries from existing WORM log files
    pub async fn read_all_entries(&self) -> AuditResult<Vec<SignedAuditEntry>> {
        let mut entries: Vec<(u64, SignedAuditEntry)> = Vec::new();
        let mut dir = tokio::fs::read_dir(&self.base_path).await?;

        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }

            // Extract timestamp from filename for ordering
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let ts = stem
                .strip_prefix("audit-")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);

            let content = tokio::fs::read_to_string(&path)
                .await
                .map_err(AuditError::Io)?;

            for line in content.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<SignedAuditEntry>(line) {
                    Ok(entry) => entries.push((ts, entry)),
                    Err(e) => {
                        tracing::warn!(
                            "Failed to parse audit entry from {}: {}",
                            path.display(),
                            e
                        );
                    }
                }
            }
        }

        // Sort by timestamp then by sequence within file
        entries.sort_by_key(|(ts, _)| *ts);
        let entries: Vec<SignedAuditEntry> = entries.into_iter().map(|(_, e)| e).collect();

        Ok(entries)
    }
}

/// Verify the audit chain at server startup.
///
/// Reads all WORM log files from the given directory, reconstructs the hash
/// chain, and returns a verification report. This should be called during
/// server initialization to detect tampering that occurred while the server
/// was stopped.
pub async fn startup_verify_chain(audit_dir: &Path) -> AuditResult<VerificationReport> {
    let writer = WormWriter::new(audit_dir.to_path_buf())?;
    let entries = writer.read_all_entries().await?;

    if entries.is_empty() {
        return Ok(VerificationReport {
            valid: true,
            entries_checked: 0,
            first_invalid_index: None,
            error: None,
        });
    }

    writer.verify_chain(&entries).await
}

/// Hash chain state for tamper detection
#[derive(Debug, Clone)]
pub struct HashChainState {
    /// Running hash of all entries
    running_hash: [u8; 32],
    /// Number of entries processed
    entry_count: u64,
}

impl HashChainState {
    /// Create new empty chain state
    pub fn new() -> Self {
        use ring::digest::{SHA256, digest};
        let digest_result = digest(&SHA256, b"");
        let mut running_hash = [0u8; 32];
        running_hash.copy_from_slice(digest_result.as_ref());
        Self {
            running_hash,
            entry_count: 0,
        }
    }

    /// Update chain with new entry hash
    pub fn update(&mut self, entry_hash: [u8; 32]) {
        use ring::digest::{SHA256, digest};
        // Chain hash: SHA256(running_hash || entry_hash)
        let combined: Vec<u8> = self
            .running_hash
            .iter()
            .chain(entry_hash.iter())
            .cloned()
            .collect();
        let digest_result = digest(&SHA256, &combined);
        self.running_hash.copy_from_slice(digest_result.as_ref());
        self.entry_count += 1;
    }

    /// Get number of entries in chain
    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }
}

impl Default for HashChainState {
    fn default() -> Self {
        Self::new()
    }
}

/// Verification report for hash chain integrity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Whether the chain is valid
    pub valid: bool,
    /// Number of entries checked
    pub entries_checked: usize,
    /// Index of first invalid entry (if any)
    pub first_invalid_index: Option<usize>,
    /// Error description (if invalid)
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditEvent;
    use kms_core::EventType;

    fn create_test_entry(sequence: u64) -> SignedAuditEntry {
        let event = AuditEvent {
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
        };

        let signing_key = b"test-signing-key-32-bytes-long!!";
        SignedAuditEntry::new(event, sequence, signing_key, None, None)
    }

    #[tokio::test]
    async fn test_worm_writer_basic() -> AuditResult<()> {
        let temp_dir = tempfile::tempdir()?;
        let path = temp_dir.path().join("audit");
        let writer = WormWriter::new(path)?;

        // Write several entries
        for i in 0..5 {
            let entry = create_test_entry(i);
            writer.append(&entry).await?;
        }

        // Verify chain state
        let state = writer.get_chain_state().await;
        assert_eq!(state.entry_count, 5);

        Ok(())
    }

    #[tokio::test]
    async fn test_hash_chain_state() {
        let mut state = HashChainState::new();
        assert_eq!(state.entry_count, 0);

        let hash1 = [0u8; 32];
        let hash2 = [1u8; 32];

        state.update(hash1);
        assert_eq!(state.entry_count, 1);

        state.update(hash2);
        assert_eq!(state.entry_count, 2);
    }

    #[test]
    fn test_entry_hash_computation() {
        let entry = create_test_entry(0);
        let hash1 = WormWriter::compute_entry_hash(&entry);
        let hash2 = WormWriter::compute_entry_hash(&entry);
        assert_eq!(hash1, hash2, "Same entry should produce same hash");
    }

    #[test]
    fn test_entry_hash_differs_for_different_entries() {
        let entry1 = create_test_entry(0);
        let entry2 = create_test_entry(1);
        let hash1 = WormWriter::compute_entry_hash(&entry1);
        let hash2 = WormWriter::compute_entry_hash(&entry2);
        assert_ne!(
            hash1, hash2,
            "Different entries should produce different hashes"
        );
    }

    #[test]
    fn test_entry_hash_is_sha256_length() {
        let entry = create_test_entry(0);
        let hash = WormWriter::compute_entry_hash(&entry);
        assert_eq!(hash.len(), 32, "SHA-256 hash should be 32 bytes");
    }

    #[tokio::test]
    async fn test_worm_writer_multiple_writes() -> AuditResult<()> {
        let temp_dir = tempfile::tempdir()?;
        let path = temp_dir.path().join("audit-multi");
        let writer = WormWriter::new(path)?;

        for i in 0..10 {
            let entry = create_test_entry(i);
            writer.append(&entry).await?;
        }

        let state = writer.get_chain_state().await;
        assert_eq!(state.entry_count, 10);
        Ok(())
    }

    #[tokio::test]
    async fn test_worm_writer_batch_append() -> AuditResult<()> {
        let temp_dir = tempfile::tempdir()?;
        let path = temp_dir.path().join("audit-batch");
        let writer = WormWriter::new(path)?;

        let entries: Vec<SignedAuditEntry> = (0..5).map(create_test_entry).collect();
        writer.append_batch(&entries).await?;

        let state = writer.get_chain_state().await;
        assert_eq!(state.entry_count, 5);
        Ok(())
    }

    #[tokio::test]
    async fn test_worm_writer_chain_progression() -> AuditResult<()> {
        let temp_dir = tempfile::tempdir()?;
        let path = temp_dir.path().join("audit-chain");
        let writer = WormWriter::new(path)?;

        let state_before = writer.get_chain_state().await;
        assert_eq!(state_before.entry_count, 0);

        writer.append(&create_test_entry(0)).await?;
        let state_after_1 = writer.get_chain_state().await;
        assert_eq!(state_after_1.entry_count, 1);

        writer.append(&create_test_entry(1)).await?;
        let state_after_2 = writer.get_chain_state().await;
        assert_eq!(state_after_2.entry_count, 2);

        // Running hash should change with each entry
        assert_ne!(state_before.running_hash, state_after_1.running_hash);
        assert_ne!(state_after_1.running_hash, state_after_2.running_hash);
        Ok(())
    }

    #[tokio::test]
    async fn test_worm_writer_creates_directory() -> AuditResult<()> {
        let temp_dir = tempfile::tempdir()?;
        let nested = temp_dir.path().join("nested").join("audit");
        let writer = WormWriter::new(nested.clone())?;

        writer.append(&create_test_entry(0)).await?;
        assert!(nested.exists(), "Directory should be created");
        Ok(())
    }

    #[tokio::test]
    async fn test_worm_writer_rotation_age_configurable() -> AuditResult<()> {
        // Just verify that rotation age can be set without error
        let temp_dir = tempfile::tempdir()?;
        let path = temp_dir.path().join("audit-rotate-cfg");
        let writer = WormWriter::new(path)?.with_rotation_age(Duration::from_secs(3600));

        writer.append(&create_test_entry(0)).await?;
        let state = writer.get_chain_state().await;
        assert_eq!(state.entry_count, 1);
        Ok(())
    }

    #[test]
    fn test_hash_chain_state_default() {
        let state = HashChainState::default();
        assert_eq!(state.entry_count, 0);
        // Running hash should be SHA-256 of empty bytes
        let expected = {
            use ring::digest::{SHA256, digest};
            let d = digest(&SHA256, b"");
            let mut h = [0u8; 32];
            h.copy_from_slice(d.as_ref());
            h
        };
        assert_eq!(state.running_hash, expected);
    }

    #[test]
    fn test_hash_chain_state_update_changes_hash() {
        let mut state = HashChainState::new();
        let initial_hash = state.running_hash;
        state.update([0xFFu8; 32]);
        assert_ne!(state.running_hash, initial_hash);
        assert_eq!(state.entry_count, 1);
    }

    #[test]
    fn test_hash_chain_state_multiple_updates() {
        let mut state = HashChainState::new();
        for i in 0..100u8 {
            state.update([i; 32]);
        }
        assert_eq!(state.entry_count, 100);
    }

    #[test]
    fn test_hash_chain_state_deterministic() {
        let mut state1 = HashChainState::new();
        let mut state2 = HashChainState::new();
        for i in 0..10u8 {
            state1.update([i; 32]);
            state2.update([i; 32]);
        }
        assert_eq!(state1.running_hash, state2.running_hash);
        assert_eq!(state1.entry_count, state2.entry_count);
    }

    #[test]
    fn test_verification_report_serde() {
        let report = VerificationReport {
            valid: true,
            entries_checked: 42,
            first_invalid_index: None,
            error: None,
        };
        let json = serde_json::to_string(&report).unwrap();
        let de: VerificationReport = serde_json::from_str(&json).unwrap();
        assert!(de.valid);
        assert_eq!(de.entries_checked, 42);
        assert!(de.first_invalid_index.is_none());
    }

    #[test]
    fn test_verification_report_invalid() {
        let report = VerificationReport {
            valid: false,
            entries_checked: 10,
            first_invalid_index: Some(5),
            error: Some("hash mismatch at entry 5".to_string()),
        };
        let json = serde_json::to_string(&report).unwrap();
        let de: VerificationReport = serde_json::from_str(&json).unwrap();
        assert!(!de.valid);
        assert_eq!(de.first_invalid_index, Some(5));
        assert_eq!(de.error, Some("hash mismatch at entry 5".to_string()));
    }
}
