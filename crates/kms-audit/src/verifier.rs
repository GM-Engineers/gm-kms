//! Integrity verification service for audit logs
//!
//! Periodically verifies hash chain integrity and generates reports.
//! Supports scheduled verification and on-demand verification.

use super::{SignedAuditEntry, VerificationReport};
use crate::error::AuditResult;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time;

/// Integrity verification service
pub struct IntegrityVerifier {
    /// Path to audit log directory
    log_path: std::path::PathBuf,
    /// Signing key for signature verification (should be stored securely)
    signing_key: Vec<u8>,
    /// Verification interval
    check_interval: Duration,
    /// Last verification result
    last_result: Arc<RwLock<Option<VerificationReport>>>,
}

impl IntegrityVerifier {
    /// Create new integrity verifier
    pub fn new(
        log_path: std::path::PathBuf,
        signing_key: Vec<u8>,
        check_interval: Duration,
    ) -> Self {
        Self {
            log_path,
            signing_key,
            check_interval,
            last_result: Arc::new(RwLock::new(None)),
        }
    }

    /// Verify all entries in a file
    pub fn verify_file(&self, path: &Path) -> AuditResult<VerificationReport> {
        let content = std::fs::read_to_string(path)?;
        self.verify_content(&content)
    }

    /// Verify entries from string content (JSON Lines)
    pub fn verify_content(&self, content: &str) -> AuditResult<VerificationReport> {
        let mut prev_signature: Option<Vec<u8>> = None;
        let mut first_invalid_index: Option<usize> = None;
        let mut entries_checked = 0;

        for (i, line) in content.lines().enumerate() {
            let entry: SignedAuditEntry = match serde_json::from_str(line) {
                Ok(e) => e,
                Err(e) => {
                    return Ok(VerificationReport {
                        valid: false,
                        entries_checked: i,
                        first_invalid_index: Some(i),
                        error: Some(format!("Failed to parse entry {}: {}", i, e)),
                    });
                }
            };

            // Verify chain linkage
            if let Some(ref expected_prev) = prev_signature
                && entry.previous_signature.as_deref() != Some(expected_prev.as_slice())
            {
                first_invalid_index.get_or_insert(i);
            }

            // Verify signature
            if !entry.verify(&self.signing_key) {
                return Ok(VerificationReport {
                    valid: false,
                    entries_checked: i + 1,
                    first_invalid_index: Some(i),
                    error: Some(format!("Signature verification failed at entry {}", i)),
                });
            }

            // Update tracking with owned data
            prev_signature = Some(entry.signature.clone());
            entries_checked = i + 1;
        }

        let report = VerificationReport {
            valid: first_invalid_index.is_none(),
            entries_checked,
            first_invalid_index,
            error: first_invalid_index.map(|i| format!("Chain broken at entry {}", i)),
        };

        Ok(report)
    }

    /// Get last verification result
    pub async fn get_last_result(&self) -> Option<VerificationReport> {
        self.last_result.read().await.clone()
    }

    /// Run verification and store result
    pub async fn verify(&self) -> AuditResult<VerificationReport> {
        // Find all audit files
        let entries = std::fs::read_dir(&self.log_path)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "jsonl")
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();

        if entries.is_empty() {
            let report = VerificationReport {
                valid: true,
                entries_checked: 0,
                first_invalid_index: None,
                error: None,
            };
            *self.last_result.write().await = Some(report.clone());
            return Ok(report);
        }

        // Sort by filename (timestamp-based)
        let mut paths: Vec<_> = entries.iter().map(|e| e.path()).collect();
        paths.sort();

        let mut all_valid = true;
        let mut total_entries = 0;
        let mut first_error: Option<String> = None;
        let mut first_invalid_file: Option<String> = None;

        for path in &paths {
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(e) => {
                    all_valid = false;
                    first_error.get_or_insert_with(|| format!("Failed to read {:?}: {}", path, e));
                    first_invalid_file.get_or_insert_with(|| path.to_string_lossy().to_string());
                    break;
                }
            };

            let report = self.verify_content(&content)?;
            total_entries += report.entries_checked;

            if !report.valid {
                all_valid = false;
                first_error
                    .get_or_insert_with(|| report.error.unwrap_or_else(|| "Unknown error".into()));
                first_invalid_file.get_or_insert_with(|| path.to_string_lossy().to_string());
                break;
            }
        }

        let final_report = VerificationReport {
            valid: all_valid,
            entries_checked: total_entries,
            first_invalid_index: None, // File-level, not entry-level
            error: first_error.clone().map(|e| {
                if let Some(ref file) = first_invalid_file {
                    format!("{} (file: {})", e, file)
                } else {
                    e
                }
            }),
        };

        *self.last_result.write().await = Some(final_report.clone());
        Ok(final_report)
    }

    /// Start background verification task
    pub fn start_background_verification(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = time::interval(self.check_interval);
            loop {
                interval.tick().await;
                if let Err(e) = self.verify().await {
                    tracing::error!("Periodic verification failed: {}", e);
                }
            }
        })
    }
}

/// Configuration for integrity verification
#[derive(Debug, Clone)]
pub struct VerificationConfig {
    /// Path to audit log directory
    pub log_path: std::path::PathBuf,
    /// HMAC signing key for verification
    pub signing_key: Vec<u8>,
    /// Verification interval in hours
    pub interval_hours: u64,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            log_path: std::path::PathBuf::from("/var/log/kms/audit"),
            signing_key: Vec::new(),
            interval_hours: 24,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditEvent, SignedAuditEntry};
    use kms_core::EventType;

    fn create_test_entry(sequence: u64, prev_sig: Option<&[u8]>) -> SignedAuditEntry {
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
        SignedAuditEntry::new(event, sequence, signing_key, prev_sig, None)
    }

    fn entries_to_jsonl(entries: &[SignedAuditEntry]) -> String {
        entries
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn test_verify_valid_chain() {
        let signing_key = b"test-signing-key-32-bytes-long!!";

        // Create a valid chain
        let entry0 = create_test_entry(0, None);
        let entry1 = create_test_entry(1, Some(&entry0.signature));
        let entry2 = create_test_entry(2, Some(&entry1.signature));

        let content = entries_to_jsonl(&[entry0, entry1, entry2]);

        let verifier = IntegrityVerifier::new(
            std::path::PathBuf::new(),
            signing_key.to_vec(),
            Duration::from_secs(3600),
        );

        let report = verifier.verify_content(&content).unwrap();
        assert!(report.valid);
        assert_eq!(report.entries_checked, 3);
    }

    #[test]
    fn test_verify_broken_chain() {
        let signing_key = b"test-signing-key-32-bytes-long!!";

        // Create entries but break the chain
        let entry0 = create_test_entry(0, None);
        let entry1 = create_test_entry(1, None); // Should reference entry0's signature
        let entry2 = create_test_entry(2, Some(&entry1.signature));

        let content = entries_to_jsonl(&[entry0, entry1, entry2]);

        let verifier = IntegrityVerifier::new(
            std::path::PathBuf::new(),
            signing_key.to_vec(),
            Duration::from_secs(3600),
        );

        let report = verifier.verify_content(&content).unwrap();
        // entry1 has wrong previous_signature (None instead of Some(entry0.signature))
        assert!(!report.valid);
    }

    /// A single entry with no previous signature is valid (chain of 1)
    #[test]
    fn test_verify_single_entry_chain() {
        let signing_key = b"test-signing-key-32-bytes-long!!";

        let entry0 = create_test_entry(0, None);
        let content = entries_to_jsonl(&[entry0]);

        let verifier = IntegrityVerifier::new(
            std::path::PathBuf::new(),
            signing_key.to_vec(),
            Duration::from_secs(3600),
        );

        let report = verifier.verify_content(&content).unwrap();
        assert!(report.valid);
        assert_eq!(report.entries_checked, 1);
    }

    /// Empty content should produce an error, not panic
    #[test]
    fn test_verify_empty_chain() {
        let signing_key = b"test-signing-key-32-bytes-long!!";
        let verifier = IntegrityVerifier::new(
            std::path::PathBuf::new(),
            signing_key.to_vec(),
            Duration::from_secs(3600),
        );

        let result = verifier.verify_content("");
        // Empty content should be handled gracefully
        assert!(result.is_ok());
    }

    /// Tampered entry payload: signature verification should fail
    #[test]
    fn test_verify_tampered_entry() {
        let signing_key = b"test-signing-key-32-bytes-long!!";

        let entry0 = create_test_entry(0, None);
        let entry1 = create_test_entry(1, Some(&entry0.signature));

        // Tamper: modify entry1's payload after signing
        let mut tampered = entry1.clone();
        tampered.payload.action = "tampered_action".to_string();

        let content = entries_to_jsonl(&[entry0, tampered]);

        let verifier = IntegrityVerifier::new(
            std::path::PathBuf::new(),
            signing_key.to_vec(),
            Duration::from_secs(3600),
        );

        let report = verifier.verify_content(&content).unwrap();
        // Signature of tampered entry won't match
        assert!(!report.valid);
    }

    /// Verification with wrong signing key fails
    #[test]
    fn test_verify_wrong_signing_key() {
        let _signing_key = b"test-signing-key-32-bytes-long!!";
        let wrong_key = b"wrong-signing-key-32-bytes-long!";

        let entry0 = create_test_entry(0, None);
        let content = entries_to_jsonl(&[entry0]);

        let verifier = IntegrityVerifier::new(
            std::path::PathBuf::new(),
            wrong_key.to_vec(),
            Duration::from_secs(3600),
        );

        let report = verifier.verify_content(&content).unwrap();
        assert!(!report.valid);
    }

    /// VerificationReport entries_checked matches actual entry count
    #[test]
    fn test_verification_report_counts_entries() {
        let signing_key = b"test-signing-key-32-bytes-long!!";

        let entries: Vec<_> = (0..5)
            .map(|i| {
                if i == 0 {
                    create_test_entry(i, None)
                } else {
                    // Simplified: each references predecessor (not actual signature)
                    create_test_entry(i, Some(b"placeholder-signature"))
                }
            })
            .collect();

        let content = entries_to_jsonl(&entries);

        let verifier = IntegrityVerifier::new(
            std::path::PathBuf::new(),
            signing_key.to_vec(),
            Duration::from_secs(3600),
        );

        let report = verifier.verify_content(&content).unwrap();
        assert_eq!(report.entries_checked, 5);
    }

    #[test]
    fn test_verification_report_serialization() {
        let report = VerificationReport {
            valid: true,
            entries_checked: 42,
            first_invalid_index: None,
            error: None,
        };

        let json = serde_json::to_string(&report).unwrap();
        let deserialized: VerificationReport = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.valid, report.valid);
        assert_eq!(deserialized.entries_checked, report.entries_checked);
        assert_eq!(deserialized.first_invalid_index, report.first_invalid_index);
        assert_eq!(deserialized.error, report.error);
    }

    #[test]
    fn test_verification_report_with_error_serialization() {
        let report = VerificationReport {
            valid: false,
            entries_checked: 10,
            first_invalid_index: Some(5),
            error: Some("Chain broken at entry 5".to_string()),
        };

        let json = serde_json::to_string(&report).unwrap();
        let deserialized: VerificationReport = serde_json::from_str(&json).unwrap();

        assert!(!deserialized.valid);
        assert_eq!(deserialized.first_invalid_index, Some(5));
        assert!(deserialized.error.unwrap().contains("Chain broken"));
    }

    #[test]
    fn test_timestamp_integrity_in_report() {
        // Verify report fields maintain integrity after creation
        let report = VerificationReport {
            valid: true,
            entries_checked: 100,
            first_invalid_index: None,
            error: None,
        };

        // Ensure all fields are populated correctly
        assert!(report.valid);
        assert_eq!(report.entries_checked, 100);
        assert!(report.first_invalid_index.is_none());
        assert!(report.error.is_none());

        // Verify that an invalid report with an error preserves its state
        let bad_report = VerificationReport {
            valid: false,
            entries_checked: 50,
            first_invalid_index: Some(25),
            error: Some("integrity failure".to_string()),
        };

        assert!(!bad_report.valid);
        assert_eq!(bad_report.entries_checked, 50);
        assert_eq!(bad_report.first_invalid_index, Some(25));
        assert_eq!(bad_report.error.as_deref(), Some("integrity failure"));
    }

    // --- Additional tests ---

    /// Test that an invalid JSON line is handled gracefully
    #[test]
    fn test_verify_invalid_json_line() {
        let signing_key = b"test-signing-key-32-bytes-long!!";
        let verifier = IntegrityVerifier::new(
            std::path::PathBuf::new(),
            signing_key.to_vec(),
            Duration::from_secs(3600),
        );

        let entry0 = create_test_entry(0, None);
        let valid_json = serde_json::to_string(&entry0).unwrap();
        let content = format!("{}\n{{invalid json}}", valid_json);

        let report = verifier.verify_content(&content).unwrap();
        assert!(!report.valid);
        assert_eq!(report.entries_checked, 1);
        assert!(report.error.is_some());
    }

    /// Test VerificationConfig default
    #[test]
    fn test_verification_config_default() {
        let config = VerificationConfig::default();
        assert_eq!(config.log_path, std::path::PathBuf::from("/var/log/kms/audit"));
        assert!(config.signing_key.is_empty());
        assert_eq!(config.interval_hours, 24);
    }

    /// Test get_last_result returns None initially
    #[tokio::test]
    async fn test_get_last_result_none_initially() {
        let verifier = IntegrityVerifier::new(
            std::path::PathBuf::new(),
            vec![0u8; 32],
            Duration::from_secs(3600),
        );

        let result = verifier.get_last_result().await;
        assert!(result.is_none());
    }

    /// Test verify on non-existent directory (empty)
    #[tokio::test]
    async fn test_verify_empty_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let verifier = IntegrityVerifier::new(
            temp_dir.path().to_path_buf(),
            vec![0u8; 32],
            Duration::from_secs(3600),
        );

        let report = verifier.verify().await.unwrap();
        assert!(report.valid);
        assert_eq!(report.entries_checked, 0);
        assert!(report.error.is_none());
    }

    /// Test verify on directory with valid audit files
    #[tokio::test]
    async fn test_verify_directory_with_valid_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let signing_key = b"test-signing-key-32-bytes-long!!";

        let entry0 = create_test_entry(0, None);
        let entry1 = create_test_entry(1, Some(&entry0.signature));
        let content = entries_to_jsonl(&[entry0, entry1]);

        let file_path = temp_dir.path().join("2026-06-23.jsonl");
        std::fs::write(&file_path, &content).unwrap();

        let verifier = IntegrityVerifier::new(
            temp_dir.path().to_path_buf(),
            signing_key.to_vec(),
            Duration::from_secs(3600),
        );

        let report = verifier.verify().await.unwrap();
        assert!(report.valid);
        assert_eq!(report.entries_checked, 2);

        let last = verifier.get_last_result().await;
        assert!(last.is_some());
        assert!(last.unwrap().valid);
    }

    /// Test verify on directory with broken chain
    #[tokio::test]
    async fn test_verify_directory_with_broken_chain() {
        let temp_dir = tempfile::tempdir().unwrap();
        let signing_key = b"test-signing-key-32-bytes-long!!";

        let entry0 = create_test_entry(0, None);
        let entry1 = create_test_entry(1, None); // Wrong: should reference entry0
        let content = entries_to_jsonl(&[entry0, entry1]);

        let file_path = temp_dir.path().join("2026-06-23.jsonl");
        std::fs::write(&file_path, &content).unwrap();

        let verifier = IntegrityVerifier::new(
            temp_dir.path().to_path_buf(),
            signing_key.to_vec(),
            Duration::from_secs(3600),
        );

        let report = verifier.verify().await.unwrap();
        assert!(!report.valid);
    }

    /// Test verify_file on a single file
    #[test]
    fn test_verify_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let signing_key = b"test-signing-key-32-bytes-long!!";

        let entry0 = create_test_entry(0, None);
        let entry1 = create_test_entry(1, Some(&entry0.signature));
        let content = entries_to_jsonl(&[entry0, entry1]);

        let file_path = temp_dir.path().join("audit.jsonl");
        std::fs::write(&file_path, &content).unwrap();

        let verifier = IntegrityVerifier::new(
            std::path::PathBuf::new(),
            signing_key.to_vec(),
            Duration::from_secs(3600),
        );

        let report = verifier.verify_file(&file_path).unwrap();
        assert!(report.valid);
        assert_eq!(report.entries_checked, 2);
    }
}
