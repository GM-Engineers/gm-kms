//! kms-audit - Audit logging for KMS

pub mod error;
pub mod logger;
pub mod s3_archive;
pub mod timestamp;
pub mod verifier;
pub mod worm_logger;
pub mod worm_writer;

pub use error::{AuditError, AuditResult};

pub use logger::{AuditConfig, AuditLogger, SignedAuditConfig, SignedAuditLogger};
pub use s3_archive::{ArchiveEntry, ArchiveManager, LockMode, S3ArchiveClient, S3ArchiveConfig};
pub use timestamp::{
    TimestampAuthority, TimestampConfig, TimestampHashAlgorithm, TimestampRequest,
    TimestampResponse, TrustedTimestamp,
};
pub use verifier::{IntegrityVerifier, VerificationConfig};
pub use worm_logger::{WormSignedAuditConfig, WormSignedAuditLogger};
pub use worm_writer::{HashChainState, VerificationReport, WormWriter, startup_verify_chain};

// New TSA-enabled types (from logger)
pub use logger::{TimestampedAuditConfig, TimestampedAuditLogger};
pub use timestamp::TsaClientConfig;

use kms_core::{EventType, event::Event};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Shared trait for audit loggers.
///
/// Enables polymorphic audit logging: both plain `AuditLogger` and
/// `TimestampedAuditLogger` implement this trait, so `KmsState` can
/// use `Arc<dyn AuditLog>` without knowing the concrete type.
#[async_trait::async_trait]
pub trait AuditLog: Send + Sync + 'static {
    /// Log a KMS event
    async fn log_event(&self, event: &Event);

    /// Query audit events with a filter
    async fn query(&self, filter: AuditFilter) -> Vec<AuditEvent>;

    /// Return the current buffer backlog depth (number of un-flushed events).
    ///
    /// Default implementation returns 0. Loggers with internal buffers
    /// should override this.
    async fn backlog_depth(&self) -> usize {
        0
    }
}

/// Signed audit entry with tamper-evident chaining
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAuditEntry {
    /// The audit event payload
    pub payload: AuditEvent,
    /// HMAC-SHA256 signature of the entry
    pub signature: Vec<u8>,
    /// Sequence number for ordering and replay prevention
    pub sequence: u64,
    /// Previous entry's signature (for chaining), None for first entry
    pub previous_signature: Option<Vec<u8>>,
    /// Trusted timestamp from RFC 3161 TSA (when available)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub trusted_timestamp: Option<TrustedTimestamp>,
}

impl SignedAuditEntry {
    /// Create a new signed audit entry
    ///
    /// # Arguments
    /// * `payload` - The audit event to sign
    /// * `sequence` - Sequence number for ordering
    /// * `signing_key` - The HMAC signing key
    /// * `previous_signature` - Optional previous entry's signature for chaining
    /// * `trusted_timestamp` - Optional RFC 3161 trusted timestamp
    pub fn new(
        payload: AuditEvent,
        sequence: u64,
        signing_key: &[u8],
        previous_signature: Option<&[u8]>,
        trusted_timestamp: Option<TrustedTimestamp>,
    ) -> Self {
        // Build canonical bytes for signing: sequence || previous_sig || payload_json
        // NOTE: trusted_timestamp is NOT included in signing input — it is metadata
        // about the chain, not the entry itself.
        let payload_json = serde_json::to_string(&payload).unwrap_or_default();
        let mut signing_input = sequence.to_le_bytes().to_vec();
        if let Some(prev_sig) = previous_signature {
            signing_input.extend_from_slice(prev_sig);
        }
        signing_input.extend_from_slice(payload_json.as_bytes());

        // Create HMAC key and compute signature using ring
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, signing_key);
        let signature = ring::hmac::sign(&key, &signing_input).as_ref().to_vec();

        Self {
            payload,
            signature,
            sequence,
            previous_signature: previous_signature.map(|s| s.to_vec()),
            trusted_timestamp,
        }
    }

    /// Verify the entry's signature
    pub fn verify(&self, signing_key: &[u8]) -> bool {
        let payload_json = serde_json::to_string(&self.payload).unwrap_or_default();
        let mut signing_input = self.sequence.to_le_bytes().to_vec();
        if let Some(prev_sig) = &self.previous_signature {
            signing_input.extend_from_slice(prev_sig);
        }
        signing_input.extend_from_slice(payload_json.as_bytes());

        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, signing_key);
        ring::hmac::verify(&key, &signing_input, &self.signature).is_ok()
    }

    /// Verify the chain of entries (checks previous_signature matches and verifies signature)
    ///
    /// # Arguments
    /// * `signing_key` - The HMAC signing key to verify signatures
    /// * `previous_signature` - The previous entry's signature for chain verification
    ///
    /// Returns true if both the signature is valid AND the chain link is correct.
    pub fn verify_chain(&self, signing_key: &[u8], previous_signature: Option<&[u8]>) -> bool {
        // First verify the signature of this entry
        if !self.verify(signing_key) {
            tracing::warn!("Signature verification failed for entry {}", self.sequence);
            return false;
        }

        // Check previous signature matches (chain link verification)
        match (&self.previous_signature, previous_signature) {
            (Some(curr), Some(prev)) if curr.as_slice() == prev => {}
            (None, None) => {}
            _ => {
                tracing::warn!(
                    "Chain link mismatch for entry {}: expected {:?}, got {:?}",
                    self.sequence,
                    previous_signature,
                    self.previous_signature
                );
                return false;
            }
        }

        true
    }
}

/// Audit event structure for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: EventType,
    pub actor_id: String,
    pub actor_type: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub result: String,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl From<Event> for AuditEvent {
    fn from(event: Event) -> Self {
        Self {
            event_id: event.event_id,
            timestamp: event.timestamp,
            event_type: event.event_type,
            actor_id: event.actor_id,
            actor_type: event.actor_type,
            action: event.action,
            resource_type: event.resource_type,
            resource_id: event.resource_id,
            result: event.result,
            metadata: event.metadata,
        }
    }
}

/// Audit query filter
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuditFilter {
    #[serde(default)]
    pub event_types: Option<Vec<EventType>>,
    #[serde(default)]
    pub actor_id: Option<String>,
    #[serde(default)]
    pub resource_id: Option<String>,
    #[serde(default)]
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kms_core::EventType;

    fn make_audit_event() -> AuditEvent {
        AuditEvent {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            event_type: EventType::KeyCreated,
            actor_id: "test-actor".into(),
            actor_type: "user".into(),
            action: "create_key".into(),
            resource_type: "key".into(),
            resource_id: Some("key-123".into()),
            result: "success".into(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_signed_entry_create_and_verify() {
        let signing_key = b"test-signing-key-32-bytes-long!!";
        let event = make_audit_event();
        let entry = SignedAuditEntry::new(event.clone(), 0, signing_key, None, None);

        assert_eq!(entry.sequence, 0);
        assert!(entry.previous_signature.is_none());
        assert!(entry.trusted_timestamp.is_none());
        assert!(entry.verify(signing_key));
    }

    #[test]
    fn test_signed_entry_with_previous_signature() {
        let signing_key = b"test-signing-key-32-bytes-long!!";

        let entry0 = SignedAuditEntry::new(make_audit_event(), 0, signing_key, None, None);
        let entry1 = SignedAuditEntry::new(
            make_audit_event(),
            1,
            signing_key,
            Some(&entry0.signature),
            None,
        );

        assert_eq!(entry1.sequence, 1);
        assert_eq!(
            entry1.previous_signature.as_deref(),
            Some(entry0.signature.as_slice())
        );
        assert!(entry1.verify(signing_key));
        // Chain verification: entry1 references entry0's signature
        assert!(entry1.verify_chain(signing_key, Some(&entry0.signature)));
    }

    #[test]
    fn test_signed_entry_chain_verification_rejects_wrong_prev() {
        let signing_key = b"test-signing-key-32-bytes-long!!";

        let entry0 = SignedAuditEntry::new(make_audit_event(), 0, signing_key, None, None);
        let entry1 = SignedAuditEntry::new(
            make_audit_event(),
            1,
            signing_key,
            Some(&entry0.signature),
            None,
        );

        // Chain verification with wrong previous should fail
        let fake_prev = vec![0u8; 32];
        assert!(!entry1.verify_chain(signing_key, Some(&fake_prev)));
    }

    #[test]
    fn test_signed_entry_complete_roundtrip() {
        let signing_key = b"test-signing-key-32-bytes-long!!";
        let event = make_audit_event();

        // Create
        let entry = SignedAuditEntry::new(event.clone(), 42, signing_key, None, None);

        // Verify all fields round-trip correctly
        assert_eq!(entry.sequence, 42);
        assert_eq!(entry.payload.event_id, event.event_id);
        assert_eq!(entry.payload.actor_id, "test-actor");
        assert_eq!(entry.payload.action, "create_key");
        assert_eq!(entry.payload.result, "success");
        assert!(!entry.signature.is_empty());

        // Serialize and deserialize
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: SignedAuditEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.sequence, entry.sequence);
        assert_eq!(deserialized.payload.event_id, entry.payload.event_id);
        assert_eq!(deserialized.signature, entry.signature);
        assert_eq!(deserialized.previous_signature, entry.previous_signature);

        // Deserialized entry should still verify
        assert!(deserialized.verify(signing_key));
    }

    #[test]
    fn test_signed_entry_verify_with_wrong_key_fails() {
        let signing_key = b"test-signing-key-32-bytes-long!!";
        let wrong_key = b"wrong-signing-key-32-bytes-long!";
        let entry = SignedAuditEntry::new(make_audit_event(), 0, signing_key, None, None);

        assert!(entry.verify(signing_key));
        assert!(!entry.verify(wrong_key));
    }

    #[test]
    fn test_signed_entry_tampered_payload_fails_verification() {
        let signing_key = b"test-signing-key-32-bytes-long!!";
        let mut entry = SignedAuditEntry::new(make_audit_event(), 0, signing_key, None, None);

        // Tamper with the action
        entry.payload.action = "tampered".into();
        assert!(!entry.verify(signing_key));
    }
}
