//! Audit logger implementation
//!
//! Outputs audit events in JSON Lines format to file, stdout, or Kafka.

use super::timestamp::{TimestampAuthority, TrustedTimestamp, TsaClientConfig};
use super::{AuditEvent, AuditFilter};
use crate::error::AuditResult;
use kms_core::event::Event;
#[cfg(feature = "kafka")]
use rdkafka::config::ClientConfig;
#[cfg(feature = "kafka")]
use rdkafka::producer::{FutureProducer, FutureRecord};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, oneshot};

/// Audit logger configuration
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Output path (file path or "stdout")
    pub output_path: PathBuf,
    /// Flush interval in seconds
    pub flush_interval_secs: u64,
    /// Buffer size before flush
    pub buffer_size: usize,
    /// Kafka broker address (optional)
    pub kafka_brokers: Option<String>,
    /// Kafka topic for audit events
    pub kafka_topic: Option<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            output_path: PathBuf::from("stdout"),
            flush_interval_secs: 5,
            buffer_size: 100,
            kafka_brokers: None,
            kafka_topic: None,
        }
    }
}

/// Audit logger that writes JSON Lines format
pub struct AuditLogger {
    config: AuditConfig,
    buffer: Arc<Mutex<Vec<AuditEvent>>>,
    #[cfg(feature = "kafka")]
    kafka_producer: Option<FutureProducer>,
}

impl AuditLogger {
    pub fn new(config: AuditConfig) -> Self {
        #[cfg(feature = "kafka")]
        let kafka_producer: Option<FutureProducer> =
            config.kafka_brokers.as_ref().and_then(|brokers| {
                tracing::info!("Kafka producer connecting to {}", brokers);
                ClientConfig::new()
                    .set("bootstrap.servers", brokers.as_str())
                    .set("message.timeout.ms", "5000")
                    .create()
                    .ok()
            });

        Self {
            config,
            buffer: Arc::new(Mutex::new(Vec::new())),
            #[cfg(feature = "kafka")]
            kafka_producer,
        }
    }

    pub fn with_stdout() -> Self {
        Self::new(AuditConfig {
            output_path: PathBuf::from("stdout"),
            ..Default::default()
        })
    }

    /// Log an audit event
    pub async fn log(&self, event: impl Into<AuditEvent>) {
        let audit_event: AuditEvent = event.into();
        let mut buffer = self.buffer.lock().await;
        buffer.push(audit_event);

        // Flush if buffer is full
        if buffer.len() >= self.config.buffer_size {
            drop(buffer);
            self.flush().await;
        }
    }

    /// Log from an Event
    pub async fn log_event(&self, event: &Event) {
        self.log(AuditEvent::from(event.clone())).await;
    }

    /// Flush buffer to output (stdout, file, or Kafka)
    pub async fn flush(&self) {
        let events = {
            let mut buffer = self.buffer.lock().await;
            buffer.drain(..).collect::<Vec<_>>()
        };

        if events.is_empty() {
            return;
        }

        // Clone events for Kafka since we iterate twice
        #[cfg(feature = "kafka")]
        let kafka_events = if self.kafka_producer.is_some() && self.config.kafka_topic.is_some() {
            Some(events.clone())
        } else {
            None
        };

        // Write to stdout/file in a block so `output` (non-Send) is dropped before any await
        {
            // Output to stdout or file
            let stdout = std::io::stdout();
            let mut output: Box<dyn Write> =
                if self.config.output_path.to_string_lossy() == "stdout" {
                    Box::new(stdout)
                } else {
                    match std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&self.config.output_path)
                    {
                        Ok(file) => Box::new(file) as Box<dyn Write>,
                        Err(_) => Box::new(stdout) as Box<dyn Write>,
                    }
                };

            for event in &events {
                if let Ok(line) = serde_json::to_string(event) {
                    let _ = writeln!(output, "{}", line);
                }
            }
        } // `output` dropped here, before any .await

        // Output to Kafka if configured
        #[cfg(feature = "kafka")]
        if let (Some(producer), Some(topic), Some(kafka_events)) =
            (&self.kafka_producer, &self.config.kafka_topic, kafka_events)
        {
            use std::time::Duration;
            let timeout = Duration::from_millis(5000);
            for event in kafka_events {
                if let Ok(payload) = serde_json::to_string(&event) {
                    let key = event.event_id.to_string();
                    let record = FutureRecord::to(topic).payload(&payload).key(&key);
                    let _ = producer.send(record, timeout).await;
                }
            }
            tracing::debug!("Flushed {} events to Kafka", events.len());
        }
    }

    /// Query audit events
    pub async fn query(&self, filter: AuditFilter) -> Vec<AuditEvent> {
        let buffer = self.buffer.lock().await;

        buffer
            .iter()
            .filter(|event| {
                // Filter by event type
                if let Some(ref types) = filter.event_types
                    && !types.contains(&event.event_type)
                {
                    return false;
                }

                // Filter by actor_id
                if let Some(ref actor_id) = filter.actor_id
                    && &event.actor_id != actor_id
                {
                    return false;
                }

                // Filter by resource_id
                if let Some(ref resource_id) = filter.resource_id
                    && event.resource_id.as_ref() != Some(resource_id)
                {
                    return false;
                }

                // Filter by start_time
                if let Some(ref start) = filter.start_time
                    && event.timestamp < *start
                {
                    return false;
                }

                // Filter by end_time
                if let Some(ref end) = filter.end_time
                    && event.timestamp > *end
                {
                    return false;
                }

                true
            })
            .skip(filter.offset.unwrap_or(0))
            .take(filter.limit.unwrap_or(100))
            .cloned()
            .collect()
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::with_stdout()
    }
}

#[async_trait::async_trait]
impl super::AuditLog for AuditLogger {
    async fn log_event(&self, event: &kms_core::event::Event) {
        self.log_event(event).await;
    }

    async fn query(&self, filter: super::AuditFilter) -> Vec<super::AuditEvent> {
        self.query(filter).await
    }

    async fn backlog_depth(&self) -> usize {
        self.buffer.lock().await.len()
    }
}

/// Configuration for signed audit logging
#[derive(Debug, Clone)]
pub struct SignedAuditConfig {
    /// Base audit configuration
    pub base: AuditConfig,
    /// HMAC signing key (32 bytes recommended for HMAC-SHA256)
    /// Wrapped in Zeroizing for memory protection (M-4)
    pub signing_key: zeroize::Zeroizing<Vec<u8>>,
    /// Initial sequence number
    pub initial_sequence: u64,
}

impl SignedAuditConfig {
    /// Create a new signed audit config with a random signing key
    pub fn new(base: AuditConfig, initial_sequence: u64) -> Self {
        // Generate a random 32-byte signing key using CSPRNG
        let mut signing_key_raw = vec![0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut signing_key_raw);
        // Zeroizing ensures the key is zeroed when dropped (M-4)
        let signing_key = zeroize::Zeroizing::new(signing_key_raw);

        Self {
            base,
            signing_key,
            initial_sequence,
        }
    }

    /// Create with a specific signing key
    pub fn with_key(base: AuditConfig, signing_key: Vec<u8>, initial_sequence: u64) -> Self {
        Self {
            base,
            signing_key: zeroize::Zeroizing::new(signing_key),
            initial_sequence,
        }
    }

    /// Load signing key from a file path, or generate a new ephemeral key.
    ///
    /// For production deployments, the signing key file MUST reside on a separate
    /// volume from the WORM audit log directory (P2-6). If both are compromised
    /// simultaneously, an attacker could forge signatures on forged log entries.
    ///
    /// If the env var `KMS_AUDIT_SIGNING_KEY_FILE` is set, the key is loaded
    /// from that file. If the file does not exist, a new key is generated,
    /// written to the file (with 0o600 permissions), and returned.
    ///
    /// If the env var is not set, an ephemeral key is generated (not persisted).
    /// This is acceptable for development, but means signatures cannot be
    /// verified across restarts.
    pub fn from_env_or_ephemeral(base: AuditConfig, initial_sequence: u64) -> (Self, bool) {
        let key_path = std::env::var("KMS_AUDIT_SIGNING_KEY_FILE").ok();
        let (key, persisted) = match key_path.as_deref() {
            Some(path) => match Self::load_or_create_key_file(path) {
                Ok(key_bytes) => {
                    if key_bytes.len() >= 32 {
                        tracing::info!(
                            "Loaded audit signing key from {} ({} bytes)",
                            path,
                            key_bytes.len()
                        );
                        (key_bytes, true)
                    } else {
                        tracing::warn!(
                            "Audit signing key file {} too short ({} bytes), generating ephemeral key",
                            path,
                            key_bytes.len()
                        );
                        (Self::generate_key(), false)
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to load audit signing key from {}: {} — generating ephemeral key",
                        path,
                        e
                    );
                    (Self::generate_key(), false)
                }
            },
            None => {
                tracing::info!(
                    "KMS_AUDIT_SIGNING_KEY_FILE not set — using ephemeral signing key (signatures not verifiable across restarts)"
                );
                (Self::generate_key(), false)
            }
        };
        (
            Self {
                base,
                signing_key: zeroize::Zeroizing::new(key),
                initial_sequence,
            },
            persisted,
        )
    }

    /// Generate a random 32-byte key.
    fn generate_key() -> Vec<u8> {
        let mut raw = vec![0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut raw);
        raw
    }

    /// Load an existing signing key file or create a new one with 0o600 permissions.
    fn load_or_create_key_file(path: &str) -> std::io::Result<Vec<u8>> {
        use std::io::Write;

        match std::fs::read(path) {
            Ok(existing) => Ok(existing),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Generate a new key and persist it
                let raw = Self::generate_key();

                // Write with restrictive permissions (0o600)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)?;
                    f.write_all(&raw)?;
                }
                #[cfg(not(unix))]
                {
                    tracing::warn!(
                        "Audit signing key at {} created without restrictive permissions (non-Unix platform)",
                        path
                    );
                    let mut f = std::fs::File::create(path)?;
                    f.write_all(&raw)?;
                }

                tracing::info!(
                    "Created new audit signing key at {} (32 bytes, mode 0o600)",
                    path
                );
                Ok(raw)
            }
            Err(e) => Err(e),
        }
    }
}

/// Signed audit logger that provides tamper-evident audit trail
pub struct SignedAuditLogger {
    config: SignedAuditConfig,
    buffer: Arc<Mutex<Vec<super::SignedAuditEntry>>>,
    current_sequence: Arc<Mutex<u64>>,
    previous_signature: Arc<Mutex<Option<Vec<u8>>>>,
    #[cfg(feature = "kafka")]
    kafka_producer: Option<FutureProducer>,
    #[cfg(feature = "kafka")]
    kafka_topic: Option<String>,
}

impl SignedAuditLogger {
    /// Create a new signed audit logger
    pub fn new(config: SignedAuditConfig) -> Self {
        #[cfg(feature = "kafka")]
        let (kafka_producer, kafka_topic) = if let Some(ref brokers) = config.base.kafka_brokers {
            let kafka_topic = config.base.kafka_topic.clone();
            tracing::info!("Kafka producer connecting to {}", brokers);
            let producer = ClientConfig::new()
                .set("bootstrap.servers", brokers.as_str())
                .set("message.timeout.ms", "5000")
                .create()
                .ok();
            (producer, kafka_topic)
        } else {
            (None, None)
        };

        #[cfg(not(feature = "kafka"))]
        let _kafka_topic: Option<String> = None;

        Self {
            config,
            buffer: Arc::new(Mutex::new(Vec::new())),
            current_sequence: Arc::new(Mutex::new(0)),
            previous_signature: Arc::new(Mutex::new(None)),
            #[cfg(feature = "kafka")]
            kafka_producer,
            #[cfg(feature = "kafka")]
            kafka_topic,
        }
    }

    /// Log an audit event with signature
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

        let signing_key = &self.config.signing_key;
        let prev_sig_ref = prev_sig.as_deref();
        let signed_entry =
            super::SignedAuditEntry::new(audit_event, sequence, signing_key, prev_sig_ref, None);

        // Update previous signature
        {
            let mut prev_guard = self.previous_signature.lock().await;
            *prev_guard = Some(signed_entry.signature.clone());
        }

        let mut buffer = self.buffer.lock().await;
        buffer.push(signed_entry);

        // Flush if buffer is full
        if buffer.len() >= self.config.base.buffer_size {
            drop(buffer);
            self.flush().await;
        }
    }

    /// Log from an Event
    pub async fn log_event(&self, event: &Event) {
        self.log(super::AuditEvent::from(event.clone())).await;
    }

    /// Flush buffer to output
    pub async fn flush(&self) {
        let entries = {
            let mut buffer = self.buffer.lock().await;
            buffer.drain(..).collect::<Vec<_>>()
        };

        if entries.is_empty() {
            return;
        }

        // Output to stdout or file
        let stdout = std::io::stdout();
        let mut output: Box<dyn Write> =
            if self.config.base.output_path.to_string_lossy() == "stdout" {
                Box::new(stdout)
            } else {
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.config.base.output_path)
                {
                    Ok(file) => Box::new(file) as Box<dyn Write>,
                    Err(_) => Box::new(stdout) as Box<dyn Write>,
                }
            };

        // Clone entries for Kafka since we iterate twice
        #[cfg(feature = "kafka")]
        let kafka_entries = if self.kafka_producer.is_some() && self.kafka_topic.is_some() {
            Some(entries.clone())
        } else {
            None
        };

        for entry in &entries {
            if let Ok(line) = serde_json::to_string(entry) {
                let _ = writeln!(output, "{}", line);
            }
        }

        // Output to Kafka if configured
        #[cfg(feature = "kafka")]
        if let (Some(producer), Some(topic), Some(kafka_entries)) =
            (&self.kafka_producer, &self.kafka_topic, kafka_entries)
        {
            use std::time::Duration;
            let timeout = Duration::from_millis(5000);
            for entry in kafka_entries {
                if let Ok(payload) = serde_json::to_string(&entry) {
                    let key = entry.payload.event_id.to_string();
                    let record = FutureRecord::to(topic).payload(&payload).key(&key);
                    let _ = producer.send(record, timeout).await;
                }
            }
            tracing::debug!("Flushed {} signed entries to Kafka", entries.len());
        }
    }

    /// Get the current buffer backlog depth.
    pub async fn backlog_depth(&self) -> usize {
        self.buffer.lock().await.len()
    }

    /// Get the current hash chain head (previous_signature) for TSA timestamping.
    ///
    /// Returns a 32-byte SHA-256 hash that represents the current chain head.
    /// This is used by TimestampedAuditLogger to request TSA timestamps.
    pub async fn get_chain_head(&self) -> [u8; 32] {
        let prev = self.previous_signature.lock().await;
        match prev.as_ref() {
            Some(sig) => {
                // Use first 32 bytes of HMAC output as chain head
                let mut hash = [0u8; 32];
                let len = sig.len().min(32);
                hash[..len].copy_from_slice(&sig[..len]);
                hash
            }
            None => {
                // Before any entry is logged, use HMAC of "genesis" as chain start
                let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"kms-audit-genesis");
                let genesis = ring::hmac::sign(&key, b"genesis");
                let mut hash = [0u8; 32];
                hash.copy_from_slice(genesis.as_ref());
                hash
            }
        }
    }

    /// Verify all entries in buffer (for testing)
    #[cfg(test)]
    pub async fn verify_all(&self) -> bool {
        let buffer = self.buffer.lock().await;
        let signing_key = &self.config.signing_key;
        let mut prev_sig: Option<&[u8]> = None;

        for entry in buffer.iter() {
            // Verify chain and signature together
            if !entry.verify_chain(signing_key, prev_sig) {
                return false;
            }
            prev_sig = Some(entry.signature.as_slice());
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kms_core::EventType;

    #[tokio::test]
    async fn test_log_event() {
        // Create logger that outputs to stdout for testing
        let logger = AuditLogger::with_stdout();

        let event = AuditEvent {
            event_id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            event_type: EventType::KeyCreated,
            actor_id: "user1".to_string(),
            actor_type: "user".to_string(),
            action: "create_key".to_string(),
            resource_type: "key".to_string(),
            resource_id: Some("key-123".to_string()),
            result: "success".to_string(),
            metadata: std::collections::HashMap::new(),
        };

        // This should not panic
        logger.log(event).await;
        logger.flush().await;
    }

    #[tokio::test]
    async fn test_query_events() {
        let logger = AuditLogger::with_stdout();

        // Log several events
        for i in 0..5 {
            let event = AuditEvent {
                event_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                event_type: if i % 2 == 0 {
                    EventType::KeyCreated
                } else {
                    EventType::KeyDeleted
                },
                actor_id: format!("user{}", i % 2),
                actor_type: "user".to_string(),
                action: "test".to_string(),
                resource_type: "key".to_string(),
                resource_id: Some(format!("key-{}", i)),
                result: "success".to_string(),
                metadata: std::collections::HashMap::new(),
            };
            logger.log(event).await;
        }

        // Query all events
        let all_events = logger.query(AuditFilter::default()).await;
        assert!(all_events.len() >= 5);

        // Query by actor_id
        let user0_events = logger
            .query(AuditFilter {
                actor_id: Some("user0".to_string()),
                ..Default::default()
            })
            .await;
        assert!(user0_events.iter().all(|e| e.actor_id == "user0"));

        // Query by event type
        let created_events = logger
            .query(AuditFilter {
                event_types: Some(vec![EventType::KeyCreated]),
                ..Default::default()
            })
            .await;
        assert!(
            created_events
                .iter()
                .all(|e| e.event_type == EventType::KeyCreated)
        );

        // Query with limit
        let limited_events = logger
            .query(AuditFilter {
                limit: Some(2),
                ..Default::default()
            })
            .await;
        assert!(limited_events.len() <= 2);
    }

    // --- Additional tests ---

    /// Test AuditConfig default values
    #[test]
    fn test_audit_config_default() {
        let config = AuditConfig::default();
        assert_eq!(config.output_path, PathBuf::from("stdout"));
        assert_eq!(config.flush_interval_secs, 5);
        assert_eq!(config.buffer_size, 100);
        assert!(config.kafka_brokers.is_none());
        assert!(config.kafka_topic.is_none());
    }

    /// Test AuditLogger default
    #[tokio::test]
    async fn test_audit_logger_default() {
        let logger = AuditLogger::default();
        // Should be able to log without panic
        let event = AuditEvent {
            event_id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            event_type: EventType::KeyCreated,
            actor_id: "test".to_string(),
            actor_type: "user".to_string(),
            action: "test".to_string(),
            resource_type: "key".to_string(),
            resource_id: None,
            result: "success".to_string(),
            metadata: std::collections::HashMap::new(),
        };
        logger.log(event).await;
        logger.flush().await;
    }

    /// Test log_event from Event
    #[tokio::test]
    async fn test_log_event_from_event() {
        let logger = AuditLogger::with_stdout();

        let event = Event::new(
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
    }

    /// Test query with resource_id filter
    #[tokio::test]
    async fn test_query_by_resource_id() {
        let logger = AuditLogger::with_stdout();

        for i in 0..5 {
            let event = AuditEvent {
                event_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                event_type: EventType::KeyCreated,
                actor_id: "user1".to_string(),
                actor_type: "user".to_string(),
                action: "test".to_string(),
                resource_type: "key".to_string(),
                resource_id: Some(format!("key-{}", i)),
                result: "success".to_string(),
                metadata: std::collections::HashMap::new(),
            };
            logger.log(event).await;
        }

        let filtered = logger
            .query(AuditFilter {
                resource_id: Some("key-2".to_string()),
                ..Default::default()
            })
            .await;
        assert!(
            filtered
                .iter()
                .all(|e| e.resource_id == Some("key-2".to_string()))
        );
    }

    /// Test query with offset
    #[tokio::test]
    async fn test_query_with_offset() {
        let logger = AuditLogger::with_stdout();

        for i in 0..5 {
            let event = AuditEvent {
                event_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                event_type: EventType::KeyCreated,
                actor_id: format!("user{}", i),
                actor_type: "user".to_string(),
                action: "test".to_string(),
                resource_type: "key".to_string(),
                resource_id: None,
                result: "success".to_string(),
                metadata: std::collections::HashMap::new(),
            };
            logger.log(event).await;
        }

        // offset=2 should skip first 2
        let paged = logger
            .query(AuditFilter {
                offset: Some(2),
                limit: Some(10),
                ..Default::default()
            })
            .await;
        assert!(paged.len() <= 3); // 5 - 2 = 3
    }

    /// Test backlog_depth
    #[tokio::test]
    async fn test_backlog_depth() {
        use crate::AuditLog;
        let logger = AuditLogger::with_stdout();

        assert_eq!(logger.backlog_depth().await, 0);

        for _ in 0..3 {
            let event = AuditEvent {
                event_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                event_type: EventType::KeyCreated,
                actor_id: "test".to_string(),
                actor_type: "user".to_string(),
                action: "test".to_string(),
                resource_type: "key".to_string(),
                resource_id: None,
                result: "success".to_string(),
                metadata: std::collections::HashMap::new(),
            };
            logger.log(event).await;
        }

        assert_eq!(logger.backlog_depth().await, 3);
    }

    /// Test SignedAuditConfig::new generates 32-byte key
    #[test]
    fn test_signed_audit_config_new_generates_key() {
        let config = SignedAuditConfig::new(AuditConfig::default(), 0);
        assert_eq!(config.signing_key.len(), 32);
        assert_eq!(config.initial_sequence, 0);
    }

    /// Test SignedAuditConfig::with_key
    #[test]
    fn test_signed_audit_config_with_key() {
        let key = vec![0xAB; 32];
        let config = SignedAuditConfig::with_key(AuditConfig::default(), key.clone(), 100);
        assert_eq!(*config.signing_key, key);
        assert_eq!(config.initial_sequence, 100);
    }

    /// Test SignedAuditLogger log and verify chain
    #[tokio::test]
    async fn test_signed_audit_logger_log_and_verify() {
        let config = SignedAuditConfig::new(
            AuditConfig {
                output_path: PathBuf::from("stdout"),
                ..Default::default()
            },
            0,
        );
        let logger = SignedAuditLogger::new(config);

        for _ in 0..3 {
            let event = AuditEvent {
                event_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                event_type: EventType::KeyCreated,
                actor_id: "test".to_string(),
                actor_type: "user".to_string(),
                action: "test".to_string(),
                resource_type: "key".to_string(),
                resource_id: None,
                result: "success".to_string(),
                metadata: std::collections::HashMap::new(),
            };
            logger.log(event).await;
        }

        // Verify chain integrity
        assert!(logger.verify_all().await);
    }

    /// Test SignedAuditLogger backlog_depth
    #[tokio::test]
    async fn test_signed_audit_logger_backlog_depth() {
        let config = SignedAuditConfig::new(
            AuditConfig {
                output_path: PathBuf::from("stdout"),
                ..Default::default()
            },
            0,
        );
        let logger = SignedAuditLogger::new(config);

        assert_eq!(logger.backlog_depth().await, 0);

        let event = AuditEvent {
            event_id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            event_type: EventType::KeyCreated,
            actor_id: "test".to_string(),
            actor_type: "user".to_string(),
            action: "test".to_string(),
            resource_type: "key".to_string(),
            resource_id: None,
            result: "success".to_string(),
            metadata: std::collections::HashMap::new(),
        };
        logger.log(event).await;

        assert_eq!(logger.backlog_depth().await, 1);
    }
}

// =============================================================================
// TimestampedAuditLogger — Signed audit logging with TSA timestamps
// =============================================================================

/// Configuration for timestamped audit logging
#[derive(Debug, Clone)]
pub struct TimestampedAuditConfig {
    /// Base signed audit config (hash chain + HMAC)
    pub signed_config: SignedAuditConfig,
    /// TSA client configuration (None = no TSA, signed logging only)
    pub tsa_config: Option<TsaClientConfig>,
    /// Polling interval for TSA (seconds, default 60)
    pub tsa_interval_secs: u64,
    /// If true, emit CRITICAL alerts when TSA is unreachable
    pub require_tsa: bool,
}

impl Default for TimestampedAuditConfig {
    fn default() -> Self {
        Self {
            signed_config: SignedAuditConfig::new(AuditConfig::default(), 0),
            tsa_config: None,
            tsa_interval_secs: 60,
            require_tsa: false,
        }
    }
}

/// Audit logger that provides both hash-chain integrity AND RFC 3161 trusted timestamps.
///
/// # Architecture
///
/// - Hot write path: creates `SignedAuditEntry` with hash chain + current `TrustedTimestamp`
///   from shared state. Never blocks on TSA.
/// - Background task: periodically requests TSA timestamps for the hash chain head,
///   updating the shared `TrustedTimestamp`. On failure, logs an alert and continues.
#[allow(dead_code)]
pub struct TimestampedAuditLogger {
    /// Inner signed audit logger (hash chain + HMAC)
    signed_logger: Arc<SignedAuditLogger>,
    /// TSA client (None if not configured)
    tsa: Option<Arc<TimestampAuthority>>,
    /// TSA failover endpoints
    tsa_endpoints: Vec<String>,
    /// Current trusted timestamp, shared with background task
    current_ts: Arc<Mutex<Option<TrustedTimestamp>>>,
    /// Shutdown signal sender for background task
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Whether TSA is required (CRITICAL alert on failure)
    require_tsa: bool,
    /// TSA request counter (shared with KmsMetrics via Arc)
    tsa_requests: Option<Arc<AtomicU64>>,
    /// TSA success counter (shared with KmsMetrics via Arc)
    tsa_successes: Option<Arc<AtomicU64>>,
    /// TSA failure counter (shared with KmsMetrics via Arc)
    tsa_failures: Option<Arc<AtomicU64>>,
}

impl TimestampedAuditLogger {
    /// Create a new timestamped audit logger.
    ///
    /// If `tsa_config` is Some and has endpoints, a background task is spawned
    /// to periodically request TSA timestamps.
    ///
    /// Optional `tsa_requests`, `tsa_successes`, `tsa_failures` provide shared
    /// counters (as `Arc<AtomicU64>`) that the background TSA task will increment.
    pub fn new(
        config: TimestampedAuditConfig,
        tsa_counters: Option<(Arc<AtomicU64>, Arc<AtomicU64>, Arc<AtomicU64>)>,
    ) -> AuditResult<Self> {
        let signed_logger = Arc::new(SignedAuditLogger::new(config.signed_config));
        let current_ts = Arc::new(Mutex::new(None::<TrustedTimestamp>));

        let tsa_config = config.tsa_config;
        let tsa_endpoints = tsa_config
            .as_ref()
            .map(|c| c.endpoints.clone())
            .unwrap_or_default();
        let tsa_interval = Duration::from_secs(config.tsa_interval_secs);
        let require_tsa = config.require_tsa;

        let (tsa_counters_for_task, tsa_counters_for_struct) =
            if let Some((req, ok, fail)) = tsa_counters {
                (
                    Some((Arc::clone(&req), Arc::clone(&ok), Arc::clone(&fail))),
                    (Some(req), Some(ok), Some(fail)),
                )
            } else {
                (None, (None, None, None))
            };

        let (tsa, shutdown_tx) = if let Some(ref tsa_cfg) = tsa_config {
            let primary_url = tsa_cfg.endpoints.first().cloned().unwrap_or_default();
            if primary_url.is_empty() {
                tracing::info!("TSA not configured (no endpoints), using signed-only logging");
                (None, None)
            } else {
                let tsa_client = TimestampAuthority::from_client_config(tsa_cfg)?;
                let tsa = Arc::new(tsa_client);

                // Spawn background task
                let shutdown = Self::start_background_tsa_task(
                    signed_logger.clone(),
                    tsa.clone(),
                    tsa_endpoints.clone(),
                    current_ts.clone(),
                    tsa_interval,
                    require_tsa,
                    tsa_counters_for_task,
                );
                tracing::info!(
                    "TSA timestamping enabled: endpoints={:?}, interval={}s, require_tsa={}",
                    tsa_endpoints,
                    tsa_interval.as_secs(),
                    require_tsa
                );
                (Some(tsa), Some(shutdown))
            }
        } else {
            tracing::info!("TSA not configured, using signed-only logging");
            (None, None)
        };

        Ok(Self {
            signed_logger,
            tsa,
            tsa_endpoints,
            current_ts,
            shutdown_tx,
            require_tsa,
            tsa_requests: tsa_counters_for_struct.0,
            tsa_successes: tsa_counters_for_struct.1,
            tsa_failures: tsa_counters_for_struct.2,
        })
    }

    /// Log an audit event.
    ///
    /// The event is signed with the hash chain and carries the `trusted_timestamp`
    /// from the latest TSA response (if available). This call never blocks on TSA.
    pub async fn log(&self, event: impl Into<AuditEvent>) {
        let audit_event: AuditEvent = event.into();

        let sequence = {
            let mut seq_guard = self.signed_logger.current_sequence.lock().await;
            let seq = *seq_guard;
            *seq_guard += 1;
            seq
        };

        let prev_sig = {
            let prev_guard = self.signed_logger.previous_signature.lock().await;
            prev_guard.clone()
        };

        let signing_key = &*self.signed_logger.config.signing_key;
        let prev_sig_ref = prev_sig.as_deref();

        // Get current trusted timestamp (non-blocking read from shared state)
        let ts = self.current_ts.lock().await.clone();

        let signed_entry =
            super::SignedAuditEntry::new(audit_event, sequence, signing_key, prev_sig_ref, ts);

        // Update previous signature
        {
            let mut prev_guard = self.signed_logger.previous_signature.lock().await;
            *prev_guard = Some(signed_entry.signature.clone());
        }

        let mut buffer = self.signed_logger.buffer.lock().await;
        buffer.push(signed_entry);

        // Flush if buffer is full
        if buffer.len() >= self.signed_logger.config.base.buffer_size {
            drop(buffer);
            self.flush().await;
        }
    }

    /// Log from an Event
    pub async fn log_event(&self, event: &Event) {
        self.log(AuditEvent::from(event.clone())).await;
    }

    /// Flush buffer to output
    pub async fn flush(&self) {
        let entries = {
            let mut buffer = self.signed_logger.buffer.lock().await;
            buffer.drain(..).collect::<Vec<_>>()
        };

        if entries.is_empty() {
            return;
        }

        let stdout = std::io::stdout();
        let mut output: Box<dyn Write> =
            if self.signed_logger.config.base.output_path.to_string_lossy() == "stdout" {
                Box::new(stdout)
            } else {
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.signed_logger.config.base.output_path)
                {
                    Ok(file) => Box::new(file) as Box<dyn Write>,
                    Err(_) => Box::new(stdout) as Box<dyn Write>,
                }
            };

        for entry in &entries {
            if let Ok(line) = serde_json::to_string(entry) {
                let _ = writeln!(output, "{}", line);
            }
        }
    }

    /// Query audit events (extracts AuditEvent from SignedAuditEntry)
    pub async fn query(&self, filter: AuditFilter) -> Vec<AuditEvent> {
        let buffer = self.signed_logger.buffer.lock().await;
        buffer
            .iter()
            .filter(|entry| {
                if let Some(ref types) = filter.event_types
                    && !types.contains(&entry.payload.event_type)
                {
                    return false;
                }
                if let Some(ref actor_id) = filter.actor_id
                    && entry.payload.actor_id != *actor_id
                {
                    return false;
                }
                if let Some(ref resource_id) = filter.resource_id
                    && entry.payload.resource_id.as_ref() != Some(resource_id)
                {
                    return false;
                }
                if let Some(ref start) = filter.start_time
                    && entry.payload.timestamp < *start
                {
                    return false;
                }
                if let Some(ref end) = filter.end_time
                    && entry.payload.timestamp > *end
                {
                    return false;
                }
                true
            })
            .skip(filter.offset.unwrap_or(0))
            .take(filter.limit.unwrap_or(100))
            .map(|entry| entry.payload.clone())
            .collect()
    }

    /// Get the current trusted timestamp (for inspection/testing)
    #[allow(dead_code)]
    pub async fn current_timestamp(&self) -> Option<TrustedTimestamp> {
        self.current_ts.lock().await.clone()
    }

    /// Spawn background TSA task.
    ///
    /// Periodically requests TSA timestamps for the hash chain head and updates
    /// the shared `current_ts` state.
    ///
    /// If `tsa_counters` is provided, increments the shared counters for each
    /// TSA request, success, and failure.
    fn start_background_tsa_task(
        signed_logger: Arc<SignedAuditLogger>,
        tsa: Arc<TimestampAuthority>,
        tsa_endpoints: Vec<String>,
        current_ts: Arc<Mutex<Option<TrustedTimestamp>>>,
        interval: Duration,
        require_tsa: bool,
        tsa_counters: Option<(Arc<AtomicU64>, Arc<AtomicU64>, Arc<AtomicU64>)>,
    ) -> oneshot::Sender<()> {
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Skip immediate first tick — wait one interval before first request
            ticker.tick().await;

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        // Increment request counter
                        if let Some((ref req, _, _)) = tsa_counters {
                            req.fetch_add(1, Ordering::Relaxed);
                        }

                        let chain_head = signed_logger.get_chain_head().await;

                        match tsa.request_timestamp_with_failover(&chain_head, &tsa_endpoints).await {
                            Ok(response) => {
                                match tsa.verify_timestamp(&chain_head, &response) {
                                    Ok(true) => {
                                        // Increment success counter
                                        if let Some((_, ref ok, _)) = tsa_counters {
                                            ok.fetch_add(1, Ordering::Relaxed);
                                        }
                                        let nonce = tsa.last_nonce.lock().clone().unwrap_or_default();
                                        let ts = TrustedTimestamp {
                                            raw_token: response.token,
                                            gen_time: response
                                                .timestamp
                                                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                                                .unwrap_or_default()
                                                .as_secs() as i64,
                                            serial_number: response.serial_number,
                                            policy: response.policy,
                                            hash_algorithm: "sha256".to_string(),
                                            nonce,
                                            accuracy_millis: response.accuracy_millis,
                                        };
                                        *current_ts.lock().await = Some(ts);
                                        tracing::debug!("TSA timestamp acquired successfully");
                                    }
                                    Ok(false) => {
                                        // Increment failure counter
                                        if let Some((_, _, ref fail)) = tsa_counters {
                                            fail.fetch_add(1, Ordering::Relaxed);
                                        }
                                        tracing::error!("TSA response verification failed");
                                        *current_ts.lock().await = None;
                                    }
                                    Err(e) => {
                                        if let Some((_, _, ref fail)) = tsa_counters {
                                            fail.fetch_add(1, Ordering::Relaxed);
                                        }
                                        tracing::error!("TSA verification error: {}", e);
                                        *current_ts.lock().await = None;
                                    }
                                }
                            }
                            Err(e) => {
                                if let Some((_, _, ref fail)) = tsa_counters {
                                    fail.fetch_add(1, Ordering::Relaxed);
                                }
                                tracing::error!("TSA request failed: {}", e);
                                *current_ts.lock().await = None;
                                if require_tsa {
                                    tracing::error!(
                                        "CRITICAL: TSA unavailable and require_tsa=true. \
                                         Audit log timestamps are MISSING."
                                    );
                                }
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        tracing::info!("TSA background task shutting down");
                        break;
                    }
                }
            }
        });

        shutdown_tx
    }
}

#[async_trait::async_trait]
impl super::AuditLog for TimestampedAuditLogger {
    async fn log_event(&self, event: &Event) {
        self.log_event(event).await;
    }

    async fn query(&self, filter: AuditFilter) -> Vec<AuditEvent> {
        self.query(filter).await
    }

    async fn backlog_depth(&self) -> usize {
        self.signed_logger.backlog_depth().await
    }
}

impl Drop for TimestampedAuditLogger {
    fn drop(&mut self) {
        // Signal background task to shut down
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

#[cfg(test)]
mod timestamped_tests {
    use super::*;
    use kms_core::EventType;

    #[tokio::test]
    async fn test_timestamped_logger_no_tsa() {
        let config = TimestampedAuditConfig {
            signed_config: SignedAuditConfig::new(
                AuditConfig {
                    output_path: PathBuf::from("stdout"),
                    ..Default::default()
                },
                0,
            ),
            tsa_config: None,
            tsa_interval_secs: 60,
            require_tsa: false,
        };

        let logger = TimestampedAuditLogger::new(config, None).unwrap();

        let event = AuditEvent {
            event_id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            event_type: EventType::KeyCreated,
            actor_id: "user1".to_string(),
            actor_type: "user".to_string(),
            action: "create_key".to_string(),
            resource_type: "key".to_string(),
            resource_id: Some("key-123".to_string()),
            result: "success".to_string(),
            metadata: std::collections::HashMap::new(),
        };

        // Should not panic — entries have trusted_timestamp: None
        logger.log(event).await;

        // Query before flush (flush drains the buffer)
        let events = logger.query(AuditFilter::default()).await;
        assert!(!events.is_empty());

        logger.flush().await;
    }

    #[tokio::test]
    async fn test_timestamped_logger_query() {
        let config = TimestampedAuditConfig::default();

        let logger = TimestampedAuditLogger::new(config, None).unwrap();

        // Log several events
        for i in 0..5 {
            let event = AuditEvent {
                event_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                event_type: if i % 2 == 0 {
                    EventType::KeyCreated
                } else {
                    EventType::KeyDeleted
                },
                actor_id: format!("user{}", i % 2),
                actor_type: "user".to_string(),
                action: "test".to_string(),
                resource_type: "key".to_string(),
                resource_id: Some(format!("key-{}", i)),
                result: "success".to_string(),
                metadata: std::collections::HashMap::new(),
            };
            logger.log(event).await;
        }

        // Query by actor_id
        let user0_events = logger
            .query(AuditFilter {
                actor_id: Some("user0".to_string()),
                ..Default::default()
            })
            .await;
        assert!(user0_events.iter().all(|e| e.actor_id == "user0"));
    }

    #[tokio::test]
    async fn test_timestamped_logger_current_ts_none_without_tsa() {
        let config = TimestampedAuditConfig::default();
        let logger = TimestampedAuditLogger::new(config, None).unwrap();

        let ts = logger.current_timestamp().await;
        assert!(ts.is_none());
    }
}
