//! Webhook Event System
//!
//! This module provides webhook notifications for KMS events.
//! External systems can subscribe to events and receive HTTP callbacks.
//!
//! ## Features
//!
//! - Configurable webhook endpoints
//! - Event filtering (subscribe to specific event types)
//! - HMAC signature for payload verification
//! - Retry with exponential backoff
//! - Async delivery (non-blocking)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use kms_core::webhook::{WebhookClient, WebhookConfig, EventFilter};
//!
//! let config = WebhookConfig {
//!     url: "https://example.com/webhook".to_string(),
//!     secret: b"webhook-signing-secret".to_vec(),
//!     ..Default::default()
//! };
//!
//! let client = WebhookClient::new(config);
//! client.send_event(&event).await;
//! ```

use crate::event::Event;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio::time::{Duration, sleep};

/// Webhook delivery status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// Successfully delivered
    Delivered,
    /// Failed to deliver
    Failed,
    /// Pending delivery
    Pending,
    /// Retrying delivery
    Retrying,
}

/// Webhook delivery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    /// Delivery ID
    pub id: uuid::Uuid,
    /// Event that was delivered
    pub event_id: uuid::Uuid,
    /// Delivery status
    pub status: DeliveryStatus,
    /// HTTP status code (if delivered)
    pub status_code: Option<u16>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Attempt number
    pub attempts: u32,
    /// Next retry time (if pending)
    pub next_retry_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Event filter configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventFilter {
    /// Event types to include (empty = all)
    pub include_types: HashSet<String>,
    /// Event types to exclude
    pub exclude_types: HashSet<String>,
    /// Actor ID filter (empty = all)
    pub actor_ids: HashSet<String>,
    /// Resource ID filter (empty = all)
    pub resource_ids: HashSet<String>,
}

impl EventFilter {
    /// Create a filter that matches all events
    pub fn all() -> Self {
        Self::default()
    }

    /// Create a filter that matches specific event types
    pub fn event_types<T: Into<String>>(types: impl IntoIterator<Item = T>) -> Self {
        let include_types = types.into_iter().map(Into::into).collect();
        Self {
            include_types,
            exclude_types: HashSet::new(),
            actor_ids: HashSet::new(),
            resource_ids: HashSet::new(),
        }
    }

    /// Check if an event matches this filter
    pub fn matches(&self, event: &Event) -> bool {
        let event_type = format!("{:?}", event.event_type);

        // Check include_types (empty = all)
        if !self.include_types.is_empty() && !self.include_types.contains(&event_type) {
            return false;
        }

        // Check exclude_types
        if self.exclude_types.contains(&event_type) {
            return false;
        }

        // Check actor_ids (empty = all)
        if !self.actor_ids.is_empty() && !self.actor_ids.contains(&event.actor_id) {
            return false;
        }

        // Check resource_ids (empty = all)
        if !self.resource_ids.is_empty()
            && !matches!(event.resource_id.as_deref(), Some(rid) if self.resource_ids.contains(rid))
        {
            return false;
        }

        true
    }
}

/// Webhook configuration
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// Webhook endpoint URL
    pub url: String,
    /// HMAC signing secret
    pub secret: Vec<u8>,
    /// Timeout for delivery
    pub timeout_secs: u64,
    /// Max retry attempts
    pub max_retries: u32,
    /// Initial retry delay (exponential backoff base)
    pub retry_delay_ms: u64,
    /// Event filter
    pub filter: EventFilter,
    /// Content type
    pub content_type: String,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            secret: Vec::new(),
            timeout_secs: 30,
            max_retries: 3,
            retry_delay_ms: 1000,
            filter: EventFilter::default(),
            content_type: "application/json".to_string(),
        }
    }
}

/// Webhook client for sending events
#[derive(Debug, Clone)]
pub struct WebhookClient {
    config: WebhookConfig,
    http_client: reqwest::Client,
}

impl WebhookClient {
    /// Create a new webhook client
    pub fn new(config: WebhookConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .unwrap_or_default();

        Self {
            config,
            http_client,
        }
    }

    /// Create a new webhook client with default config
    pub fn with_url(url: &str, secret: &[u8]) -> Result<Self, url::ParseError> {
        let config = WebhookConfig {
            url: url.to_string(),
            secret: secret.to_vec(),
            ..Default::default()
        };
        Ok(Self::new(config))
    }

    /// Check if an event should be sent to this webhook
    pub fn should_send(&self, event: &Event) -> bool {
        self.config.filter.matches(event)
    }

    /// Send an event to the webhook
    pub async fn send_event(&self, event: &Event) -> WebhookDelivery {
        let delivery = self.deliver_with_retry(event, 0).await;
        tracing::info!(
            event_id = %event.event_id,
            status = ?delivery.status,
            attempts = delivery.attempts,
            "Webhook event delivered"
        );
        delivery
    }

    /// Deliver event with retry logic
    async fn deliver_with_retry(&self, event: &Event, attempt: u32) -> WebhookDelivery {
        let delivery_id = uuid::Uuid::new_v4();
        let mut current_attempt = attempt;

        loop {
            match self.deliver(event).await {
                Ok(status_code) => {
                    return WebhookDelivery {
                        id: delivery_id,
                        event_id: event.event_id,
                        status: DeliveryStatus::Delivered,
                        status_code: Some(status_code),
                        error: None,
                        attempts: current_attempt + 1,
                        next_retry_at: None,
                    };
                }
                Err(e) => {
                    if current_attempt < self.config.max_retries {
                        // Calculate exponential backoff
                        let delay = self.config.retry_delay_ms * 2u64.pow(current_attempt);

                        tracing::warn!(
                            event_id = %event.event_id,
                            attempt = current_attempt + 1,
                            delay_ms = delay,
                            error = %e,
                            "Webhook delivery failed, retrying"
                        );

                        sleep(Duration::from_millis(delay)).await;
                        current_attempt += 1;
                    } else {
                        tracing::error!(
                            event_id = %event.event_id,
                            attempts = current_attempt + 1,
                            error = %e,
                            "Webhook delivery failed after max retries"
                        );
                        return WebhookDelivery {
                            id: delivery_id,
                            event_id: event.event_id,
                            status: DeliveryStatus::Failed,
                            status_code: None,
                            error: Some(e),
                            attempts: current_attempt + 1,
                            next_retry_at: None,
                        };
                    }
                }
            }
        }
    }

    /// Deliver a single event
    async fn deliver(&self, event: &Event) -> Result<u16, String> {
        use ring::hmac::{HMAC_SHA256, Key};

        // Serialize event to JSON
        let payload =
            serde_json::to_vec(event).map_err(|e| format!("failed to serialize event: {}", e))?;

        // Generate HMAC signature
        let signing_key = Key::new(HMAC_SHA256, &self.config.secret);
        let signature = ring::hmac::sign(&signing_key, &payload);
        let signature_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signature.as_ref(),
        );

        // Send HTTP POST request
        let response = self
            .http_client
            .post(&self.config.url)
            .header("Content-Type", &self.config.content_type)
            .header("X-Webhook-Signature", &signature_b64)
            .header("X-Webhook-Event-ID", event.event_id.to_string())
            .header("X-Webhook-Timestamp", event.timestamp.to_rfc3339())
            .body(payload)
            .send()
            .await
            .map_err(|e| format!("failed to send webhook: {}", e))?;

        let status = response.status();

        if status.is_success() {
            Ok(status.as_u16())
        } else {
            Err(format!("webhook returned status {}", status.as_u16()))
        }
    }
}

/// Webhook manager for handling multiple webhook subscriptions
#[derive(Debug, Clone)]
pub struct WebhookManager {
    clients: Vec<WebhookClient>,
}

impl WebhookManager {
    /// Create a new webhook manager
    pub fn new() -> Self {
        Self {
            clients: Vec::new(),
        }
    }

    /// Register a webhook
    pub fn register(&mut self, config: WebhookConfig) {
        self.clients.push(WebhookClient::new(config));
    }

    /// Send an event to all matching webhooks concurrently
    pub async fn broadcast(&self, event: &Event) -> Vec<WebhookDelivery> {
        let mut handles = Vec::new();

        for client in &self.clients {
            if client.should_send(event) {
                let client = client.clone();
                let event = event.clone();
                handles.push(tokio::spawn(async move { client.send_event(&event).await }));
            }
        }

        let mut deliveries = Vec::new();
        for handle in handles {
            if let Ok(delivery) = handle.await {
                deliveries.push(delivery);
            }
        }

        deliveries
    }

    /// Get the number of registered webhooks
    pub fn len(&self) -> usize {
        self.clients.len()
    }

    /// Check if there are no registered webhooks
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }
}

impl Default for WebhookManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Async event sender trait for integration
#[async_trait]
pub trait EventSender: Send + Sync {
    /// Send an event asynchronously
    async fn send(&self, event: &Event) -> Result<WebhookDelivery, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_filter_all() {
        let filter = EventFilter::all();
        let event = Event::new(
            crate::event::EventType::KeyCreated,
            "user1",
            "user",
            "create_key",
            "key",
            Some("key-123".to_string()),
            "success",
        );

        assert!(filter.matches(&event));
    }

    #[test]
    fn test_event_filter_include_types() {
        let filter = EventFilter::event_types(["KeyCreated", "KeyDeleted"]);
        let event_created = Event::new(
            crate::event::EventType::KeyCreated,
            "user1",
            "user",
            "create_key",
            "key",
            Some("key-123".to_string()),
            "success",
        );
        let event_rotated = Event::new(
            crate::event::EventType::KeyRotated,
            "user1",
            "user",
            "rotate_key",
            "key",
            Some("key-123".to_string()),
            "success",
        );

        assert!(filter.matches(&event_created));
        assert!(!filter.matches(&event_rotated));
    }

    #[test]
    fn test_event_filter_exclude_types() {
        let mut filter = EventFilter::default();
        filter.exclude_types.insert("KeyDeleted".to_string());

        let event_created = Event::new(
            crate::event::EventType::KeyCreated,
            "user1",
            "user",
            "create_key",
            "key",
            Some("key-123".to_string()),
            "success",
        );
        let event_deleted = Event::new(
            crate::event::EventType::KeyDeleted,
            "user1",
            "user",
            "delete_key",
            "key",
            Some("key-123".to_string()),
            "success",
        );

        assert!(filter.matches(&event_created));
        assert!(!filter.matches(&event_deleted));
    }

    #[test]
    fn test_webhook_manager() {
        let mut manager = WebhookManager::new();
        manager.register(WebhookConfig {
            url: "http://example.com/webhook".to_string(),
            secret: b"secret".to_vec(),
            ..Default::default()
        });

        assert_eq!(manager.len(), 1);
        assert!(!manager.is_empty());
    }

    /// Test WebhookManager empty state
    #[test]
    fn test_webhook_manager_empty() {
        let manager = WebhookManager::new();
        assert_eq!(manager.len(), 0);
        assert!(manager.is_empty());
    }

    /// Test WebhookManager with multiple registrations
    #[test]
    fn test_webhook_manager_multiple() {
        let mut manager = WebhookManager::new();
        for i in 0..3 {
            manager.register(WebhookConfig {
                url: format!("http://example{}.com/hook", i),
                secret: b"secret".to_vec(),
                ..Default::default()
            });
        }
        assert_eq!(manager.len(), 3);
    }

    /// Test WebhookClient::with_url
    #[test]
    fn test_webhook_client_with_url() {
        let client = WebhookClient::with_url("http://localhost:9999/hook", b"secret").unwrap();
        assert!(client.should_send(&Event::new(
            crate::event::EventType::KeyCreated,
            "user1",
            "user",
            "create_key",
            "key",
            None,
            "success",
        )));
    }

    /// Test EventFilter default (no include/exclude → matches all)
    #[test]
    fn test_event_filter_default_matches_all() {
        let filter = EventFilter::default();
        let event = Event::new(
            crate::event::EventType::KeyRotated,
            "user1",
            "user",
            "rotate_key",
            "key",
            None,
            "success",
        );
        assert!(filter.matches(&event));
    }

    /// Test DeliveryStatus variants
    #[test]
    fn test_delivery_status_variants() {
        let delivered = DeliveryStatus::Delivered;
        let failed = DeliveryStatus::Failed;
        let pending = DeliveryStatus::Pending;
        let retrying = DeliveryStatus::Retrying;

        // Just verify they exist and can be matched
        match delivered {
            DeliveryStatus::Delivered => {}
            _ => panic!("Expected Delivered"),
        }
        match failed {
            DeliveryStatus::Failed => {}
            _ => panic!("Expected Failed"),
        }
        match pending {
            DeliveryStatus::Pending => {}
            _ => panic!("Expected Pending"),
        }
        match retrying {
            DeliveryStatus::Retrying => {}
            _ => panic!("Expected Retrying"),
        }
    }

    // --- Additional tests ---

    /// Test DeliveryStatus serde
    #[test]
    fn test_delivery_status_serde() {
        let json = serde_json::to_string(&DeliveryStatus::Delivered).unwrap();
        assert_eq!(json, "\"delivered\"");
        let json = serde_json::to_string(&DeliveryStatus::Failed).unwrap();
        assert_eq!(json, "\"failed\"");
        let json = serde_json::to_string(&DeliveryStatus::Pending).unwrap();
        assert_eq!(json, "\"pending\"");
        let json = serde_json::to_string(&DeliveryStatus::Retrying).unwrap();
        assert_eq!(json, "\"retrying\"");

        let status: DeliveryStatus = serde_json::from_str("\"delivered\"").unwrap();
        assert_eq!(status, DeliveryStatus::Delivered);
    }

    /// Test EventFilter with actor_ids
    #[test]
    fn test_event_filter_actor_ids() {
        let mut filter = EventFilter::default();
        filter.actor_ids.insert("user1".to_string());

        let event_user1 = Event::new(
            crate::event::EventType::KeyCreated,
            "user1",
            "user",
            "create_key",
            "key",
            None,
            "success",
        );
        let event_user2 = Event::new(
            crate::event::EventType::KeyCreated,
            "user2",
            "user",
            "create_key",
            "key",
            None,
            "success",
        );

        assert!(filter.matches(&event_user1));
        assert!(!filter.matches(&event_user2));
    }

    /// Test EventFilter with resource_ids
    #[test]
    fn test_event_filter_resource_ids() {
        let mut filter = EventFilter::default();
        filter.resource_ids.insert("key-123".to_string());

        let event_match = Event::new(
            crate::event::EventType::KeyCreated,
            "user1",
            "user",
            "create_key",
            "key",
            Some("key-123".to_string()),
            "success",
        );
        let event_no_match = Event::new(
            crate::event::EventType::KeyCreated,
            "user1",
            "user",
            "create_key",
            "key",
            Some("key-456".to_string()),
            "success",
        );
        let event_none_resource = Event::new(
            crate::event::EventType::KeyCreated,
            "user1",
            "user",
            "create_key",
            "key",
            None,
            "success",
        );

        assert!(filter.matches(&event_match));
        assert!(!filter.matches(&event_no_match));
        assert!(!filter.matches(&event_none_resource));
    }

    /// Test EventFilter combined include + exclude
    #[test]
    fn test_event_filter_include_and_exclude() {
        let mut filter = EventFilter::event_types(["KeyCreated", "KeyRotated"]);
        filter.exclude_types.insert("KeyRotated".to_string());

        let event_created = Event::new(
            crate::event::EventType::KeyCreated,
            "user1",
            "user",
            "create_key",
            "key",
            None,
            "success",
        );
        let event_rotated = Event::new(
            crate::event::EventType::KeyRotated,
            "user1",
            "user",
            "rotate_key",
            "key",
            None,
            "success",
        );
        let event_deleted = Event::new(
            crate::event::EventType::KeyDeleted,
            "user1",
            "user",
            "delete_key",
            "key",
            None,
            "success",
        );

        assert!(filter.matches(&event_created));
        assert!(!filter.matches(&event_rotated)); // excluded
        assert!(!filter.matches(&event_deleted)); // not included
    }

    /// Test WebhookConfig default
    #[test]
    fn test_webhook_config_default() {
        let config = WebhookConfig::default();
        assert_eq!(config.url, "");
        assert!(config.secret.is_empty());
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay_ms, 1000);
        assert_eq!(config.content_type, "application/json");
    }

    /// Test WebhookManager default
    #[test]
    fn test_webhook_manager_default() {
        let manager = WebhookManager::default();
        assert!(manager.is_empty());
        assert_eq!(manager.len(), 0);
    }

    /// Test WebhookClient::new with custom config
    #[test]
    fn test_webhook_client_new_custom_config() {
        let config = WebhookConfig {
            url: "http://example.com/hook".to_string(),
            secret: b"my-secret".to_vec(),
            timeout_secs: 10,
            max_retries: 5,
            retry_delay_ms: 500,
            ..Default::default()
        };
        let client = WebhookClient::new(config);
        // should_send with all-matching filter
        let event = Event::new(
            crate::event::EventType::KeyCreated,
            "user1",
            "user",
            "create_key",
            "key",
            None,
            "success",
        );
        assert!(client.should_send(&event));
    }

    /// Test WebhookDelivery fields
    #[test]
    fn test_webhook_delivery_fields() {
        let delivery = WebhookDelivery {
            id: uuid::Uuid::new_v4(),
            event_id: uuid::Uuid::new_v4(),
            status: DeliveryStatus::Pending,
            status_code: None,
            error: None,
            attempts: 0,
            next_retry_at: Some(chrono::Utc::now()),
        };
        assert_eq!(delivery.status, DeliveryStatus::Pending);
        assert_eq!(delivery.attempts, 0);
        assert!(delivery.status_code.is_none());
        assert!(delivery.error.is_none());
        assert!(delivery.next_retry_at.is_some());
    }
}
