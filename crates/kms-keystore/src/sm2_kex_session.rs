//! Redis-backed SM2-KEX session manager for multi-instance deployment
//!
//! This module provides session state sharing across multiple KMS instances
//! using Redis as a distributed session store.

use kms_core::error::Error;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Session state enum (matches gm-crypto::sm2_kex::KexState)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Init,
    WaitForResponse,
    WaitForConfirmation,
    Completed,
    Failed,
}

/// SM2-KEX session data stored in Redis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sm2KexSessionData {
    /// Session ID
    pub session_id: Uuid,
    /// Key ID for the long-term key
    pub key_id: Uuid,
    /// User ID bytes
    pub user_id: Vec<u8>,
    /// Whether this is the initiator (true) or responder (false)
    pub is_initiator: bool,
    /// Current session state
    pub state: SessionState,
    /// Nonce counter for message sequence
    pub nonce: u64,
    /// Session creation timestamp (epoch millis)
    pub created_at_ms: u64,
    /// Last activity timestamp (epoch millis)
    pub last_activity_ms: u64,
    /// Message hash history for replay protection (message hash, timestamp)
    pub message_history: Vec<(Vec<u8>, u64)>,
    /// Shared secret result (only set when completed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_secret: Option<Vec<u8>>,
    /// Confirmation value S (only set when completed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<Vec<u8>>,
}

/// Redis key prefix for SM2-KEX sessions
const SM2_KEX_SESSION_PREFIX: &str = "kms:sm2kex:session:";

/// Session TTL (5 minutes - longer than the 60 second protocol timeout)
const SESSION_TTL_SECS: u64 = 300;

/// Message history TTL (60 seconds per GM/T 002-2012)
const MESSAGE_HISTORY_TTL_SECS: u64 = 60;

/// Maximum message history size per session
const MAX_MESSAGE_HISTORY_SIZE: usize = 10;

/// Redis-backed SM2-KEX session manager
#[derive(Clone)]
pub struct Sm2KexSessionManager {
    redis: redis::aio::ConnectionManager,
}

impl Sm2KexSessionManager {
    /// Create a new session manager with a Redis connection
    pub fn new(redis: redis::aio::ConnectionManager) -> Self {
        Self { redis }
    }

    /// Generate a cache key for a session
    fn cache_key(session_id: &Uuid) -> String {
        format!("{}{}", SM2_KEX_SESSION_PREFIX, session_id)
    }

    /// Create a new session entry
    pub async fn create_session(
        &self,
        session_id: Uuid,
        key_id: Uuid,
        user_id: Vec<u8>,
        is_initiator: bool,
    ) -> Result<Sm2KexSessionData, Error> {
        let now = SystemTime::now();
        let now_ms = now.duration_since(UNIX_EPOCH).expect("system clock before UNIX epoch").as_millis() as u64;

        let session = Sm2KexSessionData {
            session_id,
            key_id,
            user_id,
            is_initiator,
            state: SessionState::Init,
            nonce: 0,
            created_at_ms: now_ms,
            last_activity_ms: now_ms,
            message_history: Vec::new(),
            shared_secret: None,
            confirmation: None,
        };

        let mut conn = self.redis.clone();
        let key = Self::cache_key(&session_id);
        let json = serde_json::to_string(&session).map_err(|e| Error::Internal(e.to_string()))?;

        conn.set_ex::<_, _, ()>(&key, &json, SESSION_TTL_SECS)
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(session)
    }

    /// Get a session by ID
    pub async fn get_session(&self, session_id: &Uuid) -> Result<Option<Sm2KexSessionData>, Error> {
        let mut conn = self.redis.clone();
        let key = Self::cache_key(session_id);

        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;

        match json {
            Some(j) => {
                let session: Sm2KexSessionData =
                    serde_json::from_str(&j).map_err(|e| Error::Internal(e.to_string()))?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    /// Update session state
    pub async fn update_state(
        &self,
        session_id: &Uuid,
        new_state: SessionState,
    ) -> Result<(), Error> {
        let mut session = self
            .get_session(session_id)
            .await?
            .ok_or_else(|| Error::KeyNotFound(format!("session {} not found", session_id)))?;

        session.state = new_state;
        session.last_activity_ms = Self::current_timestamp();

        self.save_session(&session).await
    }

    /// Add a message hash to the history and check for replay
    ///
    /// Returns Ok(true) if the message is a replay, Ok(false) if it's new
    pub async fn check_and_add_message(
        &self,
        session_id: &Uuid,
        msg_hash: Vec<u8>,
    ) -> Result<bool, Error> {
        let mut session = self
            .get_session(session_id)
            .await?
            .ok_or_else(|| Error::KeyNotFound(format!("session {} not found", session_id)))?;

        let now_ms = Self::current_timestamp();

        // Clean up expired entries from message history
        let cutoff = now_ms - (MESSAGE_HISTORY_TTL_SECS * 1000);
        session.message_history.retain(|(_, ts)| *ts > cutoff);

        // Check for replay
        let is_replay = session
            .message_history
            .iter()
            .any(|(hash, _)| hash == &msg_hash);

        if is_replay {
            return Ok(true);
        }

        // Add to history
        session.message_history.push((msg_hash, now_ms));
        session.last_activity_ms = now_ms;

        // Limit history size
        if session.message_history.len() > MAX_MESSAGE_HISTORY_SIZE {
            session.message_history.remove(0);
        }

        self.save_session(&session).await?;
        Ok(false)
    }

    /// Mark session as completed with shared secret
    pub async fn complete_session(
        &self,
        session_id: &Uuid,
        shared_secret: Vec<u8>,
        confirmation: Option<Vec<u8>>,
    ) -> Result<(), Error> {
        let mut session = self
            .get_session(session_id)
            .await?
            .ok_or_else(|| Error::KeyNotFound(format!("session {} not found", session_id)))?;

        session.state = SessionState::Completed;
        session.shared_secret = Some(shared_secret);
        session.confirmation = confirmation;
        session.last_activity_ms = Self::current_timestamp();

        self.save_session(&session).await
    }

    /// Remove a session
    pub async fn remove_session(&self, session_id: &Uuid) -> Result<(), Error> {
        let mut conn = self.redis.clone();
        let key = Self::cache_key(session_id);

        conn.del::<_, ()>(&key)
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(())
    }

    /// Check if session is expired (created more than 60 seconds ago)
    #[allow(dead_code)]
    pub async fn is_session_expired(&self, session_id: &Uuid) -> Result<bool, Error> {
        let session = self
            .get_session(session_id)
            .await?
            .ok_or_else(|| Error::KeyNotFound(format!("session {} not found", session_id)))?;

        let now_ms = Self::current_timestamp();
        let age_secs = (now_ms - session.created_at_ms) / 1000;

        Ok(age_secs > SESSION_TTL_SECS)
    }

    /// Save session back to Redis (internal method)
    async fn save_session(&self, session: &Sm2KexSessionData) -> Result<(), Error> {
        let mut conn = self.redis.clone();
        let key = Self::cache_key(&session.session_id);
        let json = serde_json::to_string(session).map_err(|e| Error::Internal(e.to_string()))?;

        // Use remaining TTL based on creation time
        let now_ms = Self::current_timestamp();
        let age_ms = now_ms - session.created_at_ms;
        let remaining_ttl = SESSION_TTL_SECS.saturating_sub(age_ms / 1000);

        if remaining_ttl > 0 {
            conn.set_ex::<_, _, ()>(&key, &json, remaining_ttl)
                .await
                .map_err(|e| Error::Internal(e.to_string()))?;
        } else {
            // Session has expired, remove it
            conn.del::<_, ()>(&key)
                .await
                .map_err(|e| Error::Internal(e.to_string()))?;
        }

        Ok(())
    }

    /// Get current timestamp in milliseconds since epoch
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH).expect("system clock before UNIX epoch")
            .as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_state_serialization() {
        let state = SessionState::WaitForResponse;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"wait_for_response\"");

        let deserialized: SessionState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, state);
    }

    #[test]
    fn test_session_data_serialization() {
        let session = Sm2KexSessionData {
            session_id: Uuid::new_v4(),
            key_id: Uuid::new_v4(),
            user_id: b"user123".to_vec(),
            is_initiator: true,
            state: SessionState::Init,
            nonce: 0,
            created_at_ms: 1000000,
            last_activity_ms: 1000000,
            message_history: Vec::new(),
            shared_secret: None,
            confirmation: None,
        };

        let json = serde_json::to_string(&session).unwrap();
        let deserialized: Sm2KexSessionData = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.session_id, session.session_id);
        assert_eq!(deserialized.is_initiator, session.is_initiator);
    }

    #[test]
    fn test_session_data_with_shared_secret_serialization() {
        let session = Sm2KexSessionData {
            session_id: Uuid::new_v4(),
            key_id: Uuid::new_v4(),
            user_id: b"user456".to_vec(),
            is_initiator: false,
            state: SessionState::Completed,
            nonce: 3,
            created_at_ms: 2000000,
            last_activity_ms: 2000005,
            message_history: vec![(vec![0xAB; 32], 2000001)],
            shared_secret: Some(vec![0x42; 32]),
            confirmation: Some(vec![0x99; 16]),
        };

        let json = serde_json::to_string(&session).unwrap();
        let deserialized: Sm2KexSessionData = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.state, SessionState::Completed);
        assert_eq!(deserialized.nonce, 3);
        assert_eq!(deserialized.shared_secret, Some(vec![0x42; 32]));
        assert_eq!(deserialized.confirmation, Some(vec![0x99; 16]));
        assert_eq!(deserialized.message_history.len(), 1);
    }

    #[test]
    fn test_all_session_state_variants_serialize() {
        for state in [
            SessionState::Init,
            SessionState::WaitForResponse,
            SessionState::WaitForConfirmation,
            SessionState::Completed,
            SessionState::Failed,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let back: SessionState = serde_json::from_str(&json).unwrap();
            assert_eq!(back, state);
        }
    }

    #[test]
    fn test_cache_key_format() {
        let session_id = Uuid::new_v4();
        let key = Sm2KexSessionManager::cache_key(&session_id);
        assert!(key.starts_with("kms:sm2kex:session:"));
        assert!(key.contains(&session_id.to_string()));
    }

    // ========================================================================
    // Redis integration tests (require Docker Redis on localhost:6379)
    // ========================================================================

    /// Helper to create a Redis connection manager for testing.
    /// Returns None if Redis is not available (tests will be skipped).
    async fn try_create_redis_manager() -> Option<redis::aio::ConnectionManager> {
        let url = std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://localhost:6379".to_string());

        let client = redis::Client::open(url.as_str()).ok()?;
        let manager = redis::aio::ConnectionManager::new(client).await.ok()?;
        Some(manager)
    }

    /// Helper to flush test keys before each test
    async fn flush_test_keys(manager: &redis::aio::ConnectionManager) {
        // Only flush if explicitly requested (tests use unique session IDs anyway)
        let _ = manager;
    }

    #[tokio::test]
    async fn test_redis_create_and_get_session() {
        let manager = match try_create_redis_manager().await {
            Some(m) => m,
            None => {
                eprintln!("Skipping Redis test: no Redis available");
                return;
            }
        };
        flush_test_keys(&manager).await;

        let session_mgr = Sm2KexSessionManager::new(manager);
        let session_id = Uuid::new_v4();
        let key_id = Uuid::new_v4();

        // Create session
        let session = session_mgr
            .create_session(session_id, key_id, b"user1".to_vec(), true)
            .await
            .unwrap();
        assert_eq!(session.session_id, session_id);
        assert_eq!(session.key_id, key_id);
        assert_eq!(session.state, SessionState::Init);
        assert!(session.is_initiator);
        assert_eq!(session.nonce, 0);

        // Get session back
        let retrieved = session_mgr
            .get_session(&session_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.session_id, session_id);
        assert_eq!(retrieved.key_id, key_id);
        assert_eq!(retrieved.user_id, b"user1".to_vec());
    }

    #[tokio::test]
    async fn test_redis_get_nonexistent_session() {
        let manager = match try_create_redis_manager().await {
            Some(m) => m,
            None => return,
        };
        flush_test_keys(&manager).await;

        let session_mgr = Sm2KexSessionManager::new(manager);
        let result = session_mgr.get_session(&Uuid::new_v4()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_redis_update_state() {
        let manager = match try_create_redis_manager().await {
            Some(m) => m,
            None => return,
        };
        flush_test_keys(&manager).await;

        let session_mgr = Sm2KexSessionManager::new(manager);
        let session_id = Uuid::new_v4();
        let key_id = Uuid::new_v4();

        session_mgr
            .create_session(session_id, key_id, b"user2".to_vec(), false)
            .await
            .unwrap();

        // Update state
        session_mgr
            .update_state(&session_id, SessionState::WaitForResponse)
            .await
            .unwrap();

        // Verify
        let session = session_mgr.get_session(&session_id).await.unwrap().unwrap();
        assert_eq!(session.state, SessionState::WaitForResponse);
    }

    #[tokio::test]
    async fn test_redis_update_state_nonexistent() {
        let manager = match try_create_redis_manager().await {
            Some(m) => m,
            None => return,
        };
        flush_test_keys(&manager).await;

        let session_mgr = Sm2KexSessionManager::new(manager);
        let result = session_mgr
            .update_state(&Uuid::new_v4(), SessionState::Completed)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redis_check_and_add_message_no_replay() {
        let manager = match try_create_redis_manager().await {
            Some(m) => m,
            None => return,
        };
        flush_test_keys(&manager).await;

        let session_mgr = Sm2KexSessionManager::new(manager);
        let session_id = Uuid::new_v4();
        let key_id = Uuid::new_v4();

        session_mgr
            .create_session(session_id, key_id, b"user3".to_vec(), true)
            .await
            .unwrap();

        // First message — should not be a replay
        let is_replay = session_mgr
            .check_and_add_message(&session_id, vec![0xAA; 32])
            .await
            .unwrap();
        assert!(!is_replay);

        // Different message — should not be a replay
        let is_replay = session_mgr
            .check_and_add_message(&session_id, vec![0xBB; 32])
            .await
            .unwrap();
        assert!(!is_replay);
    }

    #[tokio::test]
    async fn test_redis_check_and_add_message_replay_detected() {
        let manager = match try_create_redis_manager().await {
            Some(m) => m,
            None => return,
        };
        flush_test_keys(&manager).await;

        let session_mgr = Sm2KexSessionManager::new(manager);
        let session_id = Uuid::new_v4();
        let key_id = Uuid::new_v4();

        session_mgr
            .create_session(session_id, key_id, b"user4".to_vec(), true)
            .await
            .unwrap();

        let msg_hash = vec![0xCC; 32];

        // First time — not a replay
        let is_replay = session_mgr
            .check_and_add_message(&session_id, msg_hash.clone())
            .await
            .unwrap();
        assert!(!is_replay);

        // Second time — IS a replay
        let is_replay = session_mgr
            .check_and_add_message(&session_id, msg_hash)
            .await
            .unwrap();
        assert!(is_replay);
    }

    #[tokio::test]
    async fn test_redis_complete_session() {
        let manager = match try_create_redis_manager().await {
            Some(m) => m,
            None => return,
        };
        flush_test_keys(&manager).await;

        let session_mgr = Sm2KexSessionManager::new(manager);
        let session_id = Uuid::new_v4();
        let key_id = Uuid::new_v4();

        session_mgr
            .create_session(session_id, key_id, b"user5".to_vec(), true)
            .await
            .unwrap();

        // Complete the session
        session_mgr
            .complete_session(
                &session_id,
                vec![0x42; 32],
                Some(vec![0x99; 16]),
            )
            .await
            .unwrap();

        // Verify
        let session = session_mgr.get_session(&session_id).await.unwrap().unwrap();
        assert_eq!(session.state, SessionState::Completed);
        assert_eq!(session.shared_secret, Some(vec![0x42; 32]));
        assert_eq!(session.confirmation, Some(vec![0x99; 16]));
    }

    #[tokio::test]
    async fn test_redis_remove_session() {
        let manager = match try_create_redis_manager().await {
            Some(m) => m,
            None => return,
        };
        flush_test_keys(&manager).await;

        let session_mgr = Sm2KexSessionManager::new(manager);
        let session_id = Uuid::new_v4();
        let key_id = Uuid::new_v4();

        session_mgr
            .create_session(session_id, key_id, b"user6".to_vec(), false)
            .await
            .unwrap();

        // Remove
        session_mgr.remove_session(&session_id).await.unwrap();

        // Verify it's gone
        let result = session_mgr.get_session(&session_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_redis_session_ttl_expiry() {
        let manager = match try_create_redis_manager().await {
            Some(m) => m,
            None => return,
        };
        flush_test_keys(&manager).await;

        let session_mgr = Sm2KexSessionManager::new(manager);
        let session_id = Uuid::new_v4();
        let key_id = Uuid::new_v4();

        session_mgr
            .create_session(session_id, key_id, b"user7".to_vec(), true)
            .await
            .unwrap();

        // Set a very short TTL directly via Redis to test expiry
        let mut conn = session_mgr.redis.clone();
        let key = Sm2KexSessionManager::cache_key(&session_id);
        let _: () = conn
            .expire(&key, 1)
            .await
            .unwrap();

        // Wait for expiry
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let result = session_mgr.get_session(&session_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_redis_message_history_size_limit() {
        let manager = match try_create_redis_manager().await {
            Some(m) => m,
            None => return,
        };
        flush_test_keys(&manager).await;

        let session_mgr = Sm2KexSessionManager::new(manager);
        let session_id = Uuid::new_v4();
        let key_id = Uuid::new_v4();

        session_mgr
            .create_session(session_id, key_id, b"user8".to_vec(), true)
            .await
            .unwrap();

        // Add more messages than MAX_MESSAGE_HISTORY_SIZE (10)
        for i in 0..15u8 {
            session_mgr
                .check_and_add_message(&session_id, vec![i; 32])
                .await
                .unwrap();
        }

        // Verify session still works and history is bounded
        let session = session_mgr.get_session(&session_id).await.unwrap().unwrap();
        assert!(session.message_history.len() <= 10);
    }

    #[tokio::test]
    async fn test_redis_multiple_sessions_isolation() {
        let manager = match try_create_redis_manager().await {
            Some(m) => m,
            None => return,
        };
        flush_test_keys(&manager).await;

        let session_mgr = Sm2KexSessionManager::new(manager);

        // Create two sessions
        let sid1 = Uuid::new_v4();
        let sid2 = Uuid::new_v4();
        let kid = Uuid::new_v4();

        session_mgr
            .create_session(sid1, kid, b"userA".to_vec(), true)
            .await
            .unwrap();
        session_mgr
            .create_session(sid2, kid, b"userB".to_vec(), false)
            .await
            .unwrap();

        // Update one session
        session_mgr
            .update_state(&sid1, SessionState::WaitForResponse)
            .await
            .unwrap();

        // Verify the other is unaffected
        let s1 = session_mgr.get_session(&sid1).await.unwrap().unwrap();
        let s2 = session_mgr.get_session(&sid2).await.unwrap().unwrap();
        assert_eq!(s1.state, SessionState::WaitForResponse);
        assert_eq!(s2.state, SessionState::Init);
        assert_ne!(s1.user_id, s2.user_id);
    }
}
