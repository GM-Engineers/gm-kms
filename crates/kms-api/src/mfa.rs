//! MFA API Layer - Database-backed persistence with in-memory fallback
//!
//! MFA state (TOTP configs, backup codes, lockout state) is persisted to
//! PostgreSQL so that it survives process restarts and is consistent across
//! multiple KMS instances.
//!
//! When no PgPool is provided (e.g. in tests), falls back to in-memory
//! HashMap storage (the pre-existing behavior). This ensures backward
//! compatibility but warns at creation that lockouts will not survive restarts.

use kms_core::sanitize::sanitize_for_log;
use kms_mfa::MfaStatus;
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Maximum failed TOTP verification attempts before lockout
pub const MAX_TOTP_ATTEMPTS: u32 = 5;
/// Lockout duration in seconds (5 minutes)
pub const TOTP_LOCKOUT_SECS: u64 = 300;
/// Maximum backup code uses before requiring MFA reset (per TOTP lockout cycle)
pub const MAX_BACKUP_CODE_USES: u32 = 3;

/// MFA failure reason for metrics subdivision (Phase 2 #39)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaFailureReason {
    TimeSkew,
    WrongCode,
    BackupCodeUsed,
    LockedOut,
}

// ------------------------------------------------------------------
// In-memory fallback state (used when no PgPool is available)
// ------------------------------------------------------------------

use parking_lot::Mutex;

#[derive(Debug, Default)]
struct InMemoryMfaState {
    totp_configs: std::collections::HashMap<String, kms_mfa::TotpConfig>,
    backup_codes: std::collections::HashMap<String, Vec<String>>,
    failed_attempts: std::collections::HashMap<String, u32>,
    lockouts: std::collections::HashMap<String, u64>,
    backup_code_usage: std::collections::HashMap<String, u32>,
}

/// MFA Manager for handling TOTP operations
///
/// When backed by PostgreSQL, all state is persisted so that lockouts,
/// TOTP configs, and backup codes survive process restarts and are visible
/// across multiple instances.
///
/// When no pool is available (tests, dev mode), falls back to in-memory
/// HashMap storage.
///
/// TOTP secrets are encrypted at rest using AES-256-GCM with a KEK derived
/// from the `KMS_KEK` environment variable (same KEK used by the keystore).
/// When `KMS_KEK` is not set, secrets are stored in plaintext with a warning.
#[derive(Debug)]
pub struct MfaManager {
    pool: Option<sqlx::PgPool>,
    memory: Mutex<InMemoryMfaState>,
    /// Key Encryption Key for encrypting TOTP secrets at rest
    kek: Option<Zeroizing<[u8; 32]>>,
    /// Metrics for observability (Phase 2 #39)
    metrics: Option<crate::KmsMetrics>,
}

impl MfaManager {
    /// Create a new MFA manager with PostgreSQL persistence
    pub fn new(pool: sqlx::PgPool) -> Self {
        let kek = Self::load_kek();
        Self {
            pool: Some(pool),
            memory: Mutex::new(InMemoryMfaState::default()),
            kek,
            metrics: None,
        }
    }

    /// Create an in-memory-only MFA manager (for tests / dev without DB)
    ///
    /// **WARNING**: Lockouts will NOT survive process restarts.
    pub fn new_in_memory() -> Self {
        tracing::warn!(
            "MfaManager created without database — lockouts will NOT survive process restarts"
        );
        let kek = Self::load_kek();
        Self {
            pool: None,
            memory: Mutex::new(InMemoryMfaState::default()),
            kek,
            metrics: None,
        }
    }

    /// Create an in-memory MFA manager WITHOUT KEK (for testing plaintext mode)
    #[cfg(test)]
    fn new_in_memory_no_kek() -> Self {
        Self {
            pool: None,
            memory: Mutex::new(InMemoryMfaState::default()),
            kek: None,
            metrics: None,
        }
    }

    /// Create an in-memory MFA manager WITH a fixed test KEK (for testing encryption)
    #[cfg(test)]
    fn new_in_memory_with_kek() -> Self {
        // Use a deterministic test KEK (NOT for production)
        let kek_bytes: [u8; 32] = [
            0xa3, 0xf7, 0xb2, 0xc1, 0xd8, 0xe9, 0xf0, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9, 0xa0,
            0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0xa6, 0xb7, 0xc8, 0xd9, 0xe0, 0xf1, 0xa2, 0xb3, 0xc4,
            0xd5, 0xe6, 0xf7, 0x89,
        ];
        Self {
            pool: None,
            memory: Mutex::new(InMemoryMfaState::default()),
            kek: Some(Zeroizing::new(kek_bytes)),
            metrics: None,
        }
    }

    /// Load KEK from the KMS_KEK environment variable.
    /// Returns None if the variable is not set (secrets stored in plaintext).
    fn load_kek() -> Option<Zeroizing<[u8; 32]>> {
        match std::env::var("KMS_KEK") {
            Ok(kek_hex) => match hex::decode(&kek_hex) {
                Ok(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
                    Ok(arr) => Some(Zeroizing::new(arr)),
                    Err(_) => {
                        tracing::error!(
                            "KMS_KEK must be 32 bytes (64 hex characters), got {} bytes",
                            bytes.len()
                        );
                        None
                    }
                },
                Err(e) => {
                    tracing::error!("Invalid KMS_KEK hex: {}", e);
                    None
                }
            },
            Err(_) => {
                tracing::warn!(
                    "KMS_KEK not set — TOTP secrets will be stored in plaintext. Set KMS_KEK for production."
                );
                None
            }
        }
    }

    /// Compute SHA-256 hash of a backup code for secure storage.
    ///
    /// Normalized: trims whitespace, uppercases, then SHA-256 → hex.
    /// This matches the hashing in `kms-mfa::BackupCodeGenerator::hash_code`.
    fn hash_backup_code(code: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(code.trim().to_uppercase().as_bytes());
        hex::encode(hasher.finalize().as_slice())
    }

    /// Encrypt a TOTP secret using AES-256-GCM with the KEK.
    ///
    /// Returns None if no KEK is configured — TOTP secrets MUST NOT be stored
    /// in plaintext in production. Callers must reject the operation when
    /// encryption is unavailable.
    fn encrypt_secret(&self, secret: &[u8]) -> Option<Vec<u8>> {
        let kek = self.kek.as_ref()?;

        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

        let unbound_key = match UnboundKey::new(&AES_256_GCM, kek.as_ref()) {
            Ok(k) => k,
            Err(_) => return None,
        };
        let sealing_key = LessSafeKey::new(unbound_key);

        // Generate random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        use ring::rand::SecureRandom;
        ring::rand::SystemRandom::new()
            .fill(&mut nonce_bytes)
            .expect("failed to generate nonce");
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = secret.to_vec();
        let tag = match sealing_key.seal_in_place_separate_tag(nonce, Aad::empty(), &mut in_out) {
            Ok(t) => t,
            Err(_) => return None,
        };

        // Format: nonce (12) || ciphertext || tag (16)
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&in_out);
        result.extend_from_slice(tag.as_ref());
        Some(result)
    }

    /// Decrypt a TOTP secret using AES-256-GCM with the KEK.
    /// Returns the input as-is if no KEK is available (plaintext mode).
    fn decrypt_secret(&self, encrypted: &[u8]) -> Option<Vec<u8>> {
        let kek = match self.kek {
            Some(ref k) => k,
            None => return Some(encrypted.to_vec()),
        };

        // Minimum: 12 (nonce) + 16 (tag)
        if encrypted.len() < 12 + 16 {
            // Might be plaintext from before KEK was configured
            return Some(encrypted.to_vec());
        }

        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&encrypted[..12]);

        let unbound_key = match UnboundKey::new(&AES_256_GCM, kek.as_ref()) {
            Ok(k) => k,
            Err(_) => return None,
        };
        let opening_key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let ciphertext_len = encrypted.len() - 12 - 16;
        let mut in_out = encrypted[12..12 + ciphertext_len].to_vec();
        let tag = &encrypted[12 + ciphertext_len..];

        // ring's open_in_place expects tag appended to in_out
        in_out.extend_from_slice(tag);

        match opening_key.open_in_place(nonce, Aad::empty(), &mut in_out) {
            Ok(plaintext) => Some(plaintext.to_vec()),
            Err(_) => {
                // Decryption failed — might be plaintext stored before KEK was configured.
                // SECURITY: This fallback exists solely for migration from plaintext→encrypted.
                // It will be removed in a future version. Use `migrate_plaintext_secrets()`
                // to re-encrypt all plaintext secrets after configuring KMS_KEK.
                tracing::warn!(
                    "SECURITY: Failed to decrypt TOTP secret — falling back to plaintext. \
                     Run migration tool after setting KMS_KEK to encrypt all secrets."
                );
                Some(encrypted.to_vec())
            }
        }
    }

    /// Run database migrations (create MFA tables if they don't exist)
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        if let Some(ref pool) = self.pool {
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS mfa_configs (
                    user_id TEXT PRIMARY KEY,
                    totp_secret BYTEA NOT NULL,
                    totp_algorithm TEXT NOT NULL DEFAULT 'Sha1',
                    totp_digits INTEGER NOT NULL DEFAULT 6,
                    totp_period_secs INTEGER NOT NULL DEFAULT 30,
                    totp_window INTEGER NOT NULL DEFAULT 1,
                    backup_codes TEXT NOT NULL DEFAULT '[]',
                    enabled BOOLEAN NOT NULL DEFAULT true,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                "#,
            )
            .execute(pool)
            .await?;

            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS mfa_lockout_state (
                    user_id TEXT PRIMARY KEY,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until TIMESTAMPTZ,
                    backup_code_usage INTEGER NOT NULL DEFAULT 0,
                    last_attempt_at TIMESTAMPTZ,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                "#,
            )
            .execute(pool)
            .await?;
        }
        Ok(())
    }

    /// Attach metrics for observability
    pub fn with_metrics(mut self, metrics: crate::KmsMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Check if TOTP secrets are encrypted at rest
    pub fn is_secret_encrypted(&self) -> bool {
        self.kek.is_some()
    }

    /// Record an MFA verification attempt (call before verification)
    pub fn record_attempt(&self) {
        if let Some(ref m) = self.metrics {
            m.record_mfa_attempt();
        }
    }

    // ------------------------------------------------------------------
    // TOTP config persistence
    // ------------------------------------------------------------------

    /// Store a TOTP configuration for a user (upsert).
    /// The TOTP secret is encrypted at rest. Fails if no KEK is configured.
    pub async fn store_totp_config(
        &self,
        user_id: &str,
        config: &kms_mfa::TotpConfig,
        backup_codes: &[String],
    ) -> Result<(), String> {
        let encrypted_secret = self.encrypt_secret(&config.secret).ok_or_else(|| {
            "Cannot store TOTP secret: no KEK configured. Set KMS_KEK before enabling MFA."
                .to_string()
        })?;

        // Hash backup codes before storing (H-1 fix: prevent plaintext storage)
        let hashed_codes: Vec<String> = backup_codes
            .iter()
            .map(|c| Self::hash_backup_code(c))
            .collect();

        if let Some(ref pool) = self.pool {
            let backup_codes_json =
                serde_json::to_string(&hashed_codes).unwrap_or_else(|_| "[]".to_string());
            let algorithm_str = format!("{:?}", config.algorithm);

            let _ = sqlx::query(
                r#"
                INSERT INTO mfa_configs (user_id, totp_secret, totp_algorithm, totp_digits, totp_period_secs, totp_window, backup_codes)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (user_id) DO UPDATE SET
                    totp_secret = $2,
                    totp_algorithm = $3,
                    totp_digits = $4,
                    totp_period_secs = $5,
                    totp_window = $6,
                    backup_codes = $7,
                    updated_at = NOW()
                "#,
            )
            .bind(user_id)
            .bind(&encrypted_secret)
            .bind(&algorithm_str)
            .bind(config.digits as i32)
            .bind(config.time_step as i32)
            .bind(config.window as i32)
            .bind(&backup_codes_json)
            .execute(pool)
            .await;
        }

        // Always update in-memory cache (with hashed backup codes)
        self.memory
            .lock()
            .totp_configs
            .insert(user_id.to_string(), config.clone());
        self.memory
            .lock()
            .backup_codes
            .insert(user_id.to_string(), hashed_codes);
        Ok(())
    }

    /// Load the TOTP configuration for a user.
    /// Decrypts the TOTP secret if a KEK is available.
    pub async fn load_totp_config(&self, user_id: &str) -> Option<kms_mfa::TotpConfig> {
        if let Some(ref pool) = self.pool {
            let row: Option<(Vec<u8>, String, i32, i32, i32)> = sqlx::query_as(
                r#"
                SELECT totp_secret, totp_algorithm, totp_digits, totp_period_secs, totp_window
                FROM mfa_configs WHERE user_id = $1
                "#,
            )
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .ok()?;

            let (encrypted_secret, alg_str, digits, period, window) = row?;
            let secret = self.decrypt_secret(&encrypted_secret)?;

            let algorithm = match alg_str.as_str() {
                "Sha256" => kms_mfa::totp::TotpAlgorithm::Sha256,
                "Sha512" => kms_mfa::totp::TotpAlgorithm::Sha512,
                _ => kms_mfa::totp::TotpAlgorithm::Sha1,
            };

            return Some(kms_mfa::TotpConfig {
                secret,
                time_step: period as u64,
                digits: digits as u32,
                algorithm,
                window: window as u32,
            });
        }

        // Fallback: in-memory
        self.memory.lock().totp_configs.get(user_id).cloned()
    }

    /// Load the backup codes for a user
    pub async fn load_backup_codes(&self, user_id: &str) -> Option<Vec<String>> {
        if let Some(ref pool) = self.pool {
            let row: Option<(String,)> =
                sqlx::query_as("SELECT backup_codes FROM mfa_configs WHERE user_id = $1")
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await
                    .ok()?;

            return serde_json::from_str::<Vec<String>>(&row?.0).ok();
        }

        // Fallback: in-memory
        self.memory.lock().backup_codes.get(user_id).cloned()
    }

    /// Check if a user has MFA configured
    pub async fn has_totp_config(&self, user_id: &str) -> bool {
        if let Some(ref pool) = self.pool {
            let row: Option<(bool,)> =
                sqlx::query_as("SELECT enabled FROM mfa_configs WHERE user_id = $1")
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await
                    .ok()
                    .flatten();
            return row.is_some();
        }

        self.memory.lock().totp_configs.contains_key(user_id)
    }

    /// Count remaining backup codes for a user
    pub async fn backup_codes_remaining(&self, user_id: &str) -> usize {
        self.load_backup_codes(user_id)
            .await
            .map(|c| c.len())
            .unwrap_or(0)
    }

    /// Remove a used backup code (persist the updated list)
    pub async fn consume_backup_code(&self, user_id: &str, code: &str) -> bool {
        let mut codes = match self.load_backup_codes(user_id).await {
            Some(c) => c,
            None => return false,
        };

        let normalized = Self::hash_backup_code(code);
        if let Some(pos) = codes.iter().position(|c| c == &normalized) {
            codes.remove(pos);

            if let Some(ref pool) = self.pool {
                let codes_json = serde_json::to_string(&codes).unwrap_or_else(|_| "[]".to_string());
                let _ = sqlx::query(
                    "UPDATE mfa_configs SET backup_codes = $2, updated_at = NOW() WHERE user_id = $1",
                )
                .bind(user_id)
                .bind(&codes_json)
                .execute(pool)
                .await;
            }

            // Always update in-memory cache
            self.memory
                .lock()
                .backup_codes
                .insert(user_id.to_string(), codes);
            true
        } else {
            false
        }
    }

    // ------------------------------------------------------------------
    // Lockout state persistence
    // ------------------------------------------------------------------

    /// Record a failed TOTP attempt and return true if now locked out
    pub async fn record_failed_totp_attempt(&self, user_id: &str) -> bool {
        if let Some(ref m) = self.metrics {
            m.record_mfa_failure();
        }

        if let Some(ref pool) = self.pool {
            let row: (i32,) = sqlx::query_as(
                r#"
                INSERT INTO mfa_lockout_state (user_id, failed_attempts, last_attempt_at)
                VALUES ($1, 1, NOW())
                ON CONFLICT (user_id) DO UPDATE SET
                    failed_attempts = mfa_lockout_state.failed_attempts + 1,
                    last_attempt_at = NOW(),
                    updated_at = NOW()
                RETURNING failed_attempts
                "#,
            )
            .bind(user_id)
            .fetch_one(pool)
            .await
            .unwrap_or((0,));

            let attempts = row.0 as u32;

            if attempts >= MAX_TOTP_ATTEMPTS {
                let _ = sqlx::query(
                    r#"
                    UPDATE mfa_lockout_state
                    SET locked_until = NOW() + INTERVAL '300 seconds',
                        updated_at = NOW()
                    WHERE user_id = $1
                    "#,
                )
                .bind(user_id)
                .execute(pool)
                .await;

                if let Some(ref m) = self.metrics {
                    m.record_mfa_lockout();
                }
                tracing::warn!(
                    "User {} locked out due to {} failed TOTP attempts",
                    sanitize_for_log(user_id),
                    MAX_TOTP_ATTEMPTS
                );
                return true;
            }
            return false;
        }

        // Fallback: in-memory
        let mut mem = self.memory.lock();
        let attempts = mem.failed_attempts.entry(user_id.to_string()).or_insert(0);
        *attempts += 1;

        if *attempts >= MAX_TOTP_ATTEMPTS {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            mem.lockouts
                .insert(user_id.to_string(), now_secs + TOTP_LOCKOUT_SECS);

            if let Some(ref m) = self.metrics {
                m.record_mfa_lockout();
            }
            tracing::warn!(
                "User {} locked out due to {} failed TOTP attempts (in-memory — will NOT survive restart)",
                sanitize_for_log(user_id),
                MAX_TOTP_ATTEMPTS
            );
            return true;
        }
        false
    }

    /// Clear failed attempts on successful verification
    pub async fn clear_failed_attempts(&self, user_id: &str) {
        if let Some(ref pool) = self.pool {
            let _ = sqlx::query(
                r#"
                UPDATE mfa_lockout_state
                SET failed_attempts = 0, locked_until = NULL, backup_code_usage = 0, updated_at = NOW()
                WHERE user_id = $1
                "#,
            )
            .bind(user_id)
            .execute(pool)
            .await;
            return;
        }

        // Fallback: in-memory
        self.memory.lock().failed_attempts.remove(user_id);
    }

    /// Check if user is currently locked out
    pub async fn is_locked_out(&self, user_id: &str) -> bool {
        if let Some(ref pool) = self.pool {
            let row: Option<(Option<chrono::DateTime<chrono::Utc>>,)> =
                sqlx::query_as("SELECT locked_until FROM mfa_lockout_state WHERE user_id = $1")
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await
                    .ok()
                    .flatten();

            return match row {
                Some((Some(locked_until),)) => chrono::Utc::now() < locked_until,
                _ => false,
            };
        }

        // Fallback: in-memory
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Some(expiry) = self.memory.lock().lockouts.get(user_id)
            && now_secs < *expiry
        {
            return true;
        }
        false
    }

    /// Get remaining lockout seconds
    pub async fn lockout_remaining_secs(&self, user_id: &str) -> u64 {
        if let Some(ref pool) = self.pool {
            let row: Option<(Option<chrono::DateTime<chrono::Utc>>,)> =
                sqlx::query_as("SELECT locked_until FROM mfa_lockout_state WHERE user_id = $1")
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await
                    .ok()
                    .flatten();

            return match row {
                Some((Some(locked_until),)) => {
                    let remaining = (locked_until - chrono::Utc::now()).num_seconds();
                    if remaining > 0 { remaining as u64 } else { 0 }
                }
                _ => 0,
            };
        }

        // Fallback: in-memory
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Some(expiry) = self.memory.lock().lockouts.get(user_id)
            && now_secs < *expiry
        {
            return *expiry - now_secs;
        }
        0
    }

    /// Get failed attempt count for a user
    pub async fn failed_attempt_count(&self, user_id: &str) -> u32 {
        if let Some(ref pool) = self.pool {
            let row: Option<(i32,)> =
                sqlx::query_as("SELECT failed_attempts FROM mfa_lockout_state WHERE user_id = $1")
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await
                    .ok()
                    .flatten();

            return row.map(|r| r.0 as u32).unwrap_or(0);
        }

        self.memory
            .lock()
            .failed_attempts
            .get(user_id)
            .copied()
            .unwrap_or(0)
    }

    /// Record a backup code usage and return true if limit exceeded
    pub async fn record_backup_code_usage(&self, user_id: &str) -> bool {
        if let Some(ref m) = self.metrics {
            m.record_mfa_failure();
        }

        if let Some(ref pool) = self.pool {
            let row: (i32,) = sqlx::query_as(
                r#"
                INSERT INTO mfa_lockout_state (user_id, backup_code_usage, updated_at)
                VALUES ($1, 1, NOW())
                ON CONFLICT (user_id) DO UPDATE SET
                    backup_code_usage = mfa_lockout_state.backup_code_usage + 1,
                    updated_at = NOW()
                RETURNING backup_code_usage
                "#,
            )
            .bind(user_id)
            .fetch_one(pool)
            .await
            .unwrap_or((0,));

            let usage = row.0 as u32;

            tracing::info!(
                "Backup code used for user {}: {}/{} uses",
                sanitize_for_log(user_id),
                usage,
                MAX_BACKUP_CODE_USES
            );
            return usage >= MAX_BACKUP_CODE_USES;
        }

        // Fallback: in-memory
        let mut mem = self.memory.lock();
        let usage = mem
            .backup_code_usage
            .entry(user_id.to_string())
            .or_insert(0);
        *usage += 1;

        tracing::info!(
            "Backup code used for user {}: {}/{} uses (in-memory)",
            sanitize_for_log(user_id),
            *usage,
            MAX_BACKUP_CODE_USES
        );
        *usage >= MAX_BACKUP_CODE_USES
    }

    /// Get backup code usage count
    pub async fn backup_code_usage_count(&self, user_id: &str) -> u32 {
        if let Some(ref pool) = self.pool {
            let row: Option<(i32,)> = sqlx::query_as(
                "SELECT backup_code_usage FROM mfa_lockout_state WHERE user_id = $1",
            )
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();

            return row.map(|r| r.0 as u32).unwrap_or(0);
        }

        self.memory
            .lock()
            .backup_code_usage
            .get(user_id)
            .copied()
            .unwrap_or(0)
    }

    /// Reset backup code usage (called on successful TOTP verification)
    pub async fn reset_backup_code_usage(&self, user_id: &str) {
        if let Some(ref pool) = self.pool {
            let _ = sqlx::query(
                "UPDATE mfa_lockout_state SET backup_code_usage = 0, updated_at = NOW() WHERE user_id = $1",
            )
            .bind(user_id)
            .execute(pool)
            .await;
            return;
        }

        self.memory.lock().backup_code_usage.remove(user_id);
    }

    /// Migrate all plaintext TOTP secrets in the database to encrypted form.
    ///
    /// Call this after setting `KMS_KEK` to re-encrypt any secrets that were
    /// stored in plaintext (before KEK was configured). This is a no-op if
    /// no KEK is available or no database pool is configured.
    ///
    /// # Returns
    /// Number of secrets migrated, or an error if the database query fails.
    pub async fn migrate_plaintext_secrets(&self) -> Result<u64, String> {
        let pool = self.pool.as_ref().ok_or("No database pool configured")?;
        let _kek = self
            .kek
            .as_ref()
            .ok_or("No KEK configured — cannot encrypt")?;

        // Find all TOTP configs where secret_encrypted is not base64-encoded
        // (plaintext secrets won't be valid base64 of AES-GCM ciphertext)
        let rows = sqlx::query_as::<_, (String, String)>(
            "SELECT user_id, totp_secret FROM mfa_totp_configs WHERE totp_secret IS NOT NULL",
        )
        .fetch_all(pool)
        .await
        .map_err(|e| format!("Failed to query TOTP configs: {e}"))?;

        let mut migrated = 0u64;
        for (user_id, secret) in &rows {
            // Try decrypting first — if it succeeds, it was already encrypted
            if self.decrypt_secret(secret.as_bytes()).is_some() {
                // Verify it's actually encrypted by checking if plaintext fallback would also succeed
                // Encrypted secrets are base64 of nonce+ciphertext+tag, which is longer than plaintext
                match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, secret) {
                    Ok(decoded) if decoded.len() > 32 => continue, // Likely already encrypted
                    _ => {} // Probably plaintext, proceed to encrypt
                }
            }

            // Encrypt the plaintext secret
            let encrypted = match self.encrypt_secret(secret.as_bytes()) {
                Some(e) => e,
                None => {
                    tracing::error!(user_id = %user_id, "Cannot migrate TOTP secret: no KEK configured");
                    continue; // Skip this user — can't encrypt without KEK
                }
            };
            let encrypted_b64 =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted);

            sqlx::query("UPDATE mfa_totp_configs SET totp_secret = $1 WHERE user_id = $2")
                .bind(&encrypted_b64)
                .bind(user_id)
                .execute(pool)
                .await
                .map_err(|e| format!("Failed to update secret for user {user_id}: {e}"))?;

            migrated += 1;
        }

        tracing::info!(
            "Migrated {} TOTP secrets from plaintext to encrypted",
            migrated
        );
        Ok(migrated)
    }
}

/// MFA status response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MfaStatusResponse {
    pub enabled: bool,
    pub mfa_type: String,
    pub backup_codes_remaining: usize,
}

impl From<MfaStatus> for MfaStatusResponse {
    fn from(status: MfaStatus) -> Self {
        Self {
            enabled: status.enabled,
            mfa_type: format!("{:?}", status.mfa_type).to_lowercase(),
            backup_codes_remaining: status.backup_codes_remaining,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kms_mfa::{BackupCodeGenerator, TotpGenerator};

    // ------------------------------------------------------------------
    // In-memory MFA tests (no PostgreSQL required)
    // ------------------------------------------------------------------

    /// Helper: generate backup codes as plain strings for MFA storage
    fn generate_backup_code_strings(count: usize) -> Vec<String> {
        let (_, codes) = BackupCodeGenerator::generate(count);
        codes.iter().map(|c| c.code.clone()).collect()
    }

    #[tokio::test]
    async fn test_mfa_in_memory_totp_setup_and_verify() {
        let mfa = MfaManager::new_in_memory_with_kek();
        let user_id = "test-user-1";

        // Generate TOTP secret
        let secret = TotpGenerator::generate_secret().unwrap();
        let config = kms_mfa::TotpConfig {
            secret: secret.clone(),
            time_step: 30,
            digits: 6,
            algorithm: kms_mfa::totp::TotpAlgorithm::Sha1,
            window: 1,
        };

        // Generate backup codes
        let backup_codes = generate_backup_code_strings(8);

        // Store config
        mfa.store_totp_config(user_id, &config, &backup_codes)
            .await
            .unwrap();

        // Verify config was stored
        assert!(mfa.has_totp_config(user_id).await);
        let loaded = mfa.load_totp_config(user_id).await;
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().secret, secret);

        // Verify TOTP code
        let generator = TotpGenerator::with_secret(&secret).unwrap();
        let code = generator.generate().unwrap();
        assert!(generator.validate(&code.code).unwrap());
    }

    #[tokio::test]
    async fn test_mfa_in_memory_backup_codes() {
        let mfa = MfaManager::new_in_memory_with_kek();
        let user_id = "test-user-backup";

        let secret = TotpGenerator::generate_secret().unwrap();
        let config = kms_mfa::TotpConfig {
            secret,
            time_step: 30,
            digits: 6,
            algorithm: kms_mfa::totp::TotpAlgorithm::Sha1,
            window: 1,
        };

        let backup_codes = generate_backup_code_strings(8);
        let original_count = backup_codes.len();

        mfa.store_totp_config(user_id, &config, &backup_codes)
            .await
            .unwrap();

        // Verify backup codes count
        assert_eq!(mfa.backup_codes_remaining(user_id).await, original_count);

        // Consume a backup code
        let code_to_use = &backup_codes[0];
        assert!(mfa.consume_backup_code(user_id, code_to_use).await);

        // Count should decrease
        assert_eq!(
            mfa.backup_codes_remaining(user_id).await,
            original_count - 1
        );

        // Same code should not be reusable
        assert!(!mfa.consume_backup_code(user_id, code_to_use).await);

        // Wrong code should not work
        assert!(!mfa.consume_backup_code(user_id, "WRONG-CODE").await);
    }

    #[tokio::test]
    async fn test_mfa_in_memory_lockout() {
        let mfa = MfaManager::new_in_memory();
        let user_id = "test-user-lockout";

        // Should not be locked out initially
        assert!(!mfa.is_locked_out(user_id).await);
        assert_eq!(mfa.failed_attempt_count(user_id).await, 0);

        // Record failures up to MAX - 1
        for _ in 0..MAX_TOTP_ATTEMPTS - 1 {
            let locked = mfa.record_failed_totp_attempt(user_id).await;
            assert!(!locked, "Should not be locked yet");
        }
        assert_eq!(
            mfa.failed_attempt_count(user_id).await,
            MAX_TOTP_ATTEMPTS - 1
        );

        // One more failure should trigger lockout
        let locked = mfa.record_failed_totp_attempt(user_id).await;
        assert!(
            locked,
            "Should be locked after {MAX_TOTP_ATTEMPTS} attempts"
        );
        assert!(mfa.is_locked_out(user_id).await);
        assert!(mfa.lockout_remaining_secs(user_id).await > 0);

        // Clear failed attempts
        mfa.clear_failed_attempts(user_id).await;
        assert_eq!(mfa.failed_attempt_count(user_id).await, 0);
    }

    #[tokio::test]
    async fn test_mfa_in_memory_backup_code_usage_limit() {
        let mfa = MfaManager::new_in_memory();
        let user_id = "test-user-backup-limit";

        // Use backup codes up to MAX - 1
        for _ in 0..MAX_BACKUP_CODE_USES - 1 {
            let exceeded = mfa.record_backup_code_usage(user_id).await;
            assert!(!exceeded, "Should not exceed limit yet");
        }

        // One more should exceed
        let exceeded = mfa.record_backup_code_usage(user_id).await;
        assert!(exceeded, "Should exceed after {MAX_BACKUP_CODE_USES} uses");
        assert_eq!(
            mfa.backup_code_usage_count(user_id).await,
            MAX_BACKUP_CODE_USES
        );

        // Reset
        mfa.reset_backup_code_usage(user_id).await;
        assert_eq!(mfa.backup_code_usage_count(user_id).await, 0);
    }

    #[tokio::test]
    async fn test_mfa_in_memory_no_config_for_unknown_user() {
        let mfa = MfaManager::new_in_memory();

        assert!(!mfa.has_totp_config("unknown-user").await);
        assert!(mfa.load_totp_config("unknown-user").await.is_none());
        assert_eq!(mfa.backup_codes_remaining("unknown-user").await, 0);
        assert!(!mfa.is_locked_out("unknown-user").await);
        assert_eq!(mfa.failed_attempt_count("unknown-user").await, 0);
    }

    #[tokio::test]
    async fn test_mfa_status_response_from_status() {
        let status = MfaStatus {
            enabled: true,
            mfa_type: kms_mfa::MfaType::Totp,
            backup_codes_remaining: 5,
            last_verified_at: None,
        };
        let response = MfaStatusResponse::from(status);
        assert!(response.enabled);
        assert_eq!(response.mfa_type, "totp");
        assert_eq!(response.backup_codes_remaining, 5);
    }

    #[tokio::test]
    async fn test_mfa_secret_encryption_roundtrip() {
        // Test that encrypt_secret returns None when no KEK is set
        // Use a fresh MfaManager that definitely has no KEK
        let mfa = MfaManager::new_in_memory_no_kek();
        assert!(
            !mfa.is_secret_encrypted(),
            "No KEK set, should be in plaintext mode"
        );

        let secret = b"test-secret-12345";
        let encrypted = mfa.encrypt_secret(secret);
        assert!(
            encrypted.is_none(),
            "Without KEK, encrypt_secret must return None — plaintext storage is forbidden"
        );
    }

    #[tokio::test]
    async fn test_mfa_secret_encryption_with_kek() {
        let mfa = MfaManager::new_in_memory_with_kek();
        assert!(mfa.is_secret_encrypted(), "KEK set, should encrypt");

        let secret = b"test-secret-for-kek";
        let encrypted = mfa
            .encrypt_secret(secret)
            .expect("KEK set, encrypt should succeed");
        assert_ne!(
            encrypted.as_slice(),
            secret,
            "With KEK, encrypted should differ from plaintext"
        );
        assert!(
            encrypted.len() > secret.len(),
            "Encrypted should be larger (nonce + tag)"
        );

        let decrypted = mfa.decrypt_secret(&encrypted);
        assert_eq!(
            decrypted.unwrap(),
            secret,
            "Decrypted should match original"
        );
    }

    #[tokio::test]
    async fn test_mfa_totp_with_encryption_end_to_end() {
        let mfa = MfaManager::new_in_memory_with_kek();
        let user_id = "test-encryption-e2e";

        // Generate and store TOTP config
        let secret = TotpGenerator::generate_secret().unwrap();
        let config = kms_mfa::TotpConfig {
            secret: secret.clone(),
            time_step: 30,
            digits: 6,
            algorithm: kms_mfa::totp::TotpAlgorithm::Sha1,
            window: 1,
        };
        let backup_codes = generate_backup_code_strings(8);
        mfa.store_totp_config(user_id, &config, &backup_codes)
            .await
            .unwrap();

        // Load and verify the secret survives (in-memory cache stores plaintext)
        let loaded = mfa.load_totp_config(user_id).await;
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().secret, secret);

        // Verify TOTP still works
        let generator = TotpGenerator::with_secret(&secret).unwrap();
        let code = generator.generate().unwrap();
        assert!(generator.validate(&code.code).unwrap());
    }

    // ------------------------------------------------------------------
    // Database-backed MFA tests (require PostgreSQL, run with --ignored)
    // ------------------------------------------------------------------

    /// Set up MFA manager with a real PostgreSQL connection.
    /// Requires DATABASE_URL env var pointing to a running PostgreSQL instance.
    async fn setup_mfa_with_db() -> Option<MfaManager> {
        let db_url = std::env::var("DATABASE_URL").ok()?;
        let pool = sqlx::PgPool::connect(&db_url).await.ok()?;
        let mfa = MfaManager::new(pool);
        mfa.migrate().await.ok()?;
        Some(mfa)
    }

    #[tokio::test]
    #[ignore] // Requires PostgreSQL: cargo test -- --ignored
    async fn test_mfa_db_totp_persistence() {
        let mfa = setup_mfa_with_db().await.expect("DATABASE_URL must be set");
        let user_id = "db-test-persist-user";

        let secret = TotpGenerator::generate_secret().unwrap();
        let config = kms_mfa::TotpConfig {
            secret: secret.clone(),
            time_step: 30,
            digits: 6,
            algorithm: kms_mfa::totp::TotpAlgorithm::Sha1,
            window: 1,
        };
        let backup_codes = generate_backup_code_strings(8);

        mfa.store_totp_config(user_id, &config, &backup_codes)
            .await
            .unwrap();

        // Verify persistence by creating a NEW MfaManager with same pool
        let mfa2 = MfaManager::new(mfa.pool.clone().unwrap());
        let loaded = mfa2.load_totp_config(user_id).await;
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().secret, secret);
    }

    #[tokio::test]
    #[ignore]
    async fn test_mfa_db_lockout_persistence() {
        let mfa = setup_mfa_with_db().await.expect("DATABASE_URL must be set");
        let user_id = "db-test-lockout-user";

        // Trigger lockout
        for _ in 0..MAX_TOTP_ATTEMPTS {
            mfa.record_failed_totp_attempt(user_id).await;
        }
        assert!(mfa.is_locked_out(user_id).await);

        // Verify persistence by creating a NEW MfaManager
        let mfa2 = MfaManager::new(mfa.pool.clone().unwrap());
        assert!(mfa2.is_locked_out(user_id).await);
        assert_eq!(mfa2.failed_attempt_count(user_id).await, MAX_TOTP_ATTEMPTS);
    }

    #[tokio::test]
    #[ignore]
    async fn test_mfa_db_backup_code_consumption() {
        let mfa = setup_mfa_with_db().await.expect("DATABASE_URL must be set");
        let user_id = "db-test-backup-user";

        let secret = TotpGenerator::generate_secret().unwrap();
        let config = kms_mfa::TotpConfig {
            secret,
            time_step: 30,
            digits: 6,
            algorithm: kms_mfa::totp::TotpAlgorithm::Sha1,
            window: 1,
        };
        let backup_codes = generate_backup_code_strings(8);
        let first_code = backup_codes[0].clone();

        mfa.store_totp_config(user_id, &config, &backup_codes)
            .await
            .unwrap();

        // Consume on first manager
        assert!(mfa.consume_backup_code(user_id, &first_code).await);

        // Verify consumed on second manager (persistence)
        let mfa2 = MfaManager::new(mfa.pool.clone().unwrap());
        assert!(
            !mfa2.consume_backup_code(user_id, &first_code).await,
            "Code should already be consumed"
        );
        assert_eq!(mfa2.backup_codes_remaining(user_id).await, 7);
    }
}
