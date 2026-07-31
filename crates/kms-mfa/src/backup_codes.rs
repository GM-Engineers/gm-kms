//! Backup Codes for MFA Recovery
//!
//! Provides one-time backup codes for account recovery when
//! primary MFA device is unavailable.

use crate::error::{MfaError, Result};
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Maximum failed backup code attempts before lockout
const MAX_FAILED_ATTEMPTS: u32 = 5;
/// Lockout duration in seconds after too many failed attempts
const LOCKOUT_DURATION_SECS: i64 = 300; // 5 minutes

/// Backup code entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupCode {
    /// The 8-character backup code
    pub code: String,
    /// Whether this code has been used
    pub used: bool,
    /// When this code was last used (if ever)
    pub used_at: Option<i64>,
}

/// Backup codes manager with brute force protection
///
/// Backup codes are stored as SHA-256 hashes to prevent plaintext recovery
/// if the in-memory state is compromised. The original codes are only
/// returned once during generation.
#[derive(Debug, Clone)]
pub struct BackupCodeGenerator {
    /// SHA-256 hashes of valid backup codes
    codes: HashSet<String>,
    remaining: usize,
    /// Failed attempts counter
    failed_attempts: u32,
    /// Lockout end time (None if not locked)
    lockout_until: Option<i64>,
}

impl BackupCodeGenerator {
    /// Generate a set of new backup codes
    ///
    /// Returns the plaintext codes for one-time display to the user.
    /// Internally only SHA-256 hashes are stored.
    pub fn generate(count: usize) -> (Self, Vec<BackupCode>) {
        let mut codes = HashSet::new();
        let mut backup_codes = Vec::with_capacity(count);

        while codes.len() < count {
            let code = Self::generate_single_code();
            let hash = Self::hash_code(&code);
            if codes.insert(hash) {
                backup_codes.push(BackupCode {
                    code,
                    used: false,
                    used_at: None,
                });
            }
        }

        let generator = Self {
            codes,
            remaining: count,
            failed_attempts: 0,
            lockout_until: None,
        };

        (generator, backup_codes)
    }

    /// Generate a single 8-character backup code using cryptographically secure RNG
    fn generate_single_code() -> String {
        let mut bytes = [0u8; 4];
        rand::rng().fill_bytes(&mut bytes);
        let value = u32::from_ne_bytes(bytes) % 100_000_000;
        format!("{:08}", value)
    }

    /// Compute SHA-256 hash of a normalized code for secure storage
    fn hash_code(code: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(code.trim().to_uppercase().as_bytes());
        hex::encode(hasher.finalize().as_slice())
    }

    /// Check if currently locked out due to too many failed attempts
    fn is_locked_out(&self) -> Option<u64> {
        if let Some(lockout_until) = self.lockout_until {
            let now = Utc::now().timestamp();
            if now < lockout_until {
                return Some((lockout_until - now) as u64);
            }
        }
        None
    }

    /// Validate and consume a backup code with brute force protection
    pub fn consume_code(&mut self, code: &str) -> Result<()> {
        // Check if locked out
        if let Some(retry_after) = self.is_locked_out() {
            return Err(MfaError::BackupCodeLocked(retry_after));
        }

        let normalized_hash = Self::hash_code(code);

        if !self.codes.contains(&normalized_hash) {
            // Increment failed attempts
            self.failed_attempts += 1;

            // Check if we've exceeded max attempts
            if self.failed_attempts >= MAX_FAILED_ATTEMPTS {
                self.lockout_until = Some(Utc::now().timestamp() + LOCKOUT_DURATION_SECS);
                return Err(MfaError::BackupCodeLocked(LOCKOUT_DURATION_SECS as u64));
            }

            return Err(MfaError::InvalidCode);
        }

        if self.remaining == 0 {
            return Err(MfaError::NoBackupCodes);
        }

        // Successful use - reset failed attempts
        self.failed_attempts = 0;
        self.lockout_until = None;

        // Mark as used
        self.codes.remove(&normalized_hash);
        self.remaining -= 1;

        Ok(())
    }

    /// Check if a backup code is valid (but don't consume it)
    pub fn is_valid_code(&self, code: &str) -> bool {
        let normalized_hash = Self::hash_code(code);
        self.codes.contains(&normalized_hash)
    }

    /// Get number of remaining codes
    pub fn remaining(&self) -> usize {
        self.remaining
    }

    /// Check if any codes remain
    pub fn has_codes(&self) -> bool {
        self.remaining > 0
    }

    /// Load existing backup codes from persistence
    ///
    /// The codes in the `Vec<BackupCode>` should already be hashed
    /// (as stored during generation).
    pub fn load(codes: Vec<BackupCode>) -> Self {
        let mut code_set = HashSet::new();
        let mut remaining = 0;

        for backup_code in codes {
            if !backup_code.used {
                code_set.insert(backup_code.code.clone());
                remaining += 1;
            }
        }

        Self {
            codes: code_set,
            remaining,
            failed_attempts: 0,
            lockout_until: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_backup_codes() {
        let (generator, codes) = BackupCodeGenerator::generate(10);

        assert_eq!(codes.len(), 10);
        assert_eq!(generator.remaining(), 10);

        // All codes should be unique
        let mut seen = HashSet::new();
        for code in &codes {
            assert!(!seen.contains(&code.code));
            assert!(seen.insert(&code.code));
            assert!(!code.used);
        }
    }

    #[test]
    fn test_consume_backup_code() {
        let (mut generator, codes) = BackupCodeGenerator::generate(5);
        let first_code = &codes[0].code;

        // Should succeed
        generator.consume_code(first_code).unwrap();
        assert_eq!(generator.remaining(), 4);

        // Code should no longer be valid
        assert!(!generator.is_valid_code(first_code));
    }

    #[test]
    fn test_consume_invalid_code() {
        let (mut generator, _) = BackupCodeGenerator::generate(5);

        let result = generator.consume_code("INVALID");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_backup_codes() {
        let (_, codes) = BackupCodeGenerator::generate(5);
        let first_code = codes[0].code.clone();

        // Mark first code as used
        let mut modified_codes = codes;
        modified_codes[0].used = true;
        modified_codes[0].used_at = Some(chrono::Utc::now().timestamp());

        let generator = BackupCodeGenerator::load(modified_codes);

        assert_eq!(generator.remaining(), 4);
        assert!(!generator.is_valid_code(&first_code));
    }

    #[test]
    fn test_code_normalization() {
        // Test with multiple codes to avoid running out
        let (mut generator, codes) = BackupCodeGenerator::generate(5);

        // First code - lowercase should work
        let code1 = &codes[0].code;
        assert!(generator.consume_code(&code1.to_lowercase()).is_ok());

        // Second code - with spaces should work
        let code2 = &codes[1].code;
        assert!(generator.consume_code(&format!("  {}  ", code2)).is_ok());
    }

    // --- Additional tests ---

    /// Test brute force protection: max failed attempts triggers lockout
    #[test]
    fn test_brute_force_lockout() {
        let (mut generator, _) = BackupCodeGenerator::generate(5);

        // MAX_FAILED_ATTEMPTS is 5
        for _ in 0..4 {
            assert!(matches!(
                generator.consume_code("INVALID"),
                Err(MfaError::InvalidCode)
            ));
        }

        // 5th failure should trigger lockout
        let result = generator.consume_code("INVALID");
        assert!(matches!(result, Err(MfaError::BackupCodeLocked(_))));
    }

    /// Test lockout returns retry_after duration
    #[test]
    fn test_lockout_returns_retry_after() {
        let (mut generator, _) = BackupCodeGenerator::generate(5);

        // Trigger lockout
        for _ in 0..5 {
            let _ = generator.consume_code("INVALID");
        }

        // Should be locked now
        let result = generator.consume_code("INVALID");
        if let Err(MfaError::BackupCodeLocked(retry_after)) = result {
            assert!(retry_after > 0);
            assert!(retry_after <= 300); // LOCKOUT_DURATION_SECS
        } else {
            panic!("Expected BackupCodeLocked error");
        }
    }

    /// Test successful code resets failed attempts counter
    #[test]
    fn test_success_resets_failed_attempts() {
        let (mut generator, codes) = BackupCodeGenerator::generate(5);

        // 2 failed attempts
        for _ in 0..2 {
            let _ = generator.consume_code("INVALID");
        }

        // Successful use should reset counter
        generator.consume_code(&codes[0].code).unwrap();

        // Now we should have 4 more failures before lockout (not 3)
        for _ in 0..4 {
            assert!(matches!(
                generator.consume_code("INVALID"),
                Err(MfaError::InvalidCode)
            ));
        }

        // 5th failure should still trigger lockout
        let result = generator.consume_code("INVALID");
        assert!(matches!(result, Err(MfaError::BackupCodeLocked(_))));
    }

    /// Test has_codes and remaining
    #[test]
    fn test_has_codes_and_remaining() {
        let (mut generator, codes) = BackupCodeGenerator::generate(3);

        assert!(generator.has_codes());
        assert_eq!(generator.remaining(), 3);

        generator.consume_code(&codes[0].code).unwrap();
        assert_eq!(generator.remaining(), 2);
        assert!(generator.has_codes());

        generator.consume_code(&codes[1].code).unwrap();
        assert_eq!(generator.remaining(), 1);

        generator.consume_code(&codes[2].code).unwrap();
        assert_eq!(generator.remaining(), 0);
        assert!(!generator.has_codes());
    }

    /// Test consuming all codes then failing
    #[test]
    fn test_consume_all_codes() {
        let (mut generator, codes) = BackupCodeGenerator::generate(2);

        generator.consume_code(&codes[0].code).unwrap();
        generator.consume_code(&codes[1].code).unwrap();
        assert_eq!(generator.remaining(), 0);

        // Now consuming any code should fail with NoBackupCodes
        // (even a valid hash can't be consumed if remaining == 0)
        // Since all codes are consumed, any code is invalid
        let result = generator.consume_code("12345678");
        assert!(result.is_err());
    }

    /// Test is_valid_code doesn't consume
    #[test]
    fn test_is_valid_code_no_consume() {
        let (mut generator, codes) = BackupCodeGenerator::generate(3);
        let code = &codes[0].code;

        // is_valid_code should not consume
        assert!(generator.is_valid_code(code));
        assert_eq!(generator.remaining(), 3);

        // Still consumable
        generator.consume_code(code).unwrap();
        assert_eq!(generator.remaining(), 2);

        // No longer valid
        assert!(!generator.is_valid_code(code));
    }

    /// Test code format: 8 digits
    #[test]
    fn test_code_format() {
        let (_, codes) = BackupCodeGenerator::generate(10);

        for code in &codes {
            assert_eq!(code.code.len(), 8);
            assert!(code.code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    /// Test load with all used codes
    #[test]
    fn test_load_all_used_codes() {
        let (_, codes) = BackupCodeGenerator::generate(3);
        let all_used: Vec<BackupCode> = codes
            .into_iter()
            .map(|mut c| {
                c.used = true;
                c.used_at = Some(chrono::Utc::now().timestamp());
                c
            })
            .collect();

        let generator = BackupCodeGenerator::load(all_used);
        assert_eq!(generator.remaining(), 0);
        assert!(!generator.has_codes());
    }

    /// Test load with empty list
    #[test]
    fn test_load_empty() {
        let generator = BackupCodeGenerator::load(vec![]);
        assert_eq!(generator.remaining(), 0);
        assert!(!generator.has_codes());
    }

    /// Test generate produces unique codes
    #[test]
    fn test_generate_uniqueness() {
        for _ in 0..10 {
            let (_, codes) = BackupCodeGenerator::generate(20);
            let unique: std::collections::HashSet<_> = codes.iter().map(|c| &c.code).collect();
            assert_eq!(unique.len(), 20, "Generated duplicate codes");
        }
    }
}
