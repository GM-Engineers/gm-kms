//! TOTP (Time-based One-Time Password) Implementation
//!
//! Implements RFC 6238 TOTP algorithm

use crate::error::{MfaError, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

/// TOTP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Secret key (base32 encoded when stored)
    pub secret: Vec<u8>,
    /// Time step in seconds (default: 30)
    pub time_step: u64,
    /// Code digits (default: 6)
    pub digits: u32,
    /// Algorithm (SHA1, SHA256, SHA512)
    pub algorithm: TotpAlgorithm,
    /// Window size for code validation (default: 1)
    pub window: u32,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            secret: Vec::new(),
            time_step: 30,
            digits: 6,
            algorithm: TotpAlgorithm::Sha1,
            window: 1,
        }
    }
}

/// TOTP hash algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

/// Generated TOTP code with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpCode {
    /// The 6-8 digit code
    pub code: String,
    /// Unix timestamp when code was generated
    pub generated_at: u64,
    /// Unix timestamp when code expires
    pub expires_at: u64,
    /// Time step period
    pub period: u64,
}

impl TotpCode {
    /// Get remaining seconds until expiration
    pub fn remaining_seconds(&self) -> i64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.expires_at as i64 - now as i64
    }

    /// Check if code is still valid
    pub fn is_valid(&self) -> bool {
        self.remaining_seconds() > 0
    }
}

/// TOTP code generator/validator
#[derive(Debug, Clone)]
pub struct TotpGenerator {
    config: TotpConfig,
}

impl TotpGenerator {
    /// Create a new TOTP generator with the given configuration
    pub fn new(config: TotpConfig) -> Result<Self> {
        if config.secret.is_empty() {
            return Err(MfaError::InvalidSecret);
        }
        if config.digits < 6 || config.digits > 8 {
            return Err(MfaError::InvalidConfig(
                "digits must be between 6 and 8".to_string(),
            ));
        }
        if config.time_step == 0 {
            return Err(MfaError::InvalidConfig(
                "time_step must be non-zero".to_string(),
            ));
        }

        Ok(Self { config })
    }

    /// Create a new TOTP generator with default settings
    pub fn with_secret(secret: &[u8]) -> Result<Self> {
        let config = TotpConfig {
            secret: secret.to_vec(),
            ..Default::default()
        };
        Self::new(config)
    }

    /// Generate a TOTP code for the current time
    pub fn generate(&self) -> Result<TotpCode> {
        self.generate_at_timestamp(Self::current_timestamp())
    }

    /// Generate a TOTP code at a specific timestamp
    pub fn generate_at_timestamp(&self, timestamp: u64) -> Result<TotpCode> {
        let counter = timestamp / self.config.time_step;
        let code = self.compute_hotp(counter)?;

        let expires_at = ((counter + 1) * self.config.time_step) - 1;

        Ok(TotpCode {
            code,
            generated_at: timestamp,
            expires_at,
            period: self.config.time_step,
        })
    }

    /// Validate a TOTP code with window tolerance
    pub fn validate(&self, code: &str) -> Result<bool> {
        let timestamp = Self::current_timestamp();
        self.validate_at_timestamp(code, timestamp)
    }

    /// Validate a TOTP code at a specific timestamp
    pub fn validate_at_timestamp(&self, code: &str, timestamp: u64) -> Result<bool> {
        let counter = timestamp / self.config.time_step;

        // Check current and adjacent time steps (window)
        for delta in 0..=self.config.window {
            // Check forward delta
            let expected = self.compute_hotp(counter + delta as u64)?;
            if expected.as_bytes().ct_eq(code.as_bytes()).into() {
                return Ok(true);
            }

            // Check backward delta (if not at counter 0)
            if counter >= delta as u64 {
                let expected = self.compute_hotp(counter - delta as u64)?;
                if expected.as_bytes().ct_eq(code.as_bytes()).into() {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Verify a TOTP code (alias for validate)
    pub fn verify(&self, code: &str) -> Result<bool> {
        self.validate(code)
    }

    /// Compute HOTP value
    fn compute_hotp(&self, counter: u64) -> Result<String> {
        // Pack counter into 8 bytes (big-endian)
        let mut counter_bytes = [0u8; 8];
        counter_bytes[4..].copy_from_slice(&counter.to_be_bytes()[4..]);
        counter_bytes[0..4].copy_from_slice(&counter.to_be_bytes()[0..4]);

        // Compute HMAC
        let hmac = match self.config.algorithm {
            TotpAlgorithm::Sha1 => hmac_sha1(&self.config.secret, &counter_bytes),
            TotpAlgorithm::Sha256 => hmac_sha256(&self.config.secret, &counter_bytes),
            TotpAlgorithm::Sha512 => hmac_sha512(&self.config.secret, &counter_bytes),
        };

        // Dynamic truncation
        let offset = (hmac[hmac.len() - 1] & 0x0f) as usize;
        let binary = ((hmac[offset] & 0x7f) as u32) << 24
            | (hmac[offset + 1] as u32) << 16
            | (hmac[offset + 2] as u32) << 8
            | (hmac[offset + 3] as u32);

        // Generate code with specified number of digits
        let modulus = 10_u32.pow(self.config.digits);
        let otp = binary % modulus;

        Ok(format!(
            "{:0>width$}",
            otp,
            width = self.config.digits as usize
        ))
    }

    /// Get current Unix timestamp
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Generate a new random secret using cryptographically secure RNG
    pub fn generate_secret() -> Result<Vec<u8>> {
        let mut secret = vec![0u8; 20]; // 160-bit secret as per RFC 6238
        rand::rng().fill_bytes(&mut secret);
        Ok(secret)
    }

    /// Generate provisioning URI for QR code
    pub fn get_provisioning_uri(&self, account_name: &str, issuer: &str) -> String {
        let label = format!("{}:{}", issuer, account_name);
        let secret_b32 = base32::encode(
            base32::Alphabet::Rfc4648 { padding: false },
            &self.config.secret,
        );

        let params = [
            ("secret", secret_b32.as_str()),
            ("issuer", issuer),
            ("algorithm", "SHA1"),
            ("digits", &self.config.digits.to_string()),
            ("period", &self.config.time_step.to_string()),
        ];

        let query = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        format!("otpauth://totp/{}?{}", label, query)
    }
}

/// HMAC-SHA1 implementation
fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    use sha1::{Digest, Sha1};

    let block_size = 64;

    // If key is longer than block size, hash it
    let key = if key.len() > block_size {
        let mut hasher = Sha1::new();
        hasher.update(key);
        hasher.finalize().to_vec()
    } else {
        key.to_vec()
    };

    // Pad key to block size
    let mut padded_key = key;
    padded_key.resize(block_size, 0);

    // Create inner and outer padding
    let mut inner_padding = vec![0x36u8; block_size];
    let mut outer_padding = vec![0x5cu8; block_size];

    for i in 0..block_size {
        inner_padding[i] ^= padded_key[i];
        outer_padding[i] ^= padded_key[i];
    }

    // Inner hash
    let mut inner_hasher = Sha1::new();
    inner_hasher.update(&inner_padding);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    // Outer hash
    let mut outer_hasher = Sha1::new();
    outer_hasher.update(&outer_padding);
    outer_hasher.update(inner_hash);

    outer_hasher.finalize().to_vec()
}

/// HMAC-SHA256 implementation
fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let block_size = 64;

    let key = if key.len() > block_size {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.finalize().to_vec()
    } else {
        key.to_vec()
    };

    let mut padded_key = key;
    padded_key.resize(block_size, 0);

    let mut inner_padding = vec![0x36u8; block_size];
    let mut outer_padding = vec![0x5cu8; block_size];

    for i in 0..block_size {
        inner_padding[i] ^= padded_key[i];
        outer_padding[i] ^= padded_key[i];
    }

    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&inner_padding);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&outer_padding);
    outer_hasher.update(inner_hash);

    outer_hasher.finalize().to_vec()
}

/// HMAC-SHA512 implementation
fn hmac_sha512(key: &[u8], message: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha512};

    let block_size = 128;

    let key = if key.len() > block_size {
        let mut hasher = Sha512::new();
        hasher.update(key);
        hasher.finalize().to_vec()
    } else {
        key.to_vec()
    };

    let mut padded_key = key;
    padded_key.resize(block_size, 0);

    let mut inner_padding = vec![0x36u8; block_size];
    let mut outer_padding = vec![0x5cu8; block_size];

    for i in 0..block_size {
        inner_padding[i] ^= padded_key[i];
        outer_padding[i] ^= padded_key[i];
    }

    let mut inner_hasher = Sha512::new();
    inner_hasher.update(&inner_padding);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha512::new();
    outer_hasher.update(&outer_padding);
    outer_hasher.update(inner_hash);

    outer_hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generation() {
        // Test with known secret and time
        let secret = b"test_secret_key_32bytes_long!!";
        let generator = TotpGenerator::with_secret(secret).unwrap();

        // Generate code
        let code = generator.generate().unwrap();
        assert_eq!(code.code.len(), 6);
        assert!(code.is_valid());
    }

    #[test]
    fn test_totp_validation() {
        let secret = b"another_test_secret_key_!!";
        let generator = TotpGenerator::with_secret(secret).unwrap();

        // Generate and immediately validate
        let code = generator.generate().unwrap();
        let result = generator.validate(&code.code).unwrap();
        assert!(result);
    }

    #[test]
    fn test_totp_invalid_code() {
        let secret = b"test_secret_key_32bytes_long!!";
        let generator = TotpGenerator::with_secret(secret).unwrap();

        let result = generator.validate("000000").unwrap();
        assert!(!result);
    }

    #[test]
    fn test_totp_with_custom_config() {
        let config = TotpConfig {
            secret: b"test_secret_key_32bytes_long!!".to_vec(),
            time_step: 30,
            digits: 8,
            algorithm: TotpAlgorithm::Sha256,
            window: 2,
        };

        let generator = TotpGenerator::new(config).unwrap();
        let code = generator.generate().unwrap();

        assert_eq!(code.code.len(), 8);
        assert!(generator.validate(&code.code).unwrap());
    }

    #[test]
    fn test_totp_secret_generation() {
        let secret = TotpGenerator::generate_secret().unwrap();
        assert!(!secret.is_empty());
        assert_eq!(secret.len(), 20); // SHA1 output length

        let generator = TotpGenerator::with_secret(&secret).unwrap();
        let code = generator.generate().unwrap();
        assert!(generator.validate(&code.code).unwrap());
    }

    #[test]
    fn test_totp_provisioning_uri() {
        let secret = b"test_secret_key_32bytes_long!!";
        let generator = TotpGenerator::with_secret(secret).unwrap();

        let uri = generator.get_provisioning_uri("user@example.com", "gm-kms");
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("secret="));
        assert!(uri.contains("issuer=gm-kms"));
    }

    #[test]
    fn test_totp_code_expiration() {
        let secret = b"test_secret_key_32bytes_long!!";
        let generator = TotpGenerator::with_secret(secret).unwrap();

        let code = generator.generate().unwrap();
        assert!(code.expires_at > code.generated_at);
        assert!(code.remaining_seconds() > 0);
    }

    /// Test TOTP validation at a specific timestamp (deterministic)
    #[test]
    fn test_totp_validate_at_timestamp() {
        let secret = b"test_secret_key_32bytes_long!!";
        let generator = TotpGenerator::with_secret(secret).unwrap();

        let timestamp = 1700000000u64;
        let code = generator.generate_at_timestamp(timestamp).unwrap();

        // Same timestamp should validate
        assert!(
            generator
                .validate_at_timestamp(&code.code, timestamp)
                .unwrap()
        );

        // One step later should also validate (within window)
        let next_step = timestamp + 30;
        assert!(
            generator
                .validate_at_timestamp(&code.code, next_step)
                .unwrap()
        );
    }

    /// Test TOTP with expired code (outside window)
    #[test]
    fn test_totp_expired_code() {
        let secret = b"test_secret_key_32bytes_long!!";
        let generator = TotpGenerator::with_secret(secret).unwrap();

        let timestamp = 1700000000u64;
        let code = generator.generate_at_timestamp(timestamp).unwrap();

        // Far future timestamp should not validate
        let far_future = timestamp + 3600;
        assert!(
            !generator
                .validate_at_timestamp(&code.code, far_future)
                .unwrap()
        );
    }

    /// Test verify() is equivalent to validate()
    #[test]
    fn test_totp_verify() {
        let secret = b"test_secret_key_32bytes_long!!";
        let generator = TotpGenerator::with_secret(secret).unwrap();

        let code = generator.generate().unwrap();
        assert!(generator.verify(&code.code).unwrap());

        // Wrong code
        assert!(!generator.verify("999999").unwrap());
    }

    /// Test TOTP with SHA512 algorithm
    #[test]
    fn test_totp_sha512() {
        let config = TotpConfig {
            secret: b"test_secret_key_32bytes_long!!".to_vec(),
            time_step: 30,
            digits: 6,
            algorithm: TotpAlgorithm::Sha512,
            window: 1,
        };

        let generator = TotpGenerator::new(config).unwrap();
        let code = generator.generate().unwrap();
        assert_eq!(code.code.len(), 6);
        assert!(generator.validate(&code.code).unwrap());
    }

    /// Test TOTP with empty secret fails
    #[test]
    fn test_totp_empty_secret_fails() {
        let result = TotpGenerator::with_secret(b"");
        assert!(result.is_err());
    }

    /// Test TotpCode display/debug
    #[test]
    fn test_totp_code_debug() {
        let secret = b"test_secret_key_32bytes_long!!";
        let generator = TotpGenerator::with_secret(secret).unwrap();
        let code = generator.generate().unwrap();

        // Should be debuggable without panicking
        let debug_str = format!("{:?}", code);
        assert!(!debug_str.is_empty());
    }
}
