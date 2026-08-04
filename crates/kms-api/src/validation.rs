//! API input validation and sanitization
//!
//! Provides validation for all external API inputs to prevent injection
//! attacks and ensure data integrity.

use regex::Regex;
use std::sync::LazyLock;

/// Maximum key name length
pub const MAX_KEY_NAME_LENGTH: usize = 256;

/// Maximum plaintext/ciphertext length (16MB)
pub const MAX_DATA_LENGTH: usize = 16 * 1024 * 1024;

/// Maximum AAD length (64KB)
pub const MAX_AAD_LENGTH: usize = 64 * 1024;

/// Supported key spec strings (allowlist)
const SUPPORTED_SPECS: &[&str] = &[
    "aes-256-gcm",
    "ed25519",
    "ecdsa-p256",
    "ecdsa-p384",
    "sm4",
    "sm2",
    "sm9-signing",
    "sm9-encryption",
    "hmac-sha256",
    "ed448",
    "rsa4096",
];

/// Regex for valid key names (alphanumeric, dash, underscore, period, max 256 chars)
static KEY_NAME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,255}$").expect("valid static regex")
});

/// Validation error types
#[derive(Debug, Clone)]
pub enum ValidationError {
    /// Invalid key spec string
    InvalidSpec { value: String },
    /// Invalid key name
    InvalidKeyName { value: String, reason: String },
    /// Data too large
    DataTooLarge { size: usize, max: usize },
    /// Invalid base64 encoding
    InvalidBase64 { reason: String },
    /// Invalid tenant ID
    InvalidTenantId { value: String },
    /// Empty required field
    EmptyField { field: String },
}

impl ValidationError {
    pub fn message(&self) -> String {
        match self {
            ValidationError::InvalidSpec { value } => {
                format!("unsupported spec: '{value}'. Supported: {SUPPORTED_SPECS:?}")
            }
            ValidationError::InvalidKeyName { value, reason } => {
                format!("invalid key name '{value}': {reason}")
            }
            ValidationError::DataTooLarge { size, max } => {
                format!("data size {size} exceeds maximum {max}")
            }
            ValidationError::InvalidBase64 { reason } => {
                format!("invalid base64 encoding: {reason}")
            }
            ValidationError::InvalidTenantId { value } => {
                format!(
                    "invalid tenant ID: '{value}'. Tenant IDs must be 1-128 alphanumeric characters"
                )
            }
            ValidationError::EmptyField { field } => {
                format!("{field} cannot be empty")
            }
        }
    }
}

/// Validate key specification string
pub fn validate_spec(spec: &str) -> Result<(), ValidationError> {
    let spec_lower = spec.to_lowercase();
    if !SUPPORTED_SPECS.contains(&spec_lower.as_str()) {
        return Err(ValidationError::InvalidSpec {
            value: spec.to_string(),
        });
    }
    Ok(())
}

/// Validate key name
pub fn validate_key_name(name: &str) -> Result<(), ValidationError> {
    if name.is_empty() {
        return Err(ValidationError::EmptyField {
            field: "name".to_string(),
        });
    }
    if name.len() > MAX_KEY_NAME_LENGTH {
        return Err(ValidationError::InvalidKeyName {
            value: name.to_string(),
            reason: format!("exceeds maximum length of {MAX_KEY_NAME_LENGTH} characters"),
        });
    }
    if !KEY_NAME_REGEX.is_match(name) {
        return Err(ValidationError::InvalidKeyName {
            value: name.to_string(),
            reason: "must start with alphanumeric and contain only alphanumeric, dash, underscore, or period"
                .to_string(),
        });
    }
    Ok(())
}

/// Validate tenant ID format
pub fn validate_tenant_id(tenant_id: &str) -> Result<(), ValidationError> {
    if tenant_id.is_empty() {
        return Err(ValidationError::EmptyField {
            field: "tenant_id".to_string(),
        });
    }
    if tenant_id.len() > 128 {
        return Err(ValidationError::InvalidTenantId {
            value: tenant_id.to_string(),
        });
    }
    // Tenant ID must be alphanumeric only
    if !tenant_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ValidationError::InvalidTenantId {
            value: tenant_id.to_string(),
        });
    }
    Ok(())
}

/// Validate data length
pub fn validate_data_length(data: &str, max: usize) -> Result<(), ValidationError> {
    let len = data.len();
    if len > max {
        return Err(ValidationError::DataTooLarge { size: len, max });
    }
    Ok(())
}

/// Validate base64 encoded data can be decoded and check decoded length
pub fn validate_base64(data: &str, max_decoded_len: usize) -> Result<usize, ValidationError> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let decoded = STANDARD
        .decode(data)
        .map_err(|e| ValidationError::InvalidBase64 {
            reason: e.to_string(),
        })?;

    let len = decoded.len();
    if len > max_decoded_len {
        return Err(ValidationError::DataTooLarge {
            size: len,
            max: max_decoded_len,
        });
    }
    Ok(len)
}

/// Validate all CreateKeyRequest inputs
pub fn validate_create_key_request(
    name: &str,
    spec: &str,
    tenant_id: &str,
) -> Result<(), ValidationError> {
    validate_key_name(name)?;
    validate_spec(spec)?;
    validate_tenant_id(tenant_id)?;
    Ok(())
}

/// Validate EncryptRequest inputs
pub fn validate_encrypt_request(
    plaintext: &str,
    aad: &Option<String>,
) -> Result<(), ValidationError> {
    validate_data_length(plaintext, MAX_DATA_LENGTH)?;
    // Validate base64 decodes to valid length
    let decoded_len = validate_base64(plaintext, MAX_DATA_LENGTH)?;
    if decoded_len == 0 {
        return Err(ValidationError::EmptyField {
            field: "plaintext".to_string(),
        });
    }
    if let Some(aad_data) = aad {
        validate_data_length(aad_data, MAX_AAD_LENGTH)?;
        validate_base64(aad_data, MAX_AAD_LENGTH)?;
    }
    Ok(())
}

/// Validate DecryptRequest inputs
pub fn validate_decrypt_request(
    ciphertext: &str,
    nonce: &str,
    tag: &str,
    aad: &Option<String>,
) -> Result<(), ValidationError> {
    validate_data_length(ciphertext, MAX_DATA_LENGTH)?;
    validate_base64(ciphertext, MAX_DATA_LENGTH)?;

    validate_data_length(nonce, 1024)?; // Nonce should be small
    validate_base64(nonce, 1024)?;

    validate_data_length(tag, 1024)?;
    validate_base64(tag, 1024)?;

    if let Some(aad_data) = aad {
        validate_data_length(aad_data, MAX_AAD_LENGTH)?;
        validate_base64(aad_data, MAX_AAD_LENGTH)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_specs() {
        for spec in SUPPORTED_SPECS {
            assert!(validate_spec(spec).is_ok(), "spec {spec} should be valid");
        }
    }

    #[test]
    fn test_invalid_spec() {
        assert!(validate_spec("unknown-algorithm").is_err());
        assert!(validate_spec("").is_err());
        assert!(validate_spec("aes-256-gcm; DROP TABLE keys;--").is_err());
    }

    #[test]
    fn test_valid_key_names() {
        assert!(validate_key_name("my-key").is_ok());
        assert!(validate_key_name("my_key").is_ok());
        assert!(validate_key_name("my.key").is_ok());
        assert!(validate_key_name("a").is_ok());
        assert!(validate_key_name("Key123").is_ok());
    }

    #[test]
    fn test_invalid_key_names() {
        assert!(validate_key_name("").is_err());
        assert!(validate_key_name("-invalid").is_err()); // can't start with dash
        assert!(validate_key_name("_invalid").is_err()); // can't start with underscore
        assert!(validate_key_name(".invalid").is_err()); // can't start with period
        assert!(validate_key_name("has space").is_err());
        assert!(validate_key_name("has\nnewline").is_err());
        assert!(validate_key_name("has<script>").is_err());
    }

    #[test]
    fn test_key_name_length() {
        let long_name = "a".repeat(MAX_KEY_NAME_LENGTH + 1);
        assert!(validate_key_name(&long_name).is_err());

        let max_name = "a".repeat(MAX_KEY_NAME_LENGTH);
        assert!(validate_key_name(&max_name).is_ok());
    }

    #[test]
    fn test_valid_tenant_ids() {
        assert!(validate_tenant_id("default").is_ok());
        assert!(validate_tenant_id("tenant-123").is_ok());
        assert!(validate_tenant_id("tenant_123").is_ok());
        // Short max length (8 chars)
        let short = "abcdWXYZ";
        assert_eq!(short.len(), 8);
        assert!(validate_tenant_id(short).is_ok());
        // Too long (> 128 chars)
        let long_tenant = "a".repeat(130);
        assert!(validate_tenant_id(&long_tenant).is_err());
    }

    #[test]
    fn test_invalid_tenant_ids() {
        assert!(validate_tenant_id("").is_err());
        assert!(validate_tenant_id("has space").is_err());
        assert!(validate_tenant_id("has@special").is_err());
    }

    #[test]
    fn test_data_length_validation() {
        let small_data = "hello";
        assert!(validate_data_length(small_data, 100).is_ok());

        let large_data = "x".repeat(MAX_DATA_LENGTH + 1);
        assert!(validate_data_length(&large_data, MAX_DATA_LENGTH).is_err());
    }

    #[test]
    fn test_base64_validation() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        // Valid base64
        let valid = STANDARD.encode("hello");
        assert!(validate_base64(&valid, 1000).is_ok());

        // Invalid base64
        assert!(validate_base64("not!valid@base64#", 1000).is_err());

        // Too large
        let large = STANDARD.encode("x".repeat(MAX_DATA_LENGTH + 1));
        assert!(validate_base64(&large, MAX_DATA_LENGTH).is_err());
    }

    #[test]
    fn test_create_key_request_validation() {
        assert!(validate_create_key_request("my-key", "aes-256-gcm", "tenant-1").is_ok());
        assert!(validate_create_key_request("", "aes-256-gcm", "tenant-1").is_err());
        assert!(validate_create_key_request("my-key", "unknown", "tenant-1").is_err());
        assert!(validate_create_key_request("my-key", "aes-256-gcm", "").is_err());
    }

    #[test]
    fn test_encrypt_request_validation() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let plaintext = STANDARD.encode("hello");
        assert!(validate_encrypt_request(&plaintext, &None).is_ok());

        let empty_plaintext = STANDARD.encode("");
        assert!(validate_encrypt_request(&empty_plaintext, &None).is_err());

        let aad = STANDARD.encode("additional data");
        assert!(validate_encrypt_request(&plaintext, &Some(aad)).is_ok());
    }

    #[test]
    fn test_decrypt_request_validation() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let ciphertext = STANDARD.encode("hello");
        let nonce = STANDARD.encode("123456789012");
        let tag = STANDARD.encode("tagdata");
        assert!(validate_decrypt_request(&ciphertext, &nonce, &tag, &None).is_ok());

        // Invalid base64 ciphertext
        assert!(validate_decrypt_request("not!valid", &nonce, &tag, &None).is_err());

        // With AAD
        let aad = STANDARD.encode("additional data");
        assert!(validate_decrypt_request(&ciphertext, &nonce, &tag, &Some(aad)).is_ok());
    }

    // ── Security regression boundary tests ──

    /// Key names must reject SQL injection patterns
    #[test]
    fn test_key_name_rejects_sql_injection() {
        assert!(validate_key_name("'; DROP TABLE keys; --").is_err());
        assert!(validate_key_name("1' OR '1'='1").is_err());
        assert!(validate_key_name("x'; DELETE FROM users WHERE '1'='1").is_err());
        assert!(validate_key_name("admin'--").is_err());
    }

    /// Key names must reject XSS patterns
    #[test]
    fn test_key_name_rejects_xss() {
        assert!(validate_key_name("<script>alert(1)</script>").is_err());
        assert!(validate_key_name("javascript:alert(1)").is_err());
        assert!(validate_key_name("<img src=x onerror=alert(1)>").is_err());
    }

    /// Tenant ID must reject path traversal patterns
    #[test]
    fn test_tenant_id_rejects_path_traversal() {
        assert!(validate_tenant_id("../etc/passwd").is_err());
        assert!(validate_tenant_id("..\\windows").is_err());
        assert!(validate_tenant_id("tenant/../admin").is_err());
    }

    /// Every supported spec must pass validation; common false specs must fail
    #[test]
    fn test_spec_allowlist_coverage() {
        for spec in SUPPORTED_SPECS {
            assert!(
                validate_spec(spec).is_ok(),
                "valid spec '{spec}' was rejected"
            );
        }

        // Common algorithms that are NOT in the allowlist
        for bad in &["aes-128-gcm", "des", "rc4", "md5", "sha1", "null"] {
            assert!(
                validate_spec(bad).is_err(),
                "invalid spec '{bad}' should be rejected"
            );
        }
    }

    /// Empty or whitespace-only data must be rejected
    #[test]
    fn test_empty_data_rejected() {
        assert!(validate_key_name("").is_err());
        assert!(validate_tenant_id("").is_err());

        // Empty base64 data
        use base64::{Engine, engine::general_purpose::STANDARD};
        let empty_b64 = STANDARD.encode("");
        // decode gives empty — validation for encrypt should catch empty plaintext
        assert!(validate_encrypt_request(&empty_b64, &None).is_err());
    }
}
