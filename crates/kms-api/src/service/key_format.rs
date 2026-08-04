//! Key format parsing for import/export operations
//!
//! Supports parsing key material from various formats:
//! - `raw`: Raw bytes (symmetric keys)
//! - `pkcs8` / `pkcs#8` / `pem`: PKCS#8 PEM format for asymmetric keys
//! - `jwk`: JSON Web Key format (RFC 7517)

use base64::{Engine, engine::general_purpose::STANDARD};

/// Errors that can occur during key format parsing
#[derive(Debug, thiserror::Error)]
pub enum KeyFormatError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),
}

/// Parser for key material in various formats
pub struct KeyFormatParser;

impl KeyFormatParser {
    /// Parse key material from various formats (raw, PKCS#8, JWK)
    pub fn parse(format: &str, key_data: &[u8]) -> Result<Vec<u8>, KeyFormatError> {
        match format.to_lowercase().as_str() {
            "raw" => Self::parse_raw(key_data),
            "pkcs8" | "pkcs#8" | "pem" => Self::parse_pkcs8(key_data),
            "jwk" => Self::parse_jwk(key_data),
            _ => Err(KeyFormatError::UnsupportedFormat(format!(
                "unsupported key format: {format} (use: raw, pkcs8, jwk)"))),
        }
    }

    /// Parse raw format: use bytes directly
    pub fn parse_raw(key_data: &[u8]) -> Result<Vec<u8>, KeyFormatError> {
        Ok(key_data.to_vec())
    }

    /// Parse PKCS#8 PEM format
    ///
    /// Expected format:
    /// ```text
    /// -----BEGIN PRIVATE KEY-----
    /// <base64-encoded key data>
    /// -----END PRIVATE KEY-----
    /// ```
    pub fn parse_pkcs8(key_data: &[u8]) -> Result<Vec<u8>, KeyFormatError> {
        let pem_content = String::from_utf8(key_data.to_vec()).map_err(|_| {
            KeyFormatError::InvalidRequest("PKCS#8 must be valid UTF-8 PEM".to_string())
        })?;

        let start_marker = "-----BEGIN PRIVATE KEY-----";
        let end_marker = "-----END PRIVATE KEY-----";

        let start_idx = pem_content.find(start_marker).ok_or_else(|| {
            KeyFormatError::InvalidRequest("missing PKCS#8 start marker".to_string())
        })?;
        let end_idx = pem_content.find(end_marker).ok_or_else(|| {
            KeyFormatError::InvalidRequest("missing PKCS#8 end marker".to_string())
        })?;

        let base64_content = &pem_content[start_idx + start_marker.len()..end_idx];
        let base64_content = base64_content.trim();

        STANDARD
            .decode(base64_content)
            .map_err(|_| KeyFormatError::InvalidRequest("invalid base64 in PKCS#8 PEM".to_string()))
    }

    /// Parse JWK (JSON Web Key) format per RFC 7517
    pub fn parse_jwk(key_data: &[u8]) -> Result<Vec<u8>, KeyFormatError> {
        let jwk_json = String::from_utf8(key_data.to_vec()).map_err(|_| {
            KeyFormatError::InvalidRequest("JWK must be valid UTF-8 JSON".to_string())
        })?;

        let jwk: serde_json::Value = serde_json::from_str(&jwk_json).map_err(|_| {
            KeyFormatError::InvalidRequest("invalid JWK JSON structure".to_string())
        })?;

        let kty = jwk.get("kty").and_then(|v| v.as_str()).ok_or_else(|| {
            KeyFormatError::InvalidRequest("JWK missing required 'kty' field".to_string())
        })?;

        match kty {
            "oct" => Self::parse_jwk_oct(&jwk),
            "RSA" => Self::parse_jwk_rsa(&jwk),
            "EC" => Self::parse_jwk_ec(&jwk),
            "SM2" => Self::parse_jwk_sm2(&jwk),
            _ => Err(KeyFormatError::InvalidRequest(format!(
                "unsupported JWK key type '{kty}' (supported: oct, RSA, EC, SM2)"))),
        }
    }

    fn parse_jwk_oct(jwk: &serde_json::Value) -> Result<Vec<u8>, KeyFormatError> {
        let k = jwk.get("k").and_then(|v| v.as_str()).ok_or_else(|| {
            KeyFormatError::InvalidRequest("JWK oct key missing required 'k' field".to_string())
        })?;

        STANDARD.decode(k).map_err(|_| {
            KeyFormatError::InvalidRequest("JWK 'k' field is not valid base64".to_string())
        })
    }

    fn parse_jwk_rsa(jwk: &serde_json::Value) -> Result<Vec<u8>, KeyFormatError> {
        let d = jwk.get("d").and_then(|v| v.as_str()).ok_or_else(|| {
            KeyFormatError::InvalidRequest("JWK RSA key missing required 'd' field".to_string())
        })?;

        let _ = jwk.get("n").and_then(|v| v.as_str()).ok_or_else(|| {
            KeyFormatError::InvalidRequest("JWK RSA key missing required 'n' field".to_string())
        })?;

        let _ = jwk.get("e").and_then(|v| v.as_str()).ok_or_else(|| {
            KeyFormatError::InvalidRequest("JWK RSA key missing required 'e' field".to_string())
        })?;

        STANDARD.decode(d).map_err(|_| {
            KeyFormatError::InvalidRequest("JWK 'd' field is not valid base64".to_string())
        })
    }

    fn parse_jwk_ec(jwk: &serde_json::Value) -> Result<Vec<u8>, KeyFormatError> {
        let d = jwk.get("d").and_then(|v| v.as_str()).ok_or_else(|| {
            KeyFormatError::InvalidRequest("JWK EC key missing required 'd' field".to_string())
        })?;

        STANDARD.decode(d).map_err(|_| {
            KeyFormatError::InvalidRequest("JWK 'd' field is not valid base64".to_string())
        })
    }

    fn parse_jwk_sm2(jwk: &serde_json::Value) -> Result<Vec<u8>, KeyFormatError> {
        let d = jwk.get("d").and_then(|v| v.as_str()).ok_or_else(|| {
            KeyFormatError::InvalidRequest("JWK SM2 key missing required 'd' field".to_string())
        })?;

        STANDARD.decode(d).map_err(|_| {
            KeyFormatError::InvalidRequest("JWK 'd' field is not valid base64".to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_raw() {
        let key_data = b"my_secret_key_32_bytes_long!!!!";
        let result = KeyFormatParser::parse("raw", key_data).unwrap();
        assert_eq!(result, key_data.to_vec());
    }

    #[test]
    fn test_parse_raw_uppercase() {
        let key_data = b"test_key";
        let result = KeyFormatParser::parse("RAW", key_data).unwrap();
        assert_eq!(result, key_data.to_vec());
    }

    #[test]
    fn test_parse_pkcs8_pem() {
        // PKCS#8 PEM with base64-encoded "test" bytes
        let pem = b"-----BEGIN PRIVATE KEY-----\ndGVzdA==\n-----END PRIVATE KEY-----";
        let result = KeyFormatParser::parse("pkcs8", pem).unwrap();
        assert_eq!(result, b"test".to_vec());
    }

    #[test]
    fn test_parse_pkcs8_pem_with_whitespace() {
        let pem = b"-----BEGIN PRIVATE KEY-----\n  dGVzdA==  \n-----END PRIVATE KEY-----";
        let result = KeyFormatParser::parse("pkcs8", pem).unwrap();
        assert_eq!(result, b"test".to_vec());
    }

    #[test]
    fn test_parse_pkcs8_invalid_utf8() {
        let invalid_utf8 = [0x80, 0x81, 0x82]; // invalid UTF-8
        let result = KeyFormatParser::parse("pkcs8", &invalid_utf8);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pkcs8_missing_start_marker() {
        let pem = b"-----END PRIVATE KEY-----\ndGVzdA==\n-----END PRIVATE KEY-----";
        let result = KeyFormatParser::parse("pkcs8", pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pkcs8_missing_end_marker() {
        let pem = b"-----BEGIN PRIVATE KEY-----\ndGVzdA==\n";
        let result = KeyFormatParser::parse("pkcs8", pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pkcs8_invalid_base64() {
        let pem = b"-----BEGIN PRIVATE KEY-----\n!!!invalid!!!\n-----END PRIVATE KEY-----";
        let result = KeyFormatParser::parse("pkcs8", pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_jwk_oct() {
        // JWK with kty: "oct" and k: base64("test_secret")
        let jwk = r#"{"kty":"oct","k":"dGVzdF9zZWNyZXQ="}"#;
        let result = KeyFormatParser::parse_jwk(jwk.as_bytes()).unwrap();
        assert_eq!(result, b"test_secret".to_vec());
    }

    #[test]
    fn test_parse_jwk_rsa() {
        // RSA JWK with d field containing base64 of "rsa_private_key"
        // echo -n "rsa_private_key" | base64 = "cnNhX3ByaXZhdGVfa2V5"
        let jwk =
            r#"{"kty":"RSA","n":"Base64EncodedModulus","e":"AQAB","d":"cnNhX3ByaXZhdGVfa2V5"}"#;
        let result = KeyFormatParser::parse_jwk(jwk.as_bytes()).unwrap();
        assert_eq!(result, b"rsa_private_key".to_vec());
    }

    #[test]
    fn test_parse_jwk_ec() {
        // EC JWK with d field - use valid base64 for 32-byte scalar
        // "AAAA" base64 = "QUFBQQ==", so 32 A's would be 8 groups of 4
        // Let me just use the actual base64 of "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        // which is: QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=
        let jwk = r#"{"kty":"EC","crv":"P-256","x":"fvp6Ve2Wz9xOOVKWejn4O4S9-U_P5q4lFbKNuY5yb8","d":"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="}"#;
        let result = KeyFormatParser::parse_jwk(jwk.as_bytes()).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_parse_jwk_sm2() {
        // SM2 JWK with d field - 32 bytes base64 encoded
        let jwk = r#"{"kty":"SM2","d":"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="}"#;
        let result = KeyFormatParser::parse_jwk(jwk.as_bytes()).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_parse_jwk_missing_kty() {
        let jwk = r#"{"k":"dGVzdA=="}"#;
        let result = KeyFormatParser::parse_jwk(jwk.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_jwk_unsupported_kty() {
        let jwk = r#"{"kty":"OKP","crv":"Ed25519"}"#;
        let result = KeyFormatParser::parse_jwk(jwk.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_jwk_oct_missing_k() {
        let jwk = r#"{"kty":"oct"}"#;
        let result = KeyFormatParser::parse_jwk(jwk.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_jwk_rsa_missing_d() {
        let jwk = r#"{"kty":"RSA","n":"Base64EncodedModulus","e":"AQAB"}"#;
        let result = KeyFormatParser::parse_jwk(jwk.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_unsupported_format() {
        let result = KeyFormatParser::parse("der", b"some data");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_case_insensitive() {
        // Format should be case-insensitive
        let jwk = r#"{"kty":"oct","k":"dGVzdA=="}"#;
        assert!(KeyFormatParser::parse("JWK", jwk.as_bytes()).is_ok());
        assert!(KeyFormatParser::parse("jwk", jwk.as_bytes()).is_ok());
        assert!(KeyFormatParser::parse("Jwk", jwk.as_bytes()).is_ok());
    }

    #[test]
    fn test_parse_pkcs8_aliases() {
        let pem = b"-----BEGIN PRIVATE KEY-----\ndGVzdA==\n-----END PRIVATE KEY-----";
        // pkcs8, pkcs#8, and pem should all work
        assert!(KeyFormatParser::parse("pkcs8", pem).is_ok());
        assert!(KeyFormatParser::parse("pkcs#8", pem).is_ok());
        assert!(KeyFormatParser::parse("pem", pem).is_ok());
    }
}
