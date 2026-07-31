//! Key material validation
//!
//! Provides format validation for imported key material.

use kms_core::error::Error;
use kms_core::key::KeySpec;

/// Result of key validation
#[derive(Debug, Clone)]
pub struct KeyValidationResult {
    /// Whether the key is valid
    pub valid: bool,
    /// Error message if invalid
    pub error: Option<String>,
    /// Algorithm-specific metadata
    pub metadata: KeyMetadata,
}

/// Additional metadata extracted during validation
#[derive(Debug, Clone, Default)]
pub struct KeyMetadata {
    /// Curve identifier if applicable (for EC keys)
    pub curve: Option<String>,
    /// Key usage hints
    pub usage: Option<String>,
}

/// Validate key material according to its specification
pub fn validate_key_material(
    spec: &KeySpec,
    material: &[u8],
) -> Result<KeyValidationResult, Error> {
    match spec {
        KeySpec::Ed25519 => validate_ed25519_key(material),
        KeySpec::EcdsaP256 => validate_ecdsa_key(material, "P-256"),
        KeySpec::EcdsaP384 => validate_ecdsa_key(material, "P-384"),
        KeySpec::Sm2 => validate_sm2_key(material),
        KeySpec::Rsa4096 => validate_rsa_key(material),
        // Symmetric keys - only size validation
        KeySpec::Aes256Gcm | KeySpec::HmacSha256 => validate_symmetric_key(material, 32),
        KeySpec::Sm4 => validate_symmetric_key(material, 16),
        // SM9 uses identity-based crypto, skip format validation
        KeySpec::Sm9Signing | KeySpec::Sm9Encryption => Ok(KeyValidationResult {
            valid: true,
            error: None,
            metadata: KeyMetadata::default(),
        }),
        // Ed448 usescurve25519
        KeySpec::Ed448 => validate_ed448_key(material),
    }
}

/// Validate Ed25519 private key (RFC 8037)
fn validate_ed25519_key(material: &[u8]) -> Result<KeyValidationResult, Error> {
    // Ed25519 private key should be 32 bytes raw OR 48+ bytes for PKCS#8
    // RFC 8037: Private key is 32 bytes
    // PKCS#8: SEQUENCE { version, privateKey AlgorithmIdentifier, privateKey OCTET STRING }
    if material.len() == 32 {
        // Raw Ed25519 private key - valid
        Ok(KeyValidationResult {
            valid: true,
            error: None,
            metadata: KeyMetadata {
                curve: Some("Ed25519".to_string()),
                usage: Some("signing".to_string()),
            },
        })
    } else if material.len() >= 48 {
        // Could be PKCS#8 - try to parse
        validate_pkcs8_ed25519(material)?;
        Ok(KeyValidationResult {
            valid: true,
            error: None,
            metadata: KeyMetadata {
                curve: Some("Ed25519".to_string()),
                usage: Some("signing".to_string()),
            },
        })
    } else {
        Ok(KeyValidationResult {
            valid: false,
            error: Some(format!(
                "Ed25519 private key must be 32 bytes (raw) or 48+ bytes (PKCS#8), got {} bytes",
                material.len()
            )),
            metadata: KeyMetadata::default(),
        })
    }
}

/// Validate Ed448 private key
fn validate_ed448_key(material: &[u8]) -> Result<KeyValidationResult, Error> {
    // Ed448 private key should be 57 bytes raw
    if material.len() == 57 {
        Ok(KeyValidationResult {
            valid: true,
            error: None,
            metadata: KeyMetadata {
                curve: Some("Ed448".to_string()),
                usage: Some("signing".to_string()),
            },
        })
    } else if material.len() >= 64 {
        // Could be PKCS#8
        Ok(KeyValidationResult {
            valid: true,
            error: None,
            metadata: KeyMetadata {
                curve: Some("Ed448".to_string()),
                usage: Some("signing".to_string()),
            },
        })
    } else {
        Ok(KeyValidationResult {
            valid: false,
            error: Some(format!(
                "Ed448 private key must be 57 bytes (raw), got {} bytes",
                material.len()
            )),
            metadata: KeyMetadata::default(),
        })
    }
}

/// Validate PKCS#8 Ed25519 private key
fn validate_pkcs8_ed25519(material: &[u8]) -> Result<(), Error> {
    // Simplified PKCS#8 validation for Ed25519
    // Format: SEQUENCE { INTEGER(0), SEQUENCE { OID }, OCTET STRING(32) }
    if material.len() < 48 {
        return Err(Error::InvalidAlgorithm(
            "PKCS#8 Ed25519 key too short".to_string(),
        ));
    }

    // Check sequence tag
    if material[0] != 0x30 {
        return Err(Error::InvalidAlgorithm(
            "Invalid PKCS#8: expected SEQUENCE".to_string(),
        ));
    }

    // Basic ASN.1 structure check (simplified)
    // In production, use asn1 crate for full parsing
    Ok(())
}

/// Validate ECDSA private key (RFC 5915 / SEC1)
fn validate_ecdsa_key(material: &[u8], curve: &str) -> Result<KeyValidationResult, Error> {
    let expected_size = match curve {
        "P-256" => 32,
        "P-384" => 48,
        _ => return Err(Error::InvalidAlgorithm(format!("Unknown curve: {}", curve))),
    };

    if material.len() == expected_size {
        // Raw EC private key (just the scalar) - valid
        Ok(KeyValidationResult {
            valid: true,
            error: None,
            metadata: KeyMetadata {
                curve: Some(curve.to_string()),
                usage: Some("signing".to_string()),
            },
        })
    } else if material.len() >= expected_size + 8 {
        // Could be PKCS#8 or SEC1 with metadata
        validate_pkcs8_ec(curve, material)?;
        Ok(KeyValidationResult {
            valid: true,
            error: None,
            metadata: KeyMetadata {
                curve: Some(curve.to_string()),
                usage: Some("signing".to_string()),
            },
        })
    } else {
        Ok(KeyValidationResult {
            valid: false,
            error: Some(format!(
                "{} private key must be {} bytes (raw) or {} bytes (PKCS#8), got {} bytes",
                curve,
                expected_size,
                expected_size + 8,
                material.len()
            )),
            metadata: KeyMetadata::default(),
        })
    }
}

/// Validate PKCS#8 EC private key
fn validate_pkcs8_ec(curve: &str, material: &[u8]) -> Result<(), Error> {
    if material.len() < 40 {
        return Err(Error::InvalidAlgorithm(
            "PKCS#8 EC key too short".to_string(),
        ));
    }

    // Check sequence tag
    if material[0] != 0x30 {
        return Err(Error::InvalidAlgorithm(
            "Invalid PKCS#8: expected SEQUENCE".to_string(),
        ));
    }

    // Basic structure validation (simplified - full validation would parse ASN.1)
    // In production, use asn1 crate
    match curve {
        "P-256" | "P-384" => Ok(()),
        _ => Err(Error::InvalidAlgorithm(format!("Unknown curve: {}", curve))),
    }
}

/// Validate SM2 private key (GM/T 0003-2012)
fn validate_sm2_key(material: &[u8]) -> Result<KeyValidationResult, Error> {
    // SM2 private key is 32 bytes (256 bits)
    if material.len() != 32 {
        return Ok(KeyValidationResult {
            valid: false,
            error: Some(format!(
                "SM2 private key must be 32 bytes, got {} bytes",
                material.len()
            )),
            metadata: KeyMetadata::default(),
        });
    }

    // SM2 curve parameters are fixed, so we just validate the key is non-zero
    let is_zero = material.iter().all(|&b| b == 0);
    if is_zero {
        return Ok(KeyValidationResult {
            valid: false,
            error: Some("SM2 private key cannot be zero".to_string()),
            metadata: KeyMetadata::default(),
        });
    }

    // Validate key is less than the curve order
    // SM2 curve order: 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    const SM2_N: &[u8] = &[
        0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x72, 0x03, 0xDF,
        0x6B, 0x21, 0xC6, 0x05, 0x2B, 0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23,
    ];

    // Check if key >= curve order (invalid)
    let key_bytes: &[u8] = material;
    for i in (0..32).rev() {
        let key_byte = key_bytes[i];
        let n_byte = SM2_N[31 - i];
        if key_byte > n_byte {
            return Ok(KeyValidationResult {
                valid: false,
                error: Some("SM2 private key >= curve order (invalid)".to_string()),
                metadata: KeyMetadata::default(),
            });
        } else if key_byte < n_byte {
            break;
        }
    }

    Ok(KeyValidationResult {
        valid: true,
        error: None,
        metadata: KeyMetadata {
            curve: Some("SM2".to_string()),
            usage: Some("signing/encryption".to_string()),
        },
    })
}

/// Validate RSA private key (PKCS#1 or PKCS#8)
fn validate_rsa_key(material: &[u8]) -> Result<KeyValidationResult, Error> {
    // RSA-4096 private key in PKCS#8 format should be 360+ bytes minimum
    // Simplified validation - check minimum size and structure
    if material.len() < 256 {
        return Ok(KeyValidationResult {
            valid: false,
            error: Some(format!(
                "RSA-4096 private key must be at least 256 bytes (PKCS#8), got {} bytes",
                material.len()
            )),
            metadata: KeyMetadata::default(),
        });
    }

    // Check sequence tag
    if material[0] != 0x30 {
        return Ok(KeyValidationResult {
            valid: false,
            error: Some("Invalid RSA key: expected SEQUENCE (PKCS#8)".to_string()),
            metadata: KeyMetadata::default(),
        });
    }

    Ok(KeyValidationResult {
        valid: true,
        error: None,
        metadata: KeyMetadata {
            curve: None,
            usage: Some("signing/encryption".to_string()),
        },
    })
}

/// Validate symmetric key (AES, HMAC, SM4)
fn validate_symmetric_key(
    material: &[u8],
    expected_size: usize,
) -> Result<KeyValidationResult, Error> {
    if material.len() != expected_size {
        return Ok(KeyValidationResult {
            valid: false,
            error: Some(format!(
                "Symmetric key must be {} bytes, got {} bytes",
                expected_size,
                material.len()
            )),
            metadata: KeyMetadata::default(),
        });
    }

    // Check for weak keys
    let is_all_zeros = material.iter().all(|&b| b == 0);
    let is_all_ones = material.iter().all(|&b| b == 0xFF);

    if is_all_zeros {
        return Ok(KeyValidationResult {
            valid: false,
            error: Some("Weak key detected: all zeros".to_string()),
            metadata: KeyMetadata::default(),
        });
    }

    if is_all_ones {
        return Ok(KeyValidationResult {
            valid: false,
            error: Some("Weak key detected: all 0xFF".to_string()),
            metadata: KeyMetadata::default(),
        });
    }

    Ok(KeyValidationResult {
        valid: true,
        error: None,
        metadata: KeyMetadata::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_aes256_key() {
        // Valid 32-byte key
        let key = vec![0x42u8; 32];
        let result = validate_key_material(&KeySpec::Aes256Gcm, &key).unwrap();
        assert!(result.valid);

        // Wrong size
        let result = validate_key_material(&KeySpec::Aes256Gcm, &[0x42u8; 16]).unwrap();
        assert!(!result.valid);

        // Weak key (all zeros)
        let result = validate_key_material(&KeySpec::Aes256Gcm, &[0u8; 32]).unwrap();
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("Weak key"));
    }

    #[test]
    fn test_validate_sm4_key() {
        // Valid 16-byte key
        let key = vec![0xABu8; 16];
        let result = validate_key_material(&KeySpec::Sm4, &key).unwrap();
        assert!(result.valid);

        // Wrong size
        let result = validate_key_material(&KeySpec::Sm4, &[0xABu8; 32]).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_sm2_key() {
        // Valid 32-byte SM2 key (not zero, not >= curve order)
        let key = vec![0x01u8; 32];
        let result = validate_key_material(&KeySpec::Sm2, &key).unwrap();
        assert!(result.valid);
        assert_eq!(result.metadata.curve, Some("SM2".to_string()));

        // Zero key
        let result = validate_key_material(&KeySpec::Sm2, &[0u8; 32]).unwrap();
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("cannot be zero"));

        // Wrong size
        let result = validate_key_material(&KeySpec::Sm2, &[0x01u8; 31]).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_ed25519_key() {
        // Valid 32-byte raw key
        let key = vec![0x1Eu8; 32];
        let result = validate_key_material(&KeySpec::Ed25519, &key).unwrap();
        assert!(result.valid);
        assert_eq!(result.metadata.curve, Some("Ed25519".to_string()));

        // Wrong size
        let result = validate_key_material(&KeySpec::Ed25519, &[0x1Eu8; 16]).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_ecdsa_p256_key() {
        // Valid 32-byte raw key
        let key = vec![0x1Fu8; 32];
        let result = validate_key_material(&KeySpec::EcdsaP256, &key).unwrap();
        assert!(result.valid);
        assert_eq!(result.metadata.curve, Some("P-256".to_string()));

        // Wrong size (too short)
        let result = validate_key_material(&KeySpec::EcdsaP256, &[0x1Fu8; 16]).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_ecdsa_p384_key() {
        // Valid 48-byte raw key
        let key = vec![0x20u8; 48];
        let result = validate_key_material(&KeySpec::EcdsaP384, &key).unwrap();
        assert!(result.valid);
        assert_eq!(result.metadata.curve, Some("P-384".to_string()));

        // Wrong size
        let result = validate_key_material(&KeySpec::EcdsaP384, &[0x20u8; 32]).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_rsa_key() {
        // Minimum valid size for RSA-4096
        let key = vec![0x30u8; 300]; // SEQUENCE tag followed by enough bytes
        let result = validate_key_material(&KeySpec::Rsa4096, &key).unwrap();
        assert!(result.valid);

        // Too short
        let key = vec![0x30u8; 100];
        let result = validate_key_material(&KeySpec::Rsa4096, &key).unwrap();
        assert!(!result.valid);

        // Wrong tag (not SEQUENCE)
        let key = vec![0x31u8; 300];
        let result = validate_key_material(&KeySpec::Rsa4096, &key).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_sm9_keys() {
        // SM9 uses identity-based crypto, so format varies
        let key = vec![0xFFu8; 64];
        let result = validate_key_material(&KeySpec::Sm9Signing, &key).unwrap();
        assert!(result.valid);

        let result = validate_key_material(&KeySpec::Sm9Encryption, &key).unwrap();
        assert!(result.valid);
    }

    // --- Additional edge case tests ---

    #[test]
    fn test_validate_hmac_sha256_key() {
        // Valid 32-byte HMAC key
        let key = vec![0x33u8; 32];
        let result = validate_key_material(&KeySpec::HmacSha256, &key).unwrap();
        assert!(result.valid);

        // Wrong size
        let result = validate_key_material(&KeySpec::HmacSha256, &[0x33u8; 16]).unwrap();
        assert!(!result.valid);

        // Weak key (all zeros)
        let result = validate_key_material(&KeySpec::HmacSha256, &[0u8; 32]).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_aes256_empty_key() {
        let result = validate_key_material(&KeySpec::Aes256Gcm, &[]).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_sm4_empty_key() {
        let result = validate_key_material(&KeySpec::Sm4, &[]).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_ed25519_pkcs8_format() {
        // PKCS#8 Ed25519 typically ~48+ bytes
        let key = vec![0x30u8; 48];
        let result = validate_key_material(&KeySpec::Ed25519, &key).unwrap();
        // Should attempt PKCS#8 parsing
        // (result depends on parsing, but at least should not panic)
        let _ = result.valid;
    }

    #[test]
    fn test_validate_ed448_key() {
        // Ed448 private key is 57 bytes raw
        let key = vec![0x55u8; 57];
        let result = validate_key_material(&KeySpec::Ed448, &key).unwrap();
        // Should not panic
        let _ = result.valid;
    }

    #[test]
    fn test_validation_result_default_metadata() {
        let md = KeyMetadata::default();
        assert!(md.curve.is_none());
        assert!(md.usage.is_none());
    }
}
