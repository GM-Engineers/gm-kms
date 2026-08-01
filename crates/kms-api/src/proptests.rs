//! Property-based tests for validation module
//!
//! Uses proptest for comprehensive input validation testing.

use crate::validation::{
    MAX_DATA_LENGTH, MAX_KEY_NAME_LENGTH, validate_data_length, validate_key_name, validate_spec,
    validate_tenant_id,
};

/// Test that validate_key_name doesn't panic on any string
#[test]
fn test_validate_key_name_no_panic() {
    for s in ["simple", "with-dash", "valid_key_123", "", "a"] {
        let _ = validate_key_name(s);
    }
}

/// Test that validate_spec doesn't panic on any string
#[test]
fn test_validate_spec_no_panic() {
    for s in ["aes-256-gcm", "unknown", "", "invalid\n"] {
        let _ = validate_spec(s);
    }
}

/// Test that validate_tenant_id doesn't panic on any string
#[test]
fn test_validate_tenant_id_no_panic() {
    for s in ["tenant-1", "", "valid_tenant"] {
        let _ = validate_tenant_id(s);
    }
}

/// Test that valid key names pass validation
#[test]
fn test_valid_key_names() {
    let valid_names = vec![
        "simple",
        "with-dash",
        "with_underscore",
        "with.period",
        "Key123",
        "a",
        "abc123XYZ789",
    ];

    for name in valid_names {
        assert!(
            validate_key_name(name).is_ok(),
            "Expected '{}' to be valid",
            name
        );
    }
}

/// Test that valid specs pass validation
#[test]
fn test_valid_specs() {
    let valid_specs = vec![
        "aes-256-gcm",
        "ed25519",
        "ecdsa-p256",
        "ecdsa-p384",
        "sm4",
        "sm2",
        "sm9-signing",
        "sm9-encryption",
    ];

    for spec in valid_specs {
        assert!(
            validate_spec(spec).is_ok(),
            "Expected '{}' to be valid",
            spec
        );
    }
}

/// Test that invalid specs fail validation
#[test]
fn test_invalid_specs() {
    let invalid_specs = vec![
        "unknown",
        "aes-256-gcm; DROP TABLE keys;",
        "ed25519\nmalicious",
        "",
    ];

    for spec in invalid_specs {
        assert!(
            validate_spec(spec).is_err(),
            "Expected '{}' to be invalid",
            spec
        );
    }
}

/// Test that key name length limits work
#[test]
fn test_key_name_length_limit() {
    // Short name should work
    let short_name = "a".repeat(MAX_KEY_NAME_LENGTH);
    assert!(validate_key_name(&short_name).is_ok());

    // Too long should fail
    let long_name = "a".repeat(MAX_KEY_NAME_LENGTH + 1);
    assert!(validate_key_name(&long_name).is_err());
}

/// Test that data length limits work
#[test]
fn test_data_length_limit() {
    // Small data should work
    assert!(validate_data_length("hello", 100).is_ok());

    // Empty data should work
    assert!(validate_data_length("", 100).is_ok());

    // Too large should fail
    let large_data = "x".repeat(MAX_DATA_LENGTH + 1);
    assert!(validate_data_length(&large_data, MAX_DATA_LENGTH).is_err());
}
