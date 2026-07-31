//! Property-based tests for key module
//!
//! Uses proptest for comprehensive input testing.

use crate::key::{KeyFilter, KeyMeta, KeySpec, KeyStatus};
use chrono::Utc;
use proptest::prelude::*;
use uuid::Uuid;

/// Test that KeySpec JSON deserialization doesn't panic on any string input
#[test]
fn test_key_spec_json_deserialization_no_panic() {
    proptest!(|(s in "\\PC*")| {
        // Should not panic regardless of input
        let result: Result<KeySpec, _> = serde_json::from_str(&s);
        // If it parses successfully, verify the spec methods work
        if let Ok(spec) = result {
            let _ = spec.algorithm_name();
            let _ = spec.is_asymmetric();
            let _ = spec.is_symmetric();
            let _ = spec.supports_encryption();
            let _ = spec.supports_signing();
        }
    });
}

/// Test that KeySpec has consistent boolean logic
#[test]
fn test_key_spec_boolean_consistency() {
    proptest!(|(spec in prop_oneof![
        Just(KeySpec::Aes256Gcm),
        Just(KeySpec::Sm4),
        Just(KeySpec::Sm2),
        Just(KeySpec::Ed25519),
        Just(KeySpec::EcdsaP256),
        Just(KeySpec::EcdsaP384),
        Just(KeySpec::Rsa4096),
        Just(KeySpec::HmacSha256),
        Just(KeySpec::Sm9Signing),
        Just(KeySpec::Sm9Encryption),
        Just(KeySpec::Ed448),
    ])| {
        let is_asym = spec.is_asymmetric();
        let is_sym = spec.is_symmetric();

        // Symmetric and asymmetric are mutually exclusive
        prop_assert!(!(is_asym && is_sym));

        // All specs should support at least one of encryption or signing
        let supports_enc = spec.supports_encryption();
        let supports_sign = spec.supports_signing();
        prop_assert!(supports_enc || supports_sign || matches!(spec, KeySpec::HmacSha256));
    });
}

/// Test KeyStatus state machine consistency
#[test]
fn test_key_status_state_machine() {
    // Active key can be used
    assert!(KeyStatus::Active.can_use());
    assert!(KeyStatus::Active.can_decrypt());
    assert!(KeyStatus::Active.can_rotate());

    // PendingDeletion can decrypt but not use or rotate
    assert!(!KeyStatus::PendingDeletion.can_use());
    assert!(KeyStatus::PendingDeletion.can_decrypt());
    assert!(!KeyStatus::PendingDeletion.can_rotate());

    // Obsolete cannot be used but can decrypt (for backward compatibility)
    assert!(!KeyStatus::Obsolete.can_use());
    assert!(KeyStatus::Obsolete.can_decrypt());
    assert!(KeyStatus::Obsolete.can_rotate());

    // Destroyed cannot do anything
    assert!(!KeyStatus::Destroyed.can_use());
    assert!(!KeyStatus::Destroyed.can_decrypt());
    assert!(!KeyStatus::Destroyed.can_rotate());
}

/// Test KeyFilter defaults are sensible
#[test]
fn test_key_filter_default() {
    let filter = KeyFilter::default();
    assert!(filter.tenant_id.is_none());
    assert!(filter.status.is_none());
    assert!(filter.spec.is_none());
    assert!(filter.tags.is_none());
    assert!(filter.limit.is_none());
    assert!(filter.offset.is_none());
}

/// Test KeyFilter can be deserialized from partial JSON
#[test]
fn test_key_filter_partial_deserialization() {
    // Empty filter
    let filter: KeyFilter = serde_json::from_str("{}").unwrap();
    assert!(filter.tenant_id.is_none());

    // Filter with only tenant_id
    let filter: KeyFilter = serde_json::from_str(r#"{"tenant_id": "test-tenant"}"#).unwrap();
    assert_eq!(filter.tenant_id, Some("test-tenant".to_string()));
}

/// Test KeyMeta can be serialized and deserialized
#[test]
fn test_key_meta_serde_roundtrip() {
    let meta = KeyMeta {
        id: Uuid::new_v4(),
        tenant_id: "test-tenant".to_string(),
        name: "test-key".to_string(),
        spec: KeySpec::Aes256Gcm,
        status: KeyStatus::Active,
        created_at: Utc::now(),
        rotated_at: None,
        version: 1,
        description: Some("Test key".to_string()),
        metadata: Default::default(),
    };

    let json = serde_json::to_string(&meta).unwrap();
    let deserialized: KeyMeta = serde_json::from_str(&json).unwrap();

    assert_eq!(meta.id, deserialized.id);
    assert_eq!(meta.tenant_id, deserialized.tenant_id);
    assert_eq!(meta.name, deserialized.name);
    assert_eq!(meta.spec, deserialized.spec);
    assert_eq!(meta.status, deserialized.status);
    assert_eq!(meta.version, deserialized.version);
}
