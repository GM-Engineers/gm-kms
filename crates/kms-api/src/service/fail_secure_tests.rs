//! Fail-secure service layer tests
//!
//! Integration tests verifying that [`CryptoService`] and [`KeyService`] fail
//! securely when the underlying keystore is unavailable (fault injected).
//!
//! Uses [`FaultWrappedKeystore`](crate::fault_wrapper::FaultWrappedKeystore) +
//! [`SoftwareKeystore`](kms_keystore::SoftwareKeystore) to simulate keystore
//! failures and verify that:
//!
//! - Operations return errors, not panics
//! - Error messages don't leak key material or plaintext
//! - Concurrent operations all fail safely

use crate::chaos::{FaultConfig, FaultInjector};
use crate::fault_wrapper::FaultWrappedKeystore;
use crate::{KmsMetrics, KmsState, Sm9State};
use kms_core::key::KeySpec;
use kms_keystore::{KeystoreBackend, SoftwareKeystore};
use std::sync::Arc;

use super::{CryptoService, KeyService};

/// Build a KmsState with a fault-injecting keystore at the given probability.
fn make_faulty_state(software: Arc<SoftwareKeystore>, injector: Arc<FaultInjector>) -> KmsState {
    let fault_keystore = Arc::new(FaultWrappedKeystore::new(software, injector))
        as Arc<dyn kms_keystore::KeystoreBackend>;
    KmsState::new(
        fault_keystore,
        kms_policy::PBACEngine::new(),
        Arc::new(kms_audit::AuditLogger::with_stdout()),
        Sm9State {
            master_key: gm_sm9_rs::KgcMasterKey::generate().expect("failed to generate master key"),
            repository: None,
        },
        KmsMetrics::new(),
    )
}

// ── Fail-secure: CryptoService ──

/// Encrypt fails with an error when the keystore is unavailable (fault injected).
#[tokio::test]
async fn test_encrypt_fails_secure_when_keystore_unavailable() {
    let software = Arc::new(SoftwareKeystore::new());

    // Create a key directly (no fault yet)
    let meta = software
        .generate_key(&KeySpec::Aes256Gcm, "fail-enc", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    // Now inject fault at 100%
    let injector = Arc::new(FaultInjector::new());
    injector.configure(FaultConfig::fail(1.0));
    let state = make_faulty_state(software, injector);
    let svc = CryptoService::new(&state);

    let result = svc
        .encrypt(&key_id, b"plaintext", None, "test-tenant", "user1")
        .await;
    assert!(
        result.is_err(),
        "Encrypt should fail when keystore unavailable"
    );
}

/// Decrypt fails with an error when the keystore is unavailable (fault injected).
#[tokio::test]
async fn test_decrypt_fails_secure_when_keystore_unavailable() {
    let software = Arc::new(SoftwareKeystore::new());

    // Create key and ciphertext directly
    let meta = software
        .generate_key(&KeySpec::Aes256Gcm, "fail-dec", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;
    let ct = software
        .encrypt(&key_id, b"secret", None, "test-tenant")
        .await
        .unwrap();

    // Now inject fault at 100%
    let injector = Arc::new(FaultInjector::new());
    injector.configure(FaultConfig::fail(1.0));
    let state = make_faulty_state(software, injector);
    let svc = CryptoService::new(&state);

    let result = svc
        .decrypt(&key_id, &ct, None, "test-tenant", "user1")
        .await;
    assert!(
        result.is_err(),
        "Decrypt should fail when keystore unavailable"
    );
}

/// Sign fails with an error when the keystore is unavailable (fault injected).
#[tokio::test]
async fn test_sign_fails_secure_when_keystore_unavailable() {
    let software = Arc::new(SoftwareKeystore::new());

    let meta = software
        .generate_key(&KeySpec::Ed25519, "fail-sign", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    let injector = Arc::new(FaultInjector::new());
    injector.configure(FaultConfig::fail(1.0));
    let state = make_faulty_state(software, injector);
    let svc = CryptoService::new(&state);

    let result = svc.sign(&key_id, b"message", "test-tenant", "user1").await;
    assert!(
        result.is_err(),
        "Sign should fail when keystore unavailable"
    );
}

// ── Fail-secure: KeyService ──

/// Key creation fails with an error when the keystore is unavailable.
#[tokio::test]
async fn test_key_creation_fails_secure() {
    let software = Arc::new(SoftwareKeystore::new());

    let injector = Arc::new(FaultInjector::new());
    injector.configure(FaultConfig::fail(1.0));
    let state = make_faulty_state(software, injector);
    let svc = KeyService::new(&state);

    let result = svc
        .create_key(KeySpec::Aes256Gcm, "should-fail", "test-tenant", "user1")
        .await;
    assert!(
        result.is_err(),
        "Key creation should fail when keystore unavailable"
    );
}

// ── Error message sanitization ──

/// Error messages from fail-secure operations must not leak key material or plaintext.
#[tokio::test]
async fn test_fail_secure_does_not_leak_key_material_in_error() {
    let software = Arc::new(SoftwareKeystore::new());

    let meta = software
        .generate_key(&KeySpec::Aes256Gcm, "no-leak", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    let sensitive_data = b"s3cr3t-plaintext-should-not-appear";

    let injector = Arc::new(FaultInjector::new());
    injector.configure(FaultConfig::fail(1.0));
    let state = make_faulty_state(software, injector);
    let svc = CryptoService::new(&state);

    let result = svc
        .encrypt(&key_id, sensitive_data, None, "test-tenant", "user1")
        .await;
    assert!(result.is_err());

    let err_msg = result.unwrap_err().to_string();

    // Error must not contain the plaintext
    assert!(
        !err_msg.contains("s3cr3t"),
        "Error message must not leak plaintext: {err_msg}"
    );
    // Error must not contain the key_id
    assert!(
        !err_msg.contains(&key_id.to_string()),
        "Error message must not leak key_id: {err_msg}"
    );

    // Error should be a generic internal error or fault message
    assert!(
        err_msg.contains("fault injected") || err_msg.contains("internal"),
        "Error should be a generic internal error, got: {err_msg}"
    );
}

// ── Concurrent fault injection ──

/// Multiple concurrent operations with fault injection all fail safely.
#[tokio::test]
async fn test_concurrent_fault_injection() {
    let software = Arc::new(SoftwareKeystore::new());

    // Create two keys directly
    let meta_a = software
        .generate_key(&KeySpec::Aes256Gcm, "conc-a", "test-tenant")
        .await
        .unwrap();
    let meta_b = software
        .generate_key(&KeySpec::Aes256Gcm, "conc-b", "test-tenant")
        .await
        .unwrap();

    let injector = Arc::new(FaultInjector::new());
    injector.configure(FaultConfig::fail(1.0));
    let state = make_faulty_state(software, injector);
    let svc = Arc::new(CryptoService::new(&state));

    // Spawn 4 concurrent encrypt tasks — all should fail
    let mut handles = Vec::new();
    for i in 0..4 {
        let svc = svc.clone();
        let key_id = if i % 2 == 0 { meta_a.id } else { meta_b.id };
        handles.push(tokio::spawn(async move {
            svc.encrypt(&key_id, b"concurrent-data", None, "test-tenant", "user1")
                .await
        }));
    }

    for handle in handles {
        let result = handle.await.unwrap();
        assert!(
            result.is_err(),
            "All concurrent operations should fail during fault injection"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            !err.contains("concurrent-data"),
            "Error must not leak plaintext: {err}"
        );
    }
}

// ── Edge cases ──

/// With 0% fault probability, operations succeed normally (no false positives).
#[tokio::test]
async fn test_zero_fault_probability_passes_through() {
    let software = Arc::new(SoftwareKeystore::new());

    let meta = software
        .generate_key(&KeySpec::Aes256Gcm, "no-fault", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    let injector = Arc::new(FaultInjector::new());
    injector.configure(FaultConfig::fail(0.0));
    let state = make_faulty_state(software, injector);
    let svc = CryptoService::new(&state);

    let result = svc
        .encrypt(&key_id, b"hello", None, "test-tenant", "user1")
        .await;
    assert!(
        result.is_ok(),
        "With 0% fault probability, operations should succeed"
    );
}

/// KeyService rotate fails secure when keystore unavailable.
#[tokio::test]
async fn test_key_rotate_fails_secure() {
    let software = Arc::new(SoftwareKeystore::new());

    // Create key directly
    let meta = software
        .generate_key(&KeySpec::Aes256Gcm, "rot-fail", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    let injector = Arc::new(FaultInjector::new());
    injector.configure(FaultConfig::fail(1.0));
    let state = make_faulty_state(software, injector);
    let svc = KeyService::new(&state);

    let result = svc.rotate_key(&key_id, "test-tenant", "user1").await;
    assert!(
        result.is_err(),
        "Key rotation should fail when keystore unavailable"
    );
}

/// KeyService delete fails secure when keystore unavailable.
#[tokio::test]
async fn test_key_delete_fails_secure() {
    let software = Arc::new(SoftwareKeystore::new());

    let meta = software
        .generate_key(&KeySpec::Aes256Gcm, "del-fail", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    let injector = Arc::new(FaultInjector::new());
    injector.configure(FaultConfig::fail(1.0));
    let state = make_faulty_state(software, injector);
    let svc = KeyService::new(&state);

    let result = svc.delete_key(&key_id, "test-tenant", "user1").await;
    assert!(
        result.is_err(),
        "Key deletion should fail when keystore unavailable"
    );
}

/// Verify fails secure when keystore unavailable.
#[tokio::test]
async fn test_verify_fails_secure() {
    let software = Arc::new(SoftwareKeystore::new());

    let meta = software
        .generate_key(&KeySpec::Ed25519, "ver-fail", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;
    let sig = software.sign(&key_id, b"msg", "test-tenant").await.unwrap();

    let injector = Arc::new(FaultInjector::new());
    injector.configure(FaultConfig::fail(1.0));
    let state = make_faulty_state(software, injector);
    let svc = CryptoService::new(&state);

    let result = svc.verify(&key_id, b"msg", &sig, "test-tenant").await;
    assert!(
        result.is_err(),
        "Verify should fail when keystore unavailable"
    );
}

/// Data corruption fault mode produces distinct error from failure fault mode.
#[tokio::test]
async fn test_corruption_fault_mode() {
    let software = Arc::new(SoftwareKeystore::new());

    let meta = software
        .generate_key(&KeySpec::Aes256Gcm, "corrupt", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    let injector = Arc::new(FaultInjector::new());
    injector.configure(FaultConfig::corrupt(1.0));
    let state = make_faulty_state(software, injector);
    let svc = CryptoService::new(&state);

    let result = svc
        .encrypt(&key_id, b"data", None, "test-tenant", "user1")
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("corrupted"),
        "Corruption fault should mention corrupted data: {err}"
    );
}
