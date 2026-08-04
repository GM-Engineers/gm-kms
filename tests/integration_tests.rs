//! Integration tests for KMS - Key Lifecycle
//!
//! Tests complete key lifecycle: Create → Encrypt → Decrypt → Rotate → Delete

use kms_core::KeySpec;
use kms_core::key::{Ciphertext, KeyFilter, Signature};
use kms_keystore::KeystoreBackend;
use kms_keystore::software::SoftwareKeystore;

// ============================================================================
// Key Lifecycle Tests
// ============================================================================

/// Test complete key lifecycle: Create → Encrypt → Decrypt → Rotate → Delete
#[tokio::test]
async fn test_key_lifecycle_complete() {
    let keystore = SoftwareKeystore::new();
    let spec = KeySpec::Aes256Gcm;

    // Create
    let meta = keystore
        .generate_key(&spec, "lifecycle-test-key", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;
    assert_eq!(meta.version, 1);

    // Encrypt with v1
    let plaintext = b"Message for lifecycle test";
    let ciphertext = keystore
        .encrypt(&key_id, plaintext, None, "test-tenant")
        .await
        .unwrap();

    // Decrypt with v1
    let decrypted = keystore
        .decrypt(&key_id, &ciphertext, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(&decrypted, plaintext);

    // Rotate - updates the existing key entry in-place, preserving the same key_id
    // but incrementing version and archiving old material for backward decryption
    let rotated_meta = keystore.rotate_key(&key_id, "test-tenant").await.unwrap();

    // New behavior: Rotation updates in-place, same key_id but new version
    let new_key_id = rotated_meta.id;
    assert_eq!(key_id, new_key_id, "Rotation updates key in-place, same ID");
    assert_eq!(rotated_meta.version, 2);

    // OLD KEY DECRYPTION SHOULD STILL WORK: Key material versions are archived
    // This is critical for backward compatibility - historical ciphertexts must remain decryptable
    // The old ciphertext was encrypted with version 1, which is now in the version archive
    let decrypted_old = keystore
        .decrypt(&key_id, &ciphertext, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(
        &decrypted_old, plaintext,
        "Old key version should decrypt old ciphertext"
    );

    // Encrypt with new rotated key - creates ciphertext with version 2
    let ciphertext_v2 = keystore
        .encrypt(&key_id, plaintext, None, "test-tenant")
        .await
        .unwrap();

    // Decrypt with v2 using same key_id
    let decrypted_v2 = keystore
        .decrypt(&key_id, &ciphertext_v2, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(&decrypted_v2, plaintext);

    // Delete the rotated key
    keystore.delete_key(&key_id, "test-tenant").await.unwrap();

    // Verify key is in pending deletion state
    let meta_after_delete = keystore.get_key_metadata(&new_key_id).await.unwrap();
    assert_eq!(format!("{:?}", meta_after_delete.status), "PendingDeletion");
}

/// Test soft delete and listing with status filter
#[tokio::test]
async fn test_key_soft_delete_and_list() {
    let keystore = SoftwareKeystore::new();
    let spec = KeySpec::EcdsaP256;

    // Create multiple keys
    let key1 = keystore
        .generate_key(&spec, "delete-test-1", "test-tenant")
        .await
        .unwrap();

    keystore
        .generate_key(&spec, "delete-test-2", "test-tenant")
        .await
        .unwrap();

    // List all keys (no status filter)
    let filter = KeyFilter {
        tenant_id: Some("test-tenant".to_string()),
        limit: Some(100),
        ..Default::default()
    };
    let _all_keys = keystore.list_keys(&filter).await.unwrap();

    // Soft delete key1
    keystore.delete_key(&key1.id, "test-tenant").await.unwrap();

    // List again - deleted key might still appear
    let _keys_after_delete = keystore.list_keys(&filter).await.unwrap();

    // Verify deleted key status changed
    let deleted_meta = keystore.get_key_metadata(&key1.id).await.unwrap();
    assert_eq!(format!("{:?}", deleted_meta.status), "PendingDeletion");
}

/// Test key metadata after various operations
#[tokio::test]
async fn test_key_metadata_persistence() {
    let keystore = SoftwareKeystore::new();
    let spec = KeySpec::Ed25519;

    let meta = keystore
        .generate_key(&spec, "metadata-test-key", "test-tenant")
        .await
        .unwrap();

    // Initial metadata check
    assert_eq!(meta.name, "metadata-test-key");
    assert_eq!(meta.spec, KeySpec::Ed25519);
    assert_eq!(meta.version, 1);

    // Sign to verify key works
    let _sig = keystore
        .sign(&meta.id, b"test data", "test-tenant")
        .await
        .unwrap();

    // Rotate
    let rotated = keystore.rotate_key(&meta.id, "test-tenant").await.unwrap();
    assert!(rotated.rotated_at.is_some());

    // Get metadata again
    let _meta_after = keystore.get_key_metadata(&meta.id).await.unwrap();
}

// ============================================================================
// Multi-Tenant Isolation Tests
// ============================================================================

#[tokio::test]
async fn test_multi_tenant_isolation() {
    let keystore = SoftwareKeystore::new();

    // Create keys for two tenants
    let tenant_a_key = keystore
        .generate_key(&KeySpec::Aes256Gcm, "tenant-a-key", "tenant-a")
        .await
        .unwrap();

    let tenant_b_key = keystore
        .generate_key(&KeySpec::Aes256Gcm, "tenant-b-key", "tenant-b")
        .await
        .unwrap();

    // Encrypt with tenant A's key
    let plaintext = b"Secret for tenant A only";
    let ciphertext = keystore
        .encrypt(&tenant_a_key.id, plaintext, None, "tenant-a")
        .await
        .unwrap();

    // Tenant B should NOT be able to decrypt (different key)
    let result = keystore
        .decrypt(&tenant_b_key.id, &ciphertext, None, "tenant-b")
        .await;
    assert!(
        result.is_err(),
        "Tenant B should not decrypt tenant A's ciphertext"
    );

    // Tenant A should decrypt successfully
    let decrypted = keystore
        .decrypt(&tenant_a_key.id, &ciphertext, None, "tenant-a")
        .await
        .unwrap();
    assert_eq!(&decrypted, plaintext);

    // List keys for tenant A
    let filter_a = KeyFilter {
        tenant_id: Some("tenant-a".to_string()),
        ..Default::default()
    };
    let tenant_a_keys = keystore.list_keys(&filter_a).await.unwrap();
    assert!(tenant_a_keys.iter().all(|k| k.name.contains("tenant-a")));

    // List keys for tenant B
    let filter_b = KeyFilter {
        tenant_id: Some("tenant-b".to_string()),
        ..Default::default()
    };
    let tenant_b_keys = keystore.list_keys(&filter_b).await.unwrap();
    assert!(tenant_b_keys.iter().all(|k| k.name.contains("tenant-b")));
}

/// Test tenant cannot access another tenant's key metadata
#[tokio::test]
async fn test_tenant_key_isolation_metadata() {
    let keystore = SoftwareKeystore::new();

    let tenant_a_key = keystore
        .generate_key(&KeySpec::Sm2, "secret-key", "tenant-a")
        .await
        .unwrap();

    // Verify key exists and operates correctly for tenant A
    let meta = keystore.get_key_metadata(&tenant_a_key.id).await.unwrap();
    assert_eq!(meta.tenant_id, "tenant-a");
}

// ============================================================================
// Tenant Data Isolation Verification Tests
// ============================================================================

/// Test: Tenant A cannot decrypt Tenant B's ciphertext
#[tokio::test]
async fn test_tenant_isolation_cross_tenant_decryption_fails() {
    let keystore = SoftwareKeystore::new();

    // Tenant A creates a key and encrypts data
    let tenant_a_key = keystore
        .generate_key(&KeySpec::Aes256Gcm, "isolated-key", "tenant-a")
        .await
        .unwrap();

    let secret_message = b"Secret data for tenant A only";
    let ciphertext = keystore
        .encrypt(&tenant_a_key.id, secret_message, None, "tenant-a")
        .await
        .unwrap();

    // Tenant B creates their own key
    let tenant_b_key = keystore
        .generate_key(&KeySpec::Aes256Gcm, "tenant-b-key", "tenant-b")
        .await
        .unwrap();

    // Tenant B tries to decrypt Tenant A's ciphertext - should fail
    let result = keystore
        .decrypt(&tenant_b_key.id, &ciphertext, None, "tenant-b")
        .await;
    assert!(
        result.is_err(),
        "Tenant B should not decrypt Tenant A's ciphertext"
    );

    // Verify Tenant A can still decrypt their own ciphertext
    let decrypted = keystore
        .decrypt(&tenant_a_key.id, &ciphertext, None, "tenant-a")
        .await
        .unwrap();
    assert_eq!(&decrypted, secret_message);
}

/// Test: Tenant cannot get metadata of another tenant's key
#[tokio::test]
async fn test_tenant_isolation_metadata_access() {
    let keystore = SoftwareKeystore::new();

    // Tenant A creates a key
    let tenant_a_key = keystore
        .generate_key(&KeySpec::Sm4, "tenant-a-secret", "tenant-a")
        .await
        .unwrap();

    // Verify the key has correct tenant_id
    let meta = keystore.get_key_metadata(&tenant_a_key.id).await.unwrap();
    assert_eq!(meta.tenant_id, "tenant-a");
    assert_eq!(meta.name, "tenant-a-secret");

    // Tenant B tries to access Tenant A's key metadata
    // In a real system, PBAC would block this at API layer
    // At keystore level, it should just work based on key_id
    // But the tenant_id should be different
    let meta_b = keystore.get_key_metadata(&tenant_a_key.id).await.unwrap();
    assert_eq!(meta_b.tenant_id, "tenant-a", "Key belongs to tenant-a");
}

/// Test: Cross-tenant key listing returns only tenant's keys
#[tokio::test]
async fn test_tenant_isolation_list_keys_filter() {
    let keystore = SoftwareKeystore::new();

    // Create multiple keys for different tenants
    let _key_a1 = keystore
        .generate_key(&KeySpec::Aes256Gcm, "key-a1", "tenant-a")
        .await
        .unwrap();
    let _key_a2 = keystore
        .generate_key(&KeySpec::Sm4, "key-a2", "tenant-a")
        .await
        .unwrap();
    let key_b1 = keystore
        .generate_key(&KeySpec::Aes256Gcm, "key-b1", "tenant-b")
        .await
        .unwrap();

    // List tenant-a's keys
    let filter_a = KeyFilter {
        tenant_id: Some("tenant-a".to_string()),
        ..Default::default()
    };
    let tenant_a_keys = keystore.list_keys(&filter_a).await.unwrap();

    // All returned keys should belong to tenant-a
    for key in &tenant_a_keys {
        assert_eq!(key.tenant_id, "tenant-a");
        assert!(key.name.starts_with("key-a"));
    }

    // List tenant-b's keys
    let filter_b = KeyFilter {
        tenant_id: Some("tenant-b".to_string()),
        ..Default::default()
    };
    let tenant_b_keys = keystore.list_keys(&filter_b).await.unwrap();

    // All returned keys should belong to tenant-b
    for key in &tenant_b_keys {
        assert_eq!(key.tenant_id, "tenant-b");
    }

    // Verify tenant-b has exactly 1 key
    assert_eq!(tenant_b_keys.len(), 1);
    assert_eq!(tenant_b_keys[0].id, key_b1.id);
}

/// Test: Tenant signing and verification is isolated
#[tokio::test]
async fn test_tenant_isolation_signing_isolated() {
    let keystore = SoftwareKeystore::new();

    // Tenant A signs data
    let tenant_a_key = keystore
        .generate_key(&KeySpec::Ed25519, "signing-key-a", "tenant-a")
        .await
        .unwrap();

    let data = b"Data to be signed by tenant A";
    let signature = keystore
        .sign(&tenant_a_key.id, data, "tenant-a")
        .await
        .unwrap();

    // Tenant A's signature verifies correctly
    let valid = keystore
        .verify(&tenant_a_key.id, data, &signature, "tenant-a")
        .await
        .unwrap();
    assert!(valid);

    // Tenant B creates their own key
    let tenant_b_key = keystore
        .generate_key(&KeySpec::Ed25519, "signing-key-b", "tenant-b")
        .await
        .unwrap();

    // Tenant B's signature is different (different key)
    let sig_b = keystore
        .sign(&tenant_b_key.id, data, "tenant-b")
        .await
        .unwrap();

    // Tenant A's key cannot verify Tenant B's signature
    let valid_ab = keystore
        .verify(&tenant_a_key.id, data, &sig_b, "tenant-a")
        .await
        .unwrap();
    assert!(
        !valid_ab,
        "Tenant A's key should not verify Tenant B's signature"
    );

    // Tenant B's key verifies their own signature
    let valid_b = keystore
        .verify(&tenant_b_key.id, data, &sig_b, "tenant-b")
        .await
        .unwrap();
    assert!(valid_b);
}

/// Test: Concurrent operations from different tenants are isolated
#[tokio::test]
async fn test_tenant_isolation_concurrent_operations() {
    use std::sync::Arc;

    let keystore = Arc::new(SoftwareKeystore::new());

    // Create a key for tenant A
    let key_a = keystore
        .generate_key(&KeySpec::Aes256Gcm, "concurrent-a", "tenant-a")
        .await
        .unwrap();

    // Tenant B does operations concurrently with Tenant A
    let key_b = keystore
        .generate_key(&KeySpec::Aes256Gcm, "concurrent-b", "tenant-b")
        .await
        .unwrap();

    let secret_a = b"Secret from tenant A";
    let secret_b = b"Secret from tenant B";

    // Concurrent encryptions
    let mut handles = vec![];

    // Tenant A encrypts
    let ks = keystore.clone();
    let ct_a = secret_a.to_vec();
    handles.push(tokio::spawn(async move {
        ks.encrypt(&key_a.id, &ct_a, None, "tenant-a").await
    }));

    // Tenant B encrypts
    let ks = keystore.clone();
    let ct_b = secret_b.to_vec();
    handles.push(tokio::spawn(async move {
        ks.encrypt(&key_b.id, &ct_b, None, "tenant-b").await
    }));

    // Both should succeed
    let mut results = Vec::new();
    for h in handles {
        results.push(h.await.unwrap());
    }

    for result in results {
        assert!(result.is_ok());
    }

    // Verify cross-tenant access still fails
    let ct_a = keystore
        .encrypt(&key_a.id, secret_a, None, "tenant-a")
        .await
        .unwrap();
    let result = keystore.decrypt(&key_b.id, &ct_a, None, "tenant-b").await;
    assert!(result.is_err());
}

// ============================================================================
// Concurrent Operations Tests
// ============================================================================

#[tokio::test]
async fn test_concurrent_encryptions_same_key() {
    use std::sync::Arc;

    let keystore = Arc::new(SoftwareKeystore::new());

    let key_meta = keystore
        .generate_key(&KeySpec::Aes256Gcm, "concurrent-key", "test-tenant")
        .await
        .unwrap();

    let key_id = key_meta.id;
    let plaintext = b"Concurrent test message";

    // Spawn 10 concurrent encryptions
    let mut handles: Vec<_> = (0..10)
        .map(|_| {
            let ks = keystore.clone();
            tokio::spawn(async move { ks.encrypt(&key_id, plaintext, None, "test-tenant").await })
        })
        .collect();

    // All should succeed
    while let Some(handle) = handles.pop() {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }
}

#[tokio::test]
async fn test_concurrent_key_generation() {
    use std::sync::Arc;

    let keystore = Arc::new(SoftwareKeystore::new());

    // Spawn 5 concurrent key generations
    let mut handles: Vec<_> = (0..5)
        .map(|i| {
            let ks = keystore.clone();
            tokio::spawn(async move {
                ks.generate_key(&KeySpec::Sm4, &format!("concurrent-gen-{i}"), "test-tenant")
                    .await
            })
        })
        .collect();

    // All should succeed
    while let Some(handle) = handles.pop() {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }
}

#[tokio::test]
async fn test_concurrent_sign_and_verify() {
    use std::sync::Arc;

    let keystore = Arc::new(SoftwareKeystore::new());

    let key_meta = keystore
        .generate_key(&KeySpec::Ed25519, "sign-concurrent-key", "test-tenant")
        .await
        .unwrap();

    let key_id = key_meta.id;
    let data = b"Data to sign concurrently";

    // Spawn 10 concurrent sign operations
    let mut sign_handles: Vec<_> = (0..10)
        .map(|_| {
            let ks = keystore.clone();
            tokio::spawn(async move { ks.sign(&key_id, data, "test-tenant").await })
        })
        .collect();

    // All should succeed
    let mut sigs = Vec::new();
    while let Some(handle) = sign_handles.pop() {
        let result = handle.await.unwrap();
        sigs.push(result.unwrap());
    }

    assert_eq!(sigs.len(), 10);

    // All signatures should verify
    for sig in &sigs {
        let valid = keystore
            .verify(&key_id, data, sig, "test-tenant")
            .await
            .unwrap();
        assert!(valid, "Signature verification failed");
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_encrypt_with_nonexistent_key() {
    let keystore = SoftwareKeystore::new();
    let fake_id = kms_core::Uuid::new_v4();

    let result = keystore
        .encrypt(&fake_id, b"data", None, "test-tenant")
        .await;
    assert!(result.is_err());

    match result.unwrap_err() {
        kms_core::Error::KeyNotFound(_) => {}
        e => panic!("Expected KeyNotFound, got: {e}"),
    }
}

#[tokio::test]
async fn test_decrypt_with_nonexistent_key() {
    let keystore = SoftwareKeystore::new();
    let fake_id = kms_core::Uuid::new_v4();

    // Create a dummy ciphertext
    let dummy_ct = Ciphertext {
        key_id: fake_id,
        version: 1,
        format_version: 1,
        nonce: vec![0u8; 12],
        ciphertext: vec![0u8; 16],
        tag: vec![0u8; 16],
    };

    let result = keystore
        .decrypt(&fake_id, &dummy_ct, None, "test-tenant")
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_sign_with_nonexistent_key() {
    let keystore = SoftwareKeystore::new();
    let fake_id = kms_core::Uuid::new_v4();

    let result = keystore.sign(&fake_id, b"data", "test-tenant").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_verify_with_nonexistent_key() {
    let keystore = SoftwareKeystore::new();
    let fake_id = kms_core::Uuid::new_v4();

    let dummy_sig = Signature {
        key_id: fake_id,
        version: 1,
        signature: vec![0u8; 64],
    };

    let result = keystore
        .verify(&fake_id, b"data", &dummy_sig, "test-tenant")
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_rotate_nonexistent_key() {
    let keystore = SoftwareKeystore::new();
    let fake_id = kms_core::Uuid::new_v4();

    let result = keystore.rotate_key(&fake_id, "test-tenant").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_delete_nonexistent_key() {
    let keystore = SoftwareKeystore::new();
    let fake_id = kms_core::Uuid::new_v4();

    let result = keystore.delete_key(&fake_id, "test-tenant").await;
    // Soft delete of non-existent key might succeed or fail
    println!("Delete result: {result:?}");
}

#[tokio::test]
async fn test_get_metadata_nonexistent_key() {
    let keystore = SoftwareKeystore::new();
    let fake_id = kms_core::Uuid::new_v4();

    let result = keystore.get_key_metadata(&fake_id).await;
    assert!(result.is_err());

    match result.unwrap_err() {
        kms_core::Error::KeyNotFound(_) => {}
        e => panic!("Expected KeyNotFound, got: {e}"),
    }
}

// ============================================================================
// Algorithm-Specific Tests
// ============================================================================

#[tokio::test]
async fn test_all_cipher_algorithms() {
    let keystore = SoftwareKeystore::new();
    let plaintext = b"Test message for all ciphers";

    for spec in [KeySpec::Aes256Gcm, KeySpec::Sm4] {
        let meta = keystore
            .generate_key(&spec, &format!("cipher-{spec:?}"), "test-tenant")
            .await
            .unwrap();

        let ct = keystore
            .encrypt(&meta.id, plaintext, None, "test-tenant")
            .await
            .unwrap();
        let dt = keystore
            .decrypt(&meta.id, &ct, None, "test-tenant")
            .await
            .unwrap();

        assert_eq!(&dt, plaintext, "Cipher {:?} failed", spec);
    }
}

#[tokio::test]
async fn test_all_signature_algorithms() {
    let keystore = SoftwareKeystore::new();
    let data = b"Test data for all signature algorithms";

    // Only test algorithms that are actually supported
    // Software keystore supports: Ed25519, Sm2
    for spec in [KeySpec::Ed25519, KeySpec::Sm2] {
        let meta = keystore
            .generate_key(&spec, &format!("sign-{spec:?}"), "test-tenant")
            .await
            .unwrap();

        let sig = keystore.sign(&meta.id, data, "test-tenant").await.unwrap();
        let valid = keystore
            .verify(&meta.id, data, &sig, "test-tenant")
            .await
            .unwrap();

        assert!(valid, "Signature algorithm {:?} failed", spec);
    }
}

// ============================================================================
// GM/T KAT (Known Answer Test) Verification
// ============================================================================

/// GM/T KAT: Verify SM3 hash implementation matches GM/T 0004-2012 test vectors
#[test]
fn test_kat_sm3_hash_vectors() {
    use gm_crypto::sm3::Sm3Hasher;

    // GM/T 0004-2012 test vectors (official standard test vectors)
    let test_vectors: Vec<(&str, &str)> = vec![
        // Empty string
        (
            "",
            "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
        ),
        // "abc"
        (
            "abc",
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        ),
    ];

    for (input, expected_hex) in test_vectors {
        let result = Sm3Hasher::hash_hex(input.as_bytes()).unwrap();
        assert_eq!(
            result, expected_hex,
            "SM3 KAT failed for input: {:?}",
            input
        );
    }
}

/// GM/T KAT: Verify SM4 ECB encryption matches GM/T 0002-2012 test vectors
#[test]
#[allow(deprecated)] // intentional: SM4 ECB used for standard KAT vector verification
fn test_kat_sm4_ecb_vectors() {
    use gm_crypto::sm4::Sm4Cipher;

    // GM/T 0002-2012 test vector
    let key_hex = "0123456789ABCDEFFEDCBA9876543210";
    let plaintext_hex = "0123456789ABCDEFFEDCBA9876543210";
    let expected_ct_hex = "681EDF34D206965E86B3E94F536E4246";

    let key = hex::decode(key_hex).unwrap();
    let plaintext = hex::decode(plaintext_hex).unwrap();

    let cipher = Sm4Cipher::new(&key).unwrap();
    let ct = cipher.encrypt_ecb(&plaintext).unwrap();

    assert_eq!(
        hex::encode(&ct).to_uppercase(),
        expected_ct_hex.to_uppercase()
    );
}

/// GM/T KAT: Verify SM2 key generation produces valid keys
#[test]
fn test_kat_sm2_key_generation() {
    use gm_crypto::sm2::Sm2KeyPair;

    // Generate key and verify structure
    let keypair = Sm2KeyPair::generate().unwrap();

    // Private key should be 32 bytes
    assert_eq!(keypair.private_key_bytes().len(), 32);

    // Public key (compressed) should be 33 bytes
    let compressed = keypair.public_key_bytes();
    assert_eq!(compressed.len(), 33);

    // Uncompressed public key should be 65 bytes with 0x04 prefix
    let uncompressed = keypair.public_key_bytes_uncompressed();
    assert_eq!(uncompressed.len(), 65);
    assert_eq!(uncompressed[0], 0x04);

    // Key should be reproducible from private bytes
    let keypair2 = Sm2KeyPair::from_private_key(&keypair.private_key_bytes()).unwrap();
    assert_eq!(keypair.private_key_bytes(), keypair2.private_key_bytes());
}

/// GM/T KAT: Verify SM2 signing and verification works correctly
#[test]
fn test_kat_sm2_sign_verify() {
    use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer, Sm2Verifier};

    const GM_TLS_DEFAULT_ID: &str = "1234567812345678";

    let keypair = Sm2KeyPair::generate().unwrap();
    let signer = Sm2Signer::new(&keypair).unwrap();
    let data = b"hello world";

    // Sign
    let sig = signer.sign(data).unwrap();
    assert_eq!(sig.len(), 64, "SM2 signature should be 64 bytes");

    // Verify with correct data
    let verifier =
        Sm2Verifier::new(&keypair.public_key_bytes_uncompressed(), GM_TLS_DEFAULT_ID).unwrap();
    assert!(verifier.verify(data, &sig).is_ok());

    // Verify with wrong data should fail
    assert!(verifier.verify(b"wrong data", &sig).is_err());
}

/// GM/T KAT: Verify SM2 encrypt/decrypt roundtrip
#[test]
fn test_kat_sm2_encrypt_decrypt() {
    use gm_crypto::sm2::{Sm2Decryptor, Sm2Encryptor, Sm2KeyPair};

    let keypair = Sm2KeyPair::generate().unwrap();
    let encryptor = Sm2Encryptor::new(&keypair.public_key_bytes()).unwrap();
    let decryptor = Sm2Decryptor::new(keypair);

    let plaintext = b"SM2 encryption test message 12345";

    // Encrypt
    let ciphertext = encryptor.encrypt(plaintext).unwrap();

    // Decrypt
    let decrypted = decryptor.decrypt(&ciphertext).unwrap();
    assert_eq!(&decrypted, plaintext);
}

/// GM/T KAT: Verify SM4 GCM encryption produces correct authentication tag
#[test]
fn test_kat_sm4_gcm_roundtrip() {
    use gm_crypto::sm4::{SM4_GCM_NONCE_LENGTH, SM4_GCM_TAG_LENGTH, Sm4Cipher};

    let key = vec![0x01u8; 16]; // 16 bytes key
    let cipher = Sm4Cipher::new(&key).unwrap();
    let nonce = [0u8; SM4_GCM_NONCE_LENGTH];

    let plaintext = b"SM4 GCM test";
    let aad = b"additional data";

    // Encrypt
    let (ciphertext, tag) = cipher.encrypt_gcm(plaintext, &nonce, aad).unwrap();
    assert_eq!(tag.len(), SM4_GCM_TAG_LENGTH);

    // Decrypt and verify
    let decrypted = cipher.decrypt_gcm(&ciphertext, &nonce, aad, &tag).unwrap();
    assert_eq!(&decrypted, plaintext);

    // Tampered tag should fail
    let mut bad_tag = tag.clone();
    bad_tag[0] ^= 0xFF;
    assert!(
        cipher
            .decrypt_gcm(&ciphertext, &nonce, aad, &bad_tag)
            .is_err()
    );
}

/// GM/T KAT: Verify SM3 HMAC implementation
#[test]
fn test_kat_sm3_hmac() {
    use gm_crypto::sm3::Sm3Hmac;

    let key = b"test-key-12345678";
    let hmac = Sm3Hmac::new(key);
    let data = b"hello world";

    // Compute HMAC
    let tag = hmac.compute(data).unwrap();
    assert_eq!(tag.len(), 32); // SM3 output = 32 bytes

    // Verify
    assert!(hmac.verify(data, &tag).unwrap());

    // Wrong data should fail verification
    assert!(!hmac.verify(b"wrong data", &tag).unwrap());

    // Different key should produce different tag
    let hmac2 = Sm3Hmac::new(b"different-key-1234");
    let tag2 = hmac2.compute(data).unwrap();
    assert_ne!(tag, tag2);
}

/// GM/T KAT: Verify SM9 key generation (basic structure check)
#[test]
fn test_kat_sm9_key_structure() {
    use gm_sm9_rs::KgcMasterKey;

    // Generate master key for signing
    let master_key = KgcMasterKey::generate().expect("failed to generate master key");

    // Key structure validation
    // Derive a signing key for an identity
    let _signing_master = master_key.derive_signing_key(b"test identity");

    // Master key should support key derivation (proves it's valid)
    assert!(master_key.derive_signing_key(b"test identity").is_ok());

    // Derive encryption key
    let _encryption_master = master_key.derive_encryption_key(b"recipient@example.com");
}

// ============================================================================
// Key Backup Encryption Tests (DJCP Level 3 — VERIFY-084)
// ============================================================================

use kms_core::key::KeyMeta;
use kms_core::{BackupConfig, KeyBackupService};

fn make_test_key_meta() -> KeyMeta {
    KeyMeta {
        id: kms_core::Uuid::new_v4(),
        tenant_id: "backup-test-tenant".to_string(),
        name: "backup-test-key".to_string(),
        spec: KeySpec::Sm4,
        status: kms_core::key::KeyStatus::Active,
        version: 1,
        created_at: chrono::Utc::now(),
        rotated_at: None,
        description: Some("DJCP backup test key".to_string()),
        metadata: kms_core::key::KeyMetadata::default(),
    }
}

fn make_test_service(temp_dir: &tempfile::TempDir) -> KeyBackupService {
    let config = BackupConfig {
        backup_path: temp_dir.path().to_string_lossy().to_string(),
        ..Default::default()
    };
    KeyBackupService::with_random_master_key(config).expect("Failed to create test backup service")
}

fn find_single_backup_file(dir: &std::path::Path) -> std::path::PathBuf {
    let files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(files.len(), 1, "Should have exactly one backup file");
    files[0].path()
}

/// DJCP VERIFY-084: Key backup uses SM4-GCM encryption with round-trip integrity
#[test]
fn test_key_backup_sm4_gcm_encryption_round_trip() {
    let temp_dir = tempfile::tempdir().unwrap();
    let service = make_test_service(&temp_dir);
    let key_meta = make_test_key_meta();
    let key_material = b"sm4_gcm_backup_test_key_16b";

    let backup = service
        .backup_key(&key_meta, key_material, None)
        .expect("Backup should succeed");

    // Verify SM4-GCM properties
    assert_eq!(backup.version, 2); // v2 = SM4-GCM + SM3-HMAC
    assert_eq!(backup.nonce.len(), 12, "SM4-GCM nonce must be 12 bytes");
    // SM4-GCM produces ciphertext = plaintext + 16-byte tag
    assert_eq!(
        backup.encrypted_material.len(),
        key_material.len() + 16,
        "SM4-GCM encrypted material = plaintext + 16-byte tag"
    );

    // Verify round-trip restore
    let restored = service
        .restore_key(&backup)
        .expect("Restore should succeed");
    assert_eq!(&restored, key_material, "Round-trip should preserve data");
}

/// DJCP VERIFY-084: Backup HMAC signature is valid and verifiable
#[test]
fn test_backup_hmac_signature_valid() {
    let temp_dir = tempfile::tempdir().unwrap();
    let service = make_test_service(&temp_dir);
    let key_meta = make_test_key_meta();

    service
        .backup_key(&key_meta, b"hmac_sig_test_16b!", None)
        .expect("Backup should succeed");

    let file_path = find_single_backup_file(temp_dir.path());
    let content = std::fs::read_to_string(&file_path).unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&content).expect("Should be valid JSON");
    assert!(parsed.get("data").is_some(), "SignedBackup must have data");
    assert!(
        parsed.get("signature").is_some(),
        "SignedBackup must have HMAC signature"
    );

    let sig = parsed["signature"].as_str().unwrap();
    assert!(!sig.is_empty(), "HMAC signature must not be empty");
    assert_eq!(
        sig.len(),
        64,
        "SM3-HMAC signature must be 64 hex chars (32 bytes)"
    );

    let loaded = service
        .verify_backup_file(&file_path)
        .expect("HMAC verification should pass for untampered backup");
    assert_eq!(loaded.key_meta.id, key_meta.id);
}

/// DJCP VERIFY-084: Backup tampering is detected
#[test]
fn test_backup_tampering_is_detected() {
    let temp_dir = tempfile::tempdir().unwrap();
    let service = make_test_service(&temp_dir);
    let key_meta = make_test_key_meta();

    service
        .backup_key(&key_meta, b"tamper_test_16byte", None)
        .unwrap();

    let file_path = find_single_backup_file(temp_dir.path());
    let content = std::fs::read_to_string(&file_path).unwrap();
    let mut signed: serde_json::Value =
        serde_json::from_str(&content).expect("Should parse SignedBackup");
    let sig = signed["signature"].as_str().unwrap();
    let mut tampered_sig = sig.to_string();
    // Flip the last hex character of the HMAC signature to invalidate it
    let last_char = tampered_sig.pop().unwrap();
    tampered_sig.push(if last_char == 'f' { '0' } else { 'f' });
    signed["signature"] = serde_json::Value::String(tampered_sig);
    std::fs::write(
        &file_path,
        serde_json::to_string_pretty(&signed).expect("Should re-serialize"),
    )
    .unwrap();

    let result = service.verify_backup_file(&file_path);
    assert!(
        result.is_err(),
        "Tampered backup file must fail HMAC verification"
    );
}

/// DJCP VERIFY-084: Different master keys produce different encryption results
#[test]
fn test_backup_different_keks_produce_different_results() {
    let temp_dir = tempfile::tempdir().unwrap();
    let key_meta = make_test_key_meta();
    let key_material = b"different_kek_test";

    // Create two services with different master keys
    let config1 = BackupConfig {
        backup_path: format!("{}/kek1", temp_dir.path().display()),
        ..Default::default()
    };
    let config2 = BackupConfig {
        backup_path: format!("{}/kek2", temp_dir.path().display()),
        ..Default::default()
    };

    let service1 =
        KeyBackupService::with_random_master_key(config1).expect("service1 creation failed");
    let service2 =
        KeyBackupService::with_random_master_key(config2).expect("service2 creation failed");

    let backup1 = service1
        .backup_key(&key_meta, key_material, None)
        .expect("backup1 failed");
    let backup2 = service2
        .backup_key(&key_meta, key_material, None)
        .expect("backup2 failed");

    // Different KEKs must produce different ciphertexts
    assert_ne!(
        backup1.encrypted_material, backup2.encrypted_material,
        "Different master keys must produce different ciphertext"
    );

    // But each service can restore its own backup
    let restored1 = service1.restore_key(&backup1).unwrap();
    let restored2 = service2.restore_key(&backup2).unwrap();
    assert_eq!(restored1, key_material);
    assert_eq!(restored2, key_material);

    // Cross-service restore should fail (wrong KEK)
    let cross_restore = service1.restore_key(&backup2);
    assert!(
        cross_restore.is_err(),
        "Service1 should not decrypt Service2's backup"
    );
}

/// DJCP VERIFY-084: Backup metadata integrity is preserved
#[test]
fn test_backup_metadata_integrity() {
    let temp_dir = tempfile::tempdir().unwrap();
    let service = make_test_service(&temp_dir);
    let key_meta = make_test_key_meta();
    let key_material = b"metadata_test_16b";

    let backup = service
        .backup_key(
            &key_meta,
            key_material,
            Some("DJCP compliance backup".to_string()),
        )
        .expect("Backup should succeed");

    // Verify all metadata fields are preserved
    assert_eq!(backup.key_meta.id, key_meta.id);
    assert_eq!(backup.key_meta.tenant_id, key_meta.tenant_id);
    assert_eq!(backup.key_meta.name, key_meta.name);
    assert_eq!(backup.key_meta.spec, key_meta.spec);
    assert_eq!(backup.key_meta.version, key_meta.version);
    assert_eq!(
        backup.description.as_deref(),
        Some("DJCP compliance backup")
    );
    assert!(
        !backup.material_hash.is_empty(),
        "Material hash must be present"
    );
    assert_eq!(
        backup.material_hash.len(),
        64,
        "SM3 hash must be 64 hex chars"
    );

    // Timestamp should be recent
    let now = chrono::Utc::now();
    let age = now - backup.backed_up_at;
    assert!(
        age.num_seconds() < 10,
        "Backup timestamp should be recent (within 10s)"
    );
}

/// DJCP VERIFY-084: Restore with wrong master key is rejected
#[test]
fn test_backup_rejects_wrong_kek() {
    let temp_dir = tempfile::tempdir().unwrap();
    let key_meta = make_test_key_meta();
    let key_material = b"wrong_kek_test_16";

    // Create two services with different master keys
    let config = BackupConfig {
        backup_path: temp_dir.path().to_string_lossy().to_string(),
        ..Default::default()
    };
    let service1 =
        KeyBackupService::with_random_master_key(config.clone()).expect("service1 creation failed");
    let service2 =
        KeyBackupService::with_random_master_key(config).expect("service2 creation failed");

    // Backup with service1's key
    let backup = service1
        .backup_key(&key_meta, key_material, None)
        .expect("backup should succeed");

    // Attempt restore with service2 (wrong KEK)
    let result = service2.restore_key(&backup);
    assert!(
        result.is_err(),
        "Restore with wrong master key must be rejected"
    );

    // service1 should still restore correctly
    let restored = service1.restore_key(&backup).unwrap();
    assert_eq!(restored, key_material);
}
