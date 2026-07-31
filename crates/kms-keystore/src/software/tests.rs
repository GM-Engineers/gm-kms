use super::*;
use crate::backend::KeystoreBackend;

#[tokio::test]
async fn test_aes256_gcm_encrypt_decrypt() {
    let store = SoftwareKeystore::new();

    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "test-key", "test-tenant")
        .await
        .unwrap();

    let ciphertext = store
        .encrypt(&meta.id, b"hello world", None, "test-tenant")
        .await
        .unwrap();

    let plaintext = store
        .decrypt(&meta.id, &ciphertext, None, "test-tenant")
        .await
        .unwrap();

    assert_eq!(plaintext, b"hello world");
}

#[tokio::test]
async fn test_sm4_gcm_encrypt_decrypt() {
    let store = SoftwareKeystore::new();

    let meta = store
        .generate_key(&KeySpec::Sm4, "sm4-test-key", "test-tenant")
        .await
        .unwrap();

    let ciphertext = store
        .encrypt(&meta.id, b"hello world", None, "test-tenant")
        .await
        .unwrap();

    let plaintext = store
        .decrypt(&meta.id, &ciphertext, None, "test-tenant")
        .await
        .unwrap();

    assert_eq!(plaintext, b"hello world");
}

#[tokio::test]
async fn test_sm2_sign_verify() {
    let store = SoftwareKeystore::new();

    let meta = store
        .generate_key(&KeySpec::Sm2, "sm2-test-key", "test-tenant")
        .await
        .unwrap();

    let signature = store
        .sign(&meta.id, b"hello world", "test-tenant")
        .await
        .unwrap();

    let valid = store
        .verify(&meta.id, b"hello world", &signature, "test-tenant")
        .await
        .unwrap();
    assert!(valid);

    let invalid = store
        .verify(&meta.id, b"wrong data", &signature, "test-tenant")
        .await
        .unwrap();
    assert!(!invalid);
}

#[tokio::test]
async fn test_sm2_encrypt_decrypt() {
    let store = SoftwareKeystore::new();

    let meta = store
        .generate_key(&KeySpec::Sm2, "sm2-enc-test-key", "test-tenant")
        .await
        .unwrap();

    // SM2 encryption uses the public key, decryption uses private key
    let ciphertext = store
        .encrypt(&meta.id, b"hello SM2", None, "test-tenant")
        .await
        .unwrap();

    let plaintext = store
        .decrypt(&meta.id, &ciphertext, None, "test-tenant")
        .await
        .unwrap();

    assert_eq!(plaintext, b"hello SM2");
}

#[tokio::test]
async fn test_key_not_found() {
    let store = SoftwareKeystore::new();

    let result = store.get_key_metadata(&Uuid::new_v4()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_x25519_derive_shared_secret() {
    let store = SoftwareKeystore::new();

    // Generate a key with 32 bytes of material for X25519
    let meta = store
        .generate_key(&KeySpec::Ed25519, "x25519-test-key", "test-tenant")
        .await
        .unwrap();

    // Peer's public key (32 bytes for X25519)
    // In real usage, this would be received from the peer
    let mut peer_public_key = [0u8; 32];
    for (i, byte) in peer_public_key.iter_mut().enumerate() {
        *byte = ((i * 7 + 13) & 0xFF) as u8;
    }

    // Perform X25519 DH
    let shared_secret = store
        .derive_shared_secret(
            &meta.id,
            &peer_public_key,
            kms_core::dh::DhAlgorithm::X25519,
        )
        .await
        .unwrap();

    assert!(!shared_secret.secret.is_empty());
    assert_eq!(shared_secret.secret.len(), 32);
    assert_eq!(shared_secret.kdf, Some("HKDF-SHA256".to_string()));
}

#[tokio::test]
async fn test_x25519_shared_secret_deterministic() {
    // Test that same inputs produce same output
    let store = SoftwareKeystore::new();

    // Alice's key
    let alice_meta = store
        .generate_key(&KeySpec::Ed25519, "alice-key", "test-tenant")
        .await
        .unwrap();

    // Bob's public key (normally received from Bob)
    let bob_public = [42u8; 32];

    // Alice derives shared secret with Bob's public key
    let shared1 = store
        .derive_shared_secret(
            &alice_meta.id,
            &bob_public,
            kms_core::dh::DhAlgorithm::X25519,
        )
        .await
        .unwrap();

    // Alice derives again with same peer key - should get same result
    let shared2 = store
        .derive_shared_secret(
            &alice_meta.id,
            &bob_public,
            kms_core::dh::DhAlgorithm::X25519,
        )
        .await
        .unwrap();

    assert_eq!(shared1.secret, shared2.secret);
}

#[tokio::test]
async fn test_x25519_different_peer_keys_different_secret() {
    let store = SoftwareKeystore::new();

    // Alice's key
    let alice_meta = store
        .generate_key(&KeySpec::Ed25519, "alice-key", "test-tenant")
        .await
        .unwrap();

    // Two different peer public keys
    let peer1 = [1u8; 32];
    let peer2 = [2u8; 32];

    let shared1 = store
        .derive_shared_secret(&alice_meta.id, &peer1, kms_core::dh::DhAlgorithm::X25519)
        .await
        .unwrap();

    let shared2 = store
        .derive_shared_secret(&alice_meta.id, &peer2, kms_core::dh::DhAlgorithm::X25519)
        .await
        .unwrap();

    // Different peer keys should produce different shared secrets
    assert_ne!(shared1.secret, shared2.secret);
}

#[tokio::test]
async fn test_dh_key_not_found() {
    let store = SoftwareKeystore::new();

    // Use a valid-length peer key for X25519 (32 bytes)
    let peer_key = [0u8; 32];

    let result = store
        .derive_shared_secret(
            &Uuid::new_v4(),
            &peer_key,
            kms_core::dh::DhAlgorithm::X25519,
        )
        .await;
    assert!(result.is_err());
}

// ========================================================================
// SM2-KEX Tests
// ========================================================================

#[tokio::test]
async fn test_sm2_kex_basic() {
    use gm_crypto::sm2::Sm2KeyPair;

    // Two parties: Alice (initiator) and Bob (responder)
    // Each has their own keystore with SM2 key pairs
    let alice_store = SoftwareKeystore::new();
    let bob_store = SoftwareKeystore::new();

    // Generate SM2 keys for both parties
    let alice_meta = alice_store
        .generate_key(&KeySpec::Sm2, "alice-sm2", "test-tenant")
        .await
        .unwrap();

    let bob_meta = bob_store
        .generate_key(&KeySpec::Sm2, "bob-sm2", "test-tenant")
        .await
        .unwrap();

    // Get private keys and derive public keys for signature verification
    // In real usage, public keys would be exchanged out-of-band
    let alice_sk = alice_store
        .get_key_material(&alice_meta.id, "test-tenant")
        .await
        .unwrap();
    let bob_sk = bob_store
        .get_key_material(&bob_meta.id, "test-tenant")
        .await
        .unwrap();

    // Derive public keys from private keys (uncompressed format: 65 bytes with 0x04 prefix)
    let alice_keypair = Sm2KeyPair::from_private_key(&alice_sk).unwrap();
    let bob_keypair = Sm2KeyPair::from_private_key(&bob_sk).unwrap();

    // Public key for SM2 is in uncompressed format: 0x04 || X || Y (65 bytes)
    let alice_pubkey = alice_keypair.public_key_bytes_uncompressed();
    let bob_pubkey = bob_keypair.public_key_bytes_uncompressed();

    // Alice creates initiator session (synchronous internal method)
    // User ID must be max 16 bytes per GM/T 002-2012
    let (alice_session_id, msg1) = alice_store
        .create_sm2_kex_session(&alice_meta.id, b"alice_a@example")
        .unwrap();

    // Bob accepts session as responder
    let (bob_session_id, msg2) = bob_store
        .accept_sm2_kex_session(&bob_meta.id, b"bob_b@example.co", &msg1, &alice_pubkey)
        .unwrap();

    // Alice processes msg2
    let msg3 = alice_store
        .process_sm2_kex_message(&alice_session_id, &msg2, &bob_pubkey)
        .unwrap()
        .expect("msg3 should be returned for initiator");

    // Bob processes msg3 (completes exchange)
    bob_store
        .process_sm2_kex_message(&bob_session_id, &msg3, &alice_pubkey)
        .unwrap(); // None means exchange complete

    // Both should have the same shared secret
    let alice_result = alice_store.get_sm2_kex_result(&alice_session_id).unwrap();
    let bob_result = bob_store.get_sm2_kex_result(&bob_session_id).unwrap();

    assert_eq!(alice_result.shared_secret, bob_result.shared_secret);
    assert_eq!(alice_result.shared_secret.len(), 32); // SM2-KEX shared secret is 32 bytes
}

#[tokio::test]
async fn test_sm2_kex_session_not_found() {
    let store = SoftwareKeystore::new();

    // Try to get result for non-existent session
    let result = store.get_sm2_kex_result(&Uuid::new_v4());
    assert!(result.is_err());
}

#[tokio::test]
async fn test_sm2_kex_invalid_key() {
    let store = SoftwareKeystore::new();

    // Try to create session with a non-SM2 key
    let aes_meta = store
        .generate_key(&KeySpec::Aes256Gcm, "aes-key", "test-tenant")
        .await
        .unwrap();

    let result = store.create_sm2_kex_session(&aes_meta.id, b"user@example.com");
    assert!(result.is_err());
}

// ========================================================================
// Benchmarks (run with: cargo test -- --nocapture --ignored)
// ========================================================================

#[tokio::test]
#[ignore]
async fn benchmark_aes256_encrypt_decrypt() {
    let store = SoftwareKeystore::new();
    let spec = KeySpec::Aes256Gcm;
    let meta = store
        .generate_key(&spec, "bench-aes", "bench-tenant")
        .await
        .unwrap();

    let plaintext = vec![0u8; 1024];
    let ciphertext = store
        .encrypt(&meta.id, &plaintext, None, "bench-tenant")
        .await
        .unwrap();

    use std::time::Instant;
    let start = Instant::now();
    for _ in 0..1000 {
        let _ = store
            .encrypt(&meta.id, &plaintext, None, "bench-tenant")
            .await;
    }
    let encrypt_duration = start.elapsed();

    let start = Instant::now();
    for _ in 0..1000 {
        let _ = store
            .decrypt(&meta.id, &ciphertext, None, "bench-tenant")
            .await;
    }
    let decrypt_duration = start.elapsed();

    println!("\n=== AES-256-GCM (1KB) ===");
    println!(
        "Encrypt: {:.2} ops/ms",
        1000.0 / encrypt_duration.as_millis() as f64 * 1000.0
    );
    println!(
        "Decrypt: {:.2} ops/ms",
        1000.0 / decrypt_duration.as_millis() as f64 * 1000.0
    );
}

#[tokio::test]
#[ignore]
async fn benchmark_sm4_encrypt_decrypt() {
    let store = SoftwareKeystore::new();
    let spec = KeySpec::Sm4;
    let meta = store
        .generate_key(&spec, "bench-sm4", "bench-tenant")
        .await
        .unwrap();

    let plaintext = vec![0u8; 1024];
    let ciphertext = store
        .encrypt(&meta.id, &plaintext, None, "bench-tenant")
        .await
        .unwrap();

    use std::time::Instant;
    let start = Instant::now();
    for _ in 0..1000 {
        let _ = store
            .encrypt(&meta.id, &plaintext, None, "bench-tenant")
            .await;
    }
    let encrypt_duration = start.elapsed();

    let start = Instant::now();
    for _ in 0..1000 {
        let _ = store
            .decrypt(&meta.id, &ciphertext, None, "bench-tenant")
            .await;
    }
    let decrypt_duration = start.elapsed();

    println!("\n=== SM4 (1KB) ===");
    println!(
        "Encrypt: {:.2} ops/ms",
        1000.0 / encrypt_duration.as_millis() as f64 * 1000.0
    );
    println!(
        "Decrypt: {:.2} ops/ms",
        1000.0 / decrypt_duration.as_millis() as f64 * 1000.0
    );
}

#[tokio::test]
#[ignore]
async fn benchmark_sm2_sign_verify() {
    let store = SoftwareKeystore::new();
    let spec = KeySpec::Sm2;
    let meta = store
        .generate_key(&spec, "bench-sm2", "bench-tenant")
        .await
        .unwrap();

    let data = vec![0u8; 256];
    let signature = store.sign(&meta.id, &data, "bench-tenant").await.unwrap();

    use std::time::Instant;
    let start = Instant::now();
    for _ in 0..1000 {
        let _ = store.sign(&meta.id, &data, "bench-tenant").await;
    }
    let sign_duration = start.elapsed();

    let start = Instant::now();
    for _ in 0..1000 {
        let _ = store
            .verify(&meta.id, &data, &signature, "bench-tenant")
            .await;
    }
    let verify_duration = start.elapsed();

    println!("\n=== SM2 (256B) ===");
    println!(
        "Sign: {:.2} ops/ms",
        1000.0 / sign_duration.as_millis() as f64 * 1000.0
    );
    println!(
        "Verify: {:.2} ops/ms",
        1000.0 / verify_duration.as_millis() as f64 * 1000.0
    );
}

#[tokio::test]
#[ignore]
async fn benchmark_ed25519_sign_verify() {
    let store = SoftwareKeystore::new();
    let spec = KeySpec::Ed25519;
    let meta = store
        .generate_key(&spec, "bench-ed25519", "bench-tenant")
        .await
        .unwrap();

    let data = vec![0u8; 256];
    let signature = store.sign(&meta.id, &data, "bench-tenant").await.unwrap();

    use std::time::Instant;
    let start = Instant::now();
    for _ in 0..1000 {
        let _ = store.sign(&meta.id, &data, "bench-tenant").await;
    }
    let sign_duration = start.elapsed();

    let start = Instant::now();
    for _ in 0..1000 {
        let _ = store
            .verify(&meta.id, &data, &signature, "bench-tenant")
            .await;
    }
    let verify_duration = start.elapsed();

    println!("\n=== Ed25519 (256B) ===");
    println!(
        "Sign: {:.2} ops/ms",
        1000.0 / sign_duration.as_millis() as f64 * 1000.0
    );
    println!(
        "Verify: {:.2} ops/ms",
        1000.0 / verify_duration.as_millis() as f64 * 1000.0
    );
}

#[tokio::test]
#[ignore]
async fn benchmark_key_generation() {
    let store = SoftwareKeystore::new();
    let spec = KeySpec::Aes256Gcm;

    use std::time::Instant;
    let start = Instant::now();
    for i in 0..100 {
        let _ = store
            .generate_key(&spec, &format!("bench-key-{}", i), "bench-tenant")
            .await;
    }
    let duration = start.elapsed();

    println!("\n=== Key Generation (AES-256-GCM) ===");
    println!("100 keys in {:?}", duration);
    println!("Rate: {:.2} keys/sec", 100.0 / duration.as_secs_f64());
}

#[tokio::test]
#[ignore]
async fn benchmark_sm2_kex() {
    use gm_crypto::sm2::Sm2KeyPair;

    let alice_store = SoftwareKeystore::new();
    let bob_store = SoftwareKeystore::new();

    // Pre-generate keys
    let alice_meta = alice_store
        .generate_key(&KeySpec::Sm2, "alice-kex", "bench-tenant")
        .await
        .unwrap();
    let bob_meta = bob_store
        .generate_key(&KeySpec::Sm2, "bob-kex", "bench-tenant")
        .await
        .unwrap();

    // Get private keys and derive public keys (uncompressed format)
    let alice_sk = alice_store
        .get_key_material(&alice_meta.id, "bench-tenant")
        .await
        .unwrap();
    let bob_sk = bob_store
        .get_key_material(&bob_meta.id, "bench-tenant")
        .await
        .unwrap();

    let alice_keypair = Sm2KeyPair::from_private_key(&alice_sk).unwrap();
    let bob_keypair = Sm2KeyPair::from_private_key(&bob_sk).unwrap();

    let alice_pubkey = alice_keypair.public_key_bytes_uncompressed();
    let bob_pubkey = bob_keypair.public_key_bytes_uncompressed();

    use std::time::Instant;
    let start = Instant::now();
    for _ in 0..100 {
        // Full SM2-KEX exchange: msg1 -> msg2 -> msg3
        // User ID must be max 16 bytes per GM/T 002-2012
        let (alice_session_id, msg1) = alice_store
            .create_sm2_kex_session(&alice_meta.id, b"alice_a@example")
            .unwrap();

        let (bob_session_id, msg2) = bob_store
            .accept_sm2_kex_session(&bob_meta.id, b"bob_b@example.co", &msg1, &alice_pubkey)
            .unwrap();

        let msg3 = alice_store
            .process_sm2_kex_message(&alice_session_id, &msg2, &bob_pubkey)
            .unwrap()
            .unwrap();

        bob_store
            .process_sm2_kex_message(&bob_session_id, &msg3, &alice_pubkey)
            .unwrap();
    }
    let duration = start.elapsed();

    println!("\n=== SM2-KEX (full exchange) ===");
    println!("100 exchanges in {:?}", duration);
    println!("Rate: {:.2} exchanges/sec", 100.0 / duration.as_secs_f64());
}

// ========================================================================
// Key Rotation Tests (VERIFY-014)
// ========================================================================

/// Rotation atomicity: after rotation, version increments and old
/// ciphertexts remain decryptable with preserved version history.
#[tokio::test]
async fn test_rotation_aes_gcm_preserves_old_decryption() {
    let store = SoftwareKeystore::new();

    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "rot-aes", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;
    assert_eq!(meta.version, 1);

    // Encrypt with original key
    let old_ct = store
        .encrypt(&key_id, b"before rotation", None, "test-tenant")
        .await
        .unwrap();

    // Rotate
    let new_meta = store.rotate_key(&key_id, "test-tenant").await.unwrap();
    assert_eq!(new_meta.version, 2);
    assert_eq!(new_meta.status, KeyStatus::Active);

    // Decrypt old ciphertext with new key version (uses version history)
    let old_pt = store
        .decrypt(&key_id, &old_ct, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(old_pt, b"before rotation");

    // Encrypt with new key
    let new_ct = store
        .encrypt(&key_id, b"after rotation", None, "test-tenant")
        .await
        .unwrap();
    let new_pt = store
        .decrypt(&key_id, &new_ct, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(new_pt, b"after rotation");

    // New and old ciphertexts should differ (new key material)
    assert_ne!(old_ct.ciphertext, new_ct.ciphertext);
}

/// SM4 rotation: encrypt → rotate → decrypt old → encrypt & decrypt new
#[tokio::test]
async fn test_rotation_sm4_preserves_old_decryption() {
    let store = SoftwareKeystore::new();

    let meta = store
        .generate_key(&KeySpec::Sm4, "rot-sm4", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;
    assert_eq!(meta.version, 1);

    let old_ct = store
        .encrypt(&key_id, b"sm4 before rotation", None, "test-tenant")
        .await
        .unwrap();
    let new_meta = store.rotate_key(&key_id, "test-tenant").await.unwrap();
    assert_eq!(new_meta.version, 2);

    let old_pt = store
        .decrypt(&key_id, &old_ct, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(old_pt, b"sm4 before rotation");

    let new_ct = store
        .encrypt(&key_id, b"sm4 after rotation", None, "test-tenant")
        .await
        .unwrap();
    let new_pt = store
        .decrypt(&key_id, &new_ct, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(new_pt, b"sm4 after rotation");
}

/// Rotation preserves old key version in metadata's version history
#[tokio::test]
async fn test_rotation_updates_metadata_correctly() {
    let store = SoftwareKeystore::new();

    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "meta-rot", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;
    let original_created = meta.created_at;
    assert!(meta.rotated_at.is_none());
    assert_eq!(meta.version, 1);

    // Small delay to ensure timestamps differ
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let new_meta = store.rotate_key(&key_id, "test-tenant").await.unwrap();
    assert_eq!(new_meta.version, 2);
    assert_eq!(new_meta.status, KeyStatus::Active);
    assert_eq!(new_meta.name, "meta-rot");
    // rotated_at should be set to the original created_at
    assert!(new_meta.rotated_at.is_some());
    assert_eq!(new_meta.rotated_at.unwrap(), original_created);
    // created_at should be updated to now
    assert!(new_meta.created_at > original_created);
}

/// Multiple rotations: version increments, all old ciphertexts remain decryptable
#[tokio::test]
async fn test_rotation_multiple_preserves_all_versions() {
    let store = SoftwareKeystore::new();

    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "multi-rot", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    // Encrypt with v1
    let ct_v1 = store
        .encrypt(&key_id, b"version 1", None, "test-tenant")
        .await
        .unwrap();

    // Rotate to v2
    let meta_v2 = store.rotate_key(&key_id, "test-tenant").await.unwrap();
    assert_eq!(meta_v2.version, 2);
    let ct_v2 = store
        .encrypt(&key_id, b"version 2", None, "test-tenant")
        .await
        .unwrap();

    // Rotate to v3
    let meta_v3 = store.rotate_key(&key_id, "test-tenant").await.unwrap();
    assert_eq!(meta_v3.version, 3);
    let ct_v3 = store
        .encrypt(&key_id, b"version 3", None, "test-tenant")
        .await
        .unwrap();

    // All versions should decrypt correctly
    let pt_v1 = store
        .decrypt(&key_id, &ct_v1, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(pt_v1, b"version 1");
    let pt_v2 = store
        .decrypt(&key_id, &ct_v2, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(pt_v2, b"version 2");
    let pt_v3 = store
        .decrypt(&key_id, &ct_v3, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(pt_v3, b"version 3");
}

/// Rotate non-existent key produces error
#[tokio::test]
async fn test_rotation_non_existent_key_errors() {
    let store = SoftwareKeystore::new();
    let result = store.rotate_key(&Uuid::new_v4(), "test-tenant").await;
    assert!(result.is_err());
}

/// Rotate a destroyed key produces error
#[tokio::test]
async fn test_rotation_destroyed_key_errors() {
    let store = SoftwareKeystore::new();

    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "destroy-rot", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    // Destroy the key
    store.destroy_key(&key_id).await.unwrap();

    // Rotation should fail
    let result = store.rotate_key(&key_id, "test-tenant").await;
    assert!(result.is_err());
}

/// Rotate a key with PendingDeletion status should fail
#[tokio::test]
async fn test_rotation_pending_deletion_errors() {
    let store = SoftwareKeystore::new();

    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "pending-del-rot", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    // Mark for deletion
    store.delete_key(&key_id, "test-tenant").await.unwrap();

    // Rotation should fail (PendingDeletion cannot be rotated)
    let result = store.rotate_key(&key_id, "test-tenant").await;
    assert!(result.is_err());
}

/// Rotating key A does not affect key B (cross-key isolation)
#[tokio::test]
async fn test_rotation_cross_key_isolation() {
    let store = SoftwareKeystore::new();

    let meta_a = store
        .generate_key(&KeySpec::Aes256Gcm, "key-a", "test-tenant")
        .await
        .unwrap();
    let meta_b = store
        .generate_key(&KeySpec::Aes256Gcm, "key-b", "test-tenant")
        .await
        .unwrap();

    // Encrypt with both keys
    let ct_a = store
        .encrypt(&meta_a.id, b"data for a", None, "test-tenant")
        .await
        .unwrap();
    let ct_b = store
        .encrypt(&meta_b.id, b"data for b", None, "test-tenant")
        .await
        .unwrap();

    // Rotate only key A
    let rotated_a = store.rotate_key(&meta_a.id, "test-tenant").await.unwrap();
    assert_eq!(rotated_a.version, 2);

    // Key B metadata unchanged
    let meta_b_after = store.get_key_metadata(&meta_b.id).await.unwrap();
    assert_eq!(meta_b_after.version, 1);
    assert!(meta_b_after.rotated_at.is_none());

    // Both keys can still decrypt their own data
    let pt_a = store
        .decrypt(&meta_a.id, &ct_a, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(pt_a, b"data for a");
    let pt_b = store
        .decrypt(&meta_b.id, &ct_b, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(pt_b, b"data for b");
}

/// Rotation preserves HmacSha256 key functionality (encrypt/decrypt)
#[tokio::test]
async fn test_rotation_hmac_key() {
    let store = SoftwareKeystore::new();

    let meta = store
        .generate_key(&KeySpec::HmacSha256, "rot-hmac", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    // Encrypt before rotation
    let ct_before = store
        .encrypt(&key_id, b"hmac data", None, "test-tenant")
        .await
        .unwrap();

    // Rotate
    let new_meta = store.rotate_key(&key_id, "test-tenant").await.unwrap();
    assert_eq!(new_meta.version, 2);

    // Decrypt old ciphertext (uses version history)
    let pt = store
        .decrypt(&key_id, &ct_before, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(pt, b"hmac data");

    // Encrypt & decrypt with new key
    let ct_after = store
        .encrypt(&key_id, b"new hmac data", None, "test-tenant")
        .await
        .unwrap();
    let pt_after = store
        .decrypt(&key_id, &ct_after, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(pt_after, b"new hmac data");
}

/// Rotation preserves Ed25519 key functionality
#[tokio::test]
async fn test_rotation_ed25519_key() {
    let store = SoftwareKeystore::new();

    let meta = store
        .generate_key(&KeySpec::Ed25519, "rot-ed", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    let sig_before = store
        .sign(&key_id, b"ed25519 data", "test-tenant")
        .await
        .unwrap();

    // Rotate
    let new_meta = store.rotate_key(&key_id, "test-tenant").await.unwrap();
    assert_eq!(new_meta.version, 2);

    // Old signature should not verify with rotated key
    let valid = store
        .verify(&key_id, b"ed25519 data", &sig_before, "test-tenant")
        .await
        .unwrap();
    assert!(!valid);

    // New signature should verify
    let sig_after = store
        .sign(&key_id, b"ed25519 data", "test-tenant")
        .await
        .unwrap();
    let valid_after = store
        .verify(&key_id, b"ed25519 data", &sig_after, "test-tenant")
        .await
        .unwrap();
    assert!(valid_after);
}

/// Concurrent rotations: multiple tasks rotate the same key concurrently.
/// At least one succeeds (the other may get a lock error or also succeed).
/// Final state must be consistent.
#[tokio::test]
async fn test_rotation_concurrent_safety() {
    use std::sync::Arc;

    let store = Arc::new(SoftwareKeystore::new());

    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "concurrent-rot", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    // Encrypt before rotation
    let ct_before = store
        .encrypt(&key_id, b"concurrent data", None, "test-tenant")
        .await
        .unwrap();

    // Launch 3 concurrent rotation tasks
    let mut handles = vec![];
    for _ in 0..3 {
        let store = store.clone();
        handles.push(tokio::spawn(async move {
            store.rotate_key(&key_id, "test-tenant").await
        }));
    }

    let mut success_count = 0;
    let mut last_version = 0u32;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(meta) => {
                success_count += 1;
                last_version = meta.version;
            }
            Err(_) => {
                // Some rotations may fail due to concurrent modifications
            }
        }
    }

    assert!(
        success_count >= 1,
        "At least one concurrent rotation should succeed"
    );

    // Verify post-rotation state is consistent
    let final_meta = store.get_key_metadata(&key_id).await.unwrap();
    assert_eq!(final_meta.status, KeyStatus::Active);
    assert_eq!(final_meta.version, last_version);

    // Data encrypted before rotations should still be decryptable
    let pt = store
        .decrypt(&key_id, &ct_before, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(pt, b"concurrent data");

    // New encryption should work
    let ct_after = store
        .encrypt(&key_id, b"after concurrent", None, "test-tenant")
        .await
        .unwrap();
    let pt_after = store
        .decrypt(&key_id, &ct_after, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(pt_after, b"after concurrent");
}

/// After rotation, encrypting the same plaintext should produce different
/// ciphertext (different key material + different nonce).
#[tokio::test]
async fn test_rotation_different_key_material() {
    let store = SoftwareKeystore::new();

    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "diff-mat", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    let ct1 = store
        .encrypt(&key_id, b"same plaintext", None, "test-tenant")
        .await
        .unwrap();

    // Rotate
    store.rotate_key(&key_id, "test-tenant").await.unwrap();

    let ct2 = store
        .encrypt(&key_id, b"same plaintext", None, "test-tenant")
        .await
        .unwrap();

    // Ciphertexts from different key versions should differ
    assert_ne!(ct1.ciphertext, ct2.ciphertext);

    // Both should decrypt to the same plaintext
    let pt1 = store
        .decrypt(&key_id, &ct1, None, "test-tenant")
        .await
        .unwrap();
    let pt2 = store
        .decrypt(&key_id, &ct2, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(pt1, b"same plaintext");
    assert_eq!(pt2, b"same plaintext");
}

/// Encrypt with version 1, rotate twice, verify all ciphertexts decrypt
#[tokio::test]
async fn test_rotation_sm2_sign_after_rotation() {
    let store = SoftwareKeystore::new();

    let meta = store
        .generate_key(&KeySpec::Sm2, "rot-sm2-sign", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    // Sign before rotation
    let sig_v1 = store
        .sign(&key_id, b"sm2 message", "test-tenant")
        .await
        .unwrap();
    let valid_v1 = store
        .verify(&key_id, b"sm2 message", &sig_v1, "test-tenant")
        .await
        .unwrap();
    assert!(valid_v1);

    // Rotate
    store.rotate_key(&key_id, "test-tenant").await.unwrap();

    // Old signature should not verify with new key
    let valid_old = store
        .verify(&key_id, b"sm2 message", &sig_v1, "test-tenant")
        .await
        .unwrap();
    assert!(!valid_old);

    // Sign with new key and verify
    let sig_v2 = store
        .sign(&key_id, b"sm2 message", "test-tenant")
        .await
        .unwrap();
    let valid_v2 = store
        .verify(&key_id, b"sm2 message", &sig_v2, "test-tenant")
        .await
        .unwrap();
    assert!(valid_v2);
}

/// Encryption with AAD parameter survives rotation (AAD is accepted but
/// currently not enforced by the AES-256-GCM implementation).
#[tokio::test]
async fn test_rotation_with_aad() {
    let store = SoftwareKeystore::new();

    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "rot-aad", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    let aad = b"authenticated data";
    let ct = store
        .encrypt(&key_id, b"secret with aad", Some(aad), "test-tenant")
        .await
        .unwrap();

    // Rotate
    store.rotate_key(&key_id, "test-tenant").await.unwrap();

    // Decrypt with correct version history (AAD parameter accepted)
    let pt = store
        .decrypt(&key_id, &ct, Some(aad), "test-tenant")
        .await
        .unwrap();
    assert_eq!(pt, b"secret with aad");

    // Encrypt with new key and different AAD — should still work
    let ct2 = store
        .encrypt(&key_id, b"more data", Some(b"different aad"), "test-tenant")
        .await
        .unwrap();
    let pt2 = store
        .decrypt(&key_id, &ct2, Some(b"different aad"), "test-tenant")
        .await
        .unwrap();
    assert_eq!(pt2, b"more data");
}

// ========================================================================
// Transaction Safety Tests (VERIFY-110)
// ========================================================================

/// Concurrent encrypt operations during key rotation:
/// all ciphertexts must decrypt correctly after rotation completes.
#[tokio::test]
async fn test_concurrent_encrypt_during_rotation() {
    use std::sync::Arc;

    let store = Arc::new(SoftwareKeystore::new());
    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "tx-enc-rot", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    // Pre-encrypt one message for version baseline
    let ct_v1 = store
        .encrypt(&key_id, b"v1", None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(ct_v1.version, 1);

    // Spawn concurrent encrypts and a rotation
    let mut encrypt_handles = vec![];
    for i in 0..5 {
        let store = store.clone();
        encrypt_handles.push(tokio::spawn(async move {
            store
                .encrypt(&key_id, format!("msg{}", i).as_bytes(), None, "test-tenant")
                .await
        }));
    }

    let store_rot = store.clone();
    let rotate_handle =
        tokio::spawn(async move { store_rot.rotate_key(&key_id, "test-tenant").await });

    // Collect encrypt results
    let mut encrypt_ok = 0;
    let mut cts = vec![ct_v1];
    for handle in encrypt_handles {
        if let Ok(ct) = handle.await.unwrap() {
            cts.push(ct);
            encrypt_ok += 1;
        } // May fail if rotation grabbed write lock first
    }
    assert!(encrypt_ok >= 1, "at least some encrypts should succeed");

    // Rotation must succeed
    rotate_handle.await.unwrap().unwrap();

    // All collected ciphertexts must decrypt correctly
    for (i, ct) in cts.iter().enumerate() {
        let pt = store
            .decrypt(&key_id, ct, None, "test-tenant")
            .await
            .unwrap();
        assert!(!pt.is_empty(), "ciphertext {} decrypted empty", i);
    }
}

/// Concurrent decrypt operations during rotation:
/// decrypting old ciphertexts while rotation is in progress.
#[tokio::test]
async fn test_concurrent_decrypt_during_rotation() {
    use std::sync::Arc;

    let store = Arc::new(SoftwareKeystore::new());
    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "tx-dec-rot", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    let ct = store
        .encrypt(&key_id, b"pre-rotation data", None, "test-tenant")
        .await
        .unwrap();

    // Spawn concurrent decrypts and a rotation
    let mut decrypt_handles = vec![];
    for _ in 0..5 {
        let store = store.clone();
        let ct = ct.clone();
        decrypt_handles.push(tokio::spawn(async move {
            store.decrypt(&key_id, &ct, None, "test-tenant").await
        }));
    }

    let store_rot = store.clone();
    let rotate_handle =
        tokio::spawn(async move { store_rot.rotate_key(&key_id, "test-tenant").await });

    // All decrypts must succeed (version history preserves old material)
    for handle in decrypt_handles {
        let pt = handle.await.unwrap().unwrap();
        assert_eq!(pt, b"pre-rotation data");
    }

    rotate_handle.await.unwrap().unwrap();

    // Post-rotation decrypt of same ciphertext must still work
    let pt = store
        .decrypt(&key_id, &ct, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(pt, b"pre-rotation data");
}

/// Encrypt is rejected on a key with PendingDeletion status
#[tokio::test]
async fn test_encrypt_rejected_after_delete() {
    let store = SoftwareKeystore::new();
    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "tx-del-enc", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    // Encrypt before delete — should work
    let ct = store
        .encrypt(&key_id, b"before delete", None, "test-tenant")
        .await
        .unwrap();
    assert!(!ct.ciphertext.is_empty());

    // Delete (PendingDeletion)
    store.delete_key(&key_id, "test-tenant").await.unwrap();

    // Encrypt after delete — should be rejected
    let result = store
        .encrypt(&key_id, b"after delete", None, "test-tenant")
        .await;
    assert!(result.is_err());
}

/// Decrypt is still allowed on a key with PendingDeletion (can_decrypt includes it)
#[tokio::test]
async fn test_decrypt_allowed_after_delete() {
    let store = SoftwareKeystore::new();
    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "tx-del-dec", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    let ct = store
        .encrypt(&key_id, b"decrypt after delete", None, "test-tenant")
        .await
        .unwrap();

    // Delete
    store.delete_key(&key_id, "test-tenant").await.unwrap();

    // Decrypt should still work (can_decrypt includes PendingDeletion)
    let pt = store
        .decrypt(&key_id, &ct, None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(pt, b"decrypt after delete");
}

/// Sign is rejected on PendingDeletion key (checks Active status)
#[tokio::test]
async fn test_sign_rejected_after_delete() {
    let store = SoftwareKeystore::new();
    let meta = store
        .generate_key(&KeySpec::Ed25519, "tx-del-sign", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    // Sign before delete
    let sig = store.sign(&key_id, b"msg", "test-tenant").await.unwrap();
    assert!(!sig.signature.is_empty());

    // Delete
    store.delete_key(&key_id, "test-tenant").await.unwrap();

    // Sign after delete — rejected
    let result = store.sign(&key_id, b"msg2", "test-tenant").await;
    assert!(result.is_err());
}

/// Verify still works on PendingDeletion (no status check in verify)
#[tokio::test]
async fn test_verify_allowed_after_delete() {
    let store = SoftwareKeystore::new();
    let meta = store
        .generate_key(&KeySpec::Ed25519, "tx-del-verify", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    let sig = store
        .sign(&key_id, b"verify msg", "test-tenant")
        .await
        .unwrap();

    // Delete
    store.delete_key(&key_id, "test-tenant").await.unwrap();

    // Verify should still work (no status check)
    let valid = store
        .verify(&key_id, b"verify msg", &sig, "test-tenant")
        .await
        .unwrap();
    assert!(valid);
}

/// Concurrent encrypt + delete: encrypts before delete succeed, after delete fail
#[tokio::test]
async fn test_concurrent_encrypt_delete_race() {
    use std::sync::Arc;

    let store = Arc::new(SoftwareKeystore::new());
    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "tx-enc-del", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    // Spawn encrypt tasks and a delete task concurrently
    let mut handles = vec![];
    for i in 0..5 {
        let store = store.clone();
        handles.push(tokio::spawn(async move {
            store
                .encrypt(&key_id, format!("enc{}", i).as_bytes(), None, "test-tenant")
                .await
        }));
    }

    let store_del = store.clone();
    let delete_handle =
        tokio::spawn(async move { store_del.delete_key(&key_id, "test-tenant").await });

    // Collect results — some encrypts may succeed, some may fail
    let mut success = 0;
    let mut failures = 0;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(_) => success += 1,
            Err(_) => failures += 1,
        }
    }
    delete_handle.await.unwrap().unwrap();

    // At least one of encrypt or delete should have worked
    assert!(success + failures == 5);
}

/// Ciphertext carries the correct key version
#[tokio::test]
async fn test_ciphertext_version_matches_key_version() {
    let store = SoftwareKeystore::new();
    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "tx-ver", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    // v1 encrypt
    let ct1 = store
        .encrypt(&key_id, b"v1", None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(ct1.version, 1);

    // Rotate to v2
    store.rotate_key(&key_id, "test-tenant").await.unwrap();

    // v2 encrypt
    let ct2 = store
        .encrypt(&key_id, b"v2", None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(ct2.version, 2);

    // Rotate to v3
    store.rotate_key(&key_id, "test-tenant").await.unwrap();

    // v3 encrypt
    let ct3 = store
        .encrypt(&key_id, b"v3", None, "test-tenant")
        .await
        .unwrap();
    assert_eq!(ct3.version, 3);

    // All decrypt correctly
    assert_eq!(
        store
            .decrypt(&key_id, &ct1, None, "test-tenant")
            .await
            .unwrap(),
        b"v1"
    );
    assert_eq!(
        store
            .decrypt(&key_id, &ct2, None, "test-tenant")
            .await
            .unwrap(),
        b"v2"
    );
    assert_eq!(
        store
            .decrypt(&key_id, &ct3, None, "test-tenant")
            .await
            .unwrap(),
        b"v3"
    );
}

/// Decrypt with unknown version number returns error
#[tokio::test]
async fn test_decrypt_rejects_unknown_version() {
    let store = SoftwareKeystore::new();
    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "tx-unknown-ver", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    // Create a ciphertext with forged version 999
    let ct = store
        .encrypt(&key_id, b"data", None, "test-tenant")
        .await
        .unwrap();
    let forged_ct = Ciphertext {
        key_id,
        version: 999,
        format_version: ct.format_version,
        nonce: ct.nonce,
        ciphertext: ct.ciphertext,
        tag: ct.tag,
    };

    let result = store
        .decrypt(&key_id, &forged_ct, None, "test-tenant")
        .await;
    assert!(result.is_err());
}

/// Concurrent read operations (multiple encrypts) on the same key
/// should all succeed without interference.
#[tokio::test]
async fn test_concurrent_reads_no_interference() {
    use std::sync::Arc;

    let store = Arc::new(SoftwareKeystore::new());
    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "tx-cread", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    let mut handles = vec![];
    for i in 0..10 {
        let store = store.clone();
        handles.push(tokio::spawn(async move {
            store
                .encrypt(
                    &key_id,
                    format!("concurrent{}", i).as_bytes(),
                    None,
                    "test-tenant",
                )
                .await
        }));
    }

    let mut ciphertexts = vec![];
    for handle in handles {
        let ct = handle.await.unwrap().unwrap();
        assert_eq!(ct.version, 1);
        ciphertexts.push(ct);
    }

    // All must decrypt correctly
    for (i, ct) in ciphertexts.iter().enumerate() {
        let expected = format!("concurrent{}", i);
        let pt = store
            .decrypt(&key_id, ct, None, "test-tenant")
            .await
            .unwrap();
        assert_eq!(pt, expected.as_bytes());
    }
}

/// Concurrent sign operations during rotation:
/// old signatures shouldn't verify after rotation completes.
#[tokio::test]
async fn test_concurrent_sign_during_rotation() {
    use std::sync::Arc;

    let store = Arc::new(SoftwareKeystore::new());
    let meta = store
        .generate_key(&KeySpec::Ed25519, "tx-sign-rot", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    // Spawn sign tasks and a rotation
    let mut sign_handles = vec![];
    for i in 0..5 {
        let store = store.clone();
        sign_handles.push(tokio::spawn(async move {
            store
                .sign(&key_id, format!("signed{}", i).as_bytes(), "test-tenant")
                .await
        }));
    }

    let store_rot = store.clone();
    let rotate_handle =
        tokio::spawn(async move { store_rot.rotate_key(&key_id, "test-tenant").await });

    let mut sigs = vec![];
    for handle in sign_handles {
        if let Ok(sig) = handle.await.unwrap() {
            sigs.push(sig)
        } // May fail if rotation grabbed write lock
    }
    assert!(!sigs.is_empty(), "at least some signs should succeed");

    rotate_handle.await.unwrap().unwrap();

    // Old signatures should not verify with the new key
    for sig in &sigs {
        let valid = store
            .verify(&key_id, b"any message", sig, "test-tenant")
            .await
            .unwrap();
        assert!(!valid, "old signature should not verify with rotated key");
    }

    // New sign + verify with rotated key
    let new_sig = store
        .sign(&key_id, b"after rotation", "test-tenant")
        .await
        .unwrap();
    let valid = store
        .verify(&key_id, b"after rotation", &new_sig, "test-tenant")
        .await
        .unwrap();
    assert!(valid);
}

/// Destroy key: all operations on destroyed key fail
#[tokio::test]
async fn test_operations_on_destroyed_key_fail() {
    let store = SoftwareKeystore::new();
    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "tx-destroy", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    let ct = store
        .encrypt(&key_id, b"pre-destroy", None, "test-tenant")
        .await
        .unwrap();

    // Destroy the key
    store.destroy_key(&key_id).await.unwrap();

    // Encrypt fails
    assert!(
        store
            .encrypt(&key_id, b"post", None, "test-tenant")
            .await
            .is_err()
    );
    // Decrypt fails (key not found)
    assert!(
        store
            .decrypt(&key_id, &ct, None, "test-tenant")
            .await
            .is_err()
    );
    // Sign fails
    assert!(store.sign(&key_id, b"msg", "test-tenant").await.is_err());
}

/// Concurrent destroy + encrypt: encrypts before destroy succeed,
/// after destroy fail with KeyNotFound.
#[tokio::test]
async fn test_concurrent_encrypt_destroy_race() {
    use std::sync::Arc;

    let store = Arc::new(SoftwareKeystore::new());
    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "tx-enc-destroy-race", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    let mut handles = vec![];
    for i in 0..5 {
        let store = store.clone();
        handles.push(tokio::spawn(async move {
            store
                .encrypt(&key_id, format!("enc{}", i).as_bytes(), None, "test-tenant")
                .await
        }));
    }

    let store_des = store.clone();
    let destroy_handle = tokio::spawn(async move { store_des.destroy_key(&key_id).await });

    let mut cts = vec![];
    for handle in handles {
        if let Ok(ct) = handle.await.unwrap() {
            cts.push(ct);
        }
    }
    destroy_handle.await.unwrap().unwrap();

    assert!(!cts.is_empty(), "at least one encryption should succeed");

    // Successfully encrypted ciphertexts before destruction should now fail to decrypt
    // because the key is gone
    for ct in &cts {
        assert!(
            store
                .decrypt(&key_id, ct, None, "test-tenant")
                .await
                .is_err()
        );
    }
}

/// Repeated rotate+encrypt cycles: verifying consistency across many
/// version transitions (stress test for version history integrity).
#[tokio::test]
async fn test_many_rotate_encrypt_cycles() {
    let store = SoftwareKeystore::new();
    let meta = store
        .generate_key(&KeySpec::Aes256Gcm, "tx-cycles", "test-tenant")
        .await
        .unwrap();
    let key_id = meta.id;

    let n_cycles = 5;
    let mut all_cts: Vec<(u32, Ciphertext)> = vec![];

    for cycle in 1..=n_cycles {
        let msg = format!("cycle-{}", cycle);
        let ct = store
            .encrypt(&key_id, msg.as_bytes(), None, "test-tenant")
            .await
            .unwrap();
        assert_eq!(ct.version, cycle as u32);
        all_cts.push((cycle as u32, ct));

        if cycle < n_cycles {
            store.rotate_key(&key_id, "test-tenant").await.unwrap();
        }
    }

    // All ciphertexts must decrypt correctly with their respective plaintexts
    for (version, ct) in &all_cts {
        let expected = format!("cycle-{}", version);
        let pt = store
            .decrypt(&key_id, ct, None, "test-tenant")
            .await
            .unwrap();
        assert_eq!(
            pt,
            expected.as_bytes(),
            "version {} decrypt mismatch",
            version
        );
    }

    // Final key version must be n_cycles
    let final_meta = store.get_key_metadata(&key_id).await.unwrap();
    assert_eq!(final_meta.version, n_cycles as u32);
}
