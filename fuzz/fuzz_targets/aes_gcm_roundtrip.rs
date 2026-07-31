#![no_main]

/// AES-256-GCM encrypt/decrypt roundtrip fuzz target
///
/// Verifies that encrypt(plaintext) → decrypt(ciphertext) == plaintext
/// for arbitrary inputs. The fuzzer generates random keys, nonces, and messages.
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

fn fuzz(data: &[u8]) {
    // Need at least key (32) + nonce (12) = 44 bytes
    if data.len() < 44 {
        return;
    }

    let key_bytes: [u8; 32] = match data[..32].try_into() {
        Ok(k) => k,
        Err(_) => return,
    };
    let nonce_bytes: [u8; 12] = match data[32..44].try_into() {
        Ok(n) => n,
        Err(_) => return,
    };
    let plaintext = &data[44..];
    if plaintext.is_empty() {
        return;
    }

    let unbound_key = match UnboundKey::new(&AES_256_GCM, &key_bytes) {
        Ok(k) => k,
        Err(_) => return,
    };
    let key = LessSafeKey::new(unbound_key);

    // Encrypt
    let mut ct = plaintext.to_vec();
    let tag = match key.seal_in_place_separate_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::empty(),
        &mut ct,
    ) {
        Ok(t) => t,
        Err(_) => return,
    };

    // Decrypt — rebuild combined buffer to avoid borrow issues
    let mut combined = ct.clone();
    combined.extend_from_slice(tag.as_ref());
    let decrypted = match key.open_in_place(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::empty(),
        &mut combined,
    ) {
        Ok(d) => d,
        Err(_) => {
            panic!(
                "AES-256-GCM decrypt failed for valid ciphertext (pt len={})",
                plaintext.len()
            );
        }
    };

    assert_eq!(
        decrypted, plaintext,
        "AES-256-GCM roundtrip mismatch: pt len={}",
        plaintext.len()
    );
}

use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { fuzz(data) });
