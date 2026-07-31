#![no_main]

/// SM4-GCM encrypt/decrypt roundtrip fuzz target
///
/// Verifies that encrypt(plaintext) → decrypt(ciphertext) == plaintext
/// for arbitrary inputs. The fuzzer generates random keys, nonces, and messages.
#[allow(deprecated)]
use gm_crypto::sm4::{SM4_GCM_NONCE_LENGTH, Sm4Cipher};

fn fuzz(data: &[u8]) {
    // Need at least key (16) + nonce (12) + 1 byte plaintext = 29 bytes
    if data.len() < 29 {
        return;
    }

    let key = &data[..16];
    let nonce = &data[16..28];
    let plaintext = &data[28..];
    if plaintext.is_empty() {
        return;
    }

    let cipher = match Sm4Cipher::new(key) {
        Ok(c) => c,
        Err(_) => return,
    };

    let nonce = &nonce[..SM4_GCM_NONCE_LENGTH];

    // Encrypt
    let (ct, tag) = match cipher.encrypt_gcm(plaintext, nonce, &[]) {
        Ok(result) => result,
        Err(_) => return,
    };

    // Decrypt
    let decrypted = match cipher.decrypt_gcm(&ct, nonce, &[], &tag) {
        Ok(d) => d,
        Err(_) => {
            panic!(
                "SM4-GCM decrypt failed for valid ciphertext (pt len={}, ct len={})",
                plaintext.len(),
                ct.len()
            );
        }
    };

    assert_eq!(
        decrypted, plaintext,
        "SM4-GCM roundtrip mismatch: pt len={}, ct len={}",
        plaintext.len(),
        ct.len()
    );
}

use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { fuzz(data) });
