#![no_main]

/// SM2 sign/verify roundtrip fuzz target
///
/// Verifies that sign(message) → verify(message, signature) == true
/// for arbitrary messages. Uses a single generated key pair.
use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer, Sm2Verifier};
use std::sync::OnceLock;

/// Generate key pair once, reuse for all fuzz iterations
fn keys() -> &'static (Sm2Signer, Sm2Verifier) {
    static KEYS: OnceLock<Box<(Sm2Signer, Sm2Verifier)>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let kp = Sm2KeyPair::generate().expect("SM2 key generation failed");
        let signer = Sm2Signer::new(&kp).expect("SM2 signer creation failed");
        let verifier = Sm2Verifier::new(
            &kp.public_key_bytes_uncompressed(),
            "1234567812345678",
        )
        .expect("SM2 verifier creation failed");
        Box::new((signer, verifier))
    })
}

fn fuzz(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let (signer, verifier) = keys();

    // Sign
    let sig = match signer.sign(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Verify original message
    match verifier.verify(data, &sig) {
        Ok(()) => {}
        Err(e) => {
            panic!(
                "SM2 verify failed for valid signature: {} (msg len={})",
                e,
                data.len()
            );
        }
    }

    // Verify with tampered message should fail
    let tampered_len = data.len();
    let mut tampered = data.to_vec();
    if tampered_len > 1 {
        tampered[tampered_len / 2] ^= 1;
    } else {
        tampered.push(0);
    }
    if verifier.verify(&tampered, &sig).is_ok() {
        panic!(
            "SM2 verify should reject tampered message (msg len={})",
            data.len()
        );
    }
}

use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { fuzz(data) });
