//! dudect timing side-channel analysis for gm-kms
//!
//! Tests for constant-time behavior in security-critical operations:
//! - SM2 signing (fixed vs random keys)
//! - SM4 GCM encryption (fixed vs random plaintext)
//! - API key comparison (constant-time equality)
//! - HMAC-SM3 MAC comparison
//!
//! Uses Welch's t-test. Threshold: |t| > 4.5 indicates a timing leak.
//!
//! This is NOT a libFuzzer fuzz target — it's a standalone timing analysis
//! binary. Run with: cargo run --bin dudect_timing

use std::time::Instant;

const THRESHOLD: f64 = 4.5;
const NUM_SAMPLES: usize = 1_000_000;
const WARMUP_SAMPLES: usize = 10_000;

// ---------------------------------------------------------------------------
// Statistical helpers
// ---------------------------------------------------------------------------

fn compute_stats(times: &[f64]) -> (f64, f64) {
    let n = times.len() as f64;
    let mean = times.iter().sum::<f64>() / n;
    let variance = times.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / (n - 1.0);
    (mean, variance)
}

/// Welch's t-test for two independent samples with possibly unequal variance
fn welch_t(fixed: &[f64], random: &[f64]) -> f64 {
    let (m1, v1) = compute_stats(fixed);
    let (m2, v2) = compute_stats(random);
    let n1 = fixed.len() as f64;
    let n2 = random.len() as f64;
    (m1 - m2) / (v1 / n1 + v2 / n2).sqrt()
}

fn measure_timing<F>(mut f: F) -> f64
where
    F: FnMut(),
{
    let start = Instant::now();
    f();
    start.elapsed().as_secs_f64()
}

// ---------------------------------------------------------------------------
// Test 1: SM2 Signing
// ---------------------------------------------------------------------------

fn test_sm2_sign_timing() {
    println!("\n=== Test 1: SM2 Sign Timing Analysis ===");

    // Generate two different SM2 key pairs
    use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer};

    let key1 = Sm2KeyPair::generate().expect("failed to generate SM2 key 1");
    let key2 = Sm2KeyPair::generate().expect("failed to generate SM2 key 2");
    let signer1 = Sm2Signer::new(&key1).expect("failed to create signer 1");
    let signer2 = Sm2Signer::new(&key2).expect("failed to create signer 2");

    let mut fixed_times = Vec::with_capacity(NUM_SAMPLES);
    let mut random_times = Vec::with_capacity(NUM_SAMPLES);

    let data = b"constant_time_test_data_for_sm2_signing";

    // Warmup
    for _ in 0..WARMUP_SAMPLES {
        let _ = signer1.sign(data);
    }

    // Fixed class: always use key1
    for _ in 0..NUM_SAMPLES {
        let t = measure_timing(|| {
            let _ = signer1.sign(data);
        });
        fixed_times.push(t);
    }

    // Random class: alternate between key1 and key2
    let mut toggle = false;
    for _ in 0..NUM_SAMPLES {
        let t = measure_timing(|| {
            if toggle {
                let _ = signer2.sign(data);
            } else {
                let _ = signer1.sign(data);
            }
        });
        toggle = !toggle;
        random_times.push(t);
    }

    let t_stat = welch_t(&fixed_times, &random_times);
    let (m_fixed, _) = compute_stats(&fixed_times);
    let (m_random, _) = compute_stats(&random_times);

    println!("  Fixed key mean:  {:.6} ms", m_fixed * 1000.0);
    println!("  Random key mean: {:.6} ms", m_random * 1000.0);
    println!("  t-statistic:     {:.2}", t_stat);
    println!(
        "  Result:          {}",
        if t_stat.abs() > THRESHOLD {
            "TIMING LEAK DETECTED"
        } else {
            "PASS (no leak detected)"
        }
    );
}

// ---------------------------------------------------------------------------
// Test 2: SM4 GCM Encryption
// ---------------------------------------------------------------------------

fn test_sm4_gcm_timing() {
    println!("\n=== Test 2: SM4 GCM Encryption Timing Analysis ===");

    use gm_crypto::sm4::Sm4Cipher;

    let key: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    ];
    let cipher = Sm4Cipher::new(&key).expect("failed to create SM4 cipher");

    let fixed_plaintext = b"AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD"; // 32 bytes
    let random_plaintext1 = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let random_plaintext2 = b"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";

    let nonce = [0u8; 12];
    let aad: [u8; 0] = [];

    let mut fixed_times = Vec::with_capacity(NUM_SAMPLES / 10); // SM4 is slower, use fewer samples
    let mut random_times = Vec::with_capacity(NUM_SAMPLES / 10);

    // Warmup
    for _ in 0..WARMUP_SAMPLES / 10 {
        let _ = cipher.encrypt_gcm(fixed_plaintext, &nonce, &aad);
    }

    // Fixed class: always same plaintext
    for _ in 0..NUM_SAMPLES / 10 {
        let t = measure_timing(|| {
            let _ = cipher.encrypt_gcm(fixed_plaintext, &nonce, &aad);
        });
        fixed_times.push(t);
    }

    // Random class: alternate plaintext
    let mut toggle = false;
    for _ in 0..NUM_SAMPLES / 10 {
        let t = measure_timing(|| {
            let input = if toggle {
                random_plaintext1
            } else {
                random_plaintext2
            };
            let _ = cipher.encrypt_gcm(input, &nonce, &aad);
        });
        toggle = !toggle;
        random_times.push(t);
    }

    let t_stat = welch_t(&fixed_times, &random_times);
    let (m_fixed, _) = compute_stats(&fixed_times);
    let (m_random, _) = compute_stats(&random_times);

    println!("  SM4 samples:     {}", NUM_SAMPLES / 10);
    println!("  Fixed plaintext mean:  {:.6} ms", m_fixed * 1000.0);
    println!("  Random plaintext mean: {:.6} ms", m_random * 1000.0);
    println!("  t-statistic:     {:.2}", t_stat);
    println!(
        "  Result:          {}",
        if t_stat.abs() > THRESHOLD {
            "TIMING LEAK DETECTED"
        } else {
            "PASS (no leak detected)"
        }
    );
}

// ---------------------------------------------------------------------------
// Test 3: Constant-Time Equality (subtle crate)
// ---------------------------------------------------------------------------

fn test_ct_eq_timing() {
    println!("\n=== Test 3: Constant-Time Equality Timing ===");

    use subtle::ConstantTimeEq;

    // Test using subtle crate ct_eq
    let mut fixed_times = Vec::with_capacity(NUM_SAMPLES);
    let mut random_times = Vec::with_capacity(NUM_SAMPLES);

    // Warmup
    let a = vec![0x42u8; 32];
    for _ in 0..WARMUP_SAMPLES {
        let _ = a.ct_eq(&a);
    }

    // Fixed class: compare identical values
    let identical = vec![0x42u8; 32];
    for _ in 0..NUM_SAMPLES {
        let t = measure_timing(|| {
            let _ = identical.ct_eq(&identical);
        });
        fixed_times.push(t);
    }

    // Random class: compare with different values (byte by byte variation)
    let base = vec![0x42u8; 32];
    let mut different = base.clone();
    let mut idx = 0usize;
    for _ in 0..NUM_SAMPLES {
        different[idx % 32] = different[idx % 32].wrapping_add(1);
        let t = measure_timing(|| {
            let _ = base.ct_eq(&different);
        });
        idx += 1;
        random_times.push(t);
    }

    let t_stat = welch_t(&fixed_times, &random_times);
    let (m_fixed, _) = compute_stats(&fixed_times);
    let (m_random, _) = compute_stats(&random_times);

    println!("  Fixed (identical) mean:  {:.6} us", m_fixed * 1_000_000.0);
    println!("  Random (different) mean: {:.6} us", m_random * 1_000_000.0);
    println!("  t-statistic:             {:.2}", t_stat);
    println!(
        "  Result:                  {}",
        if t_stat.abs() > THRESHOLD {
            "TIMING LEAK DETECTED"
        } else {
            "PASS (no leak detected)"
        }
    );
}

// ---------------------------------------------------------------------------
// Test 4: HMAC-SM3 constant-time verification
// ---------------------------------------------------------------------------

fn test_hmac_sm3_verify_timing() {
    println!("\n=== Test 4: HMAC-SM3 Verification Timing ===");

    use gm_crypto::sm3::Sm3Hmac;
    use subtle::ConstantTimeEq;

    let key = [0x55u8; 32];
    let hmac = Sm3Hmac::new(&key);
    let msg = b"message for hmac verification";
    let tag = hmac.compute(msg).expect("failed to compute HMAC");

    let mut fixed_times = Vec::with_capacity(NUM_SAMPLES);
    let mut random_times = Vec::with_capacity(NUM_SAMPLES);

    let wrong_tag = {
        let mut t = tag.clone();
        t[0] ^= 0xff;
        t
    };

    // Warmup
    for _ in 0..WARMUP_SAMPLES {
        let _ = tag.ct_eq(&tag);
    }

    // Fixed class: correct MAC
    for _ in 0..NUM_SAMPLES {
        let t = measure_timing(|| {
            let _ = tag.ct_eq(&tag);
        });
        fixed_times.push(t);
    }

    // Random class: mix of correct and wrong MACs
    let mut toggle = false;
    for _ in 0..NUM_SAMPLES {
        let t = measure_timing(|| {
            let cmp = if toggle { &tag } else { &wrong_tag };
            let _ = tag.ct_eq(cmp);
        });
        toggle = !toggle;
        random_times.push(t);
    }

    let t_stat = welch_t(&fixed_times, &random_times);
    let (m_fixed, _) = compute_stats(&fixed_times);
    let (m_random, _) = compute_stats(&random_times);

    println!("  Fixed (correct MAC) mean:  {:.6} us", m_fixed * 1_000_000.0);
    println!("  Random (mixed MAC) mean:   {:.6} us", m_random * 1_000_000.0);
    println!("  t-statistic:               {:.2}", t_stat);
    println!(
        "  Result:                    {}",
        if t_stat.abs() > THRESHOLD {
            "TIMING LEAK DETECTED"
        } else {
            "PASS (no leak detected)"
        }
    );
}

fn main() {
    println!("# dudect Timing Side-Channel Analysis — gm-kms");
    println!("  Samples: {} per class", NUM_SAMPLES);
    println!("  Threshold: |t| > {}", THRESHOLD);
    println!("  NOTE: This is a statistical test. Run multiple times for confidence.");

    test_sm2_sign_timing();
    test_sm4_gcm_timing();
    test_ct_eq_timing();
    test_hmac_sm3_verify_timing();

    println!("\n=== Analysis Complete ===");
    println!("Interpretation:");
    println!("  |t| < 4.5 → No detectable timing side-channel at this sample size");
    println!("  |t| > 4.5 → Potential timing leak, investigate further");
    println!("  For production verification, run with 10M+ samples per class");
}
