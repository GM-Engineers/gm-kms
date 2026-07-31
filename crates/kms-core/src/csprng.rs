//! 国密CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
//!
//! 实现 GM/T 0103-2012 和 GM/T 0105-2012 要求的随机数生成器。

use getrandom::getrandom;
use gm_crypto::sm3::Sm3Hmac;
use subtle::ConstantTimeEq;

/// 错误类型
#[derive(Debug, thiserror::Error)]
pub enum CsprngError {
    #[error("熵源获取失败: {0}")]
    EntropyError(String),
    #[error("随机字节生成失败: {0}")]
    GenerationError(String),
}

/// GM随机数生成器状态
#[derive(Clone)]
struct State {
    key: [u8; 32],
    counter: [u8; 32],
}

impl State {
    fn new() -> Result<Self, CsprngError> {
        let mut key = [0u8; 32];
        let mut counter = [0u8; 32];
        getrandom(&mut key).map_err(|e| CsprngError::EntropyError(e.to_string()))?;
        getrandom(&mut counter).map_err(|e| CsprngError::EntropyError(e.to_string()))?;
        Ok(Self { key, counter })
    }

    fn from_seed(seed: &[u8]) -> Self {
        let mut state = Self {
            key: [0u8; 32],
            counter: [0u8; 32],
        };
        let hash = Self::sm3_hash(seed);
        state.key.copy_from_slice(&hash);
        for (i, chunk) in state.counter.chunks_mut(4).enumerate() {
            let val = u32::to_le_bytes(i as u32 + 1);
            chunk.copy_from_slice(&val);
        }
        state
    }

    fn sm3_hash(data: &[u8]) -> [u8; 32] {
        use gm_crypto::sm3::Sm3Hasher;
        let hash = Sm3Hasher::hash(data).expect("SM3 hash should not fail");
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    fn generate(&mut self, mut output: &mut [u8], additional_input: Option<&[u8]>) {
        if let Some(add_input) = additional_input {
            self.update(add_input);
        }
        while !output.is_empty() {
            increment_counter(&mut self.counter);
            let mut hmac_input = Vec::with_capacity(64);
            hmac_input.extend_from_slice(&self.counter);
            if let Some(add) = additional_input {
                hmac_input.extend_from_slice(add);
            }
            let temp = self.hmac_sm3(&hmac_input);
            let copy_len = output.len().min(32);
            output[..copy_len].copy_from_slice(&temp[..copy_len]);
            output = &mut output[copy_len..];
            increment_counter(&mut self.counter);
        }
        self.update(additional_input.unwrap_or(&[]));
    }

    fn hmac_sm3(&self, data: &[u8]) -> [u8; 32] {
        let hmac = Sm3Hmac::new(&self.key);
        let result = hmac
            .compute(data)
            .expect("HMAC computation should not fail");
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }

    fn update(&mut self, additional_input: &[u8]) {
        let mut k_input = Vec::with_capacity(65 + additional_input.len());
        k_input.extend_from_slice(&self.counter);
        k_input.push(0x00);
        k_input.extend_from_slice(additional_input);
        self.key = self.hmac_sm3(&k_input);
        self.counter = self.hmac_sm3(&self.key);

        let mut k_input = Vec::with_capacity(65 + additional_input.len());
        k_input.extend_from_slice(&self.counter);
        k_input.push(0x01);
        k_input.extend_from_slice(additional_input);
        self.key = self.hmac_sm3(&k_input);
        self.counter = self.hmac_sm3(&self.key);
    }

    fn reseed(&mut self, entropy: &[u8]) {
        self.update(entropy);
    }
}

fn increment_counter(counter: &mut [u8; 32]) {
    for i in (0..32).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

/// GM加密安全随机数生成器
#[derive(Clone)]
pub struct GmRng {
    state: State,
}

impl GmRng {
    pub fn new() -> Result<Self, CsprngError> {
        Ok(Self {
            state: State::new()?,
        })
    }

    pub fn from_seed(seed: &[u8]) -> Self {
        Self {
            state: State::from_seed(seed),
        }
    }

    pub fn reseed(&mut self, entropy: &[u8]) {
        self.state.reseed(entropy);
    }

    pub fn random_bytes(&mut self, len: usize) -> Result<Vec<u8>, CsprngError> {
        let mut output = vec![0u8; len];
        self.state.generate(&mut output, None);
        Ok(output)
    }

    pub fn random_bytes_with_reseed(&mut self, len: usize) -> Result<Vec<u8>, CsprngError> {
        let mut entropy = [0u8; 32];
        getrandom(&mut entropy).map_err(|e| CsprngError::EntropyError(e.to_string()))?;
        self.state.reseed(&entropy);
        let mut output = vec![0u8; len];
        self.state.generate(&mut output, None);
        Ok(output)
    }

    pub fn fill(&mut self, dest: &mut [u8]) -> Result<(), CsprngError> {
        self.state.generate(dest, None);
        Ok(())
    }
}

impl Default for GmRng {
    fn default() -> Self {
        Self::new().expect("Failed to initialize GM CSPRNG")
    }
}

/// 生成随机DEK
pub fn generate_dek(length: usize) -> Vec<u8> {
    let mut rng = GmRng::new().expect("Failed to initialize GM CSPRNG for DEK generation");
    rng.random_bytes(length).expect("DEK generation failed")
}

/// 生成随机nonce
pub fn generate_nonce(length: usize) -> Vec<u8> {
    let mut rng = GmRng::new().expect("Failed to initialize GM CSPRNG for nonce generation");
    rng.random_bytes(length).expect("Nonce generation failed")
}

/// 生成随机字节
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = GmRng::new().expect("Failed to initialize GM CSPRNG");
    rng.random_bytes(len)
        .expect("Random bytes generation failed")
}

/// CSPRNG诊断信息
#[derive(Debug, Clone)]
pub struct CsprngDiagnostics {
    pub entropy_available: bool,
    pub implementation: &'static str,
    pub standards: &'static [&'static str],
}

impl CsprngDiagnostics {
    pub fn diagnose() -> Self {
        let entropy_available = getrandom(&mut [0u8; 1]).is_ok();
        Self {
            entropy_available,
            implementation: "GM/SM3 HMAC_DRBG",
            standards: &["GM/T 0103-2012", "GM/T 0105-2012"],
        }
    }
}

/// 验证CSPRNG是否正确工作
pub fn verify() -> Result<(), CsprngError> {
    let diag = CsprngDiagnostics::diagnose();
    if !diag.entropy_available {
        return Err(CsprngError::EntropyError(
            "OS entropy source unavailable".to_string(),
        ));
    }
    let bytes1 = random_bytes(32);
    let bytes2 = random_bytes(32);
    if bytes1.ct_eq(&bytes2).into() {
        return Err(CsprngError::GenerationError(
            "CSPRNG not producing random values".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_dek() {
        let dek1 = generate_dek(32);
        let dek2 = generate_dek(32);
        assert_eq!(dek1.len(), 32);
        assert_eq!(dek2.len(), 32);
        assert_ne!(dek1.as_slice(), dek2.as_slice());
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce(12);
        let nonce2 = generate_nonce(12);
        assert_eq!(nonce1.len(), 12);
        assert_ne!(nonce1.as_slice(), nonce2.as_slice());
    }

    #[test]
    fn test_random_bytes() {
        let bytes = random_bytes(16);
        assert_eq!(bytes.len(), 16);
        assert!(!bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_from_seed() {
        let seed = [0x42u8; 32];
        let mut rng1 = GmRng::from_seed(&seed);
        let mut rng2 = GmRng::from_seed(&seed);
        let bytes1 = rng1.random_bytes(16).unwrap();
        let bytes2 = rng2.random_bytes(16).unwrap();
        assert_eq!(bytes1.as_slice(), bytes2.as_slice());
    }

    #[test]
    fn test_different_seeds_different_output() {
        let seed1 = [0x42u8; 32];
        let seed2 = [0x43u8; 32];
        let mut rng1 = GmRng::from_seed(&seed1);
        let mut rng2 = GmRng::from_seed(&seed2);
        let bytes1 = rng1.random_bytes(16).unwrap();
        let bytes2 = rng2.random_bytes(16).unwrap();
        assert_ne!(bytes1.as_slice(), bytes2.as_slice());
    }

    #[test]
    fn test_csprng_diagnostics() {
        let diag = CsprngDiagnostics::diagnose();
        assert!(diag.entropy_available);
        assert_eq!(diag.implementation, "GM/SM3 HMAC_DRBG");
    }

    #[test]
    fn test_verify() {
        assert!(verify().is_ok());
    }
}
