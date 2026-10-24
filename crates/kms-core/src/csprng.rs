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
    /// 自动周期性重播种间隔（generate 调用次数）。`0` 表示关闭自动重播种，
    /// 用于 `from_seed()` 产生的确定性实例（KAT 自检依赖其稳定输出）。
    reseed_interval: u64,
    reseed_countdown: u64,
}

/// 熵实例（`new()`）在两次 OS 重播种之间的默认 generate 调用次数
/// （audit P3-2：周期重播种）。
const DEFAULT_RESEED_INTERVAL: u64 = 1024;

impl GmRng {
    pub fn new() -> Result<Self, CsprngError> {
        Ok(Self {
            state: State::new()?,
            reseed_interval: DEFAULT_RESEED_INTERVAL,
            reseed_countdown: DEFAULT_RESEED_INTERVAL,
        })
    }

    pub fn from_seed(seed: &[u8]) -> Self {
        Self {
            state: State::from_seed(seed),
            // 确定性实例：永不自动重播种，使固定种子始终产生同一流
            // （DRBG 实例化 KAT 自检依赖此性质）。
            reseed_interval: 0,
            reseed_countdown: 0,
        }
    }

    /// 达到配置的间隔时从 OS 拉取新熵并混入状态（audit P3-2：周期重播种）。
    /// `reseed_interval == 0` 时为空操作，保证种子实例的确定性。
    fn maybe_periodic_reseed(&mut self) -> Result<(), CsprngError> {
        if self.reseed_interval == 0 {
            return Ok(());
        }
        self.reseed_countdown = self.reseed_countdown.saturating_sub(1);
        if self.reseed_countdown == 0 {
            let mut entropy = [0u8; 32];
            getrandom(&mut entropy).map_err(|e| CsprngError::EntropyError(e.to_string()))?;
            self.state.reseed(&entropy);
            self.reseed_countdown = self.reseed_interval;
        }
        Ok(())
    }

    pub fn reseed(&mut self, entropy: &[u8]) {
        self.state.reseed(entropy);
    }

    pub fn random_bytes(&mut self, len: usize) -> Result<Vec<u8>, CsprngError> {
        self.maybe_periodic_reseed()?;
        let mut output = vec![0u8; len];
        self.state.generate(&mut output, None);
        Ok(output)
    }

    pub fn random_bytes_with_reseed(&mut self, len: usize) -> Result<Vec<u8>, CsprngError> {
        let mut entropy = [0u8; 32];
        getrandom(&mut entropy).map_err(|e| CsprngError::EntropyError(e.to_string()))?;
        self.state.reseed(&entropy);
        // 手动重播种后重置周期倒计时。
        self.reseed_countdown = self.reseed_interval;
        let mut output = vec![0u8; len];
        self.state.generate(&mut output, None);
        Ok(output)
    }

    pub fn fill(&mut self, dest: &mut [u8]) -> Result<(), CsprngError> {
        self.maybe_periodic_reseed()?;
        self.state.generate(dest, None);
        Ok(())
    }
}

impl Default for GmRng {
    fn default() -> Self {
        Self::new().expect("Failed to initialize GM CSPRNG")
    }
}

/// 从 OS CSPRNG (`getrandom`) 填充 `len` 字节。
///
/// audit P3-2：关键密码材料（DEK/nonce/随机密钥字节）统一走经过充分审计的
/// OS CSPRNG；自建 HMAC-SM3 DRBG（[`GmRng`]）限定于非密钥场景（测试/掩码等）。
fn os_random(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    getrandom(&mut buf).expect("OS CSPRNG (getrandom) must be available for key material");
    buf
}

/// 生成随机DEK（走 OS CSPRNG，audit P3-2）
pub fn generate_dek(length: usize) -> Vec<u8> {
    os_random(length)
}

/// 生成随机nonce（走 OS CSPRNG，audit P3-2）
pub fn generate_nonce(length: usize) -> Vec<u8> {
    os_random(length)
}

/// 生成随机字节（走 OS CSPRNG，audit P3-2）
pub fn random_bytes(len: usize) -> Vec<u8> {
    os_random(len)
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
    // audit P3-2: run the DRBG instantiation known-answer self-test every time.
    self_test()?;
    let bytes1 = random_bytes(32);
    let bytes2 = random_bytes(32);
    if bytes1.ct_eq(&bytes2).into() {
        return Err(CsprngError::GenerationError(
            "CSPRNG not producing random values".to_string(),
        ));
    }
    Ok(())
}

// Frozen DRBG reference vector: first 32 bytes of
// `GmRng::from_seed(&[0x01; 32]).random_bytes(32)` under the current
// HMAC-SM3 instantiation. Captured once; self_test() then guards against any
// accidental drift in the DRBG core (audit P3-2).
const DRBG_KAT_EXPECTED: [u8; 32] = [
    62, 47, 184, 75, 201, 248, 226, 119, 152, 15, 78, 78, 49, 128, 44, 151, 25, 193, 214, 24, 97,
    121, 92, 173, 207, 139, 159, 86, 59, 103, 251, 220,
];

/// DRBG 实例化 Known-Answer 自检（audit P3-2）。
///
/// 从固定种子实例化 HMAC-SM3 DRBG，校验：
/// 1. 输出与冻结的参考向量逐字节一致（防算法漂移）；
/// 2. 同种子不同实例 → 相同输出（确定性）；
/// 3. 不同种子 → 不同输出。
///
/// `from_seed` 实例关闭了自动周期重播种，故该向量稳定可复现。
pub fn self_test() -> Result<(), CsprngError> {
    use subtle::ConstantTimeEq;

    const SEED: [u8; 32] = [0x01; 32];
    // Frozen reference: first 32 bytes of `GmRng::from_seed(&[0x01; 32])`.
    const EXPECTED: [u8; 32] = DRBG_KAT_EXPECTED;
    let mut rng = GmRng::from_seed(&SEED);
    let first = rng.random_bytes(32)?;
    if !bool::from(first.as_slice().ct_eq(&EXPECTED)) {
        return Err(CsprngError::GenerationError(
            "GM DRBG KAT self-test: output mismatch".to_string(),
        ));
    }

    // Determinism across an independent instance with the same seed.
    let mut rng2 = GmRng::from_seed(&SEED);
    let second = rng2.random_bytes(32)?;
    if first != second {
        return Err(CsprngError::GenerationError(
            "GM DRBG KAT self-test: non-deterministic for fixed seed".to_string(),
        ));
    }

    // A different seed must produce a different stream.
    let mut rng3 = GmRng::from_seed(&[0x02; 32]);
    let other = rng3.random_bytes(32)?;
    if other == first {
        return Err(CsprngError::GenerationError(
            "GM DRBG KAT self-test: seed change produced identical output".to_string(),
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

    #[test]
    fn test_drbg_kat_self_test() {
        // audit P3-2: the DRBG instantiation KAT must pass and stay deterministic.
        assert!(self_test().is_ok());
    }

    #[test]
    fn test_key_material_helpers_use_os_csprng() {
        // audit P3-2: DEK/nonce/random_bytes come from the OS CSPRNG — non-zero
        // and unique across calls.
        let a = generate_dek(32);
        let b = generate_dek(32);
        assert_eq!(a.len(), 32);
        assert!(!a.iter().all(|&x| x == 0));
        assert_ne!(a.as_slice(), b.as_slice());
        assert!(!generate_nonce(12).iter().all(|&x| x == 0));
        assert_eq!(random_bytes(16).len(), 16);
    }

    #[test]
    fn test_periodic_reseed_triggers_at_interval() {
        // audit P3-2: an entropy-backed instance reseeds from the OS once the
        // countdown elapses, mutating the state and resetting the countdown.
        let mut rng = GmRng::new().unwrap();
        rng.reseed_interval = 4;
        rng.reseed_countdown = 1; // next generate() trips the reseed
        let before = rng.state.key;
        let _ = rng.random_bytes(16).unwrap();
        assert_ne!(before, rng.state.key, "reseed must mutate the DRBG key");
        assert_eq!(rng.reseed_countdown, 4, "countdown resets to the interval");
    }

    #[test]
    fn test_from_seed_instance_does_not_auto_reseed() {
        // The deterministic (seeded) path must keep reseed_interval == 0 so the
        // KAT vector stays reproducible.
        let mut rng = GmRng::from_seed(&[0x01; 32]);
        assert_eq!(rng.reseed_interval, 0);
        let _ = rng.random_bytes(32).unwrap();
        assert_eq!(rng.reseed_countdown, 0, "seeded path never reseeds");
    }
}
