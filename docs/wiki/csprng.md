# CSPRNG（密码学安全随机数生成器） / Cryptographically Secure PRNG

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **类型 Type** | 密码学原语 / Cryptographic Primitive |
| **实现位置** | `kms-core/csprng.rs` |
| **目的 Purpose** | 生成加密安全的随机数 / Generate cryptographically secure random numbers |


## 概述

CSPRNG（Cryptographically Secure Pseudo-Random Number Generator）用于生成密钥、IV、盐值等安全敏感的随机数。

## 实现机制

gm-kms 使用 `GmRng`，基于 HMAC-SM3 的确定性随机数生成器（DRBG），符合 GM/T 0103-2012 和 GM/T 0105-2012 要求：

```rust
use kms_core::csprng::{GmRng, random_bytes, generate_dek, generate_nonce};

// 创建 CSPRNG（使用系统熵源初始化）
let mut rng = GmRng::new()?;

// 生成随机字节
let mut dest = vec![0u8; 32];
rng.fill(&mut dest)?;

// 便捷函数
let key = random_bytes(32);        // 生成随机密钥
let nonce = generate_nonce(12);    // 生成随机 nonce
let dek = generate_dek(32);        // 生成 DEK
```

### 内部实现

```
┌─────────────────────────────────────────────┐
│              HMAC-SM3 DRBG                   │
│                                             │
│  熵源输入 → Key + Counter → HMAC-SM3 → 输出  │
│                    ↑                        │
│                    └── 每次生成后更新         │
└─────────────────────────────────────────────┘
```

- 使用 `getrandom` 获取系统熵源
- 基于 HMAC-SM3 的 DRBG 架构
- 内部状态：32 字节 Key + 32 字节 Counter

## GmRng 结构

```rust
pub struct GmRng {
    // 内部状态
}

impl GmRng {
    pub fn new() -> Result<Self, CsprngError> { /* 系统熵源 */ }
    pub fn from_seed(seed: &[u8]) -> Self { /* 确定种子 */ }
    pub fn reseed(&mut self, entropy: &[u8]) { /* 添加熵 */ }
    pub fn random_bytes(&mut self, len: usize) -> Result<Vec<u8>, CsprngError> { }
    pub fn fill(&mut self, dest: &mut [u8]) -> Result<(), CsprngError> { }
}
```

## 熵源

```
系统熵源
    │
    ├── /dev/urandom (Linux)
    ├── CCGenRandom (macOS)
    └── CryptGenRandom (Windows)
```

## 诊断功能

```rust
use kms_core::csprng::CsprngDiagnostics;

// 检查 CSPRNG 健康状态
let diag = CsprngDiagnostics::diagnose();
println!("Entropy source: {}", diag.source);
println!("Available: {}", diag.is_available);

// 验证 CSPRNG
verify()?; // 确认系统 CSPRNG 可用
```

## 用途 / Usage

| 用途 Use Case | 函数 Function |
|--------------|-------------|
| 密钥生成 / Key Gen | `random_bytes(32)` |
| DEK 生成 / DEK Gen | `generate_dek(32)` |
| Nonce/IV | `generate_nonce(12)` |
| 盐值 / Salt | `random_bytes(16)` |
| 会话 ID / Session ID | `random_bytes(16)` |


## 与 rand crate 的区别 / Comparison with rand Crate

| 特性 Feature | rand | GmRng |
|-------------|------|-------|
| 用途 / Purpose | 通用随机 / General-purpose random | 加密安全 / Cryptographically secure |
| 预测抵抗 / Prediction Resistance | ❌ | ✅ |
| 种子要求 / Seed Requirement | 任意 / Arbitrary | 熵源 / Entropy source |
| 性能 / Performance | 可能更快 / May be faster | 足够安全 / Secure enough |


## 安全要求 / Security Requirements

1. **不可预测性** / Unpredictability：给定历史输出，无法预测未来输出 / Given historical output, future output cannot be predicted
2. **向后保密** / Backward Secrecy：即使内部状态泄露，历史随机数也不可恢复 / Even if internal state is leaked, historical randoms cannot be recovered
3. **种子安全** / Seed Security：初始种子必须来自真随机源 / Initial seed must come from a true random source


## 参考资料

- [NIST SP 800-90A](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final) - Random Number Generation
- [RFC 4086](https://datatracker.ietf.org/doc/html/rfc4086) - Randomness Requirements
