# SSS（Shamir 秘密分享） / Shamir Secret Sharing

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Shamir Secret Sharing / (t, n)-threshold scheme |
| **中文** |  Shamir 秘密分享、门限方案 / Shamir Secret Sharing, Threshold Scheme |
| **类型 Type** | 密钥分片协议 / Key Sharding Protocol |
| **发明者** | Adi Shamir（1979） |
| **安全基础** | 多项式插值的数学原理 / Polynomial interpolation over finite fields |
| **实现位置** | `crates/kms-core/src/shamir.rs` |


## 概述

SSS 是一种将秘密分成 n 份，只有收集至少 t 份才能恢复秘密的密码学方案。它基于多项式插值的数学原理：t 个点可以唯一确定一个 t-1 次多项式。

```
SSS 示例（3-of-5）：

原始秘密：S = 42
随机生成多项式：
  f(x) = S + a₁x + a₂x²  (次数 = t-1 = 2)
      = 42 + 17x + 3x²

生成 5 份秘密（x=1,2,3,4,5）：
  share₁ = (1, 62)  → f(1)
  share₂ = (2, 96)  → f(2)
  share₃ = (3, 144) → f(3)
  share₄ = (4, 206) → f(4)
  share₅ = (5, 282) → f(5)

恢复：任意 3 份可恢复 S
  share₁、share₂、share₃ → 插值 → S = 42
```

## 数学原理 / Mathematical Principles

### 秘密分享 / Secret Sharing

SSS 基于有限域 GF(p) 上的多项式插值。gm-kms 实现使用 Mersenne 素数 p = 2^61 - 1（一个适合 u64 运算的素数）：

```
有限域: GF(p)，其中 p = 2^61 - 1（Mersenne 素数）
秘密 S: 在有限域 GF(p) 中的值
门限值 t: 至少 t 份才能恢复
总份数 n: 总共生成 n 份

1. 随机选择 t-1 个系数 a₁, a₂, ..., a_{t-1} ∈ GF(p)
2. 构造多项式：
   f(x) = S + a₁x + a₂x² + ... + a_{t-1}x^{t-1}
3. 计算 n 个份额：
   share_i = (x_i, y_i)，其中 y_i = f(x_i)，x_i = 1, 2, ..., n
4. 秘密编码：每 7 字节打包为一个 GF(p) 元素（支持任意长度秘密）
```

### 秘密恢复（拉格朗日插值）/ Reconstruction (Lagrange Interpolation)

```
使用 t 份份额恢复秘密：
S = Σ_{i=1}^{t} y_i · λ_i(0)

其中 λ_i(0) = Π_{j≠i} x_j / (x_j - x_i)（拉格朗日系数）

GM/KMS 实现使用 GF(p) 运算：
  add_mod(a, b) = (a + b) % p
  mul_mod(a, b) = (a * b) % p
  inv_mod(a) = a^{p-2} % p  (Fermat 小定理)
```


## 在 KMS 中的实现 / KMS Implementation

实际实现位于 `crates/kms-core/src/shamir.rs`，使用 Rust 实现：

### 核心结构

```rust
use kms_core::shamir::{ShamirSecretSharing, Shares, Share};

// 创建 SSS 实例（使用默认素数 p = 2^61 - 1）
let sss = ShamirSecretSharing::new();

// 将秘密分成 5 份，需要 3 份才能恢复
// Split secret into 5 shares, requiring 3 for reconstruction
let shares = sss.split(
    secret.as_bytes(),   // 秘密
    threshold: 3,         // t: 至少 3 份 / at least 3 shares
    total_shares: 5,      // n: 总共 5 份 / total 5 shares
    verifiable: true,     // 生成 VSS 承诺 / generate VSS commitments
)?;

// shares.shares: Vec<Share> — 每个 Share 包含 x, y, block_index
// shares.commitments: Option<Vec<Commitment>> — VSS 承诺
// shares.metadata: SharesMetadata — 包含 secret_hash、original_len、num_blocks
```

### 核心结构 / Core Structures

```rust
// 单条份额 / Individual share
pub struct Share {
    pub x: u32,           // x 坐标（1..n）
    pub y: u64,           // y 坐标（在 GF(p) 中）
    pub block_index: u32, // 区块索引（多区块秘密时使用）
}

// 承诺 / Commitment
pub struct Commitment {
    pub block_index: u32,  // 区块索引
    pub index: u32,        // 系数索引
    pub value: u64,        // 承诺值（SHA-256 hash-based）
}

// 份额元数据 / Shares metadata
pub struct SharesMetadata {
    pub id: Uuid,               // 份额集合唯一标识
    pub is_verifiable: bool,     // 是否启用 VSS
    pub secret_hash: Option<String>, // SHA-256(original_secret) 用于验证
    pub original_len: Option<usize>,  // 原始秘密长度（去除填充）
    pub num_blocks: Option<u32>,     // 区块数量
}
```

### 可验证秘密分享（VSS）/ Verifiable Secret Sharing

```rust
// 生成时启用 VSS：生成 SHA-256 hash-based 承诺
let shares = sss.split(secret, 3, 5, true)?;  // verifiable=true

// 验证份额有效性
let verification = sss.verify_share(&shares.shares[0], &shares.commitments.as_ref().unwrap());
assert!(verification.valid);

// 验证重构系数的承诺
let result = sss.verify_coefficients_against_commitments(
    &coefficients, &commitments, block_index,
)?;
assert!(result.valid);
```

### 多区块秘密支持 / Multi-block Secret Support

gm-kms SSS 支持任意长度的秘密，通过将秘密分块处理（每块 7 字节）：

```rust
// "my-secret-key-12345678"（22 字节）→ 4 个 7 字节块 + 4 字节填充
// 总共 4 blocks × 5 shares = 20 条份额
// 份额布局：[block0_x1..x5, block1_x1..x5, block2_x1..x5, block3_x1..x5]

// 重构：每个区块分别用拉格朗日插值恢复
// 区块内份额布局为 block-major order，不可按 x 排序（会打乱区块边界）
let result = sss.reconstruct_with_metadata(&shares, &shares.metadata)?;
assert_eq!(result.secret.unwrap(), secret.as_bytes());
```


## 安全性分析 / Security Analysis

| 攻击类型 Attack | SSS 安全性 Security | 缓解措施 Mitigation |
|----------------|--------------------|--------------------|
| **< t 份攻击** / <t-share attack | 无法获得任何秘密信息（信息论安全）/ No information with < t shares (information-theoretic security) | 保持 t 足够大 / Keep t sufficiently large |
| **份额伪造** / Share forgery | SHA-256 hash-based VSS 可检测 / Detectable via SHA-256 hash-based VSS | 使用 VSS / Use VSS |
| **份额泄露** / Share leak | 需重新分发 / Requires re-sharing | 定期更新份额 / Periodic resharing |
| **内部人员** / Insider threat | t 个内部人可合谋 / t insiders can collude | 分离保管（不同部门）/ Separate custody (different depts.) |


## 应用场景

| 场景 | 说明 |
|------|------|
| **密钥分片** | 主密钥分成多份，存储在不同位置 |
| **启动密钥** | 需要多人输入才能启动系统 |
| **灾难恢复** | 多地备份，确保密钥恢复 |
| **双人授权** | 替代传统双人授权，实现更灵活的门限 |

## 与其他方案的对比 / Comparison with Other Schemes

| 方案 Scheme | 恢复方式 Recovery | 可验证性 Verifiable | 隐私信息 Info Hiding | 复杂度 Complexity |
|-----------|------------------|--------------------|-------------------|-----------------|
| **SSS** | 插值 / Interpolation | ❌ | 完全隐藏 / Perfect | O(n) |
| **VSS（SHA-256）** | 插值 / Interpolation | ✅（hash-based）/ ✅ (hash-based) | 完全隐藏 / Perfect | O(n²) |
| **Feldman VSS** | 插值 / Interpolation | ✅（离散对数）/ ✅ (DL-based) | 完全隐藏 / Perfect | O(n²) |


## 安全注意事项 / Security Considerations

1. **素数选择** / Prime Selection：使用足够大的素数（p = 2^61 - 1，Mersenne 素数，适合高效模运算）/ Use sufficiently large prime (p = 2^61 - 1, Mersenne prime, efficient u64 arithmetic)
2. **随机性** / Randomness：系数必须使用加密安全的随机数 / Coefficients must use cryptographically secure random numbers
3. **份额传输** / Share Transmission：份额传输需加密通道 / Share transmission requires encrypted channels
4. **份额存储** / Share Storage：不同份额存储在不同安全区域 / Different shares stored in different security zones
5. **区块布局** / Block Layout：重构时使用 block-major 顺序，不要按 x 排序（会打乱区块边界）/ Use block-major order during reconstruction; do NOT sort by x (breaks block boundaries)


## 参考标准

- [Shamir, A. (1979)](https://dl.acm.org/doi/10.1145/359168.359176) - 原始论文
- [Feldman, P. (1987)](https://ieeexplore.ieee.org/document/6231537) - VSS
- [Gennaro, R. et al. (2007)](https://link.springer.com/chapter/10.1007/978-3-540-72738-5_16) - VSS 安全性分析