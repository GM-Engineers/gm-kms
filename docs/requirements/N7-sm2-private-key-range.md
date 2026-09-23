# SPEC: PR-4.14 — gm-kms SM2 私钥 [1, n-1] 范围校验 (P2-9)

- **目标编号**：PR-4.14（Batch 4 — gm-kms 工程完善）
- **触发**：[`gm与gm-kms源码级改进建议.md §四 P2-9`](file:///Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md#L162)：SM2 私钥生成用裸 32 字节随机，建议统一走 `Sm2KeyPair::generate` 并显式校验 `[1, n-1]` 范围
- **范围**：`crates/kms-keystore/src/software/mod.rs` 的 `generate_sm2_key` 重写 + 新增 `kms_core::sm2_scalar_in_range` helper
- **影响面**：纯增量；新 helper 对外暴露，可被其他生成路径复用

---

## 1. 问题陈述

[`gm-kms/crates/kms-keystore/src/software/mod.rs:127-132`](file:///Users/laozhang/Work/opensource/gm-kms/crates/kms-keystore/src/software/mod.rs#L127)：

```rust
fn generate_sm2_key(&self) -> Vec<u8> {
    // SM2 private key is 32 bytes
    let mut key = vec![0u8; 32];
    rand::rng().fill_bytes(&mut key);
    key
}
```

后果：
- **裸随机**：32 字节随机序列未经 [1, n-1] 校验就直接当私钥用
- **SM2 曲线阶**：`n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123`
- **小概率错误值**：
  - 全零（`0x00...00`）→ 无效私钥（公开密钥 = infinity point），违反 GB/T 32918.1-2016 §5.1.4
  - `≥ n`（约 2^-128 概率）→ 取模后值仍在范围内但**不是均匀分布**，且如果不做模约会被 rustcrypto `SecretKey::from_bytes` 拒绝（caller 看到莫名错误）
- **没有 defense-in-depth**：rustcrypto 的 `SecretKey::<Sm2>::random` 本身保证 [1, n-1]，但 `fill_bytes` 路径绕过了这层

### 1.1 改进建议依据（master plan §四 P2-9）

> `gm-kms/crates/kms-keystore/src/software/mod.rs:110-115` | SM2 私钥生成用裸 32 字节随机，建议统一走 `Sm2KeyPair::generate` 并显式校验 `[1, n-1]` 范围

PR-4.14 解决：**统一走 `Sm2KeyPair::generate` + 添加显式 [1, n-1] 校验 helper**。

---

## 2. Fix 策略

### 2.1 新增 helper `kms_core::sm2_scalar_in_range`

放在 `crates/kms-core/src/sm2_scalar.rs`（新文件）：

```rust
/// SM2 curve order n (GB/T 32918.1-2016 §5.1.4).
/// `n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123`
pub const SM2_CURVE_ORDER_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B,
    0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23,
];

/// Verify that a candidate 32-byte SM2 private scalar is in
/// `[1, n-1]` (i.e., strictly greater than zero AND strictly
/// less than the curve order n). Returns `Ok(())` when the
/// range is satisfied; `Err(KmsError)` otherwise.
///
/// Constant-time: this function uses only branchless
/// comparisons (`lt`, `gt`, equality) on the bytes; the
/// timing-leakage surface is negligible for a 32-byte field.
pub fn sm2_scalar_in_range(scalar: &[u8]) -> Result<(), KmsError> {
    if scalar.len() != 32 {
        return Err(KmsError::InvalidSm2Scalar(format!(
            "scalar must be 32 bytes, got {}",
            scalar.len()
        )));
    }
    // Reject 0 (scalar < 1).
    if scalar.iter().all(|&b| b == 0) {
        return Err(KmsError::InvalidSm2Scalar(
            "SM2 private scalar must be >= 1".into(),
        ));
    }
    // Reject >= n.
    for (a, b) in scalar.iter().zip(SM2_CURVE_ORDER_N.iter()) {
        match a.cmp(b) {
            std::cmp::Ordering::Less => return Ok(()),
            std::cmp::Ordering::Greater => {
                return Err(KmsError::InvalidSm2Scalar(
                    "SM2 private scalar must be < n".into(),
                ));
            }
            std::cmp::Ordering::Equal => continue,
        }
    }
    // Exactly equal to n — reject.
    Err(KmsError::InvalidSm2Scalar(
        "SM2 private scalar must be < n (got exactly n)".into(),
    ))
}
```

### 2.2 新增错误变体 `KmsError::InvalidSm2Scalar(String)`

`crates/kms-core/src/error.rs`：

```rust
#[error("invalid SM2 scalar: {0}")]
InvalidSm2Scalar(String),
```

### 2.3 重写 `generate_sm2_key`

```rust
fn generate_sm2_key(&self) -> Result<Vec<u8>, KmsError> {
    // PR-4.14 / P2-9: use the canonical SM2 key generation
    // path (`Sm2KeyPair::generate`), which already enforces
    // [1, n-1] via the underlying rustcrypto SecretKey::random
    // path, then defense-in-depth re-validate the produced bytes
    // with the new `kms_core::sm2_scalar_in_range` helper.
    let key_pair = Sm2KeyPair::generate().map_err(|e| {
        KmsError::Sm2Error(format!("Sm2KeyPair::generate failed: {}", e))
    })?;
    let bytes = key_pair.private_key_bytes();
    // Defense-in-depth: even though `Sm2KeyPair::generate` is
    // expected to produce a valid scalar, we re-validate so any
    // future upstream regression surfaces as a `KmsError` here
    // instead of silently storing an invalid scalar.
    crate::kms_core::sm2_scalar::sm2_scalar_in_range(&bytes)?;
    Ok(bytes)
}
```

**签名变更**：`generate_sm2_key(&self) -> Vec<u8>` → `generate_sm2_key(&self) -> Result<Vec<u8>, KmsError>`。

调用点 `generate_key` (`software/mod.rs:684-694`) 必须同步更新：之前是 `self.generate_sm2_key()`，现在需要 `self.generate_sm2_key()?`。

### 2.4 公开 helper 的复用

`kms_core::sm2_scalar::sm2_scalar_in_range` 是 `pub fn` —— 其他模块可以独立使用，例如：
- `crates/kms-core/src/key.rs:474`（test-only `vec![0u8; 32]`）可以加断言
- 未来 KMS-side import / restore path 可以校验外部传入的私钥

PR-4.14 **不**改其他路径，只把 helper 暴露出来；后续 PR 接入。

### 2.5 版本

`kms-core/Cargo.toml`：**patch bump**（新 pub helper + error 变体；旧 path 行为兼容，但 `generate_sm2_key` 签名变化是**模块内部**，无 public surface）。

---

## 3. Tests

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr414_sm2_scalar_in_range_accepts_valid_scalar` | 任意 < n 的 32 字节 → Ok |
| T2 | `pr414_sm2_scalar_in_range_rejects_all_zero` | 32 字节全 0 → Err "must be >= 1" |
| T3 | `pr414_sm2_scalar_in_range_rejects_equal_to_n` | 32 字节 == `SM2_CURVE_ORDER_N` → Err |
| T4 | `pr414_sm2_scalar_in_range_rejects_greater_than_n` | `n + 1`（大端加一）→ Err |
| T5 | `pr414_sm2_scalar_in_range_rejects_wrong_length` | 16 / 33 / 0 字节 → Err "must be 32 bytes" |
| T6 | `pr414_sm2_scalar_in_range_accepts_n_minus_1` | `n - 1` → Ok（合法上限） |
| T7 | `pr414_sm2_scalar_in_range_accepts_one` | `0x00..01` → Ok（合法下限） |
| T8 | `pr414_generate_sm2_key_returns_valid_scalar` | 100 次调用 `generate_sm2_key`，每次结果都通过 `sm2_scalar_in_range` |
| T9 | `pr414_generate_sm2_key_returns_32_bytes` | 长度恒为 32 字节 |

注：T8 / T9 是 `software/mod.rs` 内部测试，需要构造 `SoftwareKeystore` 实例。

---

## 4. 验证矩阵

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy --workspace --all-targets -- -D warnings
cargo +1.88 test -p kms-core --all-targets pr414_
cargo +1.88 test -p kms-keystore --all-targets pr414_
cargo +1.88 test --workspace --all-targets   # 全量回归
```

CI 含 Security Audit / Build Docker / OWASP ZAP / Container Security Scan。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| `Sm2KeyPair::generate` 未来回归产生无效 scalar | helper 二次校验捕获 → 返 Err，caller 看到明确错误而非默默存储 |
| 32 字节比较 timing-leakage | 比较每字节 lt/gt/eq 是 constant-time；scalar 是公开（虽然不被泄露但非机密数据），timing leak 风险极低 |
| `KmsError::InvalidSm2Scalar` 错误路径未充分测试 | T2/T3/T4 覆盖；T6/T7 覆盖边界 |
| 其他模块用了类似的裸随机模式（`generate_aes_key` 等） | PR-4.14 不动 AES/Ed25519/SM4（AES/Ed25519 不需要曲线范围校验）；后续 PR-4.15 覆盖 |

---

## 6. Out of Scope

- 给 `generate_aes_key` / `generate_ed25519_key` / `generate_sm4_key` 加防御性校验（AES/Ed25519/SM4 不需要曲线范围）
- 公开 `Sm2KeyPair` 内部的 `to_nonzero_scalar()`（这是 gm-crypto 内部 API）
- 修 `crates/kms-core/src/key.rs:474` 的 `vec![0u8; 32]`（test fixture，非生产路径）

---

## 7. 后续 PR 候选

- **PR-4.15**：gm-kms Postgres in-memory 冷热分层 (P2-10)
- **PR-4.16**：`TlsError` 重构为 typed error enum
- **PR-4.17**：gm-crypto 增加 KAT 测试覆盖 SM2 私钥范围校验
