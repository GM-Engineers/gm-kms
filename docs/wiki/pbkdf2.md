# PBKDF2（基于口令的密钥派生函数 2） / Password-Based Key Derivation Function 2

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Password-Based Key Derivation Function 2 |
| **类型 Type** | 密钥派生函数（KDF）/ Key Derivation Function |
| **标准 Standard** | RFC 8018（PKCS#5 v2.1） |
| **核心特性** | 迭代散列，抗暴力破解 / Iterative hashing, brute-force resistance |


## 概述

PBKDF2 是一种将低熵口令（password）转换为强密钥的密钥派生函数。通过多次迭代（iterations）计算，使得暴力破解成本大幅增加。

标准推荐最少 100,000 次迭代（对应 SHA-256），具体取决于硬件性能。

## 算法公式

```
DK = PBKDF2(Password, Salt, Iterations, KeyLength, HashFunc)
```

参数：
- `Password`：用户口令（低熵）
- `Salt`：加密安全随机盐（至少 128 位）
- `Iterations`：迭代次数（建议 ≥ 100,000）
- `KeyLength`：期望输出的密钥长度
- `HashFunc`：底层散列函数（SHA-256、SHA-384 等）

## 算法步骤

```
F(Password, Salt, c, i) = H_1 XOR H_2 XOR ... XOR H_c
其中：
  H_1 = H(Password, Salt || INT(i))
  H_2 = H(Password, H_1)
  ...
  H_c = H(Password, H_{c-1})

DK = F(Password, Salt, c, 1) || F(Password, Salt, c, 2) || ...
```

## 在 KMS 中的应用

| 场景 | 说明 |
|------|------|
| **用户口令保护** | 将用户口令转换为可用于加密的密钥 |
| **磁盘加密** | 全磁盘加密（FDE）的密钥派生 |
| **备份加密** | 本地备份文件的加密 |
| **密钥材料** | 从用户口令派生加密密钥（需配合高熵盐） |

```go
// PBKDF2 示例
func DeriveKeyFromPassword(password []byte, salt []byte) ([]byte, error) {
    iterations := 100000
    keyLength := 32 // 256 bits

    return pbkdf2.Key(password, salt, iterations, keyLength, sha256.New), nil
}
```

## 与 HKDF、Argon2 的对比 / Comparison with HKDF and Argon2

| 特性 Feature | PBKDF2 | HKDF | Argon2 |
|-----------|--------|------|--------|
| **输入类型** / Input Type | 低熵口令 / Low-entropy password | 高熵密钥材料 / High-entropy key material | 低熵口令 |
| **抗 GPU/ASIC** / GPU/ASIC Resistance | 中等（可加速）/ Medium (can be accelerated) | 无 / None | 强（memory-hard）/ Strong (memory-hard) |
| **内存需求** / Memory Requirement | 低（~1MB）/ Low | 极低 / Very low | 高（~100MB）/ High |
| **推荐迭代** / Recommended Iterations | ≥100,000 | 不适用 / N/A | 不适用 / N/A |
| **典型场景** / Typical Use | 用户口令加密 / User password encryption | 协议密钥派生 / Protocol key derivation | 用户口令（高安全）/ User password (high security) |


## 安全注意事项 / Security Considerations

1. **迭代次数** / Iteration Count：至少 100,000 次，逐年增加（建议按硬件性能提升）/ At least 100,000, increase annually per hardware performance
2. **盐值随机** / Random Salt：每个用户使用唯一的随机盐 / Each user gets a unique random salt
3. **口令质量** / Password Quality：仍需用户使用强口令，避免字典攻击 / Still require strong passwords; prevent dictionary attacks
4. **不要用于高熵输入** / Not for High-Entropy Input：PBKDF2 专为低熵口令设计，高熵密钥直接用 HKDF / PBKDF2 is for low-entropy passwords; use HKDF for high-entropy keys


## 参考标准

- [RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018) - PKCS#5 v2.1
- [NIST SP 800-132](https://doi.org/10.6028/NIST.SP.800-132) - 口令基础密钥派生推荐