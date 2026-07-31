# HKDF（基于 HMAC 的密钥派生函数） / HMAC-based Key Derivation Function

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | HMAC-based Key Derivation Function |
| **类型 Type** | 密钥派生函数（KDF）/ Key Derivation Function |
| **标准 Standard** | RFC 5869 |
| **核心输入** | 原始密钥材料（IKM）、盐（salt）、信息（info）/ Input Key Material, Salt, Info |


## 概述

HKDF 是一种基于 HMAC 的密钥派生函数，用于从原始密钥材料（Input Keying Material，IKM）派生出更强的密钥。它分为两个阶段：

1. **Extract（提取）**：将原始密钥材料转换为伪随机密钥（PRK）
2. **Expand（扩展）**：将 PRK 扩展为所需长度的多个密钥

HKDF 设计简单、安全，广泛用于 TLS、IPsec、SSH 等协议中。

## 算法步骤

### Step 1: Extract

```
PRK = HMAC-Hash(salt, IKM)
```

- `salt`：可选盐值（若无则使用全零串）
- `IKM`：输入的原始密钥材料
- `Hash`：通常使用 SHA-256 或 SHA-384

### Step 2: Expand

```
OKM = HMAC-Hash(PRK, info || 0x01)
OKM = HMAC-Hash(PRK, OKM || info || 0x02)
OKM = HMAC-Hash(PRK, OKM || info || 0x03)
...（重复直到得到足够长度的输出）
```

- `info`：上下文信息，用于区分不同用途的派生密钥
- `0x01`、`0x02` 等：计数器字节

## 在 KMS 中的应用 / KMS Applications

| 场景 Scenario | 说明 Description |
|--------------|----------------|
| **密钥层次派生** / Key Derivation | 从 Master Key 派生 KEK，从 KEK 派生 DEK / Derive KEK from Master Key, DEK from KEK |
| **会话密钥派生** / Session Key | TLS 握手后从 premaster secret 派生 session keys / Derive session keys from premaster secret after TLS handshake |
| **文件加密密钥** / File Keys | 从文件主密钥派生每个文件的唯一密钥 / Derive unique key per file from file master key |
| **多租户隔离** / Multi-tenant | 从租户根密钥派生租户专用子密钥 / Derive tenant-specific sub-keys from tenant root key |


```go
// HKDF 示例
func DeriveKey(masterKey []byte, context string, length int) ([]byte, error) {
    salt := []byte{} // 或使用盐
    info := []byte(context)

    // Extract
    h := hmac.New(sha256.New, salt)
    h.Write(masterKey)
    prk := h.Sum(nil)

    // Expand
    h.Reset()
    h.Write(prk)
    h.Write(info)
    h.Write([]byte{0x01})
    return h.Sum(nil)[:length], nil
}
```

## HKDF vs PBKDF2 vs Argon2

| 特性 Feature | HKDF | PBKDF2 | Argon2 |
|-----------|------|--------|--------|
| **用途** / Purpose | 派生更强的密钥 / Derive stronger keys | 从口令派生密钥 / Derive keys from password | 从口令派生密钥（抗GPU）/ Derive keys from password (GPU-resistant) |
| **输入** / Input | 高熵密钥材料 / High-entropy key material | 低熵口令 / Low-entropy password | 低熵口令 |
| **抗暴力破解** / Brute-force Resistance | 无（假设输入熵足够）/ None (assumes sufficient input entropy) | 中等 / Medium | 强（memory-hard）/ Strong (memory-hard) |
| **计算时间** / Compute Time | 快（毫秒级）/ Fast (ms) | 可配置（秒级）/ Configurable (seconds) | 可配置（秒级） |
| **典型场景** / Typical Use | 密钥层次化 / Key hierarchy | 用户口令加密 / User password encryption | 用户口令加密（敏感数据）/ User password (sensitive data) |


## 安全注意事项 / Security Considerations

1. **输入熵** / Input Entropy：IKM 必须是高质量随机数，不能使用低熵口令直接输入 / IKM must be high-quality random; do not use low-entropy passwords directly
2. **Info 区分** / Info Separation：不同用途使用不同的 info，防止密钥重叠 / Use different info for different purposes to prevent key overlap
3. **盐值随机** / Random Salt：salt 建议使用加密安全的随机数 / Salt should be cryptographically random
4. **输出长度** / Output Length：不要超过 hash 输出长度的合理倍数（避免穷举搜索）/ Do not exceed reasonable multiple of hash output length (prevents brute-force)


## 参考标准

- [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) - HKDF 规范
- [NIST SP 800-108](https://doi.org/10.6028/NIST.SP.800-108) - 密钥派生函数推荐