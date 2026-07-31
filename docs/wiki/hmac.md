# HMAC（基于散列函数的消息认证码） / Hash-based Message Authentication Code

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Hash-based Message Authentication Code |
| **类型 Type** | 消息认证码（MAC）/ Message Authentication Code |
| **标准 Standard** | RFC 2104、FIPS 198-1 |
| **核心算法** | HMAC-SHA256、HMAC-SHA384、HMAC-SHA512 |


## 概述

HMAC 是一种基于散列函数的消息认证码，用于验证消息的完整性和认证消息发送者。它结合了：
- 散列函数的单向性和抗碰撞性
- 密钥的保密性

即使攻击者能篡改消息，没有密钥也无法伪造有效的 HMAC 值。

## 算法原理

```
HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
```

其中：
- `K`：密钥
- `m`：消息
- `H()`：散列函数（SHA-256、SHA-384 等）
- `K'`：密钥填充到块长度（不足补0，超长先hash）
- `opad`：外填充（0x5c...）
- `ipad`：内填充（0x36...）

## 在 KMS 中的应用 / KMS Applications

| 场景 Scenario | 说明 Description |
|--------------|----------------|
| **消息完整性** / Message Integrity | 验证数据未被篡改 / Verify data has not been tampered |
| **API 请求签名** / API Signing | 验证 API 调用者身份 / Verify API caller identity |
| **Webhook 验证** / Webhook Verification | 验证回调来源（如 GitHub webhook）/ Verify callback source (e.g., GitHub webhook) |
| **密钥完整性** / Key Integrity | 验证密钥数据完整性（如 Key Checksum）/ Verify key data integrity (e.g., Key Checksum) |


```go
// HMAC 示例
func VerifyHMAC(key, message, expectedMAC []byte) bool {
    mac := hmac.New(sha256.New, key)
    mac.Write(message)
    computed := mac.Sum(nil)
    return hmac.Equal(computed, expectedMAC)
}
```

## HMAC vs CMAC vs GMAC

| 类型 Type | 底层 Primitive | 输出长度 Output | 说明 Description |
|---------|---------------|----------------|----------------|
| **HMAC** | 任意散列函数 / Any hash function | 散列输出长度 / Hash output length | 最通用，如 HMAC-SHA256 / Most generic, e.g., HMAC-SHA256 |
| **CMAC** | AES 分组密码 / AES block cipher | 128位（16字节）/ 128-bit | 基于 AES 的 MAC / AES-based MAC |
| **GMAC** | AES-GCM 认证 / AES-GCM auth | 128位（16字节）/ 128-bit | GCM 模式的认证部分 / Authentication part of GCM mode |


## 安全注意事项 / Security Considerations

1. **密钥长度** / Key Length：至少 256 位（对应 SHA-256）/ At least 256-bit (corresponding to SHA-256)
2. **防时序攻击** / Timing Attack Prevention：比较 MAC 时使用恒定时间比较（`hmac.Equal`）/ Use constant-time comparison (`hmac.Equal`)
3. **不要重复** / No Key Reuse：同一密钥不要用于不同目的 / Do not use the same key for different purposes
4. **安全传输** / Secure Transport：HMAC 值本身不需要保密，但需防重放 / HMAC value doesn't need to be secret, but must be replay-protected


## 参考标准

- [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) - HMAC 原始规范
- [FIPS 198-1](https://doi.org/10.6028/NIST.FIPS.198-1) - HMAC 标准