# TOTP / 基于时间的一次性密码

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称 Full Name** | Time-based One-Time Password |
| **类型 Type** | 一次性密码算法 One-time Password Algorithm |
| **标准 Standard** | RFC 6238 |
| **相关标准 Related** | RFC 4226（HOTP）、RFC 6030（备份码） |
| **实现位置 Implementation** | `crates/kms-mfa/src/totp.rs` |
| **密钥存储 Secret Storage** | AES-256-GCM 信封加密 Envelope encryption (AES-256-GCM) |
| **备份码 Backup Codes** | SHA-256 哈希存储 Hash-stored (Phase 2 H-1) |

## 概述 / Overview

TOTP 是一种基于时间的一次性密码算法（RFC 6238），通过共享密钥和当前时间戳生成 6-8 位数字验证码，每 30 秒更新一次。Phase 2 (H-1) 将备份码存储从明文改为 SHA-256 哈希，并将 TOTP 密钥和备份码接入 MFA-API Key 联动锁定（H-2）。

TOTP is a time-based one-time password algorithm (RFC 6238) generating 6-8 digit codes from a shared secret and current timestamp, refreshing every 30 seconds. Phase 2 (H-1) switched backup code storage to SHA-256 hashing, and (H-2) integrated TOTP secret and backup codes into the MFA-API Key lock mechanism.

## 算法原理 / Algorithm

```
TOTP = HOTP(K, T)
where:
  K = 共享密钥（160 位随机数）Shared secret (160-bit random)
  T = floor(current_unix_time / period)
  HOTP(K, C) = truncate(HMAC-SHA1(K, C))

步骤 Steps:
1. 时间戳除以 time_step（默认 30s）得到时间步数 T
   Divide Unix timestamp by time_step (default 30s) → T
2. 计算 HMAC-SHA1(K, T) 哈希
   Compute HMAC-SHA1(K, T)
3. 动态截断取最后 4 位得到偏移量
   Dynamic truncation: use last 4 bits as offset
4. 从偏移量取 4 字节 → 转换为 6 位数字
   Extract 4 bytes from offset → 6-digit code
```

### 时间线 / Timeline

```
|---30s---|---30s---|---30s---|
   123456    789012    345678   ← TOTP code per 30s window
```

## 核心类型 / Core Types

### TotpConfig — TOTP 配置 / Configuration

```rust
use kms_mfa::{TotpConfig, TotpAlgorithm};

let config = TotpConfig {
    secret: secret_bytes,           // 160-bit 原始密钥（NOT Base32 字符串）/ Raw 160-bit key (NOT Base32 string)
    time_step: 30,                  // 时间步长（秒）/ Time step in seconds
    digits: 6,                      // 验证码位数 / Code digits (6-8)
    algorithm: TotpAlgorithm::Sha1, // HMAC 算法 / HMAC algorithm
    window: 1,                      // 容差窗口（±1 = 前后各 1 个时间步）/ Tolerance window (±1 = 1 step forward and back)
};
```

### TotpGenerator — 生成器与验证器 / Generator and Validator

```rust
use kms_mfa::{TotpGenerator, TotpCode};

// 创建生成器
// Create generator from config
let generator = TotpGenerator::new(config)?;

// 生成新密钥（160-bit 随机，使用加密安全 RNG）
// Generate new random secret (160-bit, CSPRNG)
let secret = TotpGenerator::generate_secret()?;

// 生成 provisioning URI（用于 QR Code）
// Generate provisioning URI (for QR Code)
let uri = generator.get_provisioning_uri("admin@example.com", "gm-kms");
// otpauth://totp/gm-kms:admin@example.com?secret=...&issuer=gm-kms&algorithm=SHA1&digits=6&period=30

// 生成 TOTP 验证码
// Generate TOTP code
let code: TotpCode = generator.generate()?;
println!("Code: {}, expires in {}s", code.code, code.remaining_seconds());

// 验证验证码（含窗口容差 ±window）
// Validate code (with window tolerance)
let valid = generator.validate("123456")?;  // ±1 time step by default

// 指定时间戳验证（用于服务器间时钟偏差处理）
// Validate at specific timestamp (for clock skew handling)
let valid = generator.validate_at_timestamp("123456", timestamp)?;
```

### TotpCode — 验证码结构 / Code Structure

```rust
pub struct TotpCode {
    pub code: String,         // 6-8 位数字验证码 / 6-8 digit code
    pub generated_at: u64,    // 生成时的 Unix 时间戳 / Unix timestamp at generation
    pub expires_at: u64,      // 过期时的 Unix 时间戳 / Unix timestamp at expiry
    pub period: u64,          // 时间步长 / Time step
}

impl TotpCode {
    pub fn remaining_seconds(&self) -> i64 { /* ... */ }
    pub fn is_valid(&self) -> bool { /* 过期前返回 true / true if not expired */ }
}
```

## 备份码与暴力破解防护 / Backup Codes and Brute Force Protection

Phase 2 (H-1) 为备份码实现了 SHA-256 哈希存储和暴力破解锁定：

```rust
use kms_mfa::BackupCodeGenerator;

// 生成 10 个 8 位数字备份码
// Generate 10 eight-digit backup codes
let (mut generator, codes) = BackupCodeGenerator::generate(10);
// 返回纯文本一次性展示给用户，之后只存储 SHA-256 哈希
// Plaintext codes shown once to user; only SHA-256 hashes are stored

for code in &codes {
    println!("Backup code: {}", code.code);
    // 用户应立即保存！/ User must save immediately!
}

// 消费备份码（首次使用时哈希比对）
// Consume a backup code (SHA-256 hash comparison on first use)
generator.consume_code("12345678")?;  // 成功后该码永久失效 / Code permanently invalidated after success

// 暴力破解防护：连续 5 次错误触发 5 分钟锁定
// Brute force protection: 5 consecutive failures → 5-minute lockout
// Lockout duration: 300 seconds
// 锁定期间任何代码均被拒绝 / All codes rejected during lockout
if let Err(MfaError::BackupCodeLocked(retry_after)) = result {
    println!("Locked for {} seconds", retry_after);
}

// 检查剩余可用备份码数量
// Check remaining codes
println!("Remaining: {}", generator.remaining());  // 9 / 9
assert!(generator.has_codes());  // true if any remain / 有剩余时为 true
```

> ⚠️ **安全警告**：备份码明文仅在 `generate()` 返回时出现一次，用户必须立即保存。存储层只保留 SHA-256 哈希，无法恢复原始码。
>
> ⚠️ **Security Warning**: Plaintext codes appear only once during `generate()`. Store them immediately. Only SHA-256 hashes are persisted — originals cannot be recovered.

## 与 HOTP 的对比 / TOTP vs HOTP Comparison

| 特性 Feature | TOTP | HOTP |
|-------------|------|------|
| **时间依赖 Time-dependent** | 是（30s 窗口）Yes (30s window) | 否（计数器）No (counter) |
| **重放攻击Replay Attack** | 难（窗口短）Hard (short window) | 易（需计数器同步）Easy (requires counter sync) |
| **离线支持 Offline** | 是 Yes | 是 Yes |
| **服务器负担 Server Load** | 低 Low | 中 Medium (counter storage) |
| **典型用途 Typical Use** | 通用 MFA General MFA | 硬件令牌 Hardware tokens |

## TOTP 注册与验证流程 / Registration and Verification Flow

```
用户注册 TOTP / Register TOTP:
1. KMS 生成随机密钥（160-bit）Generate random 160-bit secret
2. 生成 QR Code (otpauth:// URI)  Generate QR Code
3. 用户用 Authenticator App 扫描 User scans with Authenticator App
4. App 保存密钥到设备 App stores secret on device
5. 用户验证第一个 TOTP User verifies first TOTP
6. KMS 用 AES-256-GCM 信封加密存储密钥 (with KEK) Encrypt and store secret with KEK (Phase 1 F-1)

验证 TOTP / Verify TOTP:
1. 用户输入 6 位码 User enters 6-digit code
2. 解密 TOTP 密钥 Decrypt TOTP secret
3. 计算当前时间步 T Compute current time step T
4. 验证 ±window 范围内所有候选码 Validate candidates within ±window
5. 返回验证结果 Return verification result
```

## 与 MFA-API Key 联动锁定 / MFA-API Key Lock (Phase 2 H-2)

Phase 2 将 MFA 状态与 API Key 有效性联动：

- TOTP 验证失败 N 次 → 对应 API Key 被联动锁定
- 备份码耗尽或被锁定 → API Key 无法恢复
- 锁定后需 Security Officer 介入解锁

```
MFA verify fail → API Key lock (H-2 integration)
Backup codes exhausted → API Key unrecoverable
Security Officer required to unlock
```

## 安全注意事项 / Security Notes

| 风险 Risk | 缓解措施 Mitigation |
|-----------|-------------------|
| **密钥泄露 Secret leak** | AES-256-GCM 信封加密存储 / KEK-protected storage |
| **传输泄露 Transmission** | HTTPS 全程 / HTTPS throughout |
| **暴力破解 Brute force** | 限速 + 账户锁定（Phase 2）Rate limiting + account lockout |
| **备份码猜测 Backup code guess** | SHA-256 哈希 + 5 次失败锁定 / SHA-256 hash + 5-failure lockout |
| **时钟偏差 Clock skew** | window 参数容差 ±1 时间步 / ±1 time step window tolerance |

## 参考资料 / References

- [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) — TOTP 规范 / TOTP Specification
- [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) — HOTP（事件型 OTP）/ HOTP (Event-based OTP)
- [RFC 6030](https://datatracker.ietf.org/doc/html/rfc6030) — PIV 备份码 / PIV Secret Services
- [Google Authenticator](https://github.com/google/google-authenticator) — 移动端实现 / Mobile Implementation
