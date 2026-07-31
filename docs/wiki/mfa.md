# MFA / 多因素认证

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称 Full Name** | Multi-Factor Authentication / 多因素认证 |
| **类型 Type** | 身份认证机制 / Identity authentication mechanism |
| **标准 Standards** | NIST SP 800-63B，FIDO2/WebAuthn，RFC 6238（TOTP）|
| **实现位置 Implementation** | `crates/kms-mfa/src/` |
| **TOTP 密钥存储 TOTP Secret Storage** | AES-256-GCM 信封加密 Envelope encryption (Phase 1) |
| **备份码 Backup Codes** | SHA-256 哈希 Hash storage (Phase 2 H-1) |
| **API Key 联动 API Key Lock** | MFA 验证失败 → API Key 联动锁定 MFA failure → API Key lock (Phase 2 H-2) |

## 概述 / Overview

MFA 通过结合两种或以上不同类型的认证因素来验证用户身份，显著提高安全性。gm-kms 实现 MFA 保护关键管理操作（密钥删除、导出、策略修改），并通过 Phase 2 将 MFA 状态与 API Key 有效性联动（H-2）。

MFA verifies user identity by combining two or more different authentication factors. gm-kms uses MFA to protect critical operations (key deletion, export, policy changes) and integrates MFA status with API Key validity in Phase 2 (H-2).

## 认证因素类型 / Authentication Factor Types

| 因素类型 Factor Type | 示例 Examples | 说明 Description |
|---------------------|--------------|-----------------|
| **知识因素 Something You Know** | 密码、API Key、PIN | 你知道的 What you know |
| **持有因素 Something You Have** | TOTP App（手机）、硬件令牌、智能卡 | 你拥有的 What you have |
| **固有因素 Something You Are** | 指纹、人脸识别（通过 HSM）| 你本身的特征 What you are |

## 在 KMS 中的应用场景 / KMS MFA Scenarios

| 场景 Scenario | MFA 要求 MFA Requirement |
|--------------|-------------------------|
| **密钥删除 Key Deletion** | MFA + 审批工作流 MFA + Approval workflow |
| **密钥导出 Key Export** | MFA + 双人授权 MFA + Dual authorization |
| **策略修改 Policy Change** | MFA + 审批 MFA + Approval |
| **审计日志访问 Audit Log Access** | MFA |
| **超级权限 Break Glass** | 必须 MFA Mandatory MFA |

## 核心类型 / Core Types

### MfaType — MFA 类型枚举 / MFA Type Enum

```rust
use kms_mfa::MfaType;

pub enum MfaType {
    Totp,      // TOTP（RFC 6238，默认）TOTP (RFC 6238, default)
    Hardware,  // 硬件令牌 Hardware token (YubiKey, etc.)
    Sms,       // SMS OTP（生产环境不推荐）SMS OTP (not recommended for production)
}
```

### MfaStatus — MFA 状态 / MFA Status

```rust
use kms_mfa::MfaStatus;

let status = MfaStatus {
    enabled: true,
    mfa_type: MfaType::Totp,
    backup_codes_remaining: 7,     // Phase 2 H-1: 备份码 SHA-256 哈希存储 / Hash-stored
    last_verified_at: Some(now),   // 最后验证时间戳 / Last verification timestamp
};
```

## TOTP MFA 验证流程 / TOTP MFA Verification Flow

```rust
use kms_mfa::{TotpGenerator, TotpConfig, MfaError};

// 1. 创建 TOTP 生成器（从配置解密密钥后）
// Create TOTP generator (after decrypting secret from config)
let config = TotpConfig {
    secret: decrypted_secret,      // AES-256-GCM 解密后 / After AES-256-GCM decryption
    time_step: 30,                // 默认 30 秒 / Default 30 seconds
    digits: 6,                   // 6 位数字 / 6-digit
    algorithm: TotpAlgorithm::Sha1,
    window: 1,                   // ±1 时间步窗口 / ±1 time step window
};
let generator = TotpGenerator::new(config)?;

// 2. 用户输入验证码后验证（含双向窗口容差）
// Validate user-entered code (with bidirectional window tolerance)
let valid = generator.validate("482193")?;
// validate_at_timestamp 用于服务器间时钟偏差处理
// validate_at_timestamp for cross-server clock skew handling

if !valid {
    // 触发 MFA-API Key 联动锁定（Phase 2 H-2）
    // Trigger MFA-API Key lock (Phase 2 H-2)
    api_key_config.lock_key_by_id(failed_key_id).await;
    return Err(MfaError::InvalidCode);
}
```

## 备份码（H-1）与暴力破解防护 / Backup Codes (H-1) and Brute Force Protection

Phase 2 (H-1) 将备份码存储从明文改为 SHA-256 哈希，并实现暴力破解锁定：

```rust
use kms_mfa::BackupCodeGenerator;

// 生成备份码（一次性展示，明文仅在此处可用）
// Generate backup codes (shown once, plaintext only here)
let (mut generator, codes) = BackupCodeGenerator::generate(10);

for code in &codes {
    println!("Backup code: {}", code.code); // 8 位数字 8-digit numbers
}

// API 层存储前先哈希（Phase 2 H-1）
// API layer hashes before storing (Phase 2 H-1)
let hashed_codes: Vec<_> = codes.iter()
    .map(|c| hash_backup_code(&c.code))  // SHA-256 哈希
    .collect();

// 消费备份码（仅首次有效）
// Consume backup code (valid only once)
match generator.consume_code(user_input) {
    Ok(()) => { /* 成功，remaining-- */ }
    Err(MfaError::BackupCodeLocked(retry_after)) => {
        // 暴力破解：连续 5 次错误触发 5 分钟锁定
        // Brute force protection: 5 consecutive failures → 5-minute lockout
        return Err(format!("Backup codes locked for {}s", retry_after));
    }
    Err(MfaError::InvalidCode) => { /* 错误码 */ }
    Err(MfaError::NoBackupCodes) => { /* 码已用尽 */ }
}
```

## MFA-API Key 联动锁定（H-2）/ MFA-API Key Lock (Phase 2 H-2)

Phase 2 (H-2) 将 MFA 验证状态与 API Key 生命周期联动：

```rust
// crates/kms-api/src/auth.rs
impl ApiKeyConfig {
    // API Key 集合（线程安全）
    // Thread-safe API Key collection
    valid_keys: Arc<Mutex<Vec<ApiKey>>>,  // Phase 2 H-2

    /// 锁定指定 Key（由 MFA 失败触发）
    /// Lock a specific key (triggered by MFA failure)
    pub async fn lock_key_by_id(&self, key_id: Uuid) -> Result<()> {
        let mut keys = self.valid_keys.lock().await;
        if let Some(key) = keys.iter_mut().find(|k| k.id == key_id) {
            key.status = KeyStatus::Locked;
            tracing::warn!("API Key {} locked due to MFA failure", key_id);
        }
        Ok(())
    }
}
```

### 联动策略 / Lock Strategy

| 触发条件 Trigger | 响应 Response |
|-----------------|--------------|
| TOTP 验证连续失败 | 对应 API Key 联动锁定 |
| 备份码耗尽 | API Key 无法恢复，需 Security Officer 解锁 |
| BackupCodeLocked | 5 分钟拒绝所有 MFA 尝试 |

## 与传统 2FA 的对比 / MFA vs Traditional 2FA

| 维度 Dimension | 传统 2FA | gm-kms MFA |
|---------------|---------|------------|
| **因素数量 Factors** | 2 种 Exactly 2 | 2-N 种 2-N types |
| **密钥保护 Key Protection** | 无 Not included | 核心设计目标 Core design goal |
| **备份码 Backup Codes** | 通常无 Usually not | ✅ SHA-256 哈希存储 ✅ SHA-256 hash stored |
| **API Key 联动 API Key Lock** | 无 Not included | ✅ Phase 2 H-2 ✅ Phase 2 H-2 |
| **审计日志 Audit Log** | 有限 Limited | 完整 Full |

## 安全注意事项 / Security Notes

| 风险 Risk | 缓解措施 Mitigation |
|-----------|-------------------|
| **TOTP 密钥泄露** | AES-256-GCM 信封加密存储（Phase 1）/ AES-256-GCM envelope encryption (Phase 1) |
| **暴力破解验证码** | 限速（5 次失败触发锁定）/ Rate limiting (5 failures → lockout) |
| **备份码猜测** | SHA-256 哈希 + 5 次失败锁定 / SHA-256 hash + 5-failure lockout |
| **SMS OTP 拦截** | 不推荐使用 SMS / SMS not recommended |
| **硬件令牌丢失** | 备份码 + Security Officer 恢复流程 / Backup codes + SO recovery |

## 参考资料 / References

- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) — Digital Identity Guidelines
- [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) — TOTP
- [FIDO2/WebAuthn](https://fidoalliance.org/specs/fido2/) — Passwordless Authentication
- [OWASP MFA Guidelines](https://cheatsheetseries.owasp.org/) — Authentication Cheat Sheet
