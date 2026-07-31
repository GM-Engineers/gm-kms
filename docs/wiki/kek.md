# KEK（密钥加密密钥） / Key Encryption Key

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Key Encryption Key |
| **类型 Type** | 密钥层次中的上层密钥 / Upper-layer key in key hierarchy |
| **用途 Purpose** | 加密 DEK（数据加密密钥）/ Encrypts DEK (Data Encryption Key) |
| **保护等级** | 高（通常存储在 HSM/TPM 中）/ High (usually stored in HSM/TPM) |


## 概述

KEK 是密钥层次中的第二层（仅次于根密钥），用于加密 DEK。KEK 不直接加密业务数据，而是作为 DEK 的保护层。

```
根密钥（Root Key）─▶ KEK ─▶ DEK ─▶ 业务数据
  (HSM/TPM)       (HSM)    (内存)    (磁盘/网络)
```

## 密钥层次结构 / Key Hierarchy

| 层级 Level | 名称 Name | 说明 Description | 存储位置 Storage |
|-----------|----------|----------------|----------------|
| L1 | Root Key（根密钥） | 最高级别，永不离开 HSM / Highest level, never leaves HSM | HSM/TPM |
| L2 | KEK（密钥加密密钥） | 保护 DEK，生命周期长 / Protects DEK, long lifecycle | HSM/软件 / HSM/Software |
| L3 | DEK（数据加密密钥） | 直接加密数据，生命周期短 / Directly encrypts data, short lifecycle | 内存/缓存 / Memory/Cache |


## 在 Envelope Encryption 中的角色

```
┌─────────────────────────────────────────────────────┐
│                    Envelope                          │
│                                                      │
│   ┌─────────┐      ┌──────────┐      ┌───────────┐ │
│   │ KEK     │ ──▶ │ encrypted │      │ ciphertext │ │
│   │ (KMS)  │      │ DEK       │      │ (数据)    │ │
│   └─────────┘      └──────────┘      └───────────┘ │
│        │                                     │       │
│        │           ┌──────────┐              │       │
│        └─────────▶ │ encrypted │ ◀───────────┘       │
│                    │ DEK + CT  │    （信封）          │
│                    └──────────┘                      │
└─────────────────────────────────────────────────────┘
```

## KEK 的特性 / KEK Properties

| 特性 Property | 说明 Description |
|-------------|----------------|
| **高熵** / High Entropy | 必须是高质量随机数（至少 256 位）/ Must be high-quality random (≥ 256-bit) |
| **长生命周期** / Long Lifecycle | 通常数年才轮换一次 / Typically rotated once every few years |
| **隔离保护** / Isolated Protection | 存储在 HSM/TPM 中，不以明文离开 / Stored in HSM/TPM, never leaves in plaintext |
| **审计追踪** / Audit Trail | 所有操作记录在审计日志中 / All operations logged in audit trail |
| **多人授权** / Multi-party Auth | 关键操作需要多人授权（如 M-of-N）/ Key operations require multi-party auth (e.g., M-of-N) |


## 与 DEK 的对比 / DEK Comparison

| 特性 Feature | KEK | DEK |
|-------------|-----|-----|
| **用途** / Purpose | 加密 DEK / Encrypts DEK | 加密业务数据 / Encrypts business data |
| **生命周期** / Lifecycle | 长（数月~数年）/ Long | 短（数小时~数月）/ Short |
| **存储位置** / Storage | HSM/TPM | 内存（热缓存）/ Memory (hot cache) |
| **轮换频率** / Rotation | 低 / Low | 高（可频繁）/ High (can be frequent) |
| **泄露影响** / Breach Impact | 所有使用该 KEK 的 DEK / All DEKs using this KEK | 仅单个 DEK 加密的数据 / Only data encrypted by this DEK |


## 在 KMS 中的实现

```go
// KEK 操作接口
type KEKManager interface {
    // 生成 KEK
    GenerateKEK(ctx context.Context, opts GenerateOptions) (*KEK, error)
    // 加密 DEK
    EncryptDEK(ctx context.Context, kekID string, dek []byte) ([]byte, error)
    // 解密 DEK
    DecryptDEK(ctx context.Context, kekID string, encryptedDEK []byte) ([]byte, error)
    // 轮换 KEK
    RotateKEK(ctx context.Context, kekID string) (*KEK, error)
    // 获取 KEK 元数据
    GetKEKMetadata(ctx context.Context, kekID string) (*KEKMetadata, error)
}

// KEK 元数据
type KEKMetadata struct {
    ID          string    // KEK 唯一标识
    Algorithm   string    // 算法（如 AES-256-GCM）
    CreatedAt   time.Time // 创建时间
    RotatedAt    time.Time // 上次轮换时间
    Status      string    // Active、Retired 等
    KeyVersion   int       // 版本号
}
```

## 安全注意事项 / Security Considerations

1. **HSM 保护** / HSM Protection：KEK 应存储在 FIPS 140-2 L2+ 的 HSM 中 / KEK should be stored in FIPS 140-2 L2+ HSM
2. **隔离存储** / Isolated Storage：不同用途/租户的 KEK 应隔离存储 / Different purpose/tenant KEKs should be stored separately
3. **轮换策略** / Rotation Policy：定期轮换 KEK，建议每年一次 / Regularly rotate KEK, recommended annually
4. **备用 KEK** / Backup KEK：保留旧 KEK 用于解密历史 DEK / Retain old KEKs for decrypting historical DEKs


## 参考文档

- [Envelope Encryption](./envelope-encryption.md) - KEK 在信封加密中的应用
- [Software Keystore](./software-keystore.md) - KEK 的软件存储方式
- [HSM](./hsm.md) - HSM 存储 KEK 的优势