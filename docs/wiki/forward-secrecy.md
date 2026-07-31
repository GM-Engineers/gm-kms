# Forward Secrecy（正向安全） / Forward Secrecy / Perfect Forward Secrecy (PFS)

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Forward Secrecy / Perfect Forward Secrecy (PFS) |
| **中文** | 正向安全、完美前向保密 / Forward Secrecy |
| **类型 Type** | 安全属性 / Security property |
| **核心特性** | 长期密钥泄露不影响历史会话安全 / Long-term key compromise does not affect past session security |


## 概述

Forward Secrecy 是一种安全属性，确保即使长期密钥（如服务器私钥）泄露，历史上建立的会话密钥也不会被攻击者解密。这通过为每个会话使用独立的临时密钥实现。

```
正向安全 vs 非正向安全：

非正向安全：
  服务器私钥泄露 ──▶ 攻击者解密所有历史会话
                    （所有会话使用同一主密钥）

正向安全：
  服务器私钥泄露 ──▶ 攻击者只能解密当前会话
                    （历史会话使用临时密钥，已销毁）
```

## 工作原理

### 1. 临时密钥交换（Ephemeral Key Exchange）

```
TLS 1.3 正向安全流程：

1. 客户端 ──▶ 服务器：ClientHello（支持的密码套件）
2. 客户端 ◀─ 服务器：ServerHello（选中的 ephemeral 曲线）
                    + 服务器临时公钥
3. 客户端 + 服务器：
   - 使用临时公钥计算得出【会话密钥】
   - 服务器私钥不参与会话密钥计算
4. 双方销毁临时私钥
5. 后续通信使用会话密钥

即使服务器私钥泄露，攻击者也无法获得会话密钥。
```

### 2. 临时 DEK（Ephemeral DEK）模式

```go
// 临时 DEK 实现
type EphemeralDEKManager struct {
    kmsClient *KMSClient
    cache     *LRUCache  // 缓存活跃 DEK
}

type EphemeralKey struct {
    ID        string
    DEK       []byte     // 明文 DEK（仅存内存）
    CreatedAt time.Time
    ExpiresAt time.Time
    Flags     KeyFlags   // DestroyOnExpiry 等
}

func (e *EphemeralDEKManager) GenerateDEK(ctx context.Context, resourceID string) (*EphemeralKey, error) {
    // 1. 生成随机 DEK
    dek := make([]byte, 32)
    if _, err := rand.Read(dek); err != nil {
        return nil, err
    }

    // 2. 创建临时密钥
    key := &EphemeralKey{
        ID:        generateKeyID(),
        DEK:       dek,
        CreatedAt: time.Now(),
        ExpiresAt: time.Now().Add(1 * time.Hour),
        Flags:     DestroyOnExpiry,
    }

    // 3. 缓存（仅存内存，不落盘）
    e.cache.Set(key.ID, key)

    return key, nil
}

func (e *EphemeralDEKManager) Destroy(ctx context.Context, keyID string) error {
    key, err := e.cache.Get(keyID)
    if err != nil {
        return err
    }

    // 真正销毁（内存清零）
    zeroize(key.DEK)
    e.cache.Delete(keyID)

    audit.Log(ctx, "EPHEMERAL_KEY_DESTROYED", keyID)
    return nil
}
```

## 在 KMS 中的实现

### Ephemeral DEK API

```go
// 临时 DEK 接口
type EphemeralDEKService interface {
    // 生成临时 DEK（不持久化存储）
    GenerateDEK(ctx context.Context, opts GenerateOpts) (*EphemeralKey, error)

    // 使用 DEK 加密数据
    Encrypt(ctx context.Context, keyID string, plaintext []byte) (*EncryptedData, error)

    // 销毁 DEK
    Destroy(ctx context.Context, keyID string) error

    // 查询 DEK 状态
    GetStatus(ctx context.Context, keyID string) (*KeyStatus, error)
}

// EphemeralKey 特性
type KeyFlags struct {
    DestroyOnExpiry  bool  // 到期自动销毁
    DestroyOnAccess  bool  // 访问一次后销毁（单次使用）
    NoExport         bool  // 禁止导出明文
    RequireAudit     bool  // 每次使用都审计
}
```

### 使用场景

| 场景 | 说明 |
|------|------|
| **TLS 会话** | 每个 TLS 连接使用独立的临时密钥 |
| **文件加密** | 每个文件使用唯一的临时 DEK |
| **消息加密** | 每个消息会话使用不同的密钥 |
| **短期数据保护** | 敏感数据使用临时密钥，逾期自动销毁 |

## 与其他安全机制的关系

```
Forward Secrecy 在密钥体系中的位置：

长期密钥（Root Key / Master Key）
    │
    ▼
中间层密钥（KEK）- 轮换周期长（如 1 年）
    │
    ▼
临时密钥（Ephemeral DEK）- 每个会话/文件独立
    │
    ▼
会话密钥（Session Key）- TLS 1.3 AEAD 密钥
```

| 安全机制 | 作用 | 与 Forward Secrecy |
|----------|------|---------------------|
| **Ephemeral DEK** | 会话级密钥 | 直接实现 |
| **ECDHE** | 密钥交换协议 | 基于 Diffie-Hellman |
| **TLS 1.3** | 传输层安全 | 强制正向安全 |
| **HSM** | 根密钥保护 | 确保长期密钥安全 |

## 正向安全等级 / Forward Secrecy Levels

| 级别 Level | 说明 Description | 实现方式 Implementation |
|-----------|----------------|--------------------|
| **PFS（完美前向保密）** / PFS | 长期密钥泄露不影响历史会话 / LT key compromise doesn't affect past sessions | Ephemeral DH/ECDH |
| **半正向** / Semi-forward | 定期轮换密钥，历史有限保护 / Periodic key rotation, limited historical protection | 定期更新主密钥 / Periodic master key update |
| **无前向安全** / No FS | 长期密钥泄露解密所有历史 / LT key compromise decrypts all history | 静态密钥 / Static keys |


## 合规要求 / Compliance Requirements

| 标准 Standard | 正向安全要求 Forward Secrecy Requirement |
|-------------|-------------------------------------|
| **PCI-DSS 3.2** | TLS 必须使用前向保密 / TLS must use forward secrecy |
| **NIST SP 800-52** | TLS 实现指南要求 PFS / TLS implementation guide requires PFS |
| **等保三级** / Level 3 | 重要系统建议使用前向保密 / Forward secrecy recommended for important systems |


## 参考标准

- [NIST SP 800-52 Rev 2](https://doi.org/10.6028/NIST.SP.800-52r2) - TLS 实现指南
- [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) - TLS 1.3
- [IETF TLS工作组](https://datatracker.ietf.org/wg/tls/) - TLS 标准