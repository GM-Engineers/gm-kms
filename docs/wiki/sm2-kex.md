# SM2 Key Exchange（SM2 密钥交换） / SM2 Key Exchange Protocol

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **类型 Type** | 国密密钥交换协议 / GM Key Exchange Protocol |
| **实现位置** | `kms-keystore/sm2_kex_session.rs` |
| **标准** | GM/T 0003.3-2012 / GB/T 32918.3 |


## 概述

SM2 密钥交换协议允许通信双方协商出一个共享密钥，用于后续的对称加密通信。

## 协议流程

```
Initiator                          Responder
    │                                    │
    │ ──>  KeyExchangeInit (Ephemeral PK) ──▶  │
    │                                    │
    │ ◀──  KeyExchangeResponse (Ephemeral PK) ◀──  │
    │                                    │
    │ ──>  KeyExchangeConfirm1 ──────────────▶  │
    │                                    │
    │ ◀──  KeyExchangeConfirm2 ◀──────────────  │
    │                                    │
    ▼                                    ▼
  共享密钥                              共享密钥
```

## 会话状态机

```
Init → WaitForResponse → WaitForConfirmation → Completed
                │                │              │
                └────────────────┴──────────────┘
                         超时/错误 → Failed
```

## 实现机制

### 创建会话

```rust
use kms_keystore::sm2_kex_session::{Sm2KexSessionManager, Sm2KexSessionData};

let manager = Sm2KexSessionManager::new(redis_client);

// 创建发起方会话
let session_id = manager.create_session(
    tenant_id,       // 租户 ID
    key_id,          // 长期密钥 ID
    user_id,         // 用户标识
    true,            // is_initiator
).await?;

let session_data = manager.get_session(&session_id).await?;
```

### 更新会话状态与消息记录

```rust
// 更新会话状态（状态机转换）
manager.update_state(&session_id, SessionState::WaitForResponse).await?;

// 添加消息到历史记录（防重放）
manager.check_and_add_message(&session_id, &message_hash).await?;
```

### 完成会话

```rust
// 设置共享密钥和确认值
manager.complete_session(
    &session_id,
    shared_secret,      // Vec<u8>: 协商的共享密钥
    Some(confirmation), // Option<Vec<u8>>: 确认值
).await?;

// 删除会话
manager.remove_session(&session_id).await?;

// 检查会话是否过期
let expired = manager.is_session_expired(&session_id).await?;
```

## 会话数据

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sm2KexSessionData {
    pub session_id: Uuid,                    // 会话 ID
    pub key_id: Uuid,                       // 长期密钥 ID
    pub user_id: Vec<u8>,                   // 用户标识字节
    pub is_initiator: bool,                 // 是否为发起方
    pub state: SessionState,                // 会话状态
    pub nonce: u64,                          // 消息序列号
    pub created_at_ms: u64,                 // 创建时间戳
    pub last_activity_ms: u64,              // 最后活动时间戳
    pub message_history: Vec<(Vec<u8>, u64)>, // 消息哈希历史 (防重放)
    pub shared_secret: Option<Vec<u8>>,       // 共享密钥（完成时设置）
    pub confirmation: Option<Vec<u8>>,       // 确认值 S（完成时设置）
}
```

## 会话管理

| 功能 | 方法 | 说明 |
|------|------|------|
| 创建会话 | `create_session()` | 生成新的密钥交换会话 |
| 获取会话 | `get_session()` | 根据 ID 获取会话状态 |
| 更新状态 | `update_state()` | 状态机转换 |
| 消息记录 | `check_and_add_message()` | 记录消息历史、防重放 |
| 完成会话 | `complete_session()` | 设置共享密钥，结束会话 |
| 删除会话 | `remove_session()` | 清理会话数据 |
| 过期检查 | `is_session_expired()` | 检查是否超时 |

## Redis 存储

会话数据存储在 Redis，支持分布式场景：

```
sm2_kex:{tenant_id}:{session_id} → SessionData (JSON)
TTL: 300 秒（会话超时）
```

## 超时与清理

```rust
// 会话超时：300 秒
// 消息历史超时：60 秒

// 清理过期会话
manager.cleanup_expired_sessions().await?;
```

## 安全性 / Security Properties

| 特性 Property | 说明 Description |
|-------------|----------------|
| 前向安全 / Forward Secrecy | 使用临时密钥对，不依赖长期密钥 / Uses ephemeral key pairs, not dependent on long-term keys |
| 身份认证 / Identity Auth | 双方公钥可验证 / Both parties' public keys are verifiable |
| 密钥确认 / Key Confirmation | 确认消息验证对方持有私钥 / Confirmation messages verify peer holds private key |
| 防重放 / Anti-replay | 消息历史检查 / Message history check |


## 与 ECDH 的对比 / ECDH Comparison

| 特性 Feature | SM2 密钥交换 | ECDH |
|-------------|-------------|------|
| 标准 / Standard | GM/T 0003.3-2012 | NIST SP 800-56A |
| 曲线 / Curve | SM2p256v1 | P-256/P-384 |
| 密钥确认 / Key Confirmation | 双向确认消息 / Bidirectional confirmation messages | 可选 / Optional |
| 复杂度 / Complexity | 更高（3 消息）/ Higher (3 messages) | 更低（2 消息）/ Lower (2 messages) |


## 参考资料

- [GM/T 0003.3-2012](http://www.oscca.gov.cn/) - SM2 密钥交换协议
- [GB/T 32918.3](https://openstd.standsam.org/) - SM2 算法第三部分
