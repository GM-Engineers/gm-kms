# SM2 Key Exchange Requirement / SM2 密钥交换需求

> 文档版本: 1.2
> 创建日期: 2026-04-26
> 更新日期: 2026-07-08
> 参考标准: GM/T 0003-2012《SM2 椭圆曲线公钥密码算法》
> 状态: 已实现
>
> **勘误 (2026-07-08)**: 本章曾与实际代码 (`gm/gm-crypto/src/sm2.rs`、`gm/gm-crypto/src/sm2_kex.rs`) 存在偏差，已修正：
> `Sm2KeyPair` 字段 (`distid: String` 而非 `user_id: Option<Vec<u8>>`，且为私有字段)、
> `Sm2KexMessage` (`sender_id` 为 `[u8; 16]`、`r_pub` 字段、新增 `confirmation`)、
> `KexState` 变体 (`WaitForResponse`/`WaitForConfirmation`)、
> `process_msg1/2` 签名 (以 `peer_public_key` 替代 `key_pair`)、
> `Sm2KexError` 实为 `CryptoError::Sm2KexError(String)` 变体、
> 以及删除并不存在的 REST 端点 `/v1/keys/{id}/sm2-kex/create-session`。

---

## 一、概述

SM2 密钥交换协议是一种双方密钥协商协议，允许两个通信方在不安全的信道上通过交换公钥建立共享密钥。该协议基于 SM2 椭圆曲线密码算法和 SM3 密码杂凑算法。

### 1.1 协议参与方

| 参与方 | 角色 | 说明 |
|--------|------|------|
| A | 发起方 | 密钥交换的发起者 |
| B | 响应方 | 密钥交换的响应者 |
| KGC | 密钥管理中心 | 为 A 和 B 颁发 SM2 密钥对 |

### 1.2 协议目标

1. A 和 B 通过信息交换建立共同的会话密钥
2. 会话密钥由 A 和 B 的私有信息、椭圆曲线参数等通过密钥派生函数产生
3. 协议提供密钥确认机制，确保双方持有相同的会话密钥

---

## 二、算法基础

### 2.1 依赖算法

| 算法 | 要求 | 说明 |
|------|------|------|
| SM2 椭圆曲线 | 必须 | 256 位曲线参数 |
| SM3 杂凑算法 | 必须 | 256 位输出 |
| SM2 数字签名 | 必须 | 用于用户身份验证 |
| 对称加密算法 | 可选 | 用于密钥确认 |

### 2.2 椭圆曲线参数

SM2 曲线参数应支持标准推荐的曲线域参数：

```
p  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b  = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
```

### 2.3 关键数据结构

#### 2.3.1 密钥对

```rust
pub struct Sm2KeyPair {
    // 私钥 (SecretKey<Sm2>, 落盘即零化, 非 pub 字段)
    private_key: SecretKey<Sm2>,
    // 公钥 (PublicKey<Sm2>, 非 pub 字段)
    #[zeroize(skip)]
    public_key: PublicKey<Sm2>,
    /// SM2 标识 (distid, 默认 "1234567812345678")
    distid: String,
}

impl Sm2KeyPair {
    /// 使用标准 distid 生成密钥对
    pub fn generate() -> Result<Self, CryptoError>;

    /// 从私钥字节派生密钥对
    pub fn from_private_key(private_key_bytes: &[u8]) -> Result<Self, CryptoError>;

    /// 获取公钥 (返回 PublicKey<Sm2> 引用)
    pub fn public_key(&self) -> &PublicKey<Sm2>;

    /// 获取压缩格式公钥字节 (33 bytes)
    pub fn public_key_bytes(&self) -> Vec<u8>;

    /// 获取未压缩格式公钥字节 (65 bytes, 0x04 || X || Y)
    pub fn public_key_bytes_uncompressed(&self) -> Vec<u8>;

    /// 获取 distid
    pub fn distid(&self) -> &str;
}
```

#### 2.3.2 临时密钥 (Ephemeral Key)

```rust
/// 临时密钥对，用于密钥交换过程
pub struct EphemeralKeyPair {
    /// 临时私钥 r (1 <= r < n)
    pub r: [u8; 32],
    /// 临时公钥 R = r·G (64 bytes, 未压缩格式 X || Y)
    pub r_pub: [u8; 64],
}
```

#### 2.3.3 交换消息

```rust
/// SM2 密钥交换协议的消息结构
#[derive(Debug, Clone)]
pub struct Sm2KexMessage {
    /// 消息类型: 1=A向B发送, 2=B向A发送, 3=A向B发送确认
    pub msg_type: u8,
    /// 发送方标识 (16 bytes, 固定长度 USER_ID_LEN)
    pub sender_id: [u8; USER_ID_LEN],
    /// 临时公钥 R1 或 R2 (64 bytes)
    pub r_pub: [u8; 64],
    /// 可选: 签名 (用于身份验证, 仅 msg2)
    pub signature: Option<[u8; 64]>,
    /// 可选: 密钥确认值 SA/SB (32 bytes, 仅 msg3)
    pub confirmation: Option<[u8; 32]>,
}

/// 协商结果
pub struct Sm2KexResult {
    /// 协商得到的共享密钥 KDF(VA, VB, ZA, ZB)
    pub shared_secret: [u8; 32],
    /// 用于后续通信的对称密钥
    pub session_key: [u8; 32],
    /// S 值 (用于密钥确认)
    pub s: [u8; 32],
}
```

---

## 三、协议流程

### 3.1 完整协议 (3 步交互)

```
┌─────────────────────────────────────────────────────────────────┐
│                         SM2-KEX 协议流程                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│    A (发起方)                          B (响应方)                │
│    ─────────                          ─────────                 │
│                                                                   │
│  1. 生成临时密钥对                                                │
│     r1 ∈ [1, n-1]                                               │
│     R1 = r1·G                                                    │
│         │                                                        │
│         │  msg1: A || R1                                        │
│         ├───────────────────────────────────────────────────────►│
│         │                                                        │
│         │                          2. 验证 R1, 生成临时密钥对       │
│         │                             r2 ∈ [1, n-1]             │
│         │                             R2 = r2·G                 │
│         │                                                        │
│         │  msg2: B || R2 || signB(IDA, IDB, R1, R2)            │
│         ◄───────────────────────────────────────────────────────┤
│         │                                                        │
│  3. 验证 B 的签名                                                │
│     verify(signB)                                                │
│     计算 S1 = KDF(IDA, IDB, R1, R2, r1·R2)                      │
│     生成确认: A → B: A || SB                                    │
│         │                                                        │
│         │  msg3: A || SA                                        │
│         ├───────────────────────────────────────────────────────►│
│         │                                                        │
│         │                          4. 验证 A, 计算共享密钥        │
│         │                             S2 = KDF(IDA, IDB, R1, R2,  │
│         │                                    r2·R1)              │
│         │                             验证 SA                                            │
│         │                                                        │
│         ▼                                                        ▼
│                                                                   │
│    共享密钥: KDF(IDA, IDB, R1, R2, ZA, ZB)                       │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 消息格式

#### 消息 1 (A → B): 发起请求

| 字段 | 长度 | 说明 |
|------|------|------|
| A_ID | 16 字节 | 发起方用户标识 |
| R1 | 64 字节 | A 的临时公钥 (未压缩格式) |

#### 消息 2 (B → A): 响应并提供临时公钥

| 字段 | 长度 | 说明 |
|------|------|------|
| B_ID | 16 字节 | 响应方用户标识 |
| R2 | 64 字节 | B 的临时公钥 (未压缩格式) |
| signB | 64 字节 | B 对 (A_ID, B_ID, R1, R2) 的签名 |

#### 消息 3 (A → B): 密钥确认

| 字段 | 长度 | 说明 |
|------|------|------|
| A_ID | 16 字节 | 发起方用户标识 |
| SA | 32 字节 | A 计算的确认值 S1 |

### 3.3 核心算法

#### 3.3.1 密钥派生函数 (KDF)

```rust
/// SM2-KEX 使用的密钥派生函数
///
/// 参数:
/// - Z: 输入字节串
/// - klen: 期望输出密钥长度 (字节)
///
/// 输出:
/// - K: 派生得到的密钥
pub fn sm2_kdf(Z: &[u8], klen: usize) -> Vec<u8> {
    // 1. ct = 0x00000001
    // 2. 对 i = 1 to ceil(klen/v):
    //    a. ha = SM3(Z || ct)
    //    b. ct = ct + 1
    //    c. K = K || ha
    // 3. 返回 K[0:klen]
}
```

#### 3.3.2 共享密钥计算

```rust
/// 计算共享密钥成分
///
/// A 侧计算:
///   S1 = KDF(A_ID || B_ID || R1 || R2 || x2 || y2 || r1·R2)
/// B 侧计算:
///   S2 = KDF(A_ID || B_ID || R1 || R2 || x1 || y1 || r2·R1)
fn compute_shared_scalar(
    R1: &[u8; 64],
    R2: &[u8; 64],
    r_self: &[u8; 32],
    peer_R: &[u8; 64],
) -> Vec<u8> {
    // 1. 计算点乘: V = r·peer_R
    // 2. 提取 V 的 x, y 坐标
    // 3. 返回 x || y
}
```

#### 3.3.3 确认值计算

```rust
/// 计算密钥确认值
///
/// SA = SM3(A_ID || SM3(R1 || R2 || x2 || y2 || K))
/// SB = SM3(B_ID || SM3(R1 || R2 || x1 || y1 || K))
fn compute_confirmation(sender_id: &[u8], R1: &[u8], R2: &[u8], K: &[u8]) -> [u8; 32] {
    let inner = sm3_hash(R1 || R2 || K);
    sm3_hash(sender_id || inner)
}
```

---

## 四、接口设计

### 4.1 核心 API

> 以下 API 基于 `gm-crypto/src/sm2_kex.rs` 实际代码，路径 `../gm/gm-crypto/`。

```rust
/// SM2 密钥交换器
pub struct Sm2Kex {
    key_pair: Sm2KeyPair,
}

impl Sm2Kex {
    /// 创建交换器（需提供长期密钥对）
    pub fn new(key_pair: Sm2KeyPair) -> Self;

    /// 创建发起方会话
    pub fn init_session(&mut self, user_id: &[u8]) -> Result<KexSession, CryptoError>;

    /// 创建响应方会话
    pub fn accept_session(&mut self, user_id: &[u8]) -> Result<KexSession, CryptoError>;
}

/// 密钥交换会话
pub struct KexSession { /* 内部字段 */ }

impl KexSession {
    /// 创建发起方会话
    pub fn new_initiator(key_pair: &Sm2KeyPair, user_id: &[u8]) -> Result<Self, CryptoError>;

    /// 创建响应方会话
    pub fn new_responder(key_pair: &Sm2KeyPair, user_id: &[u8]) -> Result<Self, CryptoError>;

    /// 获取会话 ID
    pub fn session_id(&self) -> [u8; 16];

    /// 获取当前状态
    pub fn state(&self) -> KexState;

    /// 获取临时公钥
    pub fn ephemeral_public_key(&self) -> [u8; 64];

    /// 获取协商结果（完成后可用）
    pub fn get_result(&self) -> Option<&Sm2KexResult>;

    // 消息处理（按步骤分方法，非统一 process_message）
    /// 发起方：生成消息 1
    pub fn generate_msg1(&self) -> Result<Sm2KexMessage, CryptoError>;
    /// 响应方：处理消息 1，生成消息 2
    pub fn process_msg1(&mut self, msg: &Sm2KexMessage, peer_public_key: &PublicKey<Sm2>) -> Result<Sm2KexMessage, CryptoError>;
    /// 发起方：处理消息 2，生成消息 3
    pub fn process_msg2(&mut self, msg: &Sm2KexMessage, peer_public_key: &PublicKey<Sm2>) -> Result<Sm2KexMessage, CryptoError>;
    /// 响应方：处理消息 3，完成密钥交换
    pub fn process_msg3(&mut self, msg: &Sm2KexMessage) -> Result<(), CryptoError>;
}

/// 会话状态
pub enum KexState {
    Init,
    WaitForResponse,
    WaitForConfirmation,
    Completed,
    Failed,
}
```

### 4.2 使用示例

```rust
use gm_crypto::sm2::Sm2KeyPair;
use gm_crypto::sm2_kex::Sm2Kex;

fn main() -> Result<(), CryptoError> {
    // 初始化长期密钥对
    let alice_key = Sm2KeyPair::generate()?;
    let bob_key = Sm2KeyPair::generate()?;

    // 初始化密钥交换器
    let mut alice_kex = Sm2Kex::new(alice_key.clone());
    let mut bob_kex = Sm2Kex::new(bob_key.clone());

    // Step 1: Alice 发起会话
    let mut alice_session = alice_kex.init_session(b"userA")?;
    let msg1 = alice_session.generate_msg1()?;

    // Step 2: Bob 处理请求并响应 (peer_public_key 为发起方 Alice 的长期公钥, 用于验签)
    let mut bob_session = bob_kex.accept_session(b"userB")?;
    let msg2 = bob_session.process_msg1(&msg1, alice_key.public_key())?;

    // Step 3: Alice 处理响应并确认 (peer_public_key 为响应方 Bob 的长期公钥, 用于验签)
    let msg3 = alice_session.process_msg2(&msg2, bob_key.public_key())?;

    // Step 4: Bob 验证确认并完成
    bob_session.process_msg3(&msg3)?;

    // 获取共享密钥
    let shared_secret = alice_session.get_result().unwrap().shared_secret;
    let bob_shared = bob_session.get_result().unwrap().shared_secret;

    assert_eq!(shared_secret, bob_shared);
    Ok(())
}
```

### 4.3 错误类型

```rust
/// SM2-KEX 错误是 `CryptoError` 的一个变体 (并非独立枚举):
///
/// ```rust
/// pub enum CryptoError {
///     // ... 其他变体 ...
///     #[error("SM2 key exchange error: {0}")]
///     Sm2KexError(String),
///     // ... 其他变体 ...
/// }
/// ```
///
/// 常见触发场景 (统一以 `CryptoError::Sm2KexError(..)` 返回):
/// 临时公钥不在曲线上、用户标识非法、签名验证失败、密钥确认失败、
/// 协议状态错误、会话过期、SM3 杂凑错误等。
```

---

## 五、安全要求

### 5.1 临时密钥要求

1. **随机性**: 临时私钥必须使用密码学安全的随机数生成器
2. **唯一性**: 每次会话必须生成新的临时密钥对
3. **有效期**: 临时密钥对必须在会话结束后立即销毁

### 5.2 用户标识要求

1. 用户标识 (UserID) 应遵循 GM/T 0003-2012 规定
2. 默认 UserID: "1234567812345678" (ASCII)
3. UserID 长度建议不超过 256 字节

### 5.3 密钥派生要求

1. KDF 必须使用 SM3 作为基础杂凑函数
2. 共享密钥长度不得低于 32 字节
3. KDF 输入必须包含 A 和 B 的完整标识信息

### 5.4 抗攻击要求

| 攻击类型 | 防护措施 |
|----------|----------|
| 中间人攻击 (MITM) | 签名验证 |
| 重放攻击 | 时间戳/序列号验证 |
| 私钥泄露 | 临时密钥机制 |
| 蛮力攻击 | 足够长度的密钥 (256 位) |

---

## 六、测试用例

### 6.1 基本功能测试

```rust
#[test]
fn test_sm2_kex_basic() {
    let alice_key = Sm2KeyPair::generate().unwrap();
    let bob_key = Sm2KeyPair::generate().unwrap();

    let mut alice_kex = Sm2Kex::new(alice_key.clone());
    let mut bob_kex = Sm2Kex::new(bob_key.clone());

    // 初始化
    let mut alice_session = alice_kex.init_session(b"alice").unwrap();
    let msg1 = alice_session.generate_msg1().unwrap();

    // 响应 (peer_public_key 为 Alice 的长期公钥, 用于验签)
    let mut bob_session = bob_kex.accept_session(b"bob").unwrap();
    let msg2 = bob_session.process_msg1(&msg1, alice_key.public_key()).unwrap();

    // 确认 (peer_public_key 为 Bob 的长期公钥, 用于验签)
    let msg3 = alice_session.process_msg2(&msg2, bob_key.public_key()).unwrap();

    // 完成
    bob_session.process_msg3(&msg3).unwrap();

    // 验证共享密钥一致
    let secret_a = alice_session.get_result().unwrap().shared_secret;
    let secret_b = bob_session.get_result().unwrap().shared_secret;
    assert_eq!(secret_a, secret_b);
}
```

### 6.2 签名验证测试

```rust
#[test]
fn test_sm2_kex_signature_verification() {
    // 测试无效签名被正确拒绝
    let mut msg = create_test_message();
    // 篡改签名
    msg.signature = Some(invalid_signature());

    // peer_public_key 为发起方 (A) 的长期公钥, 用于验签
    let result = bob_session.process_msg1(&msg, peer_public_key);
    assert!(result.is_err()); // 签名验证失败
}
```

### 6.3 并发性测试

```rust
#[test]
fn test_sm2_kex_concurrent_sessions() {
    // 同时建立多个会话
    let sessions: Vec<_> = (0..10)
        .map(|i| {
            let key = Sm2KeyPair::generate().unwrap();
            let mut kex = Sm2Kex::new(key);
            kex.init_session(format!("user{}", i).as_bytes()).unwrap()
        })
        .collect();

    // 所有会话应独立工作
    for mut session in sessions {
        let msg = session.generate_msg1().unwrap();
        // ... 完整协议流程
    }
}
```

---

## 七、验收标准

### 7.1 功能验收

- [x] 能够创建和初始化密钥交换会话（通过 `Sm2Kex::init_session` / `accept_session` 在进程内建立 `KexSession`，无独立 REST 端点）
- [x] 正确生成临时密钥对
- [ ] 正确解析和处理 SM2-KEX 协议消息（完整 3 步交互）
- [ ] 正确计算共享密钥
- [ ] 正确实现密钥确认机制
- [ ] 支持 A 和 B 双方发起密钥交换

### 7.2 安全性验收

- [x] 临时密钥完全随机
- [ ] 签名验证正确实现
- [ ] 密钥确认值计算正确
- [ ] 无中间人攻击漏洞
- [x] 抵抗重放攻击（会话超时 + 撤销）

### 7.3 兼容性验收

- [ ] 与 GM/T 0003-2012 标准兼容
- [ ] 与主流国密库 (如 Tongsuo) 的 SM2-KEX 实现互操作

### 7.4 性能要求

- 单次密钥交换协商时间 < 10ms (在标准服务器上)
- 内存占用 < 1KB (单会话)

---

## 八、附录

### A. 参考标准

1. GM/T 0003-2012《SM2 椭圆曲线公钥密码算法》
2. GM/T 0003-2012《SM2 数字签名算法》
3. GM/T 0004-2012《SM3 密码杂凑算法》
4. RFC 5208 (PKCS#8)
5. RFC 5480 (Elliptic Curve Cryptography Subject Public Key Information)

### B. 术语表

| 术语 | 定义 |
|------|------|
| KGC | Key Generation Center, 密钥管理中心 |
| KDF | Key Derivation Function, 密钥派生函数 |
| Ephemeral Key | 临时密钥, 只在单次会话中使用的密钥 |
| UserID | 用户标识, 用于识别协议参与方 |
| 共享密钥 | 由双方共同协商生成的密钥 |

---

*文档结束*
