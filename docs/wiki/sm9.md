# SM9 Master Key / SM9 主密钥管理

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **类型 Type** | 国密算法 / 标识密码 Identity-based Cryptography |
| **实现位置 Implementation** | `gm-sm9-rs` crate（`gm` workspace）|
| **标准 Standards** | GM/T 0044-2016（签名/加密）、GM/T 0044.3-2016 §7（密钥交换）|
| **曲线参数 Curve Params** | `gm-sm9-rs/src/params.rs`（基于 GM/T 0044-2016）|

## 概述 / Overview

SM9 是国家密码管理局发布的标识密码算法（IBE）。gm-kms 通过 `gm-sm9-rs` crate（位于 `gm` workspace）提供 SM9 主密钥（KGC Master Key）管理功能。SM9 支持签名、加密和密钥交换三大功能，其中密钥交换由 GM/T 0044.3-2016 §7 定义，已于 2026-06-25 完成实现。

SM9 is an Identity-Based Encryption (IBE) algorithm published by OSCCA. gm-kms provides SM9 Master Key (KGC) management via the `gm-sm9-rs` crate (in the `gm` workspace). SM9 supports signature, encryption, and key exchange — the latter defined in GM/T 0044.3-2016 §7 and implemented on 2026-06-25.

## SM9 算法功能 / SM9 Algorithm Features

| 功能 Feature | gmssl 后端 gmssl Backend | pure_rust 后端 pure_rust Backend | 状态 Status |
|-------------|-------------------------|----------------------------------|------------|
| 数字签名 Digital Signature | `gm_sm9::sign::Signer` / `Verifier` | `gm_sm9::sign::Signer` / `Verifier` | ✅ |
| 加密 Encryption | `gm_sm9::encrypt::Encryptor` | `gm_sm9::encrypt::Encryptor` | ✅ |
| 密钥交换 Key Exchange | `gm_sm9::key_exchange::key_exchange` | `gm_sm9::key_exchange::key_exchange` | ✅ (2026-06-25) |

> 注：gm-sm9-rs 纯 Rust 后端使用 GM/T 0044-2016 标准曲线参数，不再依赖 `ark_bn254`。/ Note: The pure-Rust backend uses GM/T 0044-2016 standard curve parameters and no longer depends on `ark_bn254`.

## 核心类型 / Core Types

### 主密钥 / Master Keys

```rust
use gm_sm9_rs::key::{MasterKey, SignMasterKey, EncMasterKey, SignUserKey, EncUserKey};

// 生成主密钥对（签名 + 加密）
// Generate master key pair (signing + encryption)
let master = MasterKey::generate(&mut rng)?;

// 获取签名/加密主密钥
// Get signing/encryption master keys
let sign_master = master.sign_master();   // &SignMasterKey
let enc_master = master.enc_master();     // &EncMasterKey

// 从主密钥派生用户密钥（基于身份标识）
// Derive user keys from master key (identity-based)
let sign_key = sign_master.extract_key(b"alice@example.com")?;  // SignUserKey
let enc_key = enc_master.extract_key(b"bob@example.com")?;     // EncUserKey
```

### 签名与验签 / Signing and Verification

```rust
use gm_sm9_rs::sign::{Signer, Verifier, Signature};

// 签名（使用用户签名私钥）
// Sign with user signing private key
let signer = Signer::new(sign_key);
let signature = signer.sign(message, &mut rng)?;

// 验签（使用签名主公钥 + 身份）
// Verify using signing master public key + identity
let verifier = Verifier::new(sign_master.clone(), b"alice@example.com");
let valid = verifier.verify(message, &signature)?;
```

### 加密与解密 / Encryption and Decryption

```rust
use gm_sm9_rs::encrypt::{Encryptor, Ciphertext};

// IBE 加密（使用加密主公钥 + 收件人身份标识）
// IBE encryption: encrypt with master public key + recipient identity
let encryptor = Encryptor::new(b"bob@example.com", &enc_master.public_key());
let ciphertext = encryptor.encrypt(plaintext, &mut rng)?;

// 解密（使用用户加密私钥）
// Decrypt with user encryption private key
let decrypted = ciphertext.decrypt(enc_key)?;
```

### SM9 密钥交换 / SM9 Key Exchange

```rust
use gm_sm9_rs::key_exchange::{key_exchange, HID};

// GM/T 0044.3-2016 §7 标识密钥交换协议
// GM/T 0044.3-2016 §7 Identity-based Key Exchange Protocol

// Initiator 发起方
let (initiator_output, round1_msg) = key_exchange::initiator_begin(
    b"alice@example.com",   // initiator 身份
    &enc_master,            // initiator 加密主密钥
    b"bob@example.com",     // responder 身份
    HID::Encrypt,           // HID = 0x03（加密用途）/ 0x02 = 签名用途
    &mut rng,
)?;

// Responder 响应方
let responder_output = key_exchange::responder_process(
    b"bob@example.com",
    &enc_master,
    b"alice@example.com",
    &round1_msg,
    HID::Encrypt,
    &mut rng,
)?;

// Initiator 完成（验证 responder 确认值并派生共享密钥）
// Initiator finishes: verify responder confirmation, derive shared key
let initiator_finished = key_exchange::initiator_finish(
    &initiator_output,
    &responder_output.round2_msg,
    HID::Encrypt,
    &mut rng,
)?;

// 双方得到相同的共享密钥 shared_secret
// Both parties now share the same `shared_secret`
assert_eq!(
    initiator_finished.shared_secret,
    responder_output.shared_secret
);
```

## 双后端架构 / Dual-Backend Architecture

`gm-sm9-rs` 通过 Cargo feature 支持两种后端：

| Feature | 后端 Backend | 说明 Description |
|---------|-------------|------------------|
| `gmssl`（默认 default）| GmSSL 3.1.1 FFI | C 库，生产级性能 C library, production performance |
| `pure_rust` | 自定义 Rust 实现 | 基于 GM/T 0044-2016 标准参数，无 C 依赖 |

两后端通过交叉验证确保结果一致。GmSSL 版本需与 GM/T 0044-2016 参数对齐（见 `sm9-curve-design.md`）。

## 曲线参数 / Curve Parameters

纯 Rust 后端使用 GM/T 0044-2016 标准参数，定义于 `gm-sm9-rs/src/params.rs`。详见 [SM9 曲线设计文档](../compliance/sm9-curve-design.md)。

## SM9 vs SM2

| 特性 Feature | SM2 | SM9 |
|-------------|------|-----|
| 密钥类型 Key Type | 随机公私钥对 Random key pair | 标识密钥（基于身份）Identity-based |
| 密钥分发 Key Distribution | 传统 PKI | KGC 直接分发 KGC direct distribution |
| 证书 Certificate | 需要 Required | 无需证书 Certificate-free |
| 密钥交换 Key Exchange | ✅ SM2-KEX（GM/T 0003.3-2012）| ✅ SM9-KEX（GM/T 0044.3-2016 §7）|
| 典型用途 Typical Use | TLS、文档签名 | IoT、标识认证 |

## 参考资料 / References

- [GM/T 0044-2016](http://www.oscca.gov.cn/) — SM9 标识密码算法
- [GM/T 0044.3-2016](http://www.oscca.gov.cn/) — SM9 密钥交换协议
- [SM9 曲线设计](../compliance/sm9-curve-design.md) — 曲线参数与实现说明
