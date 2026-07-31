# gm-kms Architecture

> 版本 0.1.0 | 2026-06-26

## 概述

gm-kms 是一个基于国密算法（SM2/SM3/SM4/SM9）的密钥管理服务（KMS），提供密钥全生命周期管理、加密操作、数字签名、多因素认证、审计日志和策略访问控制。采用 Rust 2024 Edition，通过 gRPC + REST 双 API 提供服务。

### 技术栈

| 组件 | 技术 |
|------|------|
| 密码学后端 | gm workspace (pure Rust) + GmSSL 3.1.1 (FFI, 可选) |
| 传输协议 | gRPC (tonic) + REST (axum) |
| 密钥存储 | PostgreSQL (生产) / 软件内存 (测试) |
| 会话共享 | Redis (可选) |
| 审计日志 | WORM JSONL + HMAC-SHA256 签名 + TSA 时间戳 |
| MFA | TOTP (RFC 6238) + AES-256-GCM 信封加密 |
| 策略控制 | PBAC (Policy-Based Access Control) |

---

## Crate 架构

```
kms (root binary)
├── kms-api         ← gRPC + REST handlers, auth, MFA, rate limiting
│   ├── kms-core    ← 密码学原语、信封加密、密钥类型
│   ├── kms-keystore ← 密钥存储后端
│   ├── kms-policy  ← PBAC 策略引擎
│   ├── kms-audit   ← WORM 审计日志
│   ├── kms-mfa     ← TOTP MFA
│   └── kms-approval ← 操作审批工作流
├── kms-core        ← 基础密码学层（叶子节点，无内部 crate 依赖）
├── kms-hsm         ← HSM 后端 (TPM stub) → kms-core, kms-keystore
├── kms-keystore    ← 密钥存储 (software / postgres) → kms-core
├── kms-cli         ← CLI 工具（叶子节点）
├── kms-policy      ← PBAC 策略引擎 → kms-core
├── kms-audit       ← WORM 审计日志 → kms-core
├── kms-mfa         ← TOTP MFA（叶子节点，无内部 crate 依赖）
└── kms-approval    ← 操作审批工作流（叶子节点，无内部 crate 依赖）
```

### 依赖关系

实际依赖图存在菱形依赖（kms-api 和 kms-hsm 都依赖 kms-keystore，kms-keystore 又依赖 kms-core），难以用纯树形表达。下方先给出近似的树形视图，**完整依赖表为准**。

```
                         ┌──────────────────┐
                         │  kms (root bin)  │
                         └────────┬─────────┘
              ┌───────────────────┼───────────────────┐
         ┌────┴────┐         ┌────┴────┐         ┌────┴────┐
         │ kms-cli │         │ kms-api │         │ kms-hsm │
         │ (leaf)  │         │ (6 deps)│         │ (2 deps)│
         └─────────┘         └────┬────┘         └────┬────┘
                                 │                   │
        ┌────┬─────┬─────┬────┬──┴──┬────┐    ┌──────┴──────┐
        │    │     │     │    │     │    │    │             │
   ┌────┴┐┌─┴──┐┌─┴──┐┌─┴──┐┌┴───┐┌┴───┐    │             │
   │core ││pol-││aud-││mfa ││ap- ││key-│    │             │
   │     ││icy ││ it ││    ││prv ││store│    │             │
   └──┬──┘└────┘└────┘└────┘└────┘└──┬─┘    │             │
      │                              │      │             │
      │       (kms-keystore 间接依赖 kms-core)            │
      └──────────────────────┬────────┴──────┘             │
                             │                            │
                       ┌─────┴─────┐                      │
                       │  kms-core │  ◄── (所有非叶子 crate 链终到达此)
                       └───────────┘
```

**完整依赖表**（来自 `Cargo.toml` 实际验证）：

| Crate | 依赖的内部 crate |
|-------|------------------|
| `kms-api` | kms-core, kms-keystore, kms-policy, kms-audit, kms-mfa, kms-approval |
| `kms-hsm` | kms-core, kms-keystore |
| `kms-keystore` | kms-core |
| `kms-policy` | kms-core |
| `kms-audit` | kms-core |
| `kms-mfa` | （无） |
| `kms-approval` | （无） |
| `kms-core` | （无） |
| `kms-cli` | （无） |

所有非叶子 crate 最终依赖 `kms-core` 提供的密码学基础层。

---

## Crate 详解

### kms-core — 密码学核心

**职责**：定义所有密码学原语、密钥类型、信封加密机制、自检和 DH 密钥交换。

```
kms-core/src/
├── algorithms.rs       # 算法注册表 (EncryptionAlgorithm trait)
├── algorithms_impl.rs  # SM2/SM4 算法实现
├── csprng.rs           # CSPRNG (rand 0.10)
├── dh.rs               # DH 密钥派生 (SM2-KEX)
├── envelope.rs         # AES-256-GCM 信封加密 + KEK 机制
├── error.rs            # 错误类型
├── event.rs            # 审计事件类型
├── hybrid_kem.rs       # 混合密钥封装
├── key.rs              # 密钥类型与生命周期状态
├── key_io.rs           # 密钥序列化 (DER/PEM)
├── memory_protection.rs # mlock + 核心转储禁用
├── sanitize.rs         # 敏感数据清零 (Zeroizing)
├── secret_rotation.rs  # 密钥轮换逻辑
├── self_test.rs        # KAT 启动自检 (GB/T 37092-2018)
├── shamir.rs           # Shamir 秘密共享 (VSS)
├── sm9_key_rotation.rs # SM9 密钥轮换适配器
├── sm9_master_key.rs   # SM9 主密钥管理
└── tls_config.rs       # TLS 配置
```

**关键设计决策**：
- 密码算法敏捷性通过 `EncryptionAlgorithm` trait 实现，支持运行时切换 SM2/SM4
- DEK (数据加密密钥) 由 KEK (密钥加密密钥) 以 AES-256-GCM 信封方式保护
- 密钥轮换通过 `Sm9RotationAdapter` 将 gm-sm9-rs 轮换逻辑桥接到 gm-kms
- 恒定时间原语采用 `conditional_select` + 被动去线性化策略

### kms-keystore — 密钥存储

**职责**：密钥的持久化存储，支持软件内存和 PostgreSQL 双后端。

```
kms-keystore/src/
├── software/
│   ├── mod.rs        # 软件后端 (HashMap + mlock)
│   └── tests.rs      # 软件后端测试
├── backend.rs        # KeystoreBackend trait 定义
├── repository.rs     # 仓储实现 (sqlx / 内存)
├── postgres.rs       # PostgreSQL 后端 (sqlx)
├── sm2_kex_session.rs # SM2 密钥交换会话管理
├── sm9_master_key.rs # SM9 主密钥存储
├── cache.rs          # 装饰器缓存层 (CachingKeystore)
├── validation.rs     # 密钥验证
├── rate_limiter.rs   # 速率限制
└── lib.rs            # 模块入口
```

**双后端模式**：
- `KeystoreBackend` trait 定义统一接口
- 软件后端：`HashMap<KeyId, KeyMaterial>`，mlock 保护
- PG 后端：通过 sqlx 操作 PostgreSQL，支持租户隔离
- 装饰器缓存层 (`CachingKeystore`) 包装 PG 后端，减少数据库访问

### kms-api — API 层

**职责**：gRPC + REST 双 API，认证鉴权，MFA 管理，速率限制。

```
kms-api/src/
├── grpc.rs           # gRPC handler (tonic, 21 个 handler)
├── rest.rs           # REST handler (axum, 38 个 handler)
├── auth.rs           # API Key 认证 + 鉴权 + PBAC 检查
├── mfa.rs            # MFA 管理 (TOTP 配置持久化、加密、备份码)
├── rate.rs           # 速率限制 (Token Bucket)
├── pbac.rs           # PBAC 辅助函数 (check_pbac / check_rest_pbac)
├── anomaly.rs        # 异常检测
├── rotation.rs       # 密钥轮换 API
└── lib.rs            # 模块入口
```

**认证流程**：
1. `x-api-key` header → `ApiKeyConfig.validate()` → `check_permission()`
2. gRPC: `AuthInterceptor` 注入 `CallerId`，handler 调用 `check_pbac()`
3. REST: `CallerId` extractor 注入，handler 调用 `check_rest_pbac()`
4. PBAC 引擎评估策略后返回允许/拒绝

**速率限制**：
- CA Token Bucket：防止证书签发滥用
- Redis 支持的分布式速率限制

### kms-audit — 审计日志

**职责**：不可篡改审计日志，HMAC-SHA256 签名，hash 链完整性，TSA 时间戳。

```
kms-audit/src/
├── logger.rs         # SignedAuditLogger (加密 + 签名)
├── worm_writer.rs    # WORM JSONL 写入器
├── worm_logger.rs    # WORM 日志抽象
├── verifier.rs       # 链完整性验证
├── s3_archive.rs     # S3 归档支持
├── timestamp.rs      # TSA 时间戳
└── error.rs          # AuditError / AuditResult
```

**设计要点**：
- WORM (Write-Once-Read-Many): 仅追加 JSONL，不可删除/修改
- hash 链：每条目 `prev_hash = sha256(上一条目)`，启动时验证链完整性
- HMAC-SHA256 签名：使用持久化 HMAC 密钥（开发模式可用配置密钥）
- 自定义 `AuditError` 枚举（已移除 anyhow 依赖）

### kms-policy — PBAC 策略引擎

**职责**：基于属性的策略评估，控制密钥操作权限。

```
kms-policy/src/
├── engine.rs         # PolicyEngine — evaluate(action, resource, identity)，策略类型与错误定义
└── lib.rs            # 模块入口
```

### kms-mfa — TOTP 多因素认证

**职责**：RFC 6238 TOTP 生成与验证，支持 SHA1/SHA256/SHA512。

```
kms-mfa/src/
├── totp.rs           # TotpGenerator (RFC 6238)
├── backup_codes.rs   # 备份码生成
├── error.rs          # MfaError / MfaResult 错误类型
└── lib.rs            # 模块入口 (MfaType, MfaLevel 定义于此)
```

### kms-approval — 操作审批

**职责**：密钥操作审批工作流（创建、导出、删除等需要审批的操作）。

### kms-hsm — HSM 后端

**职责**：硬件安全模块集成（TPM 2.0 stub，待集成真实 TPM SDK）。

### kms-cli — CLI 工具

**职责**：命令行管理工具 (clap)，合规报告生成。

---

## 数据流

### 加密操作流程

```
Client → [gRPC/REST] → kms-api → auth.validate() 
       → check_permission() → check_pbac()
       → keystore.get_key() → kms-core.envelope.decrypt()
       → algorithm.encrypt() → keystore.audit() → audit.log()
       → response
```

### 密钥轮换流程

```
Scheduler → kms-core::Sm9RotationAdapter
          → generate_new_keys()
          → keystore.store(new_keys, status=PendingRotation)
          → for each DEK: rewrap_dek(old_kek → new_kek)
          → keystore.update(old_keys, status=Obsolete)
          → audit.log(rotation_complete)
```

### 审计日志流程

```
Handler → kms-audit::AuditLogger.log(event)
        → SignedAuditLogger.sign(event)
        → WormWriter.append(signed_entry)  ← JSONL 文件
        → (optional) TSA timestamp
        → (optional) Kafka stream
```

---

## 外部依赖

| 依赖 | 用途 | 版本 |
|------|------|------|
| axum | REST HTTP 框架 | 0.8 |
| tonic | gRPC 框架 | 0.14 |
| sqlx | PostgreSQL 驱动 | 0.8 |
| redis | Redis 客户端 | 0.26 |
| rand | CSPRNG | 0.10 |
| zeroize | 敏感数据清零 | latest |
| ring | 审计签名 (HMAC-SHA256) | 0.17 |
| rsa | RSA 互操作 (OAEP 加密侧) | 0.9 |
| gm workspace | SM2/SM3/SM4/SM9 国密 | local path |

---

## 安全设计原则

1. **纵深防御**：API 认证 → 权限检查 → PBAC 策略 → 操作审计（多层门控）
2. **最小权限**：每个 handler 仅检查必要权限（如 IMPORT_KEY ≠ CREATE_KEY）
3. **数据加密**：TOTP secret 和密钥材料使用 AES-256-GCM 信封加密
4. **不可篡改性**：审计日志 WORM + hash 链 + HMAC-SHA256 签名
5. **恒定时间**：密码原语采用 `conditional_select` + 被动去线性化
6. **内存安全**：敏感数据 zeroize-on-drop，支持 mlock，禁用核心转储
7. **默认安全**：TLS 生产模式强制 VerifyCa，仅开发模式可 Disabled
8. **隐私保护**：Zeroizing<String> 保护 API Key 明文内存
