# gm-kms 代码导读

> **目标读者**：想学习"如何在 Rust 里实现一个 KMS"的人。
> **阅读顺序**：从下到下，编号递增。每一步都给出"哪个文件 + 哪个关键函数 + 一段话解释"。
> **配套**：每个节点指向可运行的测试。

本导读覆盖约 6000 行核心代码。建议配合 [`ARCHITECTURE.md`](./ARCHITECTURE.md) 阅读：本文是"先读哪段代码"，ARCHITECTURE.md 是"模块依赖图与数据流"。

---

## 0. 起点：协议与密码学基础

如果你对国密算法不熟，先看 [docs/wiki/gmt-index.md](./docs/wiki/gmt-index.md)。如果你想直接看 TLCP（GB/T 38636-2020）握手流程，先看 [docs/wiki/tlcp.md](./docs/wiki/tlcp.md)。

---

## 1. 信封加密（DEK/KEK 模式）

**位置**：`crates/kms-core/src/envelope.rs`
**关键函数**：`EnvelopeCipher::seal`、`EnvelopeCipher::open`、`rewrap`
**测试**：`cargo test -p kms-core envelope`

信封加密是 KMS 的核心抽象：**不直接用主密钥加密业务数据**，而是每次数据加密生成一个随机 DEK（数据加密密钥），用主密钥 KEK（密钥加密密钥）把 DEK 加密后随密文一起存。解密时先用 KEK 解开 DEK，再用 DEK 解密。

gm-kms 实现：
- DEK 加密：SM4-GCM 或 AES-256-GCM
- KEK 加密（如嵌套）：同样 AES-256-GCM
- `rewrap(old_kek, new_kek)`：当 KEK 轮换时，只重包 DEK，不动业务数据

**为什么先看这个**：所有密钥操作（创建、轮换、销毁）都建立在信封加密之上。

---

## 2. 密钥类型与生命周期

**位置**：`crates/kms-core/src/key.rs`
**关键函数**：`KeySpec` enum、`KeyStatus` 状态机
**测试**：`cargo test -p kms-core key`

定义所有支持的密钥类型（SM2/SM4/SM9/AES/Ed25519...）和它们的状态机（`Active` → `PendingRotation` → `Rotated` → `Obsolete` → `Destroyed`）。状态机转换有审计事件和 PBAC 检查。

---

## 3. 密钥轮换

**位置**：`crates/kms-core/src/secret_rotation.rs`
**关键函数**：`RotationScheduler`、`rotate_dek`
**测试**：`cargo test -p kms-core secret_rotation`

轮换有两种粒度：
- **密钥版本轮换**：同一个 key id 下生成新版本，旧版本降级为 `Obsolete` 但保留解密能力
- **KEK 轮换**：见上面信封加密的 `rewrap`

阅读顺序：先看 `secret_rotation.rs` 的状态机，再看 `crates/kms-api/src/rotation.rs` 暴露的 REST/gRPC handler。

---

## 4. SM9 主密钥管理

**位置**：`crates/kms-core/src/sm9_master_key.rs` + `crates/kms-core/src/sm9_key_rotation.rs`
**测试**：`cargo test -p kms-core sm9_master_key`、`sm9_key_rotation`

SM9 是基于身份的密码学（IBE），需要一个 KGC（Key Generation Center）主密钥对。私钥派生时直接用身份（如邮箱、手机号）作为公钥。

gm-kms 的实现：
- KGC 主密钥支持两种存储：纯内存（开发用）、AES-256-GCM 加密后存 PostgreSQL（带 KEK）
- 密钥轮换：`Sm9RotationAdapter` 把 gm-sm9-rs 的轮换逻辑桥接到 gm-kms 的状态机
- 双后端交叉验证：纯 Rust 和 GmSSL FFI 两个实现 KAT 比对

**为什么独立成一节**：SM9 在其他 KMS 项目里很少见，是 gm-kms 的特色。

---

## 5. WORM 审计 + Hash Chain

**位置**：`crates/kms-audit/src/worm_writer.rs` + `logger.rs`
**关键函数**：`WormWriter::append`、`SignedAuditLogger::sign`
**测试**：`cargo test -p kms-audit`

WORM（Write-Once-Read-Many）是审计日志的"不可篡改"实现：
- 文件用 append-only 模式打开（OS 层 `O_APPEND`）
- 每条记录包含 `prev_hash = sha256(上一条)`，构成 hash chain
- 每条记录用 HMAC-SHA256 签名，启动时校验整条链
- 可选 TSA（RFC 3161 时间戳）和 Kafka 流式推送

**为什么单独提**：合规审计的难点不在"记录事件"，而在"事后能证明记录没被改"。hash chain + 签名 + TSA 一起才能做到。

---

## 6. PBAC 策略引擎

**位置**：`crates/kms-policy/src/engine.rs`
**关键函数**：`PBACEngine::evaluate`
**测试**：`cargo test -p kms-policy`

PBAC（Policy-Based Access Control）：每个操作（key:read、key:export、sm9:sign...）用一组属性（用户角色、租户、密钥状态、IP...）匹配策略。

gm-kms 实现很轻量：策略就是一组 `if subject.action matches resource.condition then allow` 规则，没有 Rego 之类的 DSL。想要更复杂的可以替换这部分。

---

## 7. MFA（TOTP）

**位置**：`crates/kms-mfa/src/totp.rs`
**关键函数**：`TotpGenerator::generate`、`verify`
**测试**：`cargo test -p kms-mfa`

RFC 6238 TOTP，支持 SHA1/SHA256/SHA512。gm-kms 在敏感操作（如密钥导出、删除）前要求 MFA 二次验证。

TOTP secret 用 KEK 信封加密后存 PostgreSQL，永不明文落盘。

---

## 8. 审批工作流（双人控制）

**位置**：`crates/kms-api/src/approval.rs`
**关键函数**：`ApprovalManager::create`、`approve`
**测试**：`cargo test -p kms-approval` + `cargo test -p kms-api approval`

敏感操作（密钥导出、删除）需要走审批工作流：
1. 申请人创建 `ApprovalRequest`，指定 quorum 数（如 3-of-5）
2. 多位审批人依次 approve
3. 达到 quorum 后，申请人带着 `approval_id` 调用实际 API

实现见 GM/T 0028-2014 §双人控制（dual custody）原则。

---

## 9. REST + gRPC 入口

### REST

**位置**：`crates/kms-api/src/rest.rs`
**关键函数**：`create_routes`
**测试**：`cargo test -p kms-api rest`

38 个 handler，路由在 `create_routes` 函数里。模式：
1. 从 extractor 取 `KmsState`（共享状态）
2. 取 `CallerId`（API key 解析后的身份）
3. 调用 `check_rest_pbac(...)` 做权限检查
4. 调业务函数
5. 记录审计事件

### gRPC

**位置**：`crates/kms-api/src/grpc.rs`
**关键函数**：`KmsGrpcService::create_key` 等
**测试**：`cargo test -p kms-api grpc`

21 个 RPC，proto 定义在 `crates/kms-api/proto/kms.proto`。gRPC handler 与 REST 共用同一组业务函数，只是请求/响应类型不同。

### TLS / TLCP listener

**位置**：
- `src/cmd/gm_listener.rs` — TLS 1.3 + SM (RFC 8446 + SM ciphers)
- `src/cmd/tlcp_listener.rs` — TLCP (GB/T 38636-2020)

两个 listener 都实现 `axum::serve::Listener`，只是底层 acceptor 不同：
- `gm_listener.rs`：`tokio::net::TcpListener` + `gm_tls::TlsAcceptor`
- `tlcp_listener.rs`：`tokio::net::TcpListener` + `gm_tlcp::TlcpAcceptor`

**对比读**：这两个文件是 TLCP 与 TLS 1.3 接入的最短路径样本，约 80 行每个。

---

## 10. 传输层协议（TLCP vs TLS 1.3 + SM）

**位置**：
- 客户端：[`../gm/gm-tlcp/examples/simple_client.rs`](../gm/gm-tlcp/examples/simple_client.rs)
- 服务端：[`../gm/gm-tlcp/examples/simple_server.rs`](../gm/gm-tlcp/examples/simple_server.rs)

TLCP 是国密合规的传输层协议（GB/T 38636-2020），与 TLS 1.3 协议层不兼容：

| 维度 | TLS 1.3 | TLCP |
|---|---|---|
| 版本字节 | `0x03, 0x03` | `0x01, 0x01` |
| 证书 | 单证 | 双证（sign + enc） |
| 密钥交换 | key_share 扩展 | ServerKeyExchange（TLS 1.2 风） |
| 密码套件 ID | `0x13xx` | `0xE0xx` |
| ALPN | 支持 | 不支持（这就是 gRPC over TLCP 难做的根因） |

如果只想看 TLCP 握手怎么实现，直接读 `gm-tlcp/src/tlcp/mod.rs:1530-1820`（`TlcpAcceptor::accept_with_certs`）。

---

## 11. 完整调用链示例：一次"加密 1KB 数据"

1. 客户端 `POST /v1/keys/{id}/encrypt` （`crates/kms-api/src/rest.rs`）
2. handler 通过 `KmsState` 取 keystore、`auth.rs` 校验 API key、`pbac.rs` 校验权限
3. `kms-core/src/algorithms_impl.rs::Sm4Cipher::encrypt` 实际加密
4. 审计事件 `Encryption` 写入 `kms-audit/src/logger.rs::SignedAuditLogger::log`
5. WORM writer 追加一条记录（`worm_writer.rs`）+ 更新 hash chain
6. 返回 ciphertext 给客户端

调用栈深度大约 8-10 层，每一层都有对应的测试。

---

## 推荐阅读顺序（精简版）

如果时间有限，按这个顺序读：

1. `crates/kms-core/src/envelope.rs` （信封加密）
2. `crates/kms-core/src/key.rs` （密钥状态机）
3. `crates/kms-audit/src/logger.rs` （WORM + 签名）
4. `crates/kms-policy/src/engine.rs` （PBAC）
5. `crates/kms-api/src/rest.rs::create_routes` 和几个 handler （请求处理）
6. `src/cmd/gm_listener.rs` 和 `src/cmd/tlcp_listener.rs` （TLS/TLCP 接入）

这 6 个文件加起来约 2500 行，能让你理解 gm-kms 70% 的设计。

---

## 不在本文导读范围（需要时再查）

- 密钥存储后端（PostgreSQL / Redis / 软件 Keystore）— 看 `crates/kms-keystore/`
- WORM 验证器（启动时校验 hash chain）— `crates/kms-audit/src/verifier.rs`
- 速率限制、租户配额 — `crates/kms-api/src/ratelimit.rs`、`quota.rs`
- Backups — `crates/kms-core/src/backup.rs`
- KAT 自检（GB/T 37092-2018）— `crates/kms-core/src/self_test.rs`
- fuzzer — `fuzz/fuzz_targets/`
