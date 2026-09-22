# gm-kms

[![GitHub Release](https://img.shields.io/github/v/release/GM-Engineers/gm-kms?include_prereleases)](https://github.com/GM-Engineers/gm-kms/releases)

**[English Version](./README.en.md)**

> **项目定位**：gm-kms 是一个 **Rust 实现的国密 KMS 参考实现**，面向学习、内部演示、生态集成和小规模辅助场景。
> 它**不是**生产可用的 KMS，**不替代**商业云 KMS（阿里云 / 华为云 / 腾讯云 / AWS KMS），**未通过**密评或等保认证。
> 详见下方"本项目是什么 / 不是什么"。

## 本项目是什么

- **Rust 国密 KMS 参考实现**：完整覆盖 SM2 / SM3 / SM4 / SM9 算法、信封加密、密钥轮换、PBAC、MFA、WORM 审计、审批工作流等 KMS 核心模式
- **学习材料**：阅读代码即可理解"一个 KMS 在 Rust 里如何实现"，见 [LEARN.md](./LEARN.md)
- **gm workspace 生态集成示范**：`gm-crypto` + `gm-tls` + `gm-sm9-rs` + `gm-tlcp` + `gm-ca` 端到端可用样例
- **小规模内部 / 演示场景**：可启动的服务二进制，REST + gRPC 双 API

## 本项目不是什么

| 不声称的能力 | 原因 |
|---|---|
| 生产可用的 KMS | 无 SLA、无商业支持、版本 v0.x；密钥生命周期 / 高可用 / 容灾等生产特性未覆盖 |
| 商业 KMS 替代品 | 阿里云 KMS / 华为云 KMS / 腾讯云 KMS / AWS KMS 提供托管 HA、合规认证、审计血缘、托管 HSM 集成 |
| 通过密评的合规交付物 | 自评估 ≠ 第三方认证；TLCP 证书链验证未集成；SM9 主密钥默认在内存 |
| 金融 / 政务生产系统直接使用 | 同上；密评等强制认证场景需自行评估 |
| 多租户 SaaS 后端 | 商业支持能力不足 |

## 适用 / 不适用场景

| 场景 | 适用？ | 备注 |
|---|---|---|
| 学习 Rust KMS 实现 | 是 | 推荐从 [LEARN.md](./LEARN.md) 开始 |
| 国密合规 PoC / 内部演示 | 是 | 注意 TLCP 证书链验证缺失 |
| gm workspace 生态集成演示 | 是 | 完整 wire-up |
| 小规模内部工具链 KMS 后端 | 是 | 需自行评估安全边界 |
| Kubernetes 内部部署 | 部分 | 见 [examples/k8s-demo/](./examples/k8s-demo/README.md)（demo，非生产） |
| 替代阿里云 / 华为云 / 腾讯云 KMS | 否 | 见上表 |
| 密评交付物 | 否 | 见上表 |
| 金融 / 政务生产 KMS | 否 | 见上表 |

## 功能特性

| 类别 | 功能 |
|------|------|
| **国密算法** | SM2 签名/加密/密钥交换、SM3 哈希、SM4 对称加密、SM9 IBE 签名/加密 |
| **国际算法** | AES-256-GCM、Ed25519、ECDSA-P256/P384、RSA-4096 |
| **密钥管理** | 密钥生成、轮换、销毁、导入/导出 |
| **访问控制** | PBAC 策略引擎、MFA (TOTP)、审批工作流 |
| **审计日志** | WORM 存储、HashChain 防篡改、3年保留 |
| **后端存储** | PostgreSQL、Redis、软件 Keystore |
| **REST API** | TLS 1.3 + SM (gm-tls) 或 **TLCP (gm-tlcp)** 双 backend 可选 |
| **gRPC API** | TLS 1.3 + SM（暂不支持 TLCP，见已知限制） |

## 技术栈

- **语言**：Rust 1.85+ (Edition 2024)
- **异步**：tokio
- **Web**：axum 0.8, tonic 0.14
- **数据库**：PostgreSQL 16+, Redis 7+
- **加密**：ring, gm-crypto (SM2/SM3/SM4/SM9)
- **外部依赖**：gm-tls (TLS 1.3 + SM), gm-sm9-rs (SM9 双后端), gm-ca (CA 证书), gm-tlcp (TLCP, GB/T 38636-2020)

## 快速开始（学习 / 演示用）

```bash
# 1. 启动依赖服务
docker compose up -d
# 启动 PostgreSQL 和 Redis（不含 kms 服务本身）

# 2. 设置环境变量
cp -n .env.example .env || true
export DATABASE_URL="postgres://kms:kms123@localhost:5432/kms"
export KMS_KEK="<your-kek-hex-64>"

# 3. 构建与测试
cargo build --release
cargo test --workspace           # 998+ tests

# 4. 启动服务（默认 TLS 1.3 + SM）
cargo run --release -p kms -- --server

# 4b. 启动 REST over TLCP（需先准备双证书）
REST_TLS_BACKEND=tlcp \
REST_TLS_TLCP_SIGN_CERT_PATH=./certs/server-sign.crt \
REST_TLS_TLCP_ENC_CERT_PATH=./certs/server-enc.crt \
REST_TLS_TLCP_SIGN_KEY_PATH=./certs/server-sign.key.pem \
REST_TLS_TLCP_ENC_KEY_PATH=./certs/server-enc.key.pem \
cargo run --release -p kms -- --server
```

完整教程：
- [docs/guides/deployment-guide.md](./docs/guides/deployment-guide.md) — 通用部署
- [docs/guides/tlcp-deployment.md](./docs/guides/tlcp-deployment.md) — TLCP 模式部署
- [LEARN.md](./LEARN.md) — 代码导读（推荐入门）
- [examples/](./examples/) — 可运行示例

## 项目结构

```
gm-kms/
├── crates/                    # 核心 crate
│   ├── kms-core/              # 核心类型、算法抽象
│   ├── kms-keystore/          # 密钥存储后端
│   ├── kms-api/               # REST/gRPC API
│   ├── kms-policy/            # PBAC 策略引擎
│   ├── kms-audit/             # 审计日志
│   ├── kms-cli/               # 命令行工具
│   ├── kms-hsm/               # TPM 2.0 HSM 模拟（stub）
│   ├── kms-mfa/               # MFA/TOTP
│   ├── kms-approval/          # 审批工作流
├── src/                       # 二进制入口
│   ├── main.rs
│   └── cmd/
│       ├── server.rs          # REST + gRPC server
│       ├── config.rs          # 配置加载
│       ├── gm_listener.rs     # TLS 1.3 + SM axum listener
│       └── tlcp_listener.rs   # TLCP axum listener（本项目接入）
├── examples/                  # 可运行示例（含 k8s-demo）
├── docs/                      # 文档
│   ├── guides/                # 部署指南
│   ├── requirements/          # 功能需求文档
│   └── wiki/                  # 术语和技术词条
├── operators/                 # K8s Operator（Go, experimental）
├── providers/terraform/       # Terraform provider（experimental）
└── fuzz/                      # Fuzz 测试目标
```

## 合规自评估

| 标准 | 自评估 |
|---|---|
| GM/T 0002-2012 (SM4) | 已实现 (kms-core) |
| GM/T 0004-2012 (SM3) | 已实现 (gm-crypto) |
| GM/T 0003-2012 (SM2) | 已实现 (gm-crypto) |
| GM/T 0044-2016 (SM9) | 已实现（双后端交叉验证） |
| GB/T 38636-2020 (TLCP) | REST 已实现；gRPC 走 TLS 1.3+SM；证书链验证未集成（已知限制） |
| 等保 2.0 三级 | 部分能力；**未通过第三方密评认证** |

> **说明**：上表是作者团队基于代码的自评估，**不等于**通过国家密码管理局密评或等保认证。
> 任何合规交付均需第三方评估。

## 已知限制（本项目固有）

| 限制 | 影响 | 缓解 |
|---|---|---|
| gRPC over TLCP 未实现 | gRPC 走 TLS 1.3 + SM，非 TLCP 协议 | TLCP REST 已可用；未来版本补 gRPC |
| TLCP 证书链验证未集成 | TLCP 握手不验证对端 CA 链 | 仅信任对端字节；等 gm-tlcp 上游 `TlcpCertPair` 接 `cert_verify` |
| SM9 主密钥默认存内存 | 进程崩溃或内存转储可泄漏 | 生产部署应使用 HSM/TPM（kms-hsm 当前是 stub） |
| 无 bug bounty | 漏洞披露无激励 | 仍可通过 GitHub Security Advisory 报告 |
| 无商业支持 / SLA | 上游不承诺响应时间 | 适用场景见上表 |

## 测试统计（实测，截至 v0.3.0）

| Crate | 测试数 | 状态 |
|-------|--------|------|
| kms-core | 282 | passed |
| kms-api | 267 (+ 5 ignored) | passed |
| kms-policy | 28 | passed |
| kms-audit | 95 | passed |
| kms-hsm | 52 | passed |
| kms-mfa | 46 | passed |
| kms-approval | 16 | passed |
| kms-keystore | 86 (+ 13 ignored) | passed |
| kms-cli | 8 | passed |
| kms binary（含 tlcp_listener + config TLCP 测试） | 37 | passed |
| integration_tests / kat_vectors | 81 | passed |
| **合计** | **998 passed**（另 25 ignored） | |

## 第三方组件

本项目依赖以下外部/社区实现（署名与许可详情见 [NOTICE](./NOTICE)）：

- **SM2 / SM3 / SM4**（`gm-crypto`）：在社区 Rust crate `sm2` / `sm3` / `sm4` 之上构建，补齐 SM2 ZA / SM3 HMAC / SM4 GCM-CBC 等业务实现
- **SM9**（`gm-sm9-rs`）：[GmSSL](https://github.com/guanzhi/GmSSL)（Apache-2.0）的 Rust 移植，提供纯 Rust 与 GmSSL FFI 双后端
- **TLCP**（`gm-tlcp`）：GB/T 38636-2020 的纯 Rust 实现
- **gm-tls / gm-ca / gm-crypto / gm-sm9-rs / gm-tlcp**：均来自 [gm workspace](https://github.com/GM-Engineers/gm)，以 crates.io 依赖 + 根 `Cargo.toml` 的 `[patch.crates-io]` 锁定到同一 git rev

## 许可证

MIT OR Apache-2.0
