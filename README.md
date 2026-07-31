# gm-kms

国密密钥管理系统 (Key Management System)，支持 GM/T 标准算法（SM2/SM3/SM4/SM9）。

## 功能特性

| 类别 | 功能 |
|------|------|
| **国密算法** | SM2 签名/加密/密钥交换、SM3 哈希、SM4 对称加密、SM9 IBE 签名/加密 |
| **国际算法** | AES-256-GCM、Ed25519、ECDSA-P256/P384、RSA-4096 |
| **密钥管理** | 密钥生成、轮换、销毁、导入/导出 |
| **访问控制** | PBAC 策略引擎、MFA (TOTP)、审批工作流 |
| **审计日志** | WORM 存储、HashChain 防篡改、3年保留 |
| **后端存储** | PostgreSQL、Redis、软件 Keystore |
| **传输安全** | REST API (axum、国密 TLS TLCP/GB/T 38636)、gRPC (tonic)、gRPC TLCP |

## 技术栈

- **语言**: Rust 1.85+ (Edition 2024)
- **异步**: tokio
- **Web**: axum 0.8, tonic 0.14
- **数据库**: PostgreSQL 16+, Redis 7+
- **加密**: ring, gm-crypto (SM2/SM3/SM4/SM9)
- **外部依赖**: gm-tls (TLCP 传输加密), gm-sm9-rs (SM9 双后端), gm-ca (CA 证书)

## 前提条件

- **Rust 1.85+**（Edition 2024）
- **GmSSL 3.1.1** 系统库（SM9 双后端所需）
  ```bash
  git clone --depth 1 --branch v3.1.1 https://github.com/guanzhi/GmSSL.git
  cd GmSSL && mkdir build && cd build
  cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON
  make -j$(nproc) && sudo make install && sudo ldconfig
  ```
- **PostgreSQL 16+** 和 **Redis 7+**（用于生产部署）
- 如无需 GmSSL，可使用纯 Rust 后端：`--features pure-rust`

## 快速开始

### 1. 启动依赖服务

```bash
docker compose up -d
# 启动 PostgreSQL 和 Redis（不含 kms 服务本身）
```

### 2. 设置环境变量

```bash
# 复制环境变量模板
cp -n .env.example .env || true
# 已内置测试密钥，生产部署需替换
export DATABASE_URL="postgres://kms:kms123@localhost:5432/kms"
export KMS_KEK="<your-kek-hex-64>"
```

### 3. 构建与测试

```bash
# 构建
cargo build --release

# 运行所有测试
cargo test --workspace

# 运行特定 crate 测试
cargo test -p kms-core
cargo test -p kms-api

# 完整 CI 检查 (format → clippy → build → test)
make check
```

### 4. 启动服务

```bash
# 方式一：直接运行
cargo run --release -p kms -- --server

# 方式二：Docker 容器（含 GmSSL）
docker build -t gm-kms .
docker run -d --name kms --network host \
  -e DATABASE_URL="postgres://kms:kms123@localhost:5432/kms" \
  -e KMS_KEK="<your-kek-hex-64>" \
  gm-kms --server
```

### 5. 开发辅助命令

```bash
# 一键 CI 检查（fmt + clippy + build + test）
make check

# 生成 SBOM（CycloneDX JSON + XML）
make sbom

# 安全扫描（需本地 Docker）
make zap-baseline       # OWASP ZAP 被动扫描
make zap-api-scan       # ZAP 主动扫描

# 合规报告
make report-crypto      # 加密配置报告
make report-compliance  # DJCP 三级自评估报告
```

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
│   ├── kms-hsm/               # TPM 2.0 HSM 模拟
│   ├── kms-mfa/               # MFA/TOTP
│   ├── kms-approval/          # 审批工作流
├── operators/                 # Kubernetes Operator
├── docs/                      # 文档
│   ├── compliance/            # 合规性检查清单、整改计划
│   ├── guides/                # 部署指南
│   ├── requirements/          # 功能需求文档
│   └── wiki/                  # 术语和技术词条
├── examples/                  # 示例代码
└── providers/terraform/       # Terraform provider
├── Makefile                   # 开发辅助命令
├── docker-compose.yml         # PostgreSQL + Redis 依赖服务
├── Dockerfile                 # 生产容器镜像（含 GmSSL）
```

## 文档

- [部署指南](docs/guides/deployment-guide.md)
- [合规性检查清单](docs/compliance/checklist.md)
- [需求文档索引](docs/requirements/README.md)
- [术语百科](docs/wiki/gmt-index.md)
- [GM/T 标准索引](docs/wiki/gmt-standards.md)

## 合规性

| 标准 | 状态 |
|------|------|
| GM/T 0002-2012 (SM4) | ✅ |
| GM/T 0004-2012 (SM3) | ✅ |
| GM/T 0003-2012 (SM2) | ✅ |
| GM/T 0044-2016 (SM9) | ✅ (GmSSL + 纯 Rust 双后端) |
| GB/T 38636-2020 (TLCP) | ✅ (gm-tls, REST + gRPC) |
| 等保 2.0 三级 | ✅ (部分) |

> **SM9 后端**: 默认使用 GmSSL 3.1.1 实现 GM/T 0044-2016 标准曲线参数和 SM3 哈希。同时提供纯 Rust 后端（`pure-rust` feature），双后端通过交叉验证确保正确性。

> **SM9**: `gm-sm9-rs` crate 位于 [gm workspace](https://github.com/GM-Engineers/gm)（`gm-crypto`、`gm-tls`、`gm-ca` 同属该 workspace）

## 测试统计

| Crate | 测试数 | 状态 |
|-------|--------|------|
| kms-core | 278 | ✅ |
| kms-policy | 28 | ✅ |
| kms-audit | 95 | ✅ |
| kms-hsm | 52 | ✅ |
| kms-mfa | 45 | ✅ |
| kms-approval | 16 | ✅ |
| kms-keystore | 87 + 6 benchmark | ✅ |
| kms-cli | 8 | ✅ |
| kms-api | 261 | ✅ |
| integration/KAT | 81 | ✅ |
| **总计** | **958 + 6 benchmark** | **全部通过** |

> 注: 6 个 benchmark 测试默认忽略，可通过 `cargo test -- --ignored` 运行

## 第三方组件

本项目依赖以下外部/社区实现（署名与许可详情见 [NOTICE](./NOTICE)）：

- **SM2 / SM3 / SM4**（`gm-crypto`）：对社区 Rust crate `sm2` / `sm3` / `sm4` 的轻量封装，并非从零自研。
- **SM9**（`gm-sm9-rs`）：[GmSSL](https://github.com/guanzhi/GmSSL)（Apache-2.0）的 Rust 移植。
- **gm-tls / gm-ca / gm-crypto**：来自 [gm workspace](https://github.com/GM-Engineers/gm)。

## 许可证

MIT OR Apache-2.0
