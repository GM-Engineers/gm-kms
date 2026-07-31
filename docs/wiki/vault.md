# HashiCorp Vault（密钥管理平台） / HashiCorp Vault

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | HashiCorp Vault |
| **类型 Type** | 企业级密钥管理和秘密管理平台 / Enterprise key management and secrets management platform |
| **开发公司** | HashiCorp |
| **开源协议** | BSL（商业源代码可用）/ BSL (Business Source License) |
| **部署方式** | 二进制、Kubernetes、Vault Enterprise / Binary, Kubernetes, Vault Enterprise |


## 概述

Vault 是 HashiCorp 开发的企业级密钥管理平台，提供了安全的秘密存储、加密服务、访问控制等功能。它支持多种存储后端（Raft、Consul、etcd 等），并提供丰富的身份认证方式和策略控制。

```
Vault 架构：

┌─────────────────────────────────────────────────────────┐
│                      Vault Core                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │ Auth Methods│  │ Secret      │  │ Policy      │   │
│  │ (Kubernetes,│  │ Engines     │  │ Engine      │   │
│  │  AppRole,   │  │ (KV, Transit,│  │ (RBAC)      │   │
│  │  OIDC, ...) │  │  Database,...)│              │   │
│  └─────────────┘  └─────────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────┘
           │                │                │
           ▼                ▼                ▼
┌─────────────────────────────────────────────────────────┐
│                  Storage Backend                         │
│            (Raft, Consul, etcd, 云存储)                  │
└─────────────────────────────────────────────────────────┘
```

## 核心功能 / Core Features

### 1. Secret Engine（秘密引擎） / Secret Engines

| 引擎 Engine | 说明 Description |
|-----------|----------------|
| **KV Engine** | 键值对秘密存储（v1/v2 版本）/ Key-value secrets storage (v1/v2) |
| **Transit Engine** | 传输加密（DEK 加密、自动轮换）/ Transit encryption (DEK encryption, auto-rotation) |
| **Database Engine** | 动态数据库凭证生成 / Dynamic database credential generation |
| **PKI Engine** | 证书颁发和管理（ACME 支持）/ Certificate issuance and management (ACME support) |
| **SSH Engine** | SSH 证书签发 / SSH certificate signing |
| **Transform Engine** | 数据加密（格式保留加密）/ Data encryption (format-preserving encryption) |

### 2. Auth Method（认证方式） / Authentication Methods

| 方式 Method | 说明 Description |
|---------|----------------|
| **Token** | 静态 Token 认证 / Static token auth |
| **AppRole** | 应用角色认证（机器对机器）/ App role auth (machine-to-machine) |
| **Kubernetes** | K8s Service Account 认证 / K8s Service Account auth |
| **JWT/OIDC** | JWT Token 认证 / JWT token auth |
| **LDAP** | 企业 LDAP/AD 认证 / Enterprise LDAP/AD auth |
| **Userpass** | 用户名密码认证 / Username/password auth |


### 3. Transit Engine（传输加密）

Transit Engine 提供服务器端的加密操作，DEK 不会以明文形式返回：

```
# Transit Engine CLI 示例
$ vault write transit/encrypt/my-key plaintext=$(echo "secret" | base64)

# 返回：
# key_id: <key-version-id>
# ciphertext: vault:v1:<encrypted-data>

# 解密
$ vault write transit/decrypt/my-key ciphertext="vault:v1:<encrypted-data>"
```

### 4. Dynamic Secrets（动态秘密）

Vault 可以按需生成临时凭证，避免静态凭证的风险：

```
# 动态数据库凭证
$ vault read database/creds/my-role
# 输出：
# Key                Value
# lease_id           database/creds/my-role/xyz
# lease_duration      1h
# username           v-token-my-role-xyz
# password           A1a-xxxxxxxxxx

# 凭证自动撤销（TTL 过期后）
```

## 在 KMS 架构中的角色

```
┌─────────────────────────────────────────────────────┐
│                    KMS 架构                          │
│                                                      │
│  ┌────────────┐      ┌────────────┐      ┌────────┐ │
│  │   应用      │ ──▶ │   KMS API  │ ──▶  │ Vault  │ │
│  └────────────┘      └──────┬─────┘      └───┬────┘ │
│                             │                  │     │
│                        ┌────▼────┐        ┌───▼────┐│
│                        │ Policy  │        │  HSM   ││
│                        │ Engine  │        │ (seal) ││
│                        └─────────┘        └────────┘│
└─────────────────────────────────────────────────────┘
```

| 角色 | 说明 |
|------|------|
| **密钥存储** | Vault 作为 KEK 存储（Seal Wrap / HSM） |
| **Secret 管理** | 数据库密码、API Key 等动态秘密 |
| **Transit 加密** | 提供加密/解密 API（应用不接触密钥） |
| **审计日志** | 内置审计日志（file/consul/kafka） |
| **多租户** | Namespace 隔离租户数据 |

## 高可用部署

```
                    ┌─────────────────┐
                    │   Load Balancer  │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼────┐        ┌────▼────┐        ┌────▼────┐
    │ Vault 1 │        │ Vault 2 │        │ Vault 3 │
    │ (Leader)│◄───────►│ (Follow)│◄───────►│ (Follow)│
    └────┬────┘        └────┬────┘        └────┬────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             │
                    ┌────────▼────────┐
                    │  HA Storage     │
                    │  (Raft/Consul)  │
                    └─────────────────┘
```

Vault 使用 Raft 共识算法实现高可用，数据存储在多个节点中。

## 与 KMS 的集成模式

| 模式 | 说明 | 适用场景 |
|------|------|----------|
| **Vault 独立** | Vault 自带密钥管理 | 轻量级 KMS |
| **Vault + HSM** | Vault 作为控制平面，HSM 保护根密钥 | 高安全要求 |
| **KMS 封装 Vault** | KMS 提供高级接口，Vault 作为实现 | 自建 KMS |
| **Vault 作为后端** | Vault Transit Engine 作为加密服务 | 企业内部 |

## 成本估算

| 版本 | 说明 | 成本 |
|------|------|------|
| **Open Source** | 基础功能 | 免费 |
| **Plus（试用）** | 试用版本 | 免费（21天） |
| **Enterprise** | 高可用、监控、策略 | 按节点/年收费 | 咨询 HashiCorp |
| **HCP Vault** | 云托管版本 | 按使用量计费 |

## 局限性 / Limitations

| 局限 Limitation | 说明 Description | 替代方案 Alternative |
|-------------|----------------|--------------------|
| **密钥层级** / Key Hierarchy | 不支持多层密钥派生 / No multi-layer key derivation | 配合 KMS / Combine with KMS |
| **国密算法** / GM Algorithms | 不支持 SM2/SM3/SM4 / SM2/SM3/SM4 not supported | 自研或国产化 Vault / Custom or domestic Vault |
| **后量子** / Post-quantum | 无后量子加密支持 / No post-quantum encryption | 扩展或自研 / Extend or custom develop |
| **KMS 完整功能** / Full KMS Features | 非完整 KMS / Not a full KMS | 基于 Vault 构建完整 KMS / Build full KMS on Vault |


## 参考资料

- [Vault 官方文档](https://developer.hashicorp.com/vault/docs)
- [Vault API 文档](https://developer.hashicorp.com/vault/api-docs)
- [Transit Engine](https://developer.hashicorp.com/vault/docs/secrets/transit)