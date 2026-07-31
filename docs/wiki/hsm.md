# HSM（硬件安全模块） / Hardware Security Module

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Hardware Security Module |
| **类型 Type** | 专用硬件密码设备 / Dedicated hardware cryptographic device |
| **安全等级** | FIPS 140-2 Level 2 / 3（美国）、EAL 4+（国际）/ FIPS 140-2 Level 2/3, EAL 4+ |
| **核心特性** | 密钥材料从不以明文离开硬件 / Key material never leaves hardware in plaintext |
| **部署方式** | 网络连接（Network HSM）或 PCIe 卡（Internal HSM）/ Network or PCIe |


## 概述

HSM 是一种专门设计用于保护密钥和执行密码操作的物理设备。密钥原材料（Raw Keying Material）在物理层面无法被导出，密码操作在硬件内部完成，仅返回结果。

```
软件系统 ──▶ HSM API ──▶ 密码操作在 HSM 内部执行
                                  │
                              密钥仅在此
                           （物理隔离，不可导出）
```

## 安全特性

| 特性 | 说明 |
|------|------|
| **防篡改** | 物理拆解触发密钥擦除（Tamper Detection & Response） |
| **密钥不可导出** | 私钥无法以明文形式离开 HSM |
| **防侧信道** | 硬件级时序和功耗分析防护 |
| **FIPS 140-2 认证** | 密码模块安全认证（共 4 个等级） |
| **物理隔离** | 独立的密码处理环境 |

## FIPS 140-2 安全等级

| 等级 | 要求 | 典型场景 |
|------|------|----------|
| **Level 1** | 基本要求，CSP 以加密形式存储 | 软件级标准 |
| **Level 2** | 角色分离、操作日志、防篡改证据 | 商业应用 |
| **Level 3** | 物理防拆、基于输入的密钥擦除 | 金融、政府 |
| **Level 4** | 物理安全最高，环境中所有物理攻击防护 | 极高安全军事场景 |

## HSM 类型 / HSM Types

### 按部署方式 / By Deployment

| 类型 Type | 连接方式 Connection | 代表产品 Products |
|---------|-------------------|-----------------|
| **Network HSM** | 网络（TCP/IP），多台服务器共享 / Network, shared by multiple servers | Thales Luna HSM、AWS CloudHSM、Azure Dedicated HSM |
| **PCIe HSM** | 直插服务器主板 / Plugged into server motherboard | Thales nShield、Utimaco SecureGuard |
| **USB HSM** | USB 连接（小型，高便携）/ USB-connected | YubiHSM（Solo/Solo/SecurNet） |
| **Cloud HSM** | 云服务商托管 / Cloud provider managed | AWS CloudHSM、GCP Cloud HSM、Azure Key Vault HSM |

### 按用途 / By Purpose

| 类型 Type | 说明 Description |
|---------|----------------|
| **PKI HSM** | CA 证书签发、CRL 签名 / CA cert signing, CRL signing |
| **Code Signing HSM** | 软件代码签名（Adobe、Microsoft 代码签名）/ Software code signing |
| **Payment HSM** | 支付卡交易密钥（如银联 PIN 验证）/ Payment card transaction keys |
| **Document Signing HSM** | 法律文档数字签名 / Legal document digital signing |


## 主流 HSM 产品

| 厂商 | 产品 | 认证等级 | 接口 |
|------|------|----------|------|
| **Thales Luna** | Luna Network HSM 7 / PCIe | FIPS 140-2 L3 | PKCS#11, REST API, Microsoft CNG |
| **Utimaco** | CryptoServer Se / Gen2 | FIPS 140-2 L3 | PKCS#11, REST API |
| **AWS** | CloudHSM | FIPS 140-2 L3 | PKCS#11, OpenSSL, JCE |
| **Azure** | Dedicated HSM | FIPS 140-2 L3 | PKCS#11, REST API |
| **GCP** | Cloud HSM | FIPS 140-2 L3 | PKCS#11, REST API |
| **Yubico** | YubiHSM 2 | FIPS 140-2 L3 | YubiHSM SDK, PKCS#11 |
| **Google** | Titan HSM | FIPS 140-2 L3 | 云内嵌使用 |

## API 接口 / API Interfaces

| 接口 Interface | 说明 Description |
|--------------|----------------|
| **PKCS#11** | 最通用，跨厂商标准接口（Citrix、Firefox 等支持）/ Most common, cross-vendor standard |
| **Microsoft CNG** | Windows 原生密钥存储接口 / Windows native key storage interface |
| **Java JCE** | Java 平台的密码服务接口 / Java cryptography service interface |
| **REST API** | 现代云 HSM 提供 HTTP API / Modern cloud HSMs provide HTTP API |
| **OpenSSL Engine** | OpenSSL 扩展集成 / OpenSSL extension integration |
| **proprietary** | 厂商私有接口（如 Thales REST API）/ Vendor-specific interfaces |


## HSM 在 KMS 中的角色

```
KMS 架构中的 HSM：

路径A — HSM 作为密钥存储：
  密钥材料 ──▶ HSM 生成 ──▶ HSM 存储（永不离开）
  加密操作 ──▶ 发送到 HSM ──▶ HSM 返回结果

路径B — HSM 作为主密钥保护：
  数据加密密钥（DEK）存软件
  DEK 的加密密钥（KEK）由 HSM 保护

路径C — Vault + HSM：
  Vault 控制平面 + 审计
  HSM 作为 seal 设备（密钥包装）
```

## 采购与维护成本 / Cost Overview

| 成本项 Cost Item | 范围 Range |
|---------------|----------|
| 设备采购 / Hardware | 硬件 HSM 3万~50万元/台 / ~$4K-$70K per unit |
| 云 HSM / Cloud HSM | 按小时或按操作计费（AWS CloudHSM ~$1.45/小时起）/ Per-hour or per-operation (AWS CloudHSM ~$1.45/hr) |
| 年维护费 / Annual Maintenance | 采购价的 10%~20%/年 / 10%-20% of purchase price per year |
| FIPS 认证更新 / FIPS Recertification | 特定版本需重新认证 / Specific versions require re-certification |


## HSM 选型考虑因素

| 因素 | 说明 |
|------|------|
| **安全等级** | L2 还是 L3，取决于合规要求 |
| **接口类型** | PKCS#11 支持是基本要求 |
| **性能** | TPS（每秒交易数），影响吞吐上限 |
| **高可用** | 集群模式，支持故障转移 |
| **合规模式** | PCI-DSS、FIPS 140-2、SOC 2 |
| **云兼容** | 是否需要同时支持本地和云 HSM |
| **供应商锁定** | 是否依赖厂商私有 API |
