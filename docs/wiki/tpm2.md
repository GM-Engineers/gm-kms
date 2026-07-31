# TPM 2.0（可信平台模块） / Trusted Platform Module 2.0

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Trusted Platform Module |
| **版本** | TPM 2.0（2015 年发布，2019 年 ISO/IEC 标准）/ TPM 2.0 (published 2015, ISO/IEC standard 2019) |
| **类型 Type** | 集成于主板的硬件安全芯片（或固件实现）/ Security chip on motherboard (or firmware implementation) |
| **安全等级** | FIPS 140-2 L1（部分实现）/ EAL 4+ |
| **标准** | ISO/IEC 11889, TCG TPM Spec 2.0 |
| **发布机构** | TCG（可信计算组织）/ TCG (Trusted Computing Group) |


## 概述

TPM 是一种安放在计算设备主板上的安全微控制器，提供安全的密钥存储、密码学和完整性测量功能。与 HSM 不同，TPM 是设备级集成芯片，而非独立的网络设备。

```
                  ┌─────────────┐
  CPU/Motherboard ─│   TPM 2.0  │── SPI/I2C 总线
                  │  (芯片)     │
                  └─────────────┘
                    │
              专用加密处理器
              密钥存储（非易失性 NVRAM）
              随机数生成（DRNG）
```

## TPM 1.2 vs TPM 2.0 差异 / TPM 1.2 vs TPM 2.0 Differences

| 特性 Feature | TPM 1.2 | TPM 2.0 |
|-------------|---------|---------|
| **算法支持** / Algorithm Support | 仅 RSA-2048、SHA-1 / RSA-2048, SHA-1 only | RSA-2048、ECC（P-256）、SM2/3/4、ECC、HMAC、AES |
| **密钥存储** / Key Storage | 固定 hierarchy / Fixed hierarchy | 灵活 hierarchy（owner hierarchy 可清除）/ Flexible hierarchy |
| **授权** / Authorization | 仅 owner password / Owner password only | 多因素授权（PCR、policy、password 组合）/ Multi-factor auth (PCR, policy, password) |
| **平台品牌** / Platform Brand | 单OEM/品牌 / Single OEM/brand | 中立标准，跨厂商 / Neutral standard, cross-vendor |
| **标准机构** / Standard Body | TCG 1.2 | ISO/IEC 11889（国际标准）/ ISO/IEC 11889 (international) |
| **易失性** / Volatility | 固定 / Fixed | 授权 policy 可变 / Authorization policy variable |


## TPM 架构层次

```
Platform Layer（平台层）
  └── CRTM（BIOS 测量根）
        └── TPM 芯片

Hierarchy（密钥层次）
  ├── Platform Hierarchy（平台层）— 出厂锁定
  ├── Storage Hierarchy（存储层）— 主种子
  ├── Endorsement Hierarchy（认可层）— TPM 身份证明
  └── Owner Hierarchy（所有者层）— 用户主导入

Keys & Objects
  ├── Primary Keys（主密钥，派生自种子）
  └── Ordinary Keys（普通密钥）
```

## TPM 2.0 核心功能

### 1. 密钥存储（Key Storage）

| 功能 | 说明 |
|------|------|
| **Endorsement Key（EK）** | TPM 出厂时内置的唯一 RSA 公钥，用于 TPM 身份证明 |
| **Storage Root Key（SRK）** | 存储层次根密钥，用于加密用户密钥 |
| **密钥不可导出** | 私钥在 TPM 内部生成，永不离开 TPM |
| **NVRAM** | 非易失性存储，持久保存密钥 |

### 2. 认可和证明（Attestation）

| 功能 | 说明 |
|------|------|
| **PCR（平台配置寄存器）** | 保存平台启动度量的哈希（BIOS、Loader、OS） |
| **AIK（Attestation Identity Key）** | 用于证明平台状态的签名密钥 |
| **Quote** | TPM 返回的 PCR 值签名，证明平台未被篡改 |
| **Remote Attestation** | 远程验证系统启动完整性（Intel TXT / AMD SKINIT） |

### 3. 密钥派生和绑定

| 功能 | 说明 |
|------|------|
| **Primary Key 派生** | 通过 KDF（密钥派生函数）从种子生成 |
| **Sealing** | 将数据绑定到特定平台状态（PCR 值） |
| **Binding** | 将数据绑定到特定 TPM 身份 |
| **Unseal** | 仅在平台状态匹配时解密数据 |

### 4. 密码操作

| 操作 | 说明 |
|------|------|
| **签名/验签** | RSA-2048、ECDSA P-256 |
| **加密/解密** | RSA-OAEP、RSA-PKCS#1 v1.5 |
| **哈希/HMAC** | SHA-1、SHA-256、SM3 |
| **随机数生成** | 硬件 DRNG（确定性随机数生成器） |

## TPM 在 KMS 中的应用

### 场景 1：系统启动密钥保护

```
BitLocker / Full Disk Encryption
  └── 磁盘加密密钥（DEK）
        └── 由 TPM Sealed Key 保护
              └── 仅在 PCR 值匹配时 Unseal
```

### 场景 2：SRK 作为 KMS 子密钥根

| 方案 | 说明 |
|------|------|
| **TPM 作为 KMS Seal Device** | KMS 主密钥（Master Key）密封到 TPM |
| **软件 Vault + TPM** | Vault 审计和策略，TPM 保护密钥根 |
| **TPM Only** | 极简场景，轻量 KMS 直接用 TPM 存储 |

### 场景 3：Platform Attestation（平台认证）

- 密钥访问需要 TPM Quote 证明当前平台未被篡改
- 用于零信任架构的设备身份验证
- 结合 TPM 报告的 PCR 值动态授权

## TPM vs HSM 对比 / HSM Comparison

| 对比项 Comparison | TPM 2.0 | HSM（Network/PCIe） |
|-----------------|---------|---------------------|
| **部署** / Deployment | 主板集成（设备级）/ On-motherboard (device-level) | 独立网络设备/PCIe 卡 / Standalone network/PCIe card |
| **性能** / Performance | 中低（受限于芯片性能）/ Medium-low | 高（专用密码 ASIC）/ High (dedicated crypto ASIC) |
| **密钥数量** / Key Quantity | 有限（NVRAM 受限）/ Limited (NVRAM constraint) | 数千~数万 / Thousands to tens of thousands |
| **接口** / Interface | TCG spec / TPM stack | PKCS#11、REST API |
| **密钥不可导出** / Non-exportable Keys | 是 / Yes | 是 / Yes |
| **防篡改** / Tamper Resistance | 中（芯片级物理防护）/ Medium (chip-level) | 强（物理密封，防拆自毁）/ Strong (physical seal, destruct on tamper) |
| **典型用途** / Typical Use | BitLocker、UEFI Secure Boot | CA 签名、金融 HSM、企业 KMS / CA signing, finance HSM, enterprise KMS |
| **成本** / Cost | 包含在主板成本中 / Included in motherboard cost | 数万~数百万元 / $10K-$1M+ |
| **FIPS 等级** / FIPS Level | L1（部分实现）/ L1 (partial) | L2/L3 |


## 固件 TPM（fTPM）

| 实现 | 说明 |
|------|------|
| **Intel Platform Trust Technology（PTT）** | Intel CPU 内置 fTPM（替代 dTPM） |
| **AMD PSP（Platform Security Processor）** | AMD CPU 内置 fTPM |
| **Microsoft Pluton** | 内嵌在 CPU 中的安全子系统（Xbox/PC） |

固件 TPM 通过 CPU 内置安全子系统实现 TPM 功能，无需独立芯片，节省成本且支持 SM2/3/4。

## 软件支持

| 软件 | TPM 支持 |
|------|----------|
| **Linux TPM2.0** | `tpm2-tools`、`tpm2-abrmd`（资源管理器） |
| **OpenSSL** | via OpenSSL engine 或 `tpm2-tss` |
| **Microsoft Windows** | BitLocker、 Credential Guard、 Windows Hello |
| **KMS（Vault）** | Vault Transit Engine / Seal |
| **Android** | StrongBox Keymaster（利用 Teegris/KeyMint） |
| **Kubernetes** | TPM Plugin（CSI Secret Store） |

## TPM 2.0 授权机制（Polices）

TPM 2.0 支持灵活的 Policy 组合授权：

| Policy 类型 | 触发条件 |
|-------------|----------|
| **PCR Policy** | 指定 PCR 值匹配（如启动后 PCR0~7 未变） |
| **Password Policy** | 提供 HMAC 授权会话 |
| **Physical Presence** | 本地物理交互（现场授权） |
| **NV Index Policy** | 特定 NV 索引已定义 |
| **Counter** | 递增计数器满足条件 |
| **OR Policy** | 满足任意一个子 Policy |
| **AND Policy** | 同时满足多个子 Policy |
