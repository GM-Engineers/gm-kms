# WORM Storage（一次写入多次读取存储） / Write Once Read Many Storage

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Write Once Read Many Storage |
| **类型 Type** | 不可篡改存储技术 / Tamper-resistant storage technology |
| **核心特性** | 数据写入后不可修改或删除 / Data cannot be modified or deleted after write |
| **合规要求** | 等保二级/三级、PCI-DSS、SOC 2 / Level 2/3, PCI-DSS, SOC 2 |


## 概述

WORM Storage 是一种确保数据在写入后无法被修改或删除的存储技术。它通过物理或逻辑机制保证数据的完整性，适用于审计日志、法规合规等场景。

```
写入流程：
  新数据 ──▶ WORM 存储 ──▶ 数据固化 ──▶ 可读（不可改/删）

篡改尝试：
  攻击者 ──▶ 修改数据 ──▶ 存储拒绝（只读）──▶ 告警
```

## 实现方式 / Implementation Methods

### 1. 物理 WORM / Physical WORM

| 类型 Type | 说明 Description |
|---------|----------------|
| **光盘/磁带** / CD/tape | 一次性写入介质，如 CD-R、磁带 / Write-once media (CD-R, tape) |
| **专用 WORM 设备** / WORM Device | 硬件级只读保证，如 WORM NAS / Hardware-level read-only guarantee |

### 2. 逻辑 WORM（软件实现） / Logical WORM (Software)

| 类型 Type | 说明 Description | 代表产品 Products |
|---------|----------------|-----------------|
| **Object Lock** | 对象存储的不可变策略 / Object storage immutability policy | AWS S3 Object Lock、Azure Immutable Blob |
| **Write-Once 模式** / Write-Once Mode | 文件系统只读属性 / Filesystem read-only attribute | ext4 / xfs readonly |
| **区块链锚定** / Blockchain Anchoring | 哈希锚定到区块链 / Hash anchored to blockchain | 比特币、以太坊锚定 / Bitcoin, Ethereum anchoring |
| **时间戳服务** / Timestamp Service | RFC 3161 时间戳 / RFC 3161 timestamp | 权威时间戳机构 / Trusted timestamp authority |


## 在 KMS 审计中的应用

### Rust WORM + HashChain 实现

gm-kms 审计模块实现：

```rust
use kms_audit::worm_writer::{WormWriter, HashChainState};
use kms_audit::SignedAuditEntry;

// 创建 WORM 写入器（追加模式）
let worm = WormWriter::new(PathBuf::from("/var/log/kms/audit"))?;

// 写入审计事件（追加，不可篡改）
let entry = SignedAuditEntry::new(event, &signing_key);
worm.append(&entry).await?;

// 验证完整性
let report = worm.verify_chain(&entries).await?;
assert!(report.valid);
```

## 合规对应表

| 合规标准 | WORM 要求 | KMS 实现 |
|----------|-----------|----------|
| **等保二级** | 审计日志保留 1 年，不可删除 | S3 Object Lock 1 年 |
| **等保三级** | 审计日志保留 3 年，防篡改 | S3 Object Lock 3 年 GOVERNANCE/COMPLIANCE |
| **PCI-DSS** | 日志保留至少 1 年 | WORM + 哈希链验证 |
| **SOC 2** | 独立审计层作为安全控制 | WORM + 多副本 |

## 与普通存储的对比 / vs Normal Storage

| 特性 Feature | WORM Storage | 普通存储 / Normal Storage |
|-------------|--------------|--------------------|
| **数据修改** / Data Modification | ❌ 禁止 / Forbidden | ✅ 可修改 / Allowed |
| **数据删除** / Data Deletion | ❌ 禁止（合规期）/ Forbidden (compliance period) | ✅ 可删除 / Allowed |
| **防篡改** / Tamper Resistance | ✅ 强保证 / Strong guarantee | ⚠️ 依赖访问控制 / Depends on access control |
| **成本** / Cost | 高 / High | 低 / Low |
| **性能** / Performance | 写入性能略低 / Slightly lower write performance | 高 / High |
| **适用场景** / Use Case | 审计日志、合规存档 / Audit logs, compliance archive | 常规业务数据 / Regular business data |


## 安全注意事项 / Security Considerations

1. **访问控制** / Access Control：WORM 配置后仍需限制管理权限，防止恶意删除 / Still restrict admin rights after WORM config to prevent malicious deletion
2. **锁定模式** / Lock Mode：COMPLIANCE 模式下即使管理员也无法删除 / Even admins cannot delete in COMPLIANCE mode
3. **密钥保护** / Key Protection：WORM 存储的审计日志密钥需单独保护 / WORM audit log keys need separate protection
4. **验证机制** / Verification：定期验证哈希链完整性 / Periodically verify hash chain integrity


## 参考标准

- [NIST SP 800-209](https://doi.org/10.6028/NIST.SP.800-209) - 安全日志管理指南
- [PCI-DSS v4.0](https://www.pcisecuritystandards.org/) - 支付卡行业数据安全标准
- AWS S3 Object Lock 文档