# Hash Chain（哈希链） / Hash Chain

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **类型 Type** | 完整性保护 / Integrity protection |
| **实现位置** | `kms-audit/worm_writer.rs` |
| **目的 Purpose** | 审计日志防篡改 / Audit log tamper detection |


## 概述

哈希链通过将每个审计条目与前一条的哈希链接，确保任何历史条目的篡改都会被检测到。

## 工作原理

```
Block 0          Block 1          Block 2          Block 3
┌────────┐       ┌────────┐       ┌────────┐       ┌────────┐
│ Event  │       │ Event  │       │ Event  │       │ Event  │
│ Prev:N │       │ Prev:H0│       │ Prev:H1│       │ Prev:H2│
│ Hash:H1│       │ Hash:H2│       │ Hash:H3│       │ Hash:H4│
└────────┘       └────────┘       └────────┘       └────────┘
     ↑
     │
  Genesis (Prev = 0)
```

每块的哈希 = Hash(Event || Prev_Hash || Timestamp)

## 实现机制

```rust
use kms_audit::worm_writer::{WormWriter, HashChainState};
use kms_audit::SignedAuditEntry;

let worm = WormWriter::new(PathBuf::from("/var/log/kms/audit"))?;

// 写入时自动更新哈希链
let entry = SignedAuditEntry::new(event, &signing_key);
worm.append(&entry).await?;

// 批量写入
worm.append_batch(&entries).await?;

// 验证完整性
let report = worm.verify_chain(&entries).await?;
if report.valid {
    println!("Audit log intact ({} entries checked)", report.entries_checked);
} else {
    println!("Integrity violation at index {:?}: {}",
        report.first_invalid_index, report.error.unwrap_or_default());
}
```

## 审计条目结构

```rust
pub struct SignedAuditEntry {
    pub sequence: u64,           // 序列号
    pub timestamp: i64,         // Unix 时间戳
    pub event: AuditEvent,       // 审计事件
    pub previous_hash: Vec<u8>,  // 前一条的哈希
    pub hash: Vec<u8>,           // 本条哈希
    pub signature: Vec<u8>,      // HMAC 签名
}
```

## 哈希计算

```rust
// HashChainState 内部实现
impl HashChainState {
    pub fn new() -> Self {
        // running_hash 初始化为 SHA256("")
        // entry_count = 0
    }

    pub fn update(&mut self, entry_hash: [u8; 32]) {
        // Chain hash: SHA256(running_hash || entry_hash)
        // running_hash = SHA256(self.running_hash || entry_hash)
        // entry_count += 1
    }
}

// WormWriter 计算单条哈希
fn compute_entry_hash(entry: &SignedAuditEntry) -> [u8; 32] {
    // SHA256(sequence || timestamp || event_json || previous_hash)
}
```

## 完整性验证

```rust
// WormWriter::verify_chain 返回 VerificationReport
pub struct VerificationReport {
    pub valid: bool,
    pub entries_checked: usize,
    pub first_invalid_index: Option<usize>,
    pub error: Option<String>,
}

// 验证流程：
// 1. 读取所有条目
// 2. 逐条计算哈希，与条目中记录的哈希比较
// 3. 验证 HMAC 签名
// 4. 返回 VerificationReport
```

## 防篡改能力 / Tamper Detection Capabilities

| 攻击类型 Attack | 检测方法 Detection Method |
|--------------|----------------------|
| 修改历史条目 / Modify historical entry | 哈希链断裂 / Hash chain broken |
| 删除条目 / Delete entry | 序列号不连续 / Sequence discontinuity |
| 重放旧条目 / Replay old entry | 时间戳异常 / Timestamp anomaly |
| 伪造条目 / Forge entry | HMAC 签名验证失败 / HMAC signature verification fails |


## 与 WORM 存储的关系

```
┌─────────────────────────────────────────────────────────┐
│                    双重保护                              │
│                                                          │
│   WORM Storage ─── 物理只读 ─── 防止删除                  │
│        │                                                    │
│        │                                                    │
│   Hash Chain ─── 密码学完整 ─── 防止篡改                   │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## 合规对应 / Compliance Mapping

| 合规标准 Standard | 要求 Requirement | 实现 Implementation |
|-------------------|----------------|-------------------|
| 等保三级 / Level 3 | 审计记录防篡改 / Audit record tamper protection | ✅ HashChainState + WormWriter |
| 银发〔2020〕35号 | 不可篡改日志 / Immutable audit logs | ✅ HashChainState + HMAC |
| PCI-DSS | 审计完整性 / Audit integrity | ✅ 完整性验证 / Integrity verification |


## 参考资料

- [Merkle Tree vs Hash Chain](https://en.wikipedia.org/wiki/Hash_chain)
- [NIST SP 800-209](https://doi.org/10.6028/NIST.SP.800-209) - Security Logging
