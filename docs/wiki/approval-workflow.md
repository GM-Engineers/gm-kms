# Approval Workflow（审批工作流） / Approval Workflow

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **类型 Type** | 访问控制/治理 / Access Control / Governance |
| **实现位置** | `kms-approval` crate |
| **目的 Purpose** | 高危操作需多级审批 / Multi-level approval required for high-risk operations |


## 概述

审批工作流为高危密钥操作引入人工审批环节，确保敏感操作（如密钥删除、导出）经过授权人员批准。

## 审批级别 / Approval Levels

| 级别 Level | 说明 Description | 适用场景 Use Case |
|-----------|----------------|-----------------|
| `Single` | 单人审批 / Single approver | 低风险操作 / Low-risk operations |
| `Double` | 双人审批 / Two approvers | 中风险操作 / Medium-risk operations |
| `Triple` | 三人审批 / Three approvers | 高风险操作 / High-risk operations |
| `Manager` | 经理审批 / Manager approval | 高价值密钥创建 / High-value key creation |
| `Admin` | 管理员审批 / Admin approval | 租户管理操作 / Tenant management |


## 触发审批的操作 / Operations Requiring Approval

| 操作 Operation | 默认级别 Default Level |
|---------------|-----------------------|
| `KeyDelete` | Double |
| `KeyExport` | Triple |
| `KeyRotate` | Double |
| `PolicyChange` | Double |
| `HighValueKeyCreate` | Manager |
| `AuditAccess` | Single |
| `MfaChange` | Single |
| `TenantAdmin` | Admin |


## 工作流状态

```
                    ┌─────────────┐
                    │  Pending    │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              ↓            ↓            ↓
        ┌─────────┐  ┌──────────┐  ┌──────────┐
        │Approved │  │ Rejected │  │Cancelled │
        └─────────┘  └──────────┘  └──────────┘
```

## 实现机制

```rust
use kms_approval::{ApprovalEngine, ApprovalLevel, OperationType};

// 创建审批引擎
let mut engine = ApprovalEngine::new();

// 创建审批请求
let request = engine.create_request(
    OperationType::KeyDelete,
    "key-123",
    "key",
    "tenant-abc",
    "user-456",
    Some("Need to delete decommissioned key".to_string()),
    None, // 使用操作默认级别
)?;

if request.status != ApprovalStatus::Approved {
    return Err(ApprovalRequired(request.id).into());
}
```

## 审批请求结构

```rust
pub struct ApprovalRequestEntity {
    pub id: Uuid,
    pub operation: OperationType,
    pub resource_id: String,
    pub resource_type: String,
    pub tenant_id: String,
    pub requestor_id: String,
    pub justification: Option<String>,
    pub status: ApprovalStatus,
    pub required_level: ApprovalLevel,
    pub current_level: ApprovalLevel,
    pub approvals: Vec<ApprovalRecord>,
    pub rejections: Vec<RejectionRecord>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub metadata: serde_json::Value,
}
```

## 多级审批

```rust
// 创建 Triple 级别审批请求
let request = engine.create_request(
    OperationType::KeyExport,
    "key-789",
    "key",
    "tenant-xyz",
    "admin-001",
    Some("Key export requested".to_string()),
    Some(ApprovalLevel::Triple),
)?;

// 审批者 1
engine.approve(&request.id, "approver-1")?;

// 审批者 2
engine.approve(&request.id, "approver-2")?;

// 审批者 3（最后一人完成审批）
engine.approve(&request.id, "approver-3")?;

assert_eq!(request.status, ApprovalStatus::Approved);
```

## 与 PBAC 集成

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   PBAC      │ ──▶ │  Approval   │ ──▶ │   Execute   │
│   Check     │     │   Flow      │     │   Op        │
└─────────────┘     └─────────────┘     └─────────────┘
     │                    │                    │
  通过但                待审批              审批通过
  需审批
```

## 超时与取消

- 默认过期时间：24 小时
- 可配置过期时间
- 请求者可取消自己创建的请求

```rust
// 取消请求
engine.cancel(&request.id, "user-456")?;

// 过期清理（非异步）
engine.cleanup_expired_break_glass();
```

## 合规对应 / Compliance Mapping

| 合规标准 Standard | 要求 Requirement | 实现 Implementation |
|-------------------|----------------|-------------------|
| 等保三级 / Level 3 | 敏感操作审批 / Sensitive operation approval | ✅ ApprovalEngine |
| PCI-DSS | 密钥删除需授权 / Key deletion requires authorization | ✅ KeyDestroy 需 Level3 / Level 3 required |
| 最佳实践 / Best Practice | 双人授权 / Dual authorization | ✅ Dual Custody |


## 参考资料

- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) - AC-1 Access Control Policies
