# F5: Audit Logging / 审计日志

> 创建 Created: 2026-04-28
> 状态 Status: ✅ 已实现 Implemented
> 更新 Updated: 2026-06-26（anyhow 迁移完成）

## 需求 / Requirement

KMS 必须维护全面的安全相关操作审计日志，用于合规和取证。

The KMS must maintain comprehensive audit logs of all security-relevant operations for compliance and forensics.

## 功能需求 / Functional Requirements

### F5.1 事件类型 / Event Types
- **FR5.1.1**: 系统必须记录密钥生命周期事件（创建、轮换、删除）
- **FR5.1.2**: 系统必须记录密码操作（加密、解密、签名、验签）
- **FR5.1.3**: 系统必须记录策略变更和评估
- **FR5.1.4**: 系统必须记录访问控制决定（授权、拒绝）
- **FR5.1.5**: 系统必须记录管理操作

### F5.2 事件结构 / Event Structure
- **FR5.2.1**: 每个事件必须包含唯一 event_id（UUID）
- **FR5.2.2**: 每个事件必须包含 UTC 时间戳
- **FR5.2.3**: 每个事件必须包含 actor_id 和 actor_type
- **FR5.2.4**: 每个事件必须包含 action 和 resource 信息
- **FR5.2.5**: 每个事件必须包含结果（成功/失败）

### F5.3 增强审计事件 / Enhanced Audit Events
- **FR5.3.1**: 系统必须记录 KeyMaterialAccessed（密钥材料访问）
- **FR5.3.2**: 系统必须记录 KeyExportRequested（密钥导出请求）
- **FR5.3.3**: 系统必须记录 PolicyChanged（策略变更）

### F5.4 日志保护 / Log Protection
- **FR5.4.1**: 审计日志必须使用 HMAC-SHA256 签名链（ring::hmac::HMAC_SHA256）
- **FR5.4.2**: 日志链完整性必须可验证
- **FR5.4.3**: 日志篡改必须可检测

### F5.5 日志存储 / Log Storage
- **FR5.5.1**: 日志必须以 JSON Lines 格式存储
- **FR5.5.2**: 系统必须支持 Kafka 流式传输（可选 feature: kafka）
- **FR5.5.3**: 必须提供本地文件回退存储

## 验收标准 / Acceptance Criteria

- [x] ✅ 所有密钥操作均被记录 / All key operations are logged
- [x] ✅ 日志包含必需字段（event_id, timestamp, actor, action, result）
- [x] ✅ KeyMaterialAccessed, KeyExportRequested, PolicyChanged 事件已实现
- [x] ✅ 日志使用 HMAC-SHA256 签名链（ring::hmac::HMAC_SHA256）

## 实现 / Implementation

- 审计日志器位于 `kms-audit` crate
- 事件定义于 `crates/kms-core/src/event.rs`
- `SignedAuditLogger` 提供日志完整性保护
- WormWriter 使用 SHA256 链哈希 + HMAC-SHA256 条目签名
- 所有审计错误使用自定义 `AuditError`（无 anyhow 依赖，2026-06-26 完成）

## 测试覆盖 / Test Coverage

- `kms-audit` crate 包含完整的单元和集成测试
- 72 个审计相关测试（2026-06-26 确认）

