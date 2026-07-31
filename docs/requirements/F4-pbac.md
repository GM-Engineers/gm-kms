# F4: Policy-Based Access Control (PBAC) / 基于策略的访问控制

> 创建 Created: 2026-04-28
> 状态 Status: ✅ 已实现 Implemented
> 更新 Updated: 2026-06-24（P0-2/P1-2/P2-2 PBAC 补全完成）

## 需求 / Requirement

KMS 必须通过基于策略的访问控制（PBAC）实现对密钥操作和 API 调用的细粒度授权。

The KMS must implement fine-grained authorization for key operations and API calls via Policy-Based Access Control (PBAC).

## 功能需求 / Functional Requirements

### F4.1 策略定义 / Policy Definition
- **FR4.1.1**: 策略必须包含主体（Subject）、操作（Action）、资源（Resource）和条件（Condition）
- **FR4.1.2**: 策略必须支持通配符和正则表达式
- **FR4.1.3**: 策略必须支持 deny-overrides 合并算法

### F4.2 策略评估 / Policy Evaluation
- **FR4.2.1**: 每次密钥操作前必须进行策略评估
- **FR4.2.2**: 策略评估必须高效（<1ms）
- **FR4.2.3**: 拒绝决定必须附带原因

### F4.3 PBAC Handler 覆盖 / PBAC Handler Coverage
- **FR4.3.1**: 所有 gRPC handlers 必须执行 PBAC 检查（2026-06-24 完成）
- **FR4.3.2**: 所有 REST handlers 必须执行 PBAC 检查（2026-06-24 完成）

> ⚠️ 注意：Phase 2 最终确认 gRPC 22 个 handlers + REST 38 个 async fn 均包含 PBAC 覆盖（原估计数有偏差）
> Note: Phase 2 final count: gRPC 22 handlers + REST 38 async fns all have PBAC coverage (previous estimate was off)

## PBAC Handler 清单 / PBAC Handler List

### gRPC Handlers（含 PBAC）
- `CreateKey` — CREATE_KEY 权限
- `DeleteKey` — DELETE_KEY + 审批门控
- `ExportKey` — EXPORT_KEY + 审批门控（2026-06-24 P0-2）
- `ImportKey` — IMPORT_KEY 权限（2026-06-24 P1-2）
- `Encrypt`/`Decrypt` — ENCRYPT/DECRYPT 权限
- `Sign`/`Verify` — SIGN/VERIFY 权限
- `GetKeyMeta` — READ 权限
- `ListKeys` — READ 权限
- `RotateKey` — ROTATE_KEY 权限
- `GetPolicy`/`SetPolicy` — POLICY_ADMIN 权限
- `MfaVerify` — MFA_VERIFY 权限
- `QueryAuditEvents` — AUDIT_READ 权限（2026-06-26）
- `Hash` — HASH 权限（2026-06-24 P0-1）
- `Sm9_*` 操作 — SM9_ADMIN 权限

### REST Endpoints（含 PBAC）
- `POST /v1/keys` — CREATE_KEY
- `DELETE /v1/keys/{id}` — DELETE_KEY + 审批
- `POST /v1/keys/{id}:export` — EXPORT_KEY + 审批
- `POST /v1/keys:import` — IMPORT_KEY
- `POST /v1/encrypt`/`/v1/decrypt` — ENCRYPT/DECRYPT
- `GET /v1/keys` — READ
- `GET /v1/audit-events` — AUDIT_READ

## 验收标准 / Acceptance Criteria

- [x] ✅ 所有关键操作执行 PBAC 评估 / All critical operations perform PBAC evaluation
- [x] ✅ 拒绝决定附带原因 / Denial decisions include reason
- [x] ✅ 策略变更触发重新评估 / Policy changes trigger re-evaluation
- [x] ✅ gRPC 22 个 handlers PBAC 全覆盖（2026-06-26）/ gRPC 22 handlers fully covered
- [x] ✅ REST 38 个 async fn PBAC 全覆盖（2026-06-26）/ REST 38 async fns fully covered

## 测试覆盖 / Test Coverage

- PBAC 引擎单元测试（`kms-policy` crate，18 个测试）
- 集成测试验证策略覆盖

## 实现说明 / Implementation Notes

- PBAC 引擎实现于 `crates/kms-policy/src/engine.rs`
- Handler 级别授权实现于 `crates/kms-api/src/auth.rs`

