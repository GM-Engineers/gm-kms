# Requirements / 功能需求文档

> 版本 Version: 1.0
> 更新 Updated: 2026-06-29

---

本目录包含 gm-kms 的功能需求文档，每份文档采用中英双语格式。

This directory contains functional requirements for gm-kms, each document in Chinese/English bilingual format.

## 文档列表 / Document List

| 文档 Document | 说明 Description | 状态 Status |
|-------------|----------------|-----------|
| **F1-key-lifecycle.md** | 密钥生命周期管理 / Key Lifecycle Management | ✅ 已实现 Implemented |
| **F2-encryption.md** | 加解密操作 / Encryption and Decryption | ✅ 已实现 Implemented |
| **F3-signature.md** | 数字签名服务 / Digital Signatures | ✅ 已实现 Implemented |
| **F4-pbac.md** | 基于策略的访问控制 / Policy-Based Access Control | ✅ 已实现 Implemented |
| **F5-audit.md** | 审计日志 / Audit Logging | ✅ 已实现 Implemented |
| **N1-security.md** | 安全控制要求 / Security Requirements | ✅ 已实现 Implemented |
| **sm2-kex-requirement.md** | SM2 密钥交换需求 / SM2 Key Exchange | ✅ 已实现 Implemented |

## 文档结构 / Document Structure

每份需求文档包含：

Each requirements document contains:

- **需求 / Requirement**: 需求陈述（英文）
- **功能需求 / Functional Requirements**: 具体功能需求条目（中文 + 英文对照）
- **验收标准 / Acceptance Criteria**: 复选框列表（✅ 已实现 / ❌ 待实现）
- **测试覆盖 / Test Coverage**: 单元和集成测试覆盖说明
- **实现说明 / Implementation Notes**: 关键实现路径和决策说明

## 状态标注说明 / Status Legend

| 状态 Status | 含义 Meaning |
|-----------|-------------|
| ✅ 已实现 Implemented | 需求已完整实现，所有验收标准通过 |
| ⚠️ 部分实现 Partial | 部分功能已实现，存在已知限制 |
| ❌ 待实现 Pending | 尚未开始实现 |

## 需求追踪 / Requirement Tracking

需求编号规则：

Requirement numbering:

- **F**: 功能需求 Functional requirement（FR）
- **N**: 非功能需求 Non-functional requirement（NR）
- **P**: 性能需求 Performance requirement
- **S**: 安全需求 Security requirement

## 关联文档 / Related Documents

- [合规性检查清单](../compliance/checklist.md) — 对照 GM/T 标准逐项检查
- [部署指南](../guides/deployment-guide.md) — 生产环境部署
- [安全评估报告](../compliance/audit/self-assessment.md) — 安全漏洞追踪
