# Key Rotation（密钥轮换） / Key Rotation

> 上次更新：2026-07-08

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Key Rotation |
| **类型 Type** | 密钥生命周期管理操作 / Key lifecycle management operation |
| **用途 Purpose** | 在业务不中断的前提下，用新版本密钥替换旧版本，降低密钥泄露的暴露窗口 / Replaces an old key version with a new one without service interruption, shrinking the exposure window of a compromised key |
| **相关 Related** | DEK、KEK、信封加密、多版本共存 / DEK, KEK, envelope encryption, multi-version coexistence |

## 概述 / Overview

密钥轮换指在不中断业务的前提下，用新版本密钥替换旧版本密钥的过程。轮换是密码合规（等保 2.0、GM/T 0054-2018）的硬性要求，目的是限制单个密钥的长期使用风险。

Key rotation is the process of replacing an old key version with a new one without interrupting service. It is a mandatory control in cryptographic compliance regimes (DJCP 2.0, GM/T 0054-2018), limiting the risk window of long-lived keys.

## 轮换模式 / Rotation Modes

| 模式 Mode | 触发方式 Trigger | 人工干预 Human | 适用场景 Use Case |
|-----------|----------------|--------------|-------------------|
| **手动轮换** Manual | 管理员 CLI / 控制台 / API 触发 | 高 High | CA 根证书、安全事件响应 / CA root, incident response |
| **自动轮换** Automatic | TTL / 使用次数到期自动触发 | 无 None | 常规 DEK、数据库密码 / Routine DEK, DB passwords |
| **策略驱动** Policy-driven | 规则引擎评估后触发 | 低 Low | 多租户、复杂业务规则 / Multi-tenant, complex rules |
| **多版本共存** Multi-version | 与以上模式配合 | 无 None | 平滑迁移、灰度切换 / Smooth migration, canary |

## 关键参数 / Key Parameters

- **TTL（MaxAge）**：密钥最大存活时间，到期触发自动轮换。
- **宽限期（Grace Period）**：旧版本保留时间，期间旧数据仍可用旧版本解密。
- **保留版本数（KeepVersions）**：最多保留的版本数（含当前版本）。

## 版本状态机 / Version State Machine

```
Active  ──轮换触发──▶  PendingDeletion（宽限期内仅可解密）
                           │
                           │ 宽限期结束
                           ▼
                        Obsolete（禁止操作，仅可查元数据）
安全事件可直接跳到 Compromised（立即吊销 + 审计）。
```

## 在 KMS 中的用法 / Usage in KMS

- 加密始终使用最新版本（preferred version）；解密按密文头部的版本字段路由。
- 应用订阅 `KeyVersionChanged` 事件以失效本地 DEK 缓存（缓存设短期 TTL）。
- 关键审计事件：`KEY_ROTATION_INITIATED`、`KEY_ROTATION_COMPLETED`、`KEY_COMPROMISED`。

## 参考 / Reference

