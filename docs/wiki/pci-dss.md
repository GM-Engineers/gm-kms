# PCI-DSS（支付卡行业数据安全标准） / Payment Card Industry Data Security Standard

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Payment Card Industry Data Security Standard |
| **中文** | 支付卡行业数据安全标准 / Payment Card Industry Data Security Standard |
| **当前版本** | v4.0（2022 年发布）/ v4.0 (published 2022) |
| **发布机构** | PCI SSC（支付卡行业安全标准委员会）/ PCI Security Standards Council |
| **适用范围** | 处理、存储或传输支付卡数据的组织 / Organizations that process, store, or transmit payment card data |


## 概述

PCI-DSS 是支付卡行业的安全标准，适用于所有处理、存储或传输信用卡/借记卡数据的组织。它定义了 12 项要求，涵盖网络安全、密钥管理、访问控制等方面。

## 核心要求（12 项） / Core Requirements (12)

| 要求 Requirement | 说明 Description | KMS 相关 KMS Related |
|---------------|----------------|--------------------|
| **1** | 安装和维护防火墙 / Install and maintain firewall | 网络隔离 / Network isolation |
| **2** | 不使用供应商默认密码 / Don't use vendor defaults | 安全配置 / Secure configuration |
| **3** | 保护存储的持卡人数据 / Protect stored cardholder data | 加密存储 / Encrypted storage |
| **4** | 传输中加密持卡人数据 / Encrypt cardholder data in transit | TLS 加密 / TLS encryption |
| **5** | 维护杀毒软件 / Maintain AV | 终端安全 / Endpoint security |
| **6** | 维护系统和应用安全 / Maintain systems | 补丁管理 / Patch management |
| **7** | 限制业务知需要 / Restrict access | 访问控制 / Access control |
| **8** | 识别和验证访问 / Identify/authenticate | 强身份认证 / Strong authentication |
| **9** | 限制物理访问 / Restrict physical access | 物理安全 / Physical security |
| **10** | 跟踪和监控访问 / Track/monitor access | 审计日志 / Audit logs |
| **11** | 测试安全系统 / Test security | 定期测试 / Regular testing |
| **12** | 维护安全策略 / Maintain policies | 安全文档 / Security documentation |


## 密钥管理相关要求（要求 3 & 4）

### 要求 3：保护存储的持卡人数据

| 控制项 | 要求 |
|--------|------|
| **3.1** | 将持卡人数据存储限制在业务最低需要 |
| **3.2** | 保护存储的持卡人数据（加密） |
| **3.3** | 最小化 SAD（敏感认证数据） |
| **3.4** | 密钥管理：使用强密钥，保护密钥 |

### 要求 4：传输中加密持卡人数据

| 控制项 | 要求 |
|--------|------|
| **4.1** | 使用强加密保护传输（TLS 1.2+） |
| **4.2** | 截获数据无法读取 |
| **4.3** | 维护无线网络密钥 |

## KMS 在 PCI-DSS 中的角色 / KMS Role in PCI-DSS

| PCI-DSS 要求 Requirement | KMS 实现 Implementation |
|------------------------|------------------------|
| **密钥管理** / Key Management | 全生命周期密钥管理 / Full lifecycle key management |
| **加密算法** / Encryption Algorithm | 使用强加密（AES-256）/ Strong encryption (AES-256) |
| **密钥存储** / Key Storage | HSM 保护密钥 / HSM-protected keys |
| **密钥轮换** / Key Rotation | 自动密钥轮换 / Automatic key rotation |
| **密钥分割** / Key Splitting | 密钥分割存储 / Key splitting storage |
| **访问控制** / Access Control | 基于角色的访问控制 / Role-based access control |
| **审计日志** / Audit Logs | 完整的密钥操作审计 / Complete key operation auditing |


## 密钥管理特定要求

```
PCI-DSS 密钥管理要求（简化）：

1. 密钥长度：对称密钥 ≥ 256 位，RSA ≥ 2048 位
2. 密钥存储：HSM 保护或等效安全
3. 密钥轮换：定期轮换（建议每年）
4. 密钥分割：需要两人或两角色参与
5. 密钥泄露响应：立即撤销和更换
6. 审计日志：保留密钥操作记录
```

## 等保与 PCI-DSS 对照

| 领域 | 等保三级 | PCI-DSS v4.0 |
|------|----------|--------------|
| **访问控制** | RBAC + MFA | 强身份验证 |
| **审计日志** | 3 年保留 | 1 年保留（至少） |
| **密钥管理** | HSM | HSM（要求 3） |
| **数据加密** | 国密算法 | AES-256 |
| **网络安全** | 网络隔离 | 防火墙、VPN |
| **合规评估** | 等保测评 | SAQ 或 ROC |

## 合规评估类型 / Compliance Assessment Types

| 类型 Type | 说明 Description | 适用范围 Scope |
|---------|----------------|---------------|
| **ROC** | 现场评估报告 / Report on Compliance | 大型商户、服务提供商 / Large merchants, service providers |
| **QSA** | 认证评估员 / Qualified Security Assessor | 外部审计 / External audit |
| **SAQ** | 自评估问卷 / Self-Assessment Questionnaire | 小型商户 / Small merchants |
| **ASV** | 扫描供应商 / Approved Scanning Vendor | 外部漏洞扫描 / External vulnerability scanning |


## 参考标准

- [PCI DSS v4.0](https://www.pcisecuritystandards.org/) - 官方标准
- [PCI SSC 文档库](https://www.pcisecuritystandards.org/document_library/) - 所有文档
- [NIST SP 800-57](https://doi.org/10.6028/NIST.SP.800-57p1r5) - 密钥管理指南