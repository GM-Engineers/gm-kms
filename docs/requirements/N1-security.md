# N1: Security Requirements / 安全控制要求

> 创建 Created: 2026-04-28
> 状态 Status: ✅ 已实现（部分 Partial）
> 更新 Updated: 2026-06-27（Phase 2 完成）

## 安全需求 / Security Requirements

### N1.1 租户隔离 / Tenant Isolation
- **NR1.1.1**: 来自一个租户的密钥不得被其他租户访问
- **NR1.1.2**: 跨租户密钥访问尝试必须记录为安全事件
- **NR1.1.3**: 租户隔离必须通过集成测试验证

### N1.2 API 安全 / API Security
- **NR1.2.1**: API 输入必须根据允许列表验证
- **NR1.2.2**: 无效输入必须返回 400 Bad Request
- **NR1.2.3**: API 必须对每个租户执行速率限制
- **NR1.2.4**: API 必须对每个租户执行配额限制

### N1.3 输入验证 / Input Validation
- **NR1.3.1**: KeySpec 必须根据支持算法允许列表验证
- **NR1.3.2**: 密钥名称限制 256 字符，字母数字 + dash/underscore/period
- **NR1.3.3**: 租户 ID 限制 128 字符，字母数字 + dash/underscore
- **NR1.3.4**: 数据载荷限制 16MB
- **NR1.3.5**: Base64 编码输入必须验证正确格式

### N1.4 内存安全 / Memory Security
- **NR1.4.1**: 密钥材料必须在使用后归零
- **NR1.4.2**: 密钥材料必须使用安全内存清零（抗编译器优化）
- **NR1.4.3**: 使用 zeroize 库保护密钥材料

### N1.5 SM2-KEX 会话安全 / SM2-KEX Session Security
- **NR1.5.1**: 会话 ID 必须可撤销以防止重放
- **NR1.5.2**: 已撤销会话必须被拒绝
- **NR1.5.3**: 会话超时必须强制执行（60 秒，符合 GM/T 0003-2012）
- **NR1.5.4**: 必须维护消息历史以检测重放

### N1.6 审计日志完整性 / Audit Log Integrity
- **NR1.6.1**: 审计日志必须使用 HMAC-SHA256 签名链
- **NR1.6.2**: 日志链必须可验证
- **NR1.6.3**: 篡改必须可检测

## 验收标准 / Acceptance Criteria

- [x] ✅ 租户隔离测试通过 / Tenant isolation tests pass
- [x] ✅ API 输入验证已实现 / API input validation implemented
- [x] ✅ 密钥材料使用 zeroize 内存保护 / Key material uses zeroize for memory protection
- [x] ✅ SM2-KEX 会话撤销已实现 / SM2-KEX session revocation implemented
- [x] ✅ 审计日志签名已实现 / Audit log signing implemented

## 实现说明 / Implementation Notes

- 输入验证：`crates/kms-api/src/validation.rs`
- 内存安全：使用 `zeroize::Zeroizing<Vec<u8>>`
- 会话撤销：使用 `RevokedSessionEntry` 追踪
- 审计签名：`ring::hmac::HMAC_SHA256` 链（`kms-audit` crate）

