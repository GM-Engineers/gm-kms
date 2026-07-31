# F3: Digital Signatures / 数字签名服务

> 创建 Created: 2026-04-28
> 状态 Status: ✅ 已实现 Implemented

## 需求 / Requirement

KMS 必须提供数字签名服务以实现数据认证和完整性校验。

The KMS must provide digital signature services for data authentication and integrity.

## 功能需求 / Functional Requirements

### F3.1 签名算法 / Signature Algorithms
- **FR3.1.1**: 系统必须支持 Ed25519 签名
- **FR3.1.2**: 系统必须支持 SM2 签名（GM/T 标准）
- **FR3.1.3**: 系统必须支持 ECDSA P-256 和 P-384 签名

### F3.2 签名操作 / Signature Operations
- **FR3.2.1**: 签名必须使用 key_id 关联的私钥
- **FR3.2.2**: 验签必须使用对应公钥
- **FR3.2.3**: 验签必须返回成功/失败结果

### F3.3 签名格式 / Signature Format
- **FR3.3.1**: Ed25519 签名必须为 64 字节
- **FR3.3.2**: SM2 签名必须为 64 字节（r ‖ s 格式）
- **FR3.3.3**: ECDSA 签名必须为 DER 编码

## 验收标准 / Acceptance Criteria

- [x] ✅ Ed25519 签名/验签正常工作 / Ed25519 sign/verify works correctly
- [x] ✅ SM2 签名/验签正常工作 / SM2 sign/verify works correctly
- [x] ✅ ECDSA P-256/P-384 签名/验签正常工作 / ECDSA P-256/P-384 sign/verify works correctly
- [x] ✅ 错误签名被正确拒绝 / Verification fails for invalid signatures

## 测试覆盖 / Test Coverage

- `test_ed25519_sign_verify` - Ed25519 操作
- `test_sm2_sign_verify` - SM2 操作

## 性能基准 / Performance Benchmarks

- Ed25519: ~2.5K ops/ms
- SM2: ~110 ops/ms

