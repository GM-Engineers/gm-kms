# F2: Encryption and Decryption / 加解密操作

> 创建 Created: 2026-04-28
> 状态 Status: ✅ 已实现 Implemented

## 需求 / Requirement

KMS 必须提供加密和解密服务以保护数据，使用符合行业标准的算法。

The KMS must provide encryption and decryption services for data protection using industry-standard algorithms.

## 功能需求 / Functional Requirements

### F2.1 对称加密 / Symmetric Encryption
- **FR2.1.1**: 系统必须支持 AES-256-GCM 加密
- **FR2.1.2**: 系统必须支持 SM4-GCM 加密（GM/T 标准）
- **FR2.1.3**: AEAD 密码必须为每次操作生成唯一 Nonce
- **FR2.1.4**: 必须生成并验证认证标签（Authentication Tag）

### F2.2 非对称加密（SM2）/ Asymmetric Encryption (SM2)
- **FR2.2.1**: 系统必须支持 GM/T 0003-2012 的 SM2 加密
- **FR2.2.2**: SM2 加密必须使用指定的曲线参数
- **FR2.2.3**: 密文格式必须为 C1 ‖ C3 ‖ C2（GM/T 标准）

### F2.3 解密 / Decryption
- **FR2.3.1**: 系统必须使用对应算法解密数据
- **FR2.3.2**: 认证标签验证失败必须返回错误
- **FR2.3.3**: 系统必须支持 AAD（附加认证数据）

### F2.4 信封加密 / Envelope Encryption
- **FR2.4.1**: 系统必须支持 DEK/KEK 双层加密
- **FR2.4.2**: DEK 必须用 KEK 加密后安全存储
- **FR2.4.3**: 信封加密对调用方透明

## 验收标准 / Acceptance Criteria

- [x] ✅ AES-256-GCM 加解密正常工作 / AES-256-GCM encryption/decryption works correctly
- [x] ✅ SM4-GCM 加解密正常工作 / SM4-GCM encryption/decryption works correctly
- [x] ✅ SM2 加解密正常工作 / SM2 encryption/decryption works correctly
- [x] ✅ 认证标签验证拒绝篡改密文 / Authentication tag verification rejects tampered ciphertexts
- [x] ✅ AAD 正确关联密文 / AAD is correctly associated with ciphertext

## 测试覆盖 / Test Coverage

- `test_aes256_gcm_encrypt_decrypt` - AES-256-GCM 操作
- `test_sm4_gcm_encrypt_decrypt` - SM4 操作
- `test_sm2_encrypt_decrypt` - SM2 操作
- 信封加密测试（集成测试）

## 性能基准 / Performance Benchmarks

- AES-256-GCM: ~500K ops/ms
- SM4: ~6K ops/ms
- SM2: ~110 ops/ms

