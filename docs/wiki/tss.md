# TSS（阈值签名方案） / Threshold Signature Scheme

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | Threshold Signature Scheme |
| **中文** | 阈值签名方案 / Threshold Signature Scheme |
| **类型 Type** | 分布式密码学协议 / Distributed cryptography protocol |
| **核心思想** | n 个签名者中至少 t 个协作才能生成有效签名 / At least t of n signers must cooperate to produce a valid signature |


## 概述

TSS 是一种将签名密钥分成 n 份，要求至少 t 个签名者协作才能生成有效签名的密码学协议。与 SSS 不同，TSS 的目标是生成可验证的数字签名，而不是恢复原始密钥。

```
TSS vs SSS：

SSS（秘密分享）：
  份额 ──▶ 恢复秘密 ──▶ 使用秘密

TSS（阈值签名）：
  份额 ──▶ 协作签名 ──▶ 签名（秘密永不重建）
```

## 工作原理

### 1. 密钥生成（DKG - 分布式密钥生成）

```
DKG 流程（t-of-n）：

1. 参与方 P₁, P₂, ..., Pₙ 各自选择随机数
2. 每方计算自己的份额并广播
3. 各方计算公钥（无需重建私钥）
4. 每个参与方持有分片密钥 sk_i

结果：
- 公钥 PK（可公开）
- 私钥分片 sk₁, sk₂, ..., skₙ（各自保管）
- 没有任何一方知道完整私钥
```

### 2. 阈值签名（t-of-n）

```
签名流程（需要 t 个参与方）：

1. 消息发送方请求签名
2. 签名方 P₁, P₂, ..., Pₜ 各自使用自己的分片密钥
3. 各方生成部分签名（partial signature）
4. 聚合部分签名生成完整签名
5. 任何人可使用公钥验证签名

关键属性：
- 签名过程不需要重建完整私钥
- 签名验证与普通签名无异（基于公钥）
```

## 算法分类

### 基于 ECDSA 的 TSS

```go
// 联合 ECDSA 签名（Gennaro et al.）
type ThresholdECDSA struct {
    parties    int
    threshold  int
    participants []*Party
}

type PartialSignature struct {
    Gamma *curve.Point  // 随机数承诺
    Delta *curve.Point  // 签名第一部分
}
```

### 基于 BLS 的 TSS

```go
// BLS 阈值签名（更简单）
type ThresholdBLS struct {
    threshold int
    signers   map[int]*BLSParty
}

func (t *ThresholdBLS) Sign(msg []byte, signerIDs []int) (*BLS_Signature, error) {
    // 1. 各签名方生成部分签名
    partialSigs := make([]*PartialBLS, len(signerIDs))
    for i, sid := range signerIDs {
        partialSigs[i] = t.signers[sid].PartialSign(msg)
    }

    // 2. 聚合签名（使用拉格朗日系数）
    return aggregateSignatures(partialSigs, signerIDs, t.threshold)
}
```

### 基于 Schnorr 的 TSS

```go
// 联合 Schnorr 签名
type ThresholdSchnorr struct {
    threshold int
    params    *SchnorrParams
}

func (t *ThresholdSchnorr) Sign(msg []byte, signerIDs []int) (*SchnorrSignature, error) {
    // 每个参与方计算 (r_i, s_i)
    // 聚合：s = Σ s_i，使用拉格朗日权重
    // 最终签名：(R, s)，其中 R = Σ R_i
}
```

## 在 KMS 中的应用

### 多管理者密钥签名

```go
// TSS KMS 签名服务
type TSSKMSServer struct {
    threshold    int
    parties      map[string]*Party
    dkg          *DKG
    partialSigners map[string]*PartialSigner
}

type SignRequest struct {
    KeyID   string
    Message []byte
    SignerIDs []int  // t 个签名者 ID
}

// 签名请求
func (s *TSSKMSServer) Sign(ctx context.Context, req *SignRequest) ([]byte, error) {
    // 1. 验证签名者授权
    if !s.isAuthorized(req.KeyID, req.SignerIDs) {
        return nil, errors.New("unauthorized")
    }

    // 2. 获取签名份额
    partials := make([]*PartialSignature, len(req.SignerIDs))
    for i, sid := range req.SignerIDs {
        party := s.parties[sid]
        partial, err := party.ComputePartial(ctx, req.KeyID, req.Message)
        if err != nil {
            return nil, err
        }
        partials[i] = partial
    }

    // 3. 聚合完整签名
    signature, err := s.aggregator.Aggregate(partials)
    if err != nil {
        return nil, err
    }

    // 4. 验证签名（确保正确）
    if !s.verify(req.KeyID, req.Message, signature) {
        return nil, errors.New("signature verification failed")
    }

    return signature, nil
}
```

### 使用场景

| 场景 | 说明 |
|------|------|
| **企业签名** | 2-of-3 高管签名（需两人同意） |
| **灾难恢复** | 3-of-5 密钥管理者（一人不在可恢复） |
| **审计追溯** | 记录所有签名参与方 |
| **合规要求** | 满足双人授权的合规要求 |

## 与其他方案的对比 / Comparison with Other Schemes

| 特性 Feature | TSS | 多重签名 / Multi-sig | SSS + 签名 |
|-------------|-----|--------------|------------|
| **签名者** / Signers | n 人中 t 人 / t of n | 所有签名者 / All signers | 一人持完整密钥 / One holds full key |
| **密钥形式** / Key Form | 分片存储 / Sharded | 多份完整密钥 / Multiple full keys | 完整密钥分片 / Full key shares |
| **密钥暴露** / Exposure | 无单点 / No single point | 多点暴露 / Multiple | 有暴露风险 / Exposure risk |
| **签名验证** / Verify | 相同（公钥）/ Same PK | 需多方公钥 / Multiple PKs | 相同（公钥）/ Same PK |
| **灵活性** / Flexibility | 高 / High | 中 / Medium | 低 / Low |


## 安全性分析 / Security Analysis

| 攻击类型 Attack | 威胁 Threat | 缓解措施 Mitigation |
|--------------|------|----------|
| **< t 方合谋** / <t-party | 无法生成签名 / Cannot forge | 门限设置合理 / Set reasonable threshold |
| **内部攻击** / Insider | 不当签名 / Improper signing | 审计+审批流程 / Audit + approval |
| **通信窃听** / Eavesdropping | 部分签名泄露 / Sig leak | TLS 加密通道 / TLS channels |
| **拒绝服务** / DoS | 部分方不响应 / Non-response | 冗余签名方 / Redundant signers |


## 实现注意事项

1. **DKG 安全性**：使用安全的分布式密钥生成协议
2. **随机性**：签名过程中的随机数必须无偏见
3. **签名者身份**：验证签名者身份和授权
4. **完整审计**：记录所有部分签名和聚合过程

## 主流 TSS 协议 / Major TSS Protocols

| 协议 Protocol | 类型 Type | 说明 Description |
|-------------|------|----------------|
| **GG（Gennaro-Jarecki）** | ECDSA | 最成熟的 ECDSA TSS / Most mature ECDSA TSS |
| **Boldyreva** | BLS | 简单 BLS 阈值签名 / Simple BLS threshold signature |
| **Pedersen** | Schnorr | 门限 Schnorr 签名 / Threshold Schnorr signature |
| **KZM** | Schnorr | 可验证的 Schnorr TSS / Verifiable Schnorr TSS |


## 参考标准

- [Gennaro, R. et al. (1999)](https://link.springer.com/chapter/10.1007/3-540-48910-X_18) - Threshold DSS
- [Boldyreva, A. (2003)](https://www.iacr.org/archive/asiacrypt2003/30070556.pdf) - BLS 门限签名
- [RFC 8235](https://datatracker.ietf.org/doc/html/rfc8235) - Schnorr 多方计算