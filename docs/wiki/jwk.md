# JWK（JSON Web Key） / JSON Web Key

> 上次更新：2026-06-29

## 基本信息 / Basic Information

| 字段 Field | 值 Value |
|------------|----------|
| **全称** | JSON Web Key |
| **类型 Type** | 密钥表示格式 / Key representation format |
| **标准 Standard** | RFC 7517 |
| **相关标准** | JWS（RFC 7515）、JWE（RFC 7516）、JWT（RFC 7519）/ JWS, JWE, JWT |


## 概述

JWK 是一种 JSON 格式的密钥表示标准，用于在 JSON 数据结构中表示加密密钥。它是 RESTful API 时代的事实标准，被 OAuth 2.0、OpenID Connect、JWT 等广泛采用。

JWK 以 JSON 对象形式表示，支持多种密钥类型（RSA、EC、Oct/对称、OKP）。

## JWK 示例

### RSA 密钥

```json
{
  "kty": "RSA",
  "use": "sig",
  "kid": "key-id-123",
  "alg": "RS256",
  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  "e": "AQAB"
}
```

### EC（椭圆曲线）密钥

```json
{
  "kty": "EC",
  "crv": "P-256",
  "kid": "ec-key-456",
  "x": "WKn-zIGU0ahVub-BzE3EsJFGhW3tGFN_5LNF8g3vOY",
  "y": "y77t-RvAHRKTs8K2f8WE4ELRsG_BnMN3klJNPw2v1g"
}
```

### 对称密钥（Oct）

```json
{
  "kty": "oct",
  "k": "GawgguFygrWKl7B8risZemY8hWz9M_lvW4MFM",
  "kid": "sym-key-789",
  "alg": "A256GCM"
}
```

## 字段说明 / Fields

| 字段 Field | 必须 Required | 说明 Description |
|----------|-----------|----------------|
| **kty** | ✅ | 密钥类型：RSA、EC、oct、OKP / Key type: RSA, EC, oct, OKP |
| **kid** | ❌ | 密钥 ID，用于匹配用途 / Key ID for matching |
| **use** | ❌ | 用途：sig（签名）、enc（加密）/ Use: sig (signing), enc (encryption) |
| **alg** | ❌ | 算法：RS256、ES256、A256GCM 等 / Algorithm: RS256, ES256, A256GCM, etc. |
| **key_ops** | ❌ | 支持的操作：sign、verify、encrypt 等 / Supported operations |

### kty=RSA 专用字段 / RSA-Specific Fields

| 字段 Field | 说明 Description |
|----------|----------------|
| **n** | RSA 模数（modulus）/ RSA modulus |
| **e** | RSA 指数（exponent）/ RSA exponent |

### kty=EC 专用字段 / EC-Specific Fields

| 字段 Field | 说明 Description |
|----------|----------------|
| **crv** | 曲线：P-256、P-384、P-521 / Curve: P-256, P-384, P-521 |
| **x** | 公钥 X 坐标 / Public key X coordinate |
| **y** | 公钥 Y 坐标 / Public key Y coordinate |
| **d** | 私钥（仅私钥表示时）/ Private key (only in private key representation) |


## 在 KMS 中的应用 / KMS Applications

| 场景 Scenario | 说明 Description |
|--------------|----------------|
| **API 响应** / API Response | KMS 返回公钥 JWK 供客户端加密 / KMS returns public key JWK for client encryption |
| **JWK Set** | 密钥集合，用于 JWKS 端点（`/.well-known/jwks.json`）/ Key set for JWKS endpoint |
| **密钥导入** / Key Import | 接受 JWK 格式的公钥导入 / Accept JWK-format public key for import |
| **密钥存储** | 内部存储使用 JWK 格式（JSON 友好）/ Internal storage uses JWK format |


```go
// JWK 解析示例
import "github.com/lestrrat-go/jwx/v2/jwk"

func ParseJWK(jsonData []byte) (jwk.Key, error) {
    return jwk.Parse(jsonData)
}

// JWK 存储
func StoreJWK(key interface{}) ([]byte, error) {
    jwkKey, _ := jwk.New(key)
    return json.Marshal(jwkKey)
}
```

## JWK 与 PKCS#8 的对比 / PKCS#8 Comparison

| 特性 Feature | JWK | PKCS#8 |
|-----------|-----|--------|
| **格式** / Format | JSON | ASN.1 DER / PEM |
| **适用场景** / Use Case | Web API、JWT、OAuth | 传统系统、HSM |
| **可读性** / Human-readable | 人类可读 / Human-readable | 二进制 / Binary |
| **文件扩展** / File Extension | `.json` | `.pem`、`.der` |
| **主流支持** / Mainstream Support | 现代 Web、云 KMS / Modern web, cloud KMS | 企业内部、传统系统 / Enterprise, legacy |


## 安全注意事项 / Security Considerations

1. **私钥保护** / Private Key Protection：JWK 中的私钥（d 字段）必须加密存储 / Private keys (d field) in JWK must be stored encrypted
2. **验证来源** / Verify Source：解析 JWK 前验证签名和来源 / Verify signature and source before parsing JWK
3. **算法限制** / Algorithm Restriction：不要相信 JWK 中的 alg 字段，需独立验证 / Do not trust the alg field in JWK; verify independently
4. **kid 唯一性** / Kid Uniqueness：确保 kid 在系统中唯一 / Ensure kid is unique within the system


## 参考标准

- [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) - JWK 规范
- [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) - JWS（JSON Web Signature）
- [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516) - JWE（JSON Web Encryption）