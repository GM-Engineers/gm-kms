# REST ↔ gRPC 语义对照表（audit P4-3）

> 更新日期：2026-10-24
> 目的：gm-kms 同时提供 REST（axum/JSON）与 gRPC（tonic/protobuf）两条通道，
> 二者**收敛到同一服务层**（`KeyService` / `CryptoService`），核心密码语义一致，
> 但在编码、错误映射、租户缺省上存在刻意或有意的差异。本表固化这些不变量，
> 并由 `tests/api_integration.rs` 的交叉一致性用例守护。任何偏离应先更新本表。

## 1. 通道与编码

| 维度 | REST | gRPC |
|------|------|------|
| 传输 | HTTP/1.1 + JSON | HTTP/2 + protobuf |
| 二进制字段 | base64 字符串（`bytes` 型 JSON 编码） | protobuf `bytes` |
| 路由/RPC | 见下表逐条映射 | `service KmsService` 逐条 `rpc` |
| 服务层 | `KeyService`/`CryptoService`（相同方法） | `KeyService`/`CryptoService`（相同方法） |

核心操作在两条通道**逐一对应且共享同一实现**：

| 操作 | REST | gRPC |
|------|------|------|
| 创建密钥 | `POST /v1/keys` | `CreateKey` |
| 导入密钥 | `POST /v1/keys/import` | `ImportKey` |
| 导出密钥 | `POST /v1/keys/export/{id}` | `ExportKey` |
| 加密 | `POST /v1/keys/{id}/encrypt` | `Encrypt` |
| 解密 | `POST /v1/keys/{id}/decrypt` | `Decrypt` |
| 签名/验签 | `POST /v1/keys/{id}/sign`、`/verify` | `Sign`、`Verify` |
| 托管 HMAC-SM3 | `POST /v1/keys/{id}/hmac`、`/hmac/verify` | `Hmac`、`HmacVerify` |
| 轮换 | `POST /v1/keys/{id}/rotate` | `RotateKey` |
| 删除 | `DELETE /v1/keys/{id}` | `DeleteKey` |
| 信封加解密/重包 | `POST /v1/envelope/{encrypt,decrypt,rewrap}` | `EnvelopeEncrypt/Decrypt/Rewrap` |
| 健康 | `GET /v1/health`、`/readyz` | （健康为 REST 侧探针） |

## 2. 租户身份派生（audit P1-3 / Batch 3）

两条通道都遵循"**认证身份优先**"原则：当 API Key 绑定了租户，绑定租户为权威值，
请求自报租户被忽略（不匹配时记 WARN，便于发现客户端租户伪装）。差异仅在**未绑定 Key** 的缺省：

| 场景 | REST | gRPC |
|------|------|------|
| Key 已绑定租户 | 用绑定租户（忽略自报） | 用绑定租户（忽略自报） |
| Key 未绑定 + 请求带非空租户 | 用请求租户 | 用请求租户 |
| Key 未绑定 + 请求租户为空 | **缺省 `"default"`** 并打印 SECURITY WARN | **显式失败** `INVALID_ARGUMENT`（"tenant_id is required"） |

> 差异说明：REST 保留 `"default"` 缺省以兼容既有部署/测试；gRPC 自 Batch 3 起对空租户
> fail-closed，移除静默放行。生产应始终为 API Key 绑定租户以消除该分叉。

## 3. 错误映射

同一 `ApiError` 变体在两通道的落地码：

| `ApiError` | REST 状态码 | gRPC `Status` | 对齐 |
|------------|-------------|---------------|------|
| `KeyNotFound` | 404（脱敏 "key not found"） | `NOT_FOUND`（脱敏） | ✅ |
| `NotFound` | 404 | `NOT_FOUND` | ✅ |
| `InvalidRequest` | 400 | `INVALID_ARGUMENT` | ✅ |
| `InvalidArgument` | 400 | `INVALID_ARGUMENT` | ✅ |
| `Forbidden` | 403 | `PERMISSION_DENIED` | ✅ |
| `QuotaExceeded` | 429 | `RESOURCE_EXHAUSTED` | ✅ |
| `Internal` | 500（脱敏） | `INTERNAL`（脱敏） | ✅ |
| `PermissionDenied` | 403 | `INTERNAL`（落入 `_` 兜底） | ⚠️ 分叉 |
| `BadRequest` | 400 | `INTERNAL`（兜底） | ⚠️ 分叉 |
| `TooManyRequests` | 429 | `INTERNAL`（兜底） | ⚠️ 分叉 |
| `NotImplemented` | 501 | `INTERNAL`（兜底） | ⚠️ 分叉 |

> ⚠️ 已知分叉（非本次修复范围，仅固化记录）：`grpc.rs::api_error_to_status` 未显式列出
> 后四类，落入 `_ => Status::internal(...)` 兜底，导致 gRPC 侧把它们报为 `INTERNAL`
> 而非 REST 对应的 403/400/429/501。建议后续（独立 PR）在 `api_error_to_status` 补齐映射，
> 使两通道的错误语义完全对齐。核心业务码（上表 ✅ 行）当前已一致并有测试守护。

## 4. 导出语义（audit P2-5 / P2-6 / P2-2）

两通道都收敛为**包裹语义（wrapped export）**，绝不回传明文材料：

- 请求：`target_public_key`（调用方公钥）、`protection_scheme`（`""`/`"rsa-oaep"` 默认，或 `"sm2"`）、
  `version`（`0`/缺省=当前版本；非零=历史版本，需密钥可导出）、`approval_id`（必填，`KeyExport` 审批）。
- 响应：`wrapped_key`（材料经临时传输密钥加密）+ `encrypted_transport_key`（传输密钥经调用方公钥加密）
  + `key_fingerprint`（材料 SHA-256 指纹，供完整性校验）。
- 传输密钥保护：`rsa-oaep` 走 RSA-OAEP；`sm2` 走 SM2 加密（国密合规路径）。

## 5. 版本与 format_version（audit P0 / P2-3）

- `Encrypt` 响应回显 `format_version`（REST `u8`、gRPC `uint32`）。当前生产格式为 **2**，
  其 AAD 绑定 `(key_id, tenant_id, version)`。
- `Decrypt` 接受 `format_version`（缺省按 **2** 重算绑定 AAD）；`format_version` 0/1 为遗留空 AAD 密文，
  需显式回传以解密历史密文。两通道此语义一致。
- `DecryptRequest.version`：用于在 format 2 下重建正确 AAD（对接历史/指定版本解密）。

## 6. 托管 HMAC-SM3（audit P2-1）

- 独立 `KeySpec::Sm3Hmac` + `Hmac`/`HmacVerify` 通道，走 `gm_crypto::sm3::Sm3Hmac`，
  **不复用** AES-GCM 分支。REST `/v1/keys/{id}/hmac[/verify]` 与 gRPC `Hmac`/`HmacVerify` 收敛同一服务方法。
- `aad` 为可选域分离输入（长度前缀混入 MAC），计算与验证必须一致。

## 7. 密钥销毁证明（audit P4-2）

- `DestructionProof` 的 HMAC 签名使用 **HMAC-SM3**（替换遗留 HMAC-SHA256）。
- 证明中的 `material_hash` 仍为 **SHA-256**（`hash_algorithm="SHA256"` 字段描述的是材料哈希，
  非签名 HMAC），两通道/各后端一致。

## 测试固化

`tests/api_integration.rs` 的 `p43_*` 用例对同一批请求断言 REST 与 gRPC 的：
- 加解密往返结果一致（SM4/AES 在 format 2 下的 AAD 绑定回环）；
- 租户越权在两条通道均被拒；
- 导出均为包裹语义（`wrapped_key` 非明文、含 `encrypted_transport_key`）；
- 共享错误码（`KeyNotFound`/`InvalidRequest`/`Forbidden`）在两通道语义对齐。

第 3 节的 ⚠️ 分叉行**不在**断言范围内，作为已知记录保留，待独立 PR 修复后并入。
