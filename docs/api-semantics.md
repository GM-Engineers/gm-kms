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
> fail-closed，移除静默放行。
>
> **如何在生产中消除该分叉**（audit B7-e）：在服务端配置里声明**绑定租户**的 API Key，
> 此时两条通道都使用绑定租户，忽略调用方自报值：
>
> ```toml
> [[api_keys]]
> key_id = "acme-admin"
> role = "key-admin"          # read-only | operator | key-admin | security-officer | audit-admin
> tenant = "acme"             # 绑定租户：服务端据此推导租户
> secret_env = "KMS_API_KEY_ACME"   # 密钥存放于环境变量，不写入配置文件
> ```
>
> 未绑定租户的 Key 启动时会打印 `warn` 日志（因为它仍依赖调用方自报租户）。

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

## 5. 版本与 format_version（audit P0 / P2-3 / B7-d）

- `Encrypt` 响应回显 `format_version`（REST `u8`、gRPC `uint32`）与 `version`（密钥版本号）。
  当前生产格式为 **2**，其 AAD 绑定 `(key_id, tenant_id, version)`。
- `Decrypt` 接受 `format_version`（缺省按 **2** 重算绑定 AAD）；`format_version` 0/1 为遗留空 AAD 密文，
  需显式回传以解密历史密文。
- **缺省 `version` 的语义**（audit B7-d 更正）：
  - REST：`version` 缺省为 **1**（`default_decrypt_version()`）。
  - gRPC：proto3 无法区分“未设置”与 0，因此服务端将 `version == 0` 归一为 **1**，
    与 REST 一致（`grpc.rs::decrypt`）。
  - 两通道的缺省值相同，但**均不代表“当前版本”**：密钥轮换后（当前版本 > 1），
    解密历史密文必须回显 `Encrypt` 返回的 `version`；不回显会按版本 1 选材，
    从而解密失败（fail-closed，不会静默使用错误密钥）。
  - 例外：`version` 缺省仅对“密钥当前版本就是 1”的密文成立。

## 6. 托管 HMAC-SM3（audit P2-1）

- 独立 `KeySpec::Sm3Hmac` + `Hmac`/`HmacVerify` 通道，走 `gm_crypto::sm3::Sm3Hmac`，
  **不复用** AES-GCM 分支。REST `/v1/keys/{id}/hmac[/verify]` 与 gRPC `Hmac`/`HmacVerify` 收敛同一服务方法。
- `aad` 为可选域分离输入（长度前缀混入 MAC），计算与验证必须一致。

## 7. 密钥销毁证明（audit P4-2）

- `DestructionProof` 的 HMAC 签名使用 **HMAC-SM3**（替换遗留 HMAC-SHA256）。
- 证明中的 `material_hash` 仍为 **SHA-256**（`hash_algorithm="SHA256"` 字段描述的是材料哈希，
  非签名 HMAC），两通道/各后端一致。

## 8. 审批工作流：身份来自认证主体（audit B7-a）

审批的**请求方、审批人、审批人角色**一律由服务端从**认证的 API Key** 推导，不再采信请求体：

| 端点 | 服务端派生字段 | 请求体中的同名字段 |
|------|----------------|---------------------|
| `POST /v1/approvals` | `requestor_id` = 认证 Key 的 `key_id`；`tenant_id` 按 §2 规则解析 | `requestor_id` 忽略（仅告警） |
| `POST /v1/approvals/{id}/approve` | `approver_id` = 认证 Key 的 `key_id`；角色 = 认证 Key 权限映射 | `approver_id` / `approver_role` 忽略（仅告警） |
| `POST /v1/approvals/{id}/reject` | 同上 | `rejector_id` / `rejector_role` 忽略 |
| `POST /v1/approvals/{id}/cancel` | `requestor_id` = 认证 Key 的 `key_id` | `requestor_id` 忽略 |

由此得到三条硬性约束：

1. **一把 Key = 一票**。多方法人法定人数（如密钥导出的 `Triple`）需要**多把不同的 Key**，
   同一把 Key 重复提交不同 `approver_id` 不再计票。
2. **角色不可自选**。审批人角色由 Key 权限映射（ReadOnly→User、Operator→Operator、
   KeyAdmin→Manager、SecurityOfficer→SecurityOfficer、AuditAdmin→User）；
   审批人级别低于操作所需级别时直接拒绝（403）。
3. **自助审批被拒**。请求方与审批人同为一把 Key 时，引擎的自审批保护生效（403）。
   取消请求同样只有发起方可用（他人 404）。

另外，审批请求的资源必须属于该请求的租户，否则返回脱敏的 404（不泄露资源是否存在）。

> 兼容性：请求体中上述字段仍可发送（未知字段被忽略），服务端会记录 `warn` 日志提示
> 这些字段不再生效；新客户端应停止发送。

## 测试固化

`tests/api_integration.rs` 的 `p43_*` 用例对同一批请求断言 REST 与 gRPC 的：
- 加解密往返结果一致（SM4/AES 在 format 2 下的 AAD 绑定回环）；
- 租户越权在两条通道均被拒；
- 导出均为包裹语义（`wrapped_key` 非明文、含 `encrypted_transport_key`）；
- 共享错误码（`KeyNotFound`/`InvalidRequest`/`Forbidden`）在两通道语义对齐。

第 3 节的 ⚠️ 分叉行**不在**断言范围内，作为已知记录保留，待独立 PR 修复后并入。
