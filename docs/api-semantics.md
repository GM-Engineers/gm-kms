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
> role = "key-admin"          # read-only | operator | key-admin | security-officer | audit-admin | tenant-admin
> tenant = "acme"             # 绑定租户：服务端据此推导租户
> secret_env = "KMS_API_KEY_ACME"   # 密钥存放于环境变量，不写入配置文件
> ```
>
> 未绑定租户的 Key 启动时会打印 `warn` 日志（因为它仍依赖调用方自报租户）。
>
> 配置校验（audit B7-g）：空密钥、重复密钥、重复 `key_id` 均导致**启动失败**。

## 3. 错误映射

同一 `ApiError` 变体在两通道的落地码：

| `ApiError` | REST 状态码 | gRPC `Status` | 对齐 |
|------------|-------------|---------------|------|
| `KeyNotFound` | 404（脱敏 "key not found"） | `NOT_FOUND`（脱敏） | ✅ |
| `NotFound` | 404 | `NOT_FOUND` | ✅ |
| `InvalidRequest` | 400 | `INVALID_ARGUMENT` | ✅ |
| `InvalidArgument` | 400 | `INVALID_ARGUMENT` | ✅ |
| `Forbidden` | 403 | `PERMISSION_DENIED` | ✅ |
| `PermissionDenied` | 403 | `PERMISSION_DENIED` | ✅（audit B7-g 补齐） |
| `BadRequest` | 400 | `INVALID_ARGUMENT` | ✅（audit B7-g 补齐） |
| `TooManyRequests` | 429 | `RESOURCE_EXHAUSTED` | ✅（audit B7-g 补齐） |
| `NotImplemented` | 501 | `UNIMPLEMENTED` | ✅（audit B7-g 补齐） |
| `QuotaExceeded` | 429 | `RESOURCE_EXHAUSTED` | ✅ |
| `Internal` | 500（脱敏） | `INTERNAL`（脱敏） | ✅ |

> 此前 `PermissionDenied`/`BadRequest`/`TooManyRequests`/`NotImplemented` 在
> `grpc.rs::api_error_to_status` 中落入 `_ => Status::internal(...)` 兜底，gRPC 侧报
> `INTERNAL` 而 REST 报 403/400/429/501（audit B7-g 已补齐映射）。
>
> **不存在的密钥版本**统一走 `KeyNotFound` → 404（脱敏），两通道一致。

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
- **缺省 `version` 的语义**（audit B7-d 更正，audit B7-g 补齐 REST 侧）：
  - REST：`version` 缺省为 **1**（`default_decrypt_version()`）；**显式传 `version: 0`
    同样归一为 1**（audit B7-g）。
  - gRPC：proto3 无法区分“未设置”与 0，因此服务端将 `version == 0` 归一为 **1**，
    与 REST 一致（`grpc.rs::decrypt`）。
  - 两通道的缺省值相同，但**均不代表“当前版本”**：密钥轮换后（当前版本 > 1），
    解密历史密文必须回显 `Encrypt` 返回的 `version`；不回显会按版本 1 选材，
    从而解密失败（fail-closed，不会静默使用错误密钥）。
  - 例外：`version` 缺省仅对“密钥当前版本就是 1”的密文成立。
- **不存在的密钥版本**是“资源不存在”，不是“算法非法”：后端统一返回
  `Error::KeyVersionNotFound`，API 层脱敏为 **404 `key not found`**（audit B7-g）。
  早期实现报 `InvalidAlgorithm`，会变成 400 并把内部文案回给客户端。

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
   KeyAdmin→Manager、SecurityOfficer→SecurityOfficer、AuditAdmin→User、
   **TenantAdmin→Admin**）；审批人级别低于操作所需级别时直接拒绝（403）。
3. **自助审批被拒**。请求方与审批人同为一把 Key 时，引擎的自审批保护生效（403）。
   取消请求同样只有发起方可用（他人 404）。

另外，审批请求的资源必须属于该请求的租户，否则返回脱敏的 404（不泄露资源是否存在）。

### 8.1 资源类型由操作推导（audit B7-g）

`resource_type` **不是**请求体字段的特权：它由 `operation` 推导（`key_delete`/`key_export`/
`key_rotate` → `key`，`high_value_key_create` → `key-request`（密钥尚不存在，批准的是创建
行为，因此不做“已存在密钥”的归属校验），`policy_change` → `policy`，`audit_access` →
`audit`，`mfa_change` → `mfa`，`tenant_admin` → `tenant`）。请求体里的 `resource_type`
与推导值不一致时**告警并忽略**。

> 原因：早期实现以请求体的 `resource_type` 决定是否做租户归属校验，调用方把密钥资源
> 标成 `"policy"` 就能跳过校验，把审批绑定到别的租户的密钥上。
>
> 修正（audit B7-h）：`high_value_key_create` 最初也被推导为 `key`，于是它要求一个**尚未
> 存在**的密钥，审批永远无法发起；改为 `key-request`。

### 8.2 `tenant_admin` 需要可达到的 `Admin` 级（audit B7-g）

`tenant_admin` 操作要求 `ApprovalLevel::Admin`，而 `Role::Admin` 之前没有任何 API Key 角色
能映射到（`read-only`/`operator`/`key-admin`/`security-officer`/`audit-admin` 只能到
`Single`/`Double`/`Triple`/`Manager`/`Single`），于是该类请求**永远无法被批准**。
新增 `tenant-admin` 角色（配置名 `tenant-admin`）映射到 `Role::Admin`；它只持有
`APPROVE_ACTION` 权限，不持有策略/审计/MFA 管理权，三员分立不受影响。

### 8.3 审批请求的可见性（audit B7-g）

绑定租户的 Key 只能读取/列举**自己租户**的审批请求：跨租户读取返回脱敏 404，
跨租户列举返回 403。未绑定租户的 Key 沿用本 API 其余部分的既有语义（自报租户）。

> audit B7-h 补齐：最初只收紧了**读**路径（读取/列举），**写**路径（审批/驳回）未收紧。
> 于是绑定租户的审批 Key 可以批准（或驳回）其它租户的请求，而被批准的请求正是导出该租户
> 密钥材料的凭据。现在 `approve`/`reject` 同样做租户校验（跨租户 → 脱敏 404）。

### 8.4 错误不再被压平（audit B7-g）

`reject` 路径此前把所有引擎错误（自审批、已投票、已过期、已终止）统一压成 404；
现在与 `approve` 路径一样按 `ApprovalError` 映射（自审批 → 403 等）。

> 兼容性：请求体中上述字段仍可发送（未知字段被忽略），服务端会记录 `warn` 日志提示
> 这些字段不再生效；新客户端应停止发送。

## 9. PBAC：两通道同源（audit B7-g）

REST 与 gRPC 通过**同一个**求值入口（`kms_api::auth::evaluate_pbac`）评估属性策略，
动作名与资源 id 逐字一致，共 23 个：

```
create_key  get_key  list_keys  delete_key  rotate_key  import_key  export_key
encrypt     decrypt  sign       verify      hmac       hmac_verify hash
dh_derive   envelope_encrypt  envelope_decrypt  envelope_rewrap
sm9_sign    sm9_verify  sm9_encrypt  sm9_decrypt  query_audit_events
```

> 原因：早期 gRPC 对全部 23 个方法都做 PBAC 求值，而 REST 有 6 个端点
> （`sign`/`verify`/`get_key`/`envelope_encrypt`/`envelope_decrypt`/`envelope_rewrap`）
> **完全不做**求值——被 gRPC 拒绝的客户端换到 REST 即可绕过。

### 9.1 空引擎 = 未启用（audit B7-g）

策略引擎对“未被任何策略覆盖”的请求返回 `Deny`。而服务端启动时**不加载任何策略**，
若直接沿用该语义，所有受 PBAC 保护的端点（含建钥、加密、解密）在**出厂状态下**
一律 403，KMS 不可用。

因此 API 层的语义分两种状态：

| 策略数量 | 语义 |
|----------|------|
| 0（出厂状态） | 属性级控制**未启用**，RBAC（API Key 权限位）是唯一闸门 |
| ≥ 1 **已启用** | 引擎默认拒绝生效，未被覆盖的请求一律拒绝（allow-list 语义可用） |

> 引擎自身的 `evaluate` 默认拒绝语义**未改动**；“空引擎不限制”只存在于 API 层的部署语义，
> 两通道共用同一入口，因此不会出现一通道放行、另一通道拒绝的分叉。显式 `Deny` 策略始终优先
> 于 `Allow`。
>
> 计数只包含**已启用**的策略（audit B7-h）：被禁用的策略不匹配任何请求，若把它计入，
> 就会在“什么都匹配不到”的状态下切到默认拒绝，把所有调用方锁在门外且无从查因。
>
> 策略只存在于内存中：**重启后全部丢失**，属性级限制随之失效。服务端每次启动都会打印
> `warn` 提示这一点（audit B7-h）。

## 测试固化

`tests/api_integration.rs` 的 `p43_*` 用例对同一批请求断言 REST 与 gRPC 的：
- 加解密往返结果一致（SM4/AES 在 format 2 下的 AAD 绑定回环）；
- 租户越权在两条通道均被拒；
- 导出均为包裹语义（`wrapped_key` 非明文、含 `encrypted_transport_key`）；
- 共享错误码（`KeyNotFound`/`InvalidRequest`/`Forbidden`）在两通道语义对齐。

第 3 节曾经存在的 ⚠️ 分叉已在 audit B7-g 中消除（`api_error_to_status` 补齐四个变体），
现在两通道的错误码完全对齐。

### Batch 7 / B7-g 的固化用例

| 前缀 | 覆盖的缺陷 |
|------|-----------|
| `b7g1_*` | 空策略引擎时服务端仍可用（PBAC 未启用）、RBAC 仍然生效、装入策略后恢复默认拒绝 |
| `b7g2_*` | REST 六个端点的 PBAC 覆盖 + 跨协议一致性（同一策略同时拒绝 REST 与 gRPC） |
| `b7g3_*` | 资源类型由操作推导、`tenant_admin` 可被批准、缺省租户为 `default`、reject 错误不被压平、跨租户不可读 |
| `b7g4_*` | 无审批权限的 Key 不能审批 |
| `b7g5_*` | 不存在的版本 → 404；REST `version: 0` 归一 |

另：`crates/kms-api/src/auth.rs` 与 `crates/kms-policy/src/engine.rs` 的单测固化 PBAC 的
引导语义与 `policy_count`；`src/cmd/server.rs` 的单测固化 API Key 配置校验；
`crates/kms-core/src/backup.rs` 的单测固化主密钥文件的原子写与不跟随符号链接。
