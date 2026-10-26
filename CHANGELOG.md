# Changelog

All notable changes to gm-kms will be documented in this file.

## [0.3.0] — Unreleased

### 上游审计整改（upstream audit remediation）

分支 `fix/upstream-audit-2026h2`（基线 `release/0.3.0` @ `51a8e16`）共 **36 个提交**，闭合上游审计报告复核确认的全部 **22 项**问题（21 项复核属实 + 1 项新发现的 P0 功能阻断），并追加两轮独立复核（B7-*）与缺口闭合（B8-*）。每项均带回归测试；每批提交前通过 `cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace`（nightly 与 CI 稳定版 1.88 双通道），以及 PostgreSQL/Redis 集成套件（`--ignored`，45 passed / 0 failed）。

#### Security

- **P0 — 接口层 AEAD 往返断裂（CRITICAL-NEW）**：REST/gRPC 的 decrypt 硬编码 `format_version: 0`，而 encrypt 产出 `format_version: 2`（AAD 绑定 `key_id`/`tenant_id`/`version`），GCM tag 校验必然失败——加解密在接口层完全不可用。`EncryptResponse` / `DecryptRequest` 增带 `format_version`，缺省按 v2 重算绑定 AAD，`format_version ∈ {0,1}` 的历史密文继续可解；REST 与 gRPC 两条通道对齐。
- **P1-3 — 请求租户来自已认证身份**：gRPC 与 REST 两个入口都从认证后的 API key 推导租户，不再信任请求体自报的 `tenant_id`；gRPC 侧移除空值默认 `"default"` 的静默放行。
- **P1-4 — fail-closed 启动**：PG 不可用 / init 失败 / `load_keys` 失败时生产模式启动失败，不再静默降级到内存密钥库；内存降级仅在显式 `dev_mode` / `allow_insecure` 下允许。`/v1/health`、`/readyz` 反映密钥库真实加载态。新增 `database.connect_timeout_secs`（默认 30，0 关闭）让拒绝在有限时间内可见。
- **P1-1 — 导出透传可信租户**：REST `export_key` 原硬编码 `""`，改为透传可信租户。
- **P1-2 / P2-8 — 审批绑定资源与有效期**：`is_approved` 增 `resource_id` 比对与 `Utc::now() <= expires_at` 判定；REST/gRPC 的 export/delete 传入被操作资源 id。基线对过期审批和绑定其他资源的审批一律返回 200 并交出 `wrapped_key`。
- **P2-4 — 轮换补审批守卫**：REST/gRPC `rotate_key` 补 `KeyRotate`（Double）审批守卫，统一由 `require_approval(op, resource_id)` 驱动，消除"枚举级别 vs 接口强制"的不一致。
- **P2-5 / P2-6 — 导出语义收敛与国密保护路径**：gRPC 导出改为与 REST 相同的包裹语义（返回 `wrapped_key` / `encrypted_transport_key`，明文材料不再直接回传）；导出保护新增 SM2 路径（SM2 加密传输密钥 + SM4-GCM 包裹），RSA-OAEP 保留为兼容选项。
- **P2-2 / P2-3 / P3-4 — 导出/解密版本语义**：`ExportKeyRequest` 增 `version`，允许导出 Obsolete/历史版本；统一 Postgres 与 Software 后端的 decrypt 版本选择行为；移除 `export_id`/`expires_at` 死字段。
- **B7-a — 审批身份来自已认证 key**：requestor/approver/rejector 与角色改由认证身份推导，body 自报字段仍接受但忽略并告警。此前单个 API key 可以用三个不同的 body 名字投三张票，满足导出所需的 Triple quorum。引擎同时拒绝低于操作所需级别的审批，并保留已达成的最高级别；审批请求的资源必须属于该请求的租户。
- **B7-g — 审批资源类型由操作推导**：此前把 key 资源标成 `policy` 即可把审批绑到别的租户的 key。类型改由操作推导，body 中的冲突值记录后忽略。
- **B7-g — 关闭 PBAC 的协议切换旁路**：gRPC 23 个方法全部评估属性策略，REST 侧 6 个 handler（`sign` / `verify` / `get_key` / `envelope_encrypt` / `envelope_decrypt` / `envelope_rewrap`）从不调用 `check_rest_pbac`——被 gRPC 拒绝的调用方换 REST 即可通过。补齐后两通道评估同一策略，动作名与 resource id 与 gRPC 逐字一致。
- **B7-g — PBAC 未配置时不再全量 403**：服务器启动时构造空策略引擎且从不加载策略，`PBACEngine::evaluate` 的默认拒绝使每个 PBAC 端点一律 403（KMS 开箱不可用）。改为：未配置策略 → 属性控制不生效，仅以 API key 权限位掩码为门；配置了策略 → 恢复默认拒绝。REST/gRPC 共用 `auth::evaluate_pbac` 一个评估点，两协议不再可能分歧。
- **B7-b — REST HMAC / DH derive 补齐 PBAC 与租户隔离**：REST `hmac`/`hmac_verify` 跳过 PBAC；DH derive 端点既无 PBAC 也无租户校验，可用他人私钥导出共享密钥。`derive_shared_secret` 改为接收操作租户并由各后端实现校验归属——校验进入 KeystoreBackend 契约而非 API 层约定（对实现方是破坏性变更；0.3.0 未发布前可接受）。
- **B7-c — 未知版本 fail-closed**：trait 默认的 `get_key_material_version` 忽略请求版本、返回当前材料，版本化导出因此交出错误的密钥并附上按错误密钥算的指纹；Redis 包装器同样未覆写而遮蔽了软件后端正确的版本处理。默认实现改为只服务当前版本、旧版本 fail-closed。
- **B7-f — 模拟 TPM 不再绕过生产门禁**：模拟 TPM 后端未走与内存软件降级相同的 fail-closed 判定，可能被误用于生产。
- **B7-g — API key 配置校验**：启动时拒绝空/空白 secret、重复 secret 与重复 key id。此前一个已设置但为空的 secret 环境变量会注册一个**空**凭据，而 `x-api-key` 头为空即可通过常量时间比较认证。
- **B7-f — 熵源失败不再 panic**：OS CSPRNG 助手改为返回错误，熵源故障不会在请求路径上变成拒绝服务。
- **P3-2 — DRBG 与随机源**：DRBG 增实例化 KAT 自检与周期重播种；密钥材料与 nonce 统一走 OS CSPRNG，DRBG 仅限非密钥场景。
- **P4-2 — 密钥销毁证明改用 HMAC-SM3**（原 HMAC-SHA256）。
- **B9-a — PBAC 策略持久化，消除静默的属性级控制降级**：策略此前只存在引擎内存里，既不落库也不在启动时加载，运维装好策略后一重启（扩缩容 / 故障恢复 / 升级）属性级限制就全部消失，引擎回落到“只看 API Key 权限位”一道闸门，且**没有任何拒绝信号**。现在策略写穿到 PostgreSQL 的 `policies` 表（`kms-policy` 新增 `PolicyRepository` trait 与 `PostgresPolicyRepository`），启动时加载回引擎。
  - **fail-closed 启动**：策略表读不到时**拒绝启动**，不把“读不到”当成“没有策略”。两者在 API 层无法区分，当成后者就是静默降级；没有 PostgreSQL（开发 / 降级模式）时保持纯内存并在启动日志说明。
  - **写穿方向同理**：落库失败就不进内存（`POST /v1/policies` 答 500），不出现“内存里有、库里没有”的策略——那种策略看起来已安装，直到下次重启静默消失。
  - **新增 `DELETE /v1/policies/{id}`**：此前策略装上后**没有任何方式撤销**（内存里也一样）；持久化后一条装错的策略会永久生效。未知 id 答 404。
  - 装/删策略均记审计事件 `policy_changed`（该事件构造函数此前从未被调用）。`effect` 列存 serde 形式（`ALLOW`/`DENY`）而非 `Debug` 形式（`Allow`/`Deny`），后者无法往返。
  - 护栏：`crates/kms-policy` 单测 9 例（写穿方向、落库失败时内存不变、读不到的存储报错而非空集、加载后仍参与求值、`effect` 往返）；`tests/api_policy_pg_integration.rs` 真实 PostgreSQL 6 例（落库、逐字段往返、**重启后仍在且仍生效**、删除后不复活、建表幂等）。
- **B9-b — PBAC 策略的租户维度**：策略此前只有 subject / resource / action 三个维度，**没有租户**——一条“某类调用方不得导出”的策略无法只作用于某一个租户，只能全局生效，或退回到用多把 API Key + 审批做隔离（而后者管不到“同租户内的不同动作”）。
  - `Policy` 新增可选的 `tenant` 字段（`Option<String>`，`serde(default)`）。省略 / 空串 = **不限租户**，对所有租户生效，与租户维度出现之前逐字一致；给定值 = 该策略只命中那个租户，支持 glob（`tenant-*` 覆盖一族租户）。
  - 引擎新增 `tenant_matches`：策略有 `tenant` 而请求**没有**租户时**不匹配**。调用方若不知道自己身处哪个租户，就不能靠一条针对别的租户的规则拿到权限；失败方向是收紧的（落到默认拒绝，而不是被放行）。
  - 参与匹配的是**有效租户**（API Key 绑定租户优先，否则请求自报），且在**策略判定之前**解析完成——因此判定用的租户就是该操作实际使用的租户，两者不可能分叉。REST 23 个端点与 gRPC 23 个方法各自解析自己的有效租户，但都把同一个字符串交给共用的 `auth::evaluate_pbac`，**换协议不能绕过**租户限定策略。
  - `policies` 表新增 `tenant` 列（`ALTER TABLE … ADD COLUMN IF NOT EXISTS`）。**B9-b 之前写入的行**（`tenant IS NULL`）加载后仍是不限租户的策略——升级不会让既有策略突然变宽或变窄。
  - 破坏性变更（0.3.0 未发布前可接受）：`evaluate_pbac` / `check_rest_pbac` / `KmsGrpcService::check_pbac` 新增 `tenant` 参数；`POST /v1/policies` 与 `GET /v1/policies` 的 DTO 新增 `tenant` 字段；Rust SDK 的 `CreatePolicyRequest` / `Policy` 同步新增 `tenant`。
  - 护栏：`crates/kms-policy` 单测 5 例（租户限定只命中自己的租户、无租户的请求不命中、不限租户的策略对所有租户生效、glob 覆盖一族、租户限定的拒绝不影响其它租户）；`crates/kms-api` 单测 1 例（租户维度穿透 `evaluate_pbac`）；`tests/api_integration.rs` 3 例（租户限定的拒绝只覆盖它点名的租户、无租户的请求不落入租户限定策略、**换协议不能绕过**）；`tests/api_policy_pg_integration.rs` 真实 PostgreSQL 2 例（`tenant` 列往返、无 `tenant` 的旧行仍按不限租户加载）。

#### Fixed

- **B8-d — 审批门的 400 / 403 语义统一**：REST 对审批门的拒绝答 400，而 gRPC 同一道门答 `permission_denied`——一个格式合法但未授权的请求被报成畸形调用，且两条通道在同一道安全门上分歧。拒绝统一为 `ApiError::Forbidden`（403）；400 保留给缺失或畸形的 `approval_id`（那是畸形调用，不是授权失败）。语义表 `docs/api-semantics.md` §8.5 补该区分。
- **B8-b — 缓存条目一步解析**：每次操作都是"lazy-load 写回缓存 → 再从缓存读出"两步，而 `insert_with_eviction` 在插入后按上限淘汰，上限为 0 时写回即淘汰自己的条目——**专门用来少留密钥材料在内存的配置反而让每个密钥都报 `KeyNotFound`**。新增 `entry_for` helper 直接返回条目（命中取缓存，未命中取新加载），8 个读操作改用。
- **B8-g — 写路径不再依赖缓存驻留**：轮换与删除改为在缓存修改闭包内做 `can_rotate()` 检查，而闭包无法返回错误，于是 panic（`rotate_key: can_rotate returned false after try_read success`）打挂请求；现在报 `KeyOperationNotAllowed`，与软件后端一致并由 API 层映射为 4xx。写入顺序改为"先落库、后刷新缓存"——旧顺序在数据库写失败时留下缓存声称 obsolete 而数据库仍称 active，且新密钥材料只存在于缓存中，一次失败的轮换会静默丢密钥。
- **B8-f — 单条坏密钥行不再拖垮整个 KMS**：一条无法使用的密钥行不再导致启动/加载失败。
- **B8-a — 导入走共享的算法感知校验器**：PG 后端的 RSA-4096 导入长度校验改按算法解析区间，与其他后端走同一校验器。
- **B8-c — 启动时校验最近一次备份可打开**：`KeyBackupService::load_or_create` 只校验主密钥本身，从不打开备份文件，损坏或用另一把主密钥写入的备份要等到真正恢复时才暴露。新增 `verify_latest_backup()`，用与恢复相同的工作打开最新备份（SM3-HMAC 验签 + SM4-GCM 解密 + SM3 材料哈希），明文由 `zeroize::Zeroizing` 持有。文件级失败记 `tracing::error!` 但不阻断启动——主密钥本身已在 `load_or_create` 中 fail-closed，拒绝启动会让运维无法进入实例修复坏文件。
- **B7-d — gRPC decrypt 版本缺省归一**：proto3 无法区分未设置与 0，gRPC 因此请求版本 0 并报 `key version 0 not found`，而 REST 缺省为版本 1。handler 现在把 0 映射到同一缺省。
- **B7-f — 加密主密钥文件原子创建**：改用 owner-only 模式原子写入，关闭此前短暂全局可读的窗口。
- **B7-g — 版本语义对齐 + 密钥文件原子写**（见上）。
- **B7-f — `ExportKeyResponse` 使用新字段号**并保留被复用的旧号，避免旧客户端误解析新 wire 类型。

#### Added

- **P2-1 — 托管 HMAC-SM3 密钥规格与独立 RPC**：新增 `KeySpec::Sm3Hmac` 与独立的 `Hmac` / `HmacVerify` RPC（`{key_id,data,aad?} -> {mac,version}`），走 `gm_crypto::sm3::Sm3Hmac`，不复用 AES-GCM 分支。
- **P2-7 — 备份主密钥跨重启持久化**：`MasterKey` 复用 KEK 的 `export_encrypted`/`import_encrypted` 机制接入启动流程；启动时校验能否解开上次备份，失败告警。
- **B7-e — `[[api_keys]]` 配置段**：key_id、role、tenant、secret_env。密钥从**环境变量**读取而非配置文件；未知角色或缺失 secret 使启动失败；未绑定租户的 key 在启动时告警。部署指南与语义表同步说明该配置面。
- **B8-e — Rust SDK（`sdk/rust`，包名 `gm-kms-sdk`）**：仓库原有 Go/Python/JavaScript SDK，Rust 消费方需自行拼装 REST 调用、base64 编码与逐端点的租户位置，且服务端 wire 格式变动时构建不会报警。新增为 workspace member（`publish = false`），`cargo test --workspace` 与 `cargo clippy --all-targets` 自动覆盖。REST/JSON 通道，无需 protoc、无 gRPC 绑定、无代码生成；`reqwest` + `rustls-tls` 不依赖系统 OpenSSL。
  - 护栏：`tests/contract.rs` 形状护栏 26 例，双向断言服务端 DTO 接受 SDK body、SDK DTO 接受服务端应答，逐层比对字段名；`tests/e2e.rs` 语义护栏 5 例，跑真实 `kms-api` server（loopback）：密钥全生命周期（create → encrypt → decrypt → hmac → hmac/verify 篡改 tag → 三个**不同** key 的三次审批 → export）、无审批导出、过期审批解锁导出、未知 key；另有 5 个 client 单元测试与 3 个 doctest。
  - 护栏当场查出两处缺陷：导出缺审批实际答 400（请求畸形）而非 403（语义见 `docs/api-semantics.md` §8.5）；`Client::endpoint` 在 base URL 以斜杠结尾时拼出 `https://host/api//v1/keys`。
- **B8-d — 审批恢复钩子**：`ApprovalEngine::restore_request` / `ApprovalManager::restore_request`，供持久化层在不延长生命周期的前提下重新装载请求。`create_request` 始终由所需级别推导新的 `expires_at`，因此"已批准但已过期"的请求无法被构造；恢复的请求保留自己的截止时间与自己的投票，重复 id 被拒绝而非静默覆盖活跃请求。

#### Changed

- **P3-1 — 分离"可生成 / 可导入 / 可声明"三清单**：校验层只放行真正支持的类型；未实现类型返回明确的"暂不支持"，不再以别的算法的名义通过。
- **P4-1 — 删除遗留 `Encryptor`/`Decryptor`/`AlgorithmFactory` 层**：避免与服务层出现两套 AAD 绑定的漂移实现。
- **P3-3 — HSM/TPM 表述改为"适配架构预留（当前 stub/模拟器）"**：仓库与 GitHub 描述同步。
- **B7-g — `tenant-admin` 角色**：映射到 `Role::Admin`，使 `tenant_admin` 操作可被审批。该角色只持 approve 权限，三名审批人的职责分离不受影响。
- **B7-g — 审批请求的读取/列举限定为拥有它的租户**；拒绝路径的引擎错误不再一律压成 "not found"，自拒为 403。
- **B7-g — Go SDK 不再发送服务端已忽略的身份字段**（`approver_id` / `approver_role` / `rejector_id` / `rejector_role` / `requestor_id`），这些字段改由服务端从 API key 推导。
- **B7-g — PBAC 策略持久化（已由 B9-a 实现）**：此前仅存内存、不落盘、不在启动时加载，重启后属性限制全部消失。**B9-a 已实现持久化 + fail-closed 启动**，原先登记为已知限制的条目从两份 README 的已知限制表中移除。
- **B8-a — `create_software_keystore` / `create_software_keystore_inner`** 走共享校验器。

#### Documentation

- **P4-3 — `docs/api-semantics.md` REST/gRPC 语义对照表**：含租户缺省、错误映射、导出语义与版本行为，并以测试固化。
- **B7-a / B7-b / B7-c / B7-d / B7-e / B7-g** 的语义同步写入该表；其中"两通道此处行为一致"的旧说法有误，已更正。
- **`docs/api-semantics.md` §8.5** 增补审批门的 400-vs-403 区分表（B8-d）。
- **`docs/api-semantics.md` §9.2** 新增“PBAC 策略持久化与 fail-closed 启动”（B9-a）：写穿方向、启动时的建表 / 加载 / 拒绝启动三种结果，以及为什么“读不到”不能当成“没有策略”。
- **`docs/api-semantics.md` §9.3** 新增“策略的租户维度”（B9-b）：`tenant` 字段的匹配规则表（不限租户 / 命中自己的租户 / glob / 无租户的请求）、“为什么无租户的请求不匹配租户限定策略”、以及“参与匹配的是有效租户且在判定前解析完成”对跨协议一致性的意义。
- **部署指南** 的 PBAC 章节改写：策略改为持久化并跨重启生效，新增 `DELETE /v1/policies/{id}` 用法，并写明策略表读不到时服务拒绝启动。
- **部署指南** 新增“Scoping a policy to one tenant”（B9-b）：`tenant` 字段的用法、glob、匹配用有效租户、旧行兼容。
- **README / `README.en.md`**：PBAC 策略不持久化的已知限制条目**移除**（B9-a 已修复），测试统计刷新。
- **README / `README.en.md`** 的仓库定位与 HSM/TPM 表述随 P3-3 更新。

### Added

- **Opt-in background preload via `PostgresKeystore::spawn_load_keys()`** (PR-4.19 / PR-4.17 follow-up): new method returns a `tokio::task::JoinHandle<Result<usize>>` so callers can decouple startup blocking from DB preload. Pre-PR-4.19 callers used `await pg_keystore.load_keys()` which blocked the gRPC/HTTP listener by 5–10 seconds for 10k keys (O(N) DB queries + KEK decrypt × N). Post-PR-4.19 the server's `create_software_keystore` and `create_software_keystore_inner` helpers fire the preload in a background task and return immediately; PR-4.17's lazy-load covers any keys not yet cached when the first request lands. Internal refactor: extracted `decrypt_material_static(kek, key_id, encrypted)` from `decrypt_material` so the spawned task can decrypt without a `&self` borrow; added shared `load_one_into_cache` helper used by both sync (`load_keys`) and async (`spawn_load_keys`) paths. `PostgresKeyRepository` now derives `Clone` so the spawned task can take its own handle to the `sqlx::PgPool` (Arc-backed; zero-cost clone). Four new tests: 3 unit tests verifying the helper's type shape and early-return error path; 1 `#[ignore]` live-DB integration test verifying that sync and background preload agree on key count. Bumps the workspace to 0.2.7 (patch; new API, no breakage).

- **`PostgresKeystore` cache-miss lazy load** (PR-4.17 /
  PR-4.15 follow-up): `verify_tenant` now falls back to a
  DB round-trip via the new `load_entry_from_db` helper
  when the bounded in-memory cache misses. Before PR-4.17,
  keys beyond `with_in_memory_cap(n)` were silently
  unreachable (only the first `n` keys loaded at startup
  worked). After PR-4.17 the cap controls **memory
  usage**, not **key access** — keys beyond the cap are
  pulled in on first use and cached via
  `BoundedKeyCache::insert_with_eviction` (which honours
  the FIFO cap automatically). Tenant isolation
  (PR-1.2 conflation) is preserved: lazy-load + wrong
  tenant still returns `Error::KeyNotFound`. KEK-rotation
  failures during lazy load are surfaced as
  `Error::Internal` with a loud comment pointing operators
  at the rotation. Four new tests: 3 live-DB `#[ignore]`
  integration tests (`pr417_lazy_load_*`) cover
  cap-beyond / unknown-id / wrong-tenant scenarios; 1 unit
  smoke test (`pr417_helper_is_inherent_method`) verifies
  the helper is reachable via inherent impl (no public
  API change). Bumps the workspace to 0.2.6 (patch; no
  API change).

- **PostgreSQL keystore in-memory cap + FIFO eviction**
  (PR-4.15 / P2-10): pre-PR-4.15, `PostgresKeystore.keys`
  was an unbounded `RwLock<HashMap<Uuid, KeyEntry>>` with no
  cap and no eviction policy. Production deployments with
  thousands of keys would consume hundreds of MB of RAM for
  material that was rarely (if ever) accessed again. PR-4.15
  introduces:
  - New `kms-keystore::bounded_cache::BoundedKeyCache`
    type: FIFO eviction via `VecDeque<Uuid>`, optional
    `capacity: Option<usize>`. Default `None` reproduces
    pre-PR-4.15 behavior byte-for-byte.
  - `PostgresKeystore::with_in_memory_cap(n)` builder
    opting the keystore into the cap. The cap is enforced
    on every `insert_with_eviction` call (which now
    replaces all 11 `keys.write().insert(...)` sites).
  - Six new mutating helpers (`mutate`,
    `mutate_and_insert`, `remove`, `try_read`, etc.) replace
    the old `keys.read()` / `keys.write()` lock ceremony
    with a more ergonomic async-free API.
  - 8 new unit tests in `pr415_*` covering unbounded,
    cap-respecting, bulk-eviction, and re-insertion
    edge cases.
  - Bumps workspace version to 0.2.5 (patch; default
    behavior unchanged).
  True lazy load (replacing eager `load_keys()`) is
  deferred to a follow-up PR; this PR caps the eager
  load to `take(cap)` entries.

- **SM2 private scalar range validation** (PR-4.14 / P2-9): new
  `kms_core::sm2_scalar` module with `sm2_scalar_in_range()`
  helper that checks a candidate 32-byte SM2 private key is
  in `[1, n-1]` per GB/T 32918.1-2016 §5.1.4. Pre-PR-4.14
  the software keystore's `generate_sm2_key()` generated raw
  32 random bytes without range validation, exposing a
  (theoretical) attack surface against upstream scalar
  generation. PR-4.14 routes SM2 key generation through the
  canonical `Sm2KeyPair::generate()` path (which already
  enforces `[1, n-1]` via rustcrypto `SecretKey::random`)
  and adds a defense-in-depth `sm2_scalar_in_range` re-check.
  New `KmsError::InvalidSm2Scalar(String)` variant surfaces
  any future upstream regression as a typed error. The
  `SM2_CURVE_ORDER_N` constant is exported and locked by a
  unit test that compares against the GB/T 32918.1-2016
  reference value. Nine new unit tests in
  `pr414_sm2_scalar_tests` cover the boundary conditions
  (accept 1, accept n-1, reject 0, reject n, reject n+1,
  reject wrong lengths, reject MSB-overflow). Bumps
  workspace version to 0.2.4 (patch; new public surface is
  additive).

- **WORM audit HMAC signing-key path isolation** (PR-4.11 / P2-6):
  the WORM-backed signed-audit logger (`kms-audit::worm_logger`)
  now allows operators to store the HMAC signing key at a path
  separate from the WORM log. Pre-PR-4.11, the key was a sibling
  file (`<worm_path>.signing_key`); a compromised process could
  replace both the log AND the key, defeating WORM's integrity
  guarantee. PR-4.11 adds:
  - `WormSignedAuditConfig::with_signing_key_path(PathBuf)`
    builder;
  - `WormSignedAuditConfig::load_or_create_with_key_path(
    worm_path, key_path, seq)` factory;
  - `WormSignedAuditConfig::effective_signing_key_path()`
    accessor (single source of truth);
  - the `signing_key_path: Option<PathBuf>` field on the config
    struct (`None` preserves pre-PR-4.11 sibling-path behavior).
  Six unit tests in `pr411_signing_key_isolation_tests` cover
  default-behavior preservation, custom-path override, 0600
  enforcement, and existing-key loading. KEK integration
  (`KekSource` wrapping the HMAC key) is deferred to PR-4.12
  to keep this PR within kms-audit crate only.

- **KEK source layering** (PR-4.7 / P1-7 阶段 1/3): new
  `kms_core::kek_source` module with `KekSource` enum (Env / File
  / Missing). Operators can now load the master KEK from either
  `KMS_KEK` (env var, hex) or `KMS_KEK_FILE` (path to a file with
  mode 0600 on Unix; the mode bit is enforced and any other mode
  is rejected with a clear error). File beats env when both are
  set (file is more secure). Replaces the inline hex-parsing in
  `kms-keystore::postgres` and `kms-api::mfa`, removing duplication.
  HSM / TPM provider integration is scoped for PR-4.8;
  KEK rotation (kek_label persistence + multi-active-KEK) is scoped
  for PR-4.9. Added 17 unit tests in `pr47_kek_source_tests`.

### 重塑定位（Breaking change in messaging, not code）

本版本将项目定位从"生产 KMS"调整为"Rust 国密 KMS 参考实现"，面向学习、内部演示、生态集成和小规模辅助场景。**不替代**商业云 KMS，**未通过**密评或等保认证。

- README.md / README.en.md 全面重写：顶部定位声明、"本项目是什么 / 不是什么"、适用 / 不适用场景矩阵、合规自评估表
- 新增 LEARN.md：按依赖关系组织的代码导读，10 个推荐起点
- 删除 deploy/kubernetes/kms-hpa-pdb.yaml、deploy/kubernetes/kms-monitoring.yaml（暗示生产的资产）
- deploy/kubernetes/ 内容迁移到 examples/k8s-demo/，README 重写为 demo 定位
- operators/kms-operator/ 和 providers/terraform/ README 顶部加 experimental / not maintained 警告
- 测试统计表数字修正：877 实测 vs 959 历史声称

### Added

- **TLCP (GB/T 38636-2020) REST 入口**：新增 `src/cmd/tlcp_listener.rs`，镜像 `gm_listener.rs` 模式，使用 `gm_tlcp::TlcpAcceptor` 替代 `gm_tls::TlsAcceptor`
- 新增 `[rest_tls].backend = "tlcp"` 配置项（向后兼容，`gm` / `rustls` 仍可用）
- 新增集成测试 `crates/kms-api/tests/tlcp_integration.rs`：TLCP 握手 + REST 端到端、双证书缺失失败、握手失败处理
- 新增文档：
  - `docs/guides/tlcp-deployment.md`：TLCP 模式部署指南
  - `docs/wiki/tlcp.md`：TLCP vs TLS 1.3 概念差异
  - `LEARN.md`：代码导读

### Changed

- `src/cmd/config.rs::RestTlsConfig`：新增 TLCP 双证书路径字段（`tlcp_sign_cert_path`、`tlcp_enc_cert_path`、`tlcp_sign_key_path`、`tlcp_enc_key_path`）
- `src/cmd/server.rs`：REST 服务启动按 `backend` 字段 dispatch 到对应 listener
- `kms.toml.example`：`[rest_tls]` 区块增加 TLCP 配置示例
- 顶层 `Cargo.toml`：新增 `gm-tlcp = "0.6"` 依赖；`[patch.crates-io]` 加入 gm-tlcp（与其他三个 gm-* crate 同一 git rev）

### Fixed

- README 测试统计表数字与实测一致（877 passed，含 18 个 ignored）
- README 合规自评估表改为如实标注（已实现 ≠ 已认证）
- **`crates/kms-core/src/algorithms_impl.rs::Aes256GcmDecryptor::decrypt`**：修复 12-byte nonce 越界 panic。
  旧实现 `if len >= 12 { [4..16] }` 对 len ∈ [12, 16) 的密文会 panic；外部导入 / 跨实现密文可触发进程崩溃（DoS）。改用穷举 `match` 接受 12（RFC 5116 §5.2 固定 N_MIN = N_MAX = 12 octets）与 16（自产 counter）两种格式，其他长度返回 `DecryptionFailed`。
  新增 4 个回归测试覆盖 12-byte 外密文解密、16-byte 截断为 12-byte 解密、长度 8 与 15 负测试。
  （对应 P0-1）
- **`crates/kms-api/src/service/crypto_service.rs`**：P0-2 修复跨租户访问走完密码路径并泄露密钥枚举 oracle。
  旧实现在 `keystore.sign` / `decrypt` / `encrypt` / `verify` 走完后才校验 `tenant_id`，造成：远程 HSM/TPM 签名额度被未授权请求消耗；响应时间可区分「不存在」与「被其他租户拥有」；错误码 `KeyNotFound` (404) 与 `Forbidden` (403) 可区分。
  改用 `fetch_owned_key_meta` 前置校验：密钥元数据 + 租户一致，未通过则统一返回 `KeyNotFound`。移除原后置 `get_key_metadata` 调用，改用前置获取的 `meta` 给批量指标复用。
  `crates/kms-api/src/service/key_service.rs` 一致性：`rotate_key` / `delete_key` / `get_key` / `export_key` 的跨租户返回从 `Forbidden` 改为 `KeyNotFound`，与「不存在」不可区分。
  新增 11 个测试：CryptoService 5 个跨租户 + 1 个非存在 + 1 个响应等价字节比较 + 1 个 keystore 不被调用；KeyService 3 个跨租户 + 1 个非存在。
  （对应 P0-2）
- **`crates/kms-keystore/src/software/mod.rs` + `crates/kms-keystore/src/postgres.rs`**：P0-3 修复 keystore trait 层 `_tenant_id` 参数被忽略的纵深防御漏洞。
  旧实现所有 sensitive 方法（`encrypt` / `decrypt` / `sign` / `verify` / `rotate_key` / `delete_key` / `export_key_material` / `get_key_material` / `get_key_material_version`）的 `_tenant_id` 参数均被下划线开头直接忽略——若新增调用方（REST/gRPC handler、CLI、运维脚本、内部 task）绕过 PR-1.2 上层校验直接调用 keystore，将导致跨租户越权访问。
  新增私有 `verify_tenant(key_id, tenant_id) -> Result<()>` helper：调 `get_key_metadata` 取元数据并比对 `tenant_id`，不匹配返回 `Error::KeyNotFound(key_id)`（与 PR-1.2 上层一致：missing 与 wrong-tenant 不可区分）。每个 sensitive 方法首行调用 `verify_tenant`；参数 `_tenant_id` → `tenant_id`（已实际使用，不再是 placeholder）。`generate_key` / `import_key_material` / `destroy_key*` 不需要校验（前者创建者即租户；后者 trait 当前无 tenant 参数）。
  新增 12 个测试：9 个跨租户返回 `KeyNotFound`（sign / decrypt / encrypt / verify / export_key_material / get_key_material / get_key_material_version / rotate_key / delete_key）+ 3 个正向不破坏（Ed25519 / SM2 sign/verify、AES encrypt/decrypt）。
  （对应 P0-3）

- **AAD 绑定到 `(key_id, tenant_id, version)`（P0-5 / PR-1.4）**：AES-GCM / SM4-GCM 用户数据加密以及 Postgres KEK 信封、KeyService 导出信封都绑定稳定上下文后，AGC 标签检查必须失败—记帐 AAD blob 。 
  旧实现 `seal_in_place_separate_tag` 传入 `Aad::empty()`：对于攻击者可以互换持久化存储行的场景，同一租户的合法 `decrypt(key_b)` 调用可能被递给 key-a 的密文。 
  新增 `crates/kms-core/src/aad.rs`：`Purpose` 枚举区分 `UserData` / `KekWrap` / `ExportWrap`； 42 字节 v2 AAD 格式 = magic(2) + aad_version(2) + purpose(2) + key_id(16) + SHA-256(tenant)[..16] + version(4)。三个公开构造器：`user_data_aad`、`kek_wrap_aad`、`export_wrap_aad`，以及 9 个 aad.rs 单元测试。 
  wire 格式向后兼容：`Ciphertext::format_version ∈ {0, 1}` 走 empty-AAD 分支；`format_version == 2` 走绑定-AAD 分支；未知 format_version 返回 `Error::InvalidCiphertext`。  五个调用点改动：
  - `crates/kms-keystore/src/software/mod.rs`：`encrypt`（AES / SM4 两个分支） 使用 `user_data_aad(*key_id, &entry.meta.tenant_id, entry.meta.version)`，输出 `format_version = 2`；`decrypt` 两 个分支按 `format_version` 分流。
  - `crates/kms-keystore/src/postgres.rs`：四个调用点（load_keys、generate_key、rotate_key 的 encrypted_dek、import_key_material）传 `key_id: &Uuid` 给 `encrypt_material` / `decrypt_material`，信封 AAD  为 `kek_wrap_aad(*key_id)`；`crypto_encrypt` / `crypto_decrypt` 加 `tenant_id: &str` 参数以使用 `user_data_aad`。SM2 分支不变（SM2 是公钥加密，无 AEAD-AAD）。
  - `crates/kms-api/src/service/key_service.rs`：导出信封使用 `export_wrap_aad(*key_id, tenant_id)` 替代 `Aad::empty()`。
  - `crates/kms-core/src/lib.rs`：增加 `pub mod aad` 及再导出。
  新增 8 个回归测试：AES/SM4 往返 、AES/SM4 跨 key 复制拒绝、跨 version 伪造拒绝、`format_version ∈ {0, 1}` 向后兼容、未知 format_version 拒绝、跨租户 AAD 发散验证。  跨租户 AES-GCM “零 AAD” 场景（与 PR-1.2 / PR-1.3 形成纵深防御：即使上层漏检，标签不匹配也拒绝）。
  （对应 P0-5）

### Security

- **SM9 key generation no longer reports success on empty material**（PR-4.5 / P1-5）。PR-4.5 之前 `SoftwareKeystore::generate_key(Sm9Signing | Sm9Encryption)` 静默返回 `Ok(KeyMeta)` 且 `material: Vec::new()`；后续所有 SM9 加解密调用都会在运行时失败，但 API 表面上报“创建成功”。PR-4.5 改为 `Err(Error::NotImplemented)`，与 RSA-4096 分支对称；rotate 路径仍保留原有的 `Error::KeyOperationNotAllowed` + Sm9RotationAdapter 提示。
- 新增 4 个 `pr45_sm9_generate_tests` 单元测试（SM9 signing / encryption 返回 NotImplemented，RSA-4096 不变，SM2 仍正常）；并删除依赖该错误行为的旧 `test_sm9_direct_keystore_rotation_errors` 测试（该路径已无法从公开 API 到达）。
- 新增双语需求文档 `docs/requirements/N4-sm9-generate-not-implemented.md` 登记在 requirements 索引。

### Security (PR-4.4 / P1-4)

- **DB / Redis TLS production-safety fail-fast**（PR-4.4 / P1-4）。`BackendTlsConfig::from_env` 由 `Self` 改为 `anyhow::Result<Self>`，三重生产安全门：
  - `KMS_DB_TLS_MODE=no_verify` 在生产环境 fail-fast（不加 `KMS_DEV_MODE=1` / `KMS_ALLOW_INSECURE=1`）—— MITM 攻击者可伪造证书
  - `KMS_DB_TLS_MODE=disabled` 在生产环境 fail-fast——明文数据库流量
  - `verify_ca` 模式要求 `KMS_DB_TLS_CA_CERT` 非空；否则启动期拒绝（不等首连接才失败）
  - 复用 PR-4.1 的 `kms_core::production_safety::is_insecure_opted_in()` helper
- `src/cmd/server.rs` 与 `crates/kms-keystore/src/{repository,rate_limiter}.rs` 的 4 个 caller 同步升级为 `unwrap_or_else(|e| std::process::exit(1))` 以保证 fail-fast 契约。
- 新增 14 个 `pr44_db_tls_defaults_tests` 单元测试覆盖所有分支（默认 / disabled / no_verify / 大小写 / 空路径 / opt-in）。
- 新增双语需求文档 `docs/requirements/N3-db-redis-tls-defaults.md` 登记在 requirements 索引。
- 现有 296 个 kms-core + 94 个 kms-keystore 单元测试继续通过。

### Security (PR-4.1 / P1-3)

- **`src/cmd/server.rs`：gRPC / REST 生产启动 TLS fail-fast**（PR-4.1 / P1-3）。仿照 KEK fail-fast 模式（`kms-keystore/src/postgres.rs:92-95`），默认启动需 TLS；仅 `KMS_ALLOW_INSECURE=1`（或测试 `KMS_DEV_MODE=1`）明确放行才使用明文。REST 两个分支（`rest_tls_config = None` 与 `rest_tls.enabled = false`）独立报错。
- 新增 `kms_core::production_safety` 模块：`is_allow_insecure()`、`is_dev_mode()`、`is_insecure_opted_in()` 三个 helper；值严格为字符串 `"1"`，避免 `"true"`/`"yes"` 误选。
- `cmd/server.rs` 拆出 `pub(crate) fn grpc_tls_failfast_message` 与 `pub(crate) fn rest_tls_failfast_message` 两个可测试 helper，避免 `cmd::server::run` 启动逻辑集成测试成本。
- 新增 12 个 PR-4.1 单元测试（`kms-core/production_safety.rs` 5 个 + `cmd/server.rs::pr41_failfast_tests` 7 个），覆盖所有 helper 分支与 REST 两条互斥错误消息。
- 新增 `discuss/40-pr-4-1-spec.md` 完整 SPEC。

### Known Limitations（本项目固有，不在本版本修复范围）

- gRPC over TLCP 未实现（TLCP 协议无 ALPN，gRPC 需要 h2）
- TLCP 证书链验证未集成（仅信任对端字节，等 gm-tlcp 上游 `TlcpCertPair` 接 `cert_verify`）
- SM9 主密钥默认存内存，无 HSM/TPM 强制（`kms-hsm` 仍为 stub）
- 无 bug bounty / 商业支持 / SLA

## [0.2.1] — 2026-09-05

### Dependencies — upstream `gm` workspace 0.3.0

- **`gm-tls` 0.1.0 → 0.2.0** (BREAKING upstream): `pub mod tlcp` removed from `gm-tls`. TLCP (GB/T 38636-2020) is now a separate `gm-tlcp` crate. gm-kms does **not** depend on `gm-tlcp` and only uses `TlsConfig` / `TlsAcceptor` / `GmTlsStream` / `grpc::GmTlsIncoming` / `TlsError` from `gm-tls`, all preserved unchanged. No source code changes required.
- **`gm-crypto` 0.1.0 → 0.2.0** (additive): 3 new APIs (`Sm4Cipher::encrypt_cbc_raw` / `decrypt_cbc_raw`, `x509::extract_sm2_pubkey_from_der`) used only by the new `gm-tlcp` crate. No breaking changes to the `Sm2KeyPair` / `Sm2Signer` / `Sm2Verifier` / `Sm2Encryptor` / `Sm2Decryptor` / `Sm3Hasher` / `Sm3Hmac` / `Sm4Cipher` APIs that gm-kms consumes.
- **`[patch.crates-io]`**: bumped from `rev = c0148032` to `rev = 37e1b21` (tag `gm-tls-v0.2.0`). Added `gm-sm9-rs` to the patch list to ensure all three crates (gm-ca, gm-crypto, gm-sm9-rs) resolve to the same git source, eliminating the dual-source type mismatch (E0308 on `Sm2KeyPair`) that previously surfaced in `cargo check --workspace --all-targets`. All direct `gm-crypto = "0.1.0"` deps bumped to `"0.2"` for the same reason.

### Fixed

- **`src/cmd/server.rs`**: pre-existing rustfmt drift in the `gm-tls` REST error message (`anyhow::bail!("TLS 1.3 + SM (gm-tls) ...")`) that had `cargo fmt --all -- --check` failing on CI since commit 8c06d24.
- **`CONTRIBUTING.md`**: clarified the dependency story — replaced the stale claim that gm-kms uses "versioned crates.io dependencies" with an accurate description of the crates.io + `[patch.crates-io]` hybrid strategy.

## [0.2.0] — 2026-08-27

### ⚠️ Breaking Changes

- **`kms-api::quota`**: `Result<_, ()>` → `Result<_, QuotaError>`. `TenantQuotaTracker::increment_key_count` / `decrement_key_count` / `get_usage` now return `Result<T, QuotaError>` instead of `Result<T, ()>`. Callers using `Match Err(())` (or `.unwrap_err()`) need to update to the new error type.
  - New type: `pub enum QuotaError { Exceeded(QuotaExceeded), Storage(String) }` with `Display` + `Error` impls.
  - This was triggered by `clippy::result_unit_err`; the `()` error carried no information and was unreachable to handle.
- **`kms-api::ratelimit`**: `TenantRateLimiter::get_usage` returns `Result<u64, RateLimitBackendError>` (new tuple struct) instead of `Result<u64, ()>`. Same reasoning as above.
  - The pre-existing `pub struct RateLimitError` (the HTTP-response body) is unchanged; the new type is named `RateLimitBackendError` to avoid collision.

### Security

- **h2 0.4.13 → 0.4.16** (RUSTSEC-2026-0258): fixes unbounded empty DATA frames DoS. Propagated via `tonic` → `tonic-prost`; `tonic` 0.14.5 accepts `h2 0.4.*`, no API break.

### Changed

- **`kms-api::metrics`**: `*count % 100 == 0` → `count.is_multiple_of(100)` (clippy::manual_is_multiple_of).
- **`kms-core::shamir`**: `original_len % block_size == 0` → `original_len.is_multiple_of(block_size)` (split PKCS#7 padding); `shares.len() % num_blocks != 0` → `!shares.len().is_multiple_of(num_blocks)` (reconstruction alignment check).
- **`src/cmd/config.rs`**: 11 nested `if let Ok(...) { if let Ok(...) { ... } }` collapsed to let-chains (`if let Ok(...) && let Ok(...) { ... }`) per clippy::collapsible_if. Env vars affected: `REST_PORT`, `GRPC_PORT`, `TLS_CERT_PATH`, `REST_TLS_CERT_PATH`, `TSA_TIMEOUT`, `TSA_INTERVAL`, `RATE_LIMIT_RPS`, `POSTGRES_PORT`, `BACKUP_RETENTION_COUNT`, `BACKUP_RETENTION_DAYS`, `BACKUP_KDF_ITERATIONS`.

### CI / Dev Tooling

- **`.github/dependabot.yml`**: tightened per SemVer discipline.
  - `open-pull-requests-limit`: 10 → 5 (cargo) / 3 (github-actions).
  - Added `cooldown`: patch 1 d / minor 4 d / major 14 d — wait for upstream fixes before opening PRs.
  - `rebase-strategy: disabled` — no silent force-push on already-opened PRs.
  - 4 new RustCrypto ecosystem groups (`rustcrypto-block-modes`, `rustcrypto-formats`, `rustcrypto-elliptic-curves`, `rustcrypto-hash`) to merge transitive upgrades into 1 PR per ecosystem instead of single-crate PRs.
  - 9 ignored dependencies (require explicit SemVer-major-style adaptation):
    `redis >= 1.x`, `tokio >= 2.x`, `x25519-dalek >= 3.x`, `curve25519-dalek >= 5.x`,
    `totp-rs >= 6.x`, `sqlx >= 0.9`, `toml >= 1.x`, `config >= 0.15`, `rdkafka >= 0.37`, `getrandom >= 0.3`.
  - Motivation: patch upgrades that pull transitive `cipher 0.4 → 0.5` (BlockEncrypt → BlockCipherEncrypt rename) are *real* breaking changes, not "low A-tier lockfile-only".

### Fixed

- **文档修正**：明确 TLCP (GB/T 38636-2020) 当前为参考实现，位于独立 `gm-tlcp` crate 中维护。gm-kms REST/gRPC 入口当前走 TLS 1.3 + SM ciphers（通过 `gm-tls` 实现）。同步更新 README.md / CONTRIBUTING.md / kms.toml.example / `src/cmd/gm_listener.rs` 中“gm-kms 部署 TLCP”的不实描述。“gm” backend 配置实际为 TLS 1.3 + SM ciphers，未接入 TLCP 协议。

## [0.1.0] — 2026-08-27

Initial public release.

### Added

- **SM2/SM3/SM4/SM9** cryptographic algorithms via the `gm` workspace
- **[planned, 未实际部署]** TLCP (Transport Layer Cryptographic Protocol) with dual-certificate ECDHE handshake and SM4-CBC suite — 参考实现见 `gm-tlcp` crate（独立维护中）。
- **gRPC + REST dual API** with full feature parity (envelope encrypt/decrypt/rewrap, import/export, hash, DH derive, audit query)
- **PBAC** (Policy-Based Access Control) engine integrated across all handlers
- **SM9 key rotation** via `Sm9RotationAdapter` bridging `gm-sm9-rs` to gm-kms
- **SM9 key exchange** protocol (GM/T 0044.3-2016 §7) with mutual key confirmation
- **MFA** (TOTP) with PostgreSQL persistence and AES-256-GCM envelope encryption for secrets
- **WORM audit log** with hash-chained integrity, TSA timestamping, and Kafka streaming
- **Shamir secret sharing** with multi-block VSS commitments
- **DEK/KEK version binding** and rewrap-after-rotation
- **TLS/mTLS** support for REST, gRPC, Redis, and PostgreSQL connections
- **Rate limiting** and **tenant quota tracking** via Redis
- **KAT self-test** at startup (GB/T 37092-2018 §7.10)
- **Health check** endpoint with periodic background monitoring
- **SM2-KEX session management** with Redis shared sessions
- **TPM stub** backend (`RealTpmKeystore`) for future HSM integration

### Security

- gRPC API key authentication with mandatory auth interceptor
- Key export requires approval flow
- Tenant isolation enforcement in all services
- TOTP secrets encrypted with KEK (AES-256-GCM envelope), never stored in plaintext
- API key protection against enumeration timing attacks
- Audit log chain integrity verification
- Constant-time cryptographic primitives (conditional_select + delinearization)
- Memory protection (mlock available, core dump disabled)
- Old key material zeroized on rotation/deletion
- TLS production default enforced (disabled only in dev mode)

### Changed

- rand 0.8 → 0.10 migration across all crates
- `software.rs` split into module directory (mod.rs + tests.rs)
- Keystore backend `Default` impl removed for explicit initialization
- `ark-bn254` dead dependency removed
- `glob_match` trailing wildcard boundary bug fixed
- `repository.list()` tenant_id from `Option<&str>` to mandatory `&str`

### Documentation

- **Architecture document** (`ARCHITECTURE.md`) added — crate dependency graph, data flow diagrams, security design principles
- **PBAC coverage** extended to all 59 handlers (21 gRPC + 38 REST)
- **kms-audit** custom error types (`AuditError`/`AuditResult`) replace `anyhow` across all modules
- **Multiple audit false positives** confirmed and documented:
  - GmSSL FFI Drop: all FFI structs are plain value types, `SM9_SIGN_CTX` Drop already implemented
  - `from_raw_parts` ordering: `.to_vec()` before `free()` — correct and safe
  - `verify_chain` startup: method present but not called at startup (not a P1 issue)

## [Pre-0.1.0 development] — 2026-06-29

Pre-release development snapshots folded into 0.1.0. Listed here for
audit-trail purposes only; these items are NOT part of any published
release and predate the v0.1.0 tag (18b32a3, 2026-08-27).

### Added

- **SM9 主密钥持久化 (F-1)**: PG 存储，AES-256-GCM 加密
- **SoftwareKeystore PG+Redis 持久化 (F-2)**: 双重后端
- **备份服务 (F-3)**: create_key best-effort 备份
- **delete_key 双人控制 (F-4)**: 新增 approval_id 字段
- **SM9 KAT 自检 (F-5)**: 签/验签 + 加解密往返测试
- **备份码哈希 (H-1)**: SHA-256 哈希化存储和对比
- **MFA-API Key 联动锁定 (H-2)**: Arc+Mutex + lock_key_by_id

### Changed

- **parking_lot 锁迁移**: 28 文件，+726/-328，全局替换 std::sync 锁
- **生产 unwrap() 清零**: 全部替换为 .expect()
- **kms-audit anyhow 迁移**: AuditError/AuditResult 全覆盖
- **ARCHITECTURE.md 依赖图修复**: 修正空箱和错误箭头，新增依赖验证表
- **README.md 测试统计修正**: kms-core 277→278，总计 957→958
- **sm2-kex-requirement.md 状态更新**: "已实现（部分）" → "已实现"
- **PBAC handler 计数修正**: 修正为 21 gRPC RPC + 38 REST handler（共 59）
