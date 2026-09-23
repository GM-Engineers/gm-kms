# SPEC: PR-4.19 — `PostgresKeystore` 后台 preload (PR-4.17 SPEC §7 引用)

- **目标编号**：PR-4.19（Batch 4 follow-up — gm-kms 工程完善）
- **触发**：[`docs/requirements/N9-keystore-lazy-load.md §6`](../requirements/N9-keystore-lazy-load.md) 明确列出 "`PostgresKeystore::load_keys()` 改为可选后台 task"
- **范围**：`crates/kms-keystore/src/postgres.rs` 新增 `spawn_load_keys()` + `src/cmd/server.rs` 调用点切换
- **影响面**：纯增量；旧的 `load_keys()` 行为完全保留；新方法是 opt-in

---

## 1. 问题陈述

[`src/cmd/server.rs:580`](file:///Users/laozhang/Work/opensource/gm-kms/src/cmd/server.rs#L580)：

```rust
match PostgresKeystore::new(repo).await {
    Ok(pg_keystore) => {
        match pg_keystore.load_keys().await {  // <-- BLOCKING
            Ok(()) => tracing::info!("Loaded keys from PostgreSQL"),
            Err(e) => tracing::warn!("Failed to load keys from PostgreSQL: {e}"),
        }
        Arc::new(pg_keystore)
    }
    ...
}
```

[`src/cmd/server.rs:619`](file:///Users/laozhang/Work/opensource/gm-kms/src/cmd/server.rs#L619)：

```rust
let _ = pg_keystore.load_keys().await;  // <-- BLOCKING, ERR SWALLOWED
```

后果：
- **启动阻塞**：`load_keys()` 是 `SELECT ...` over the entire key table，O(N) DB queries + KEK decrypt × N。生产环境 N=10000 时实测需要 ~5–10 秒
- **服务不可用窗口**：TCP listener 还没绑定，第一个 gRPC/HTTP 请求就被拒
- **K8s readiness probe failure**：probe 在 startup 期间 timeout → pod restart loop
- **PR-4.17 已解决问题的一半**：lazy load 让 cap 之外的 key 可访问，但**首次访问仍要等 DB round-trip + KEK decrypt**。preload 是消除这个延迟

### 1.1 改进建议依据

PR-4.17 SPEC §6 列出：
> **`load_keys` 改成 background task**：可作为后续 PR — 让启动更快，但 lazy load 已解决根本问题

PR-4.19 实现这个后续 PR。

---

## 2. Fix 策略

### 2.1 新增 `spawn_load_keys()` 方法

```rust
/// PR-4.19 / PR-4.17 follow-up: start the eager-load in
/// the background and return a `JoinHandle<Result>` so the
/// caller can:
///
/// 1. Continue with server startup (TCP bind, gRPC
///    start, etc.) without waiting for the DB round-trip
///    + KEK decrypt × N.
/// 2. Optionally await the handle later (e.g., a
///    readiness probe that returns 503 until load
///    completes).
///
/// Pre-PR-4.19 callers used `await pg_keystore.load_keys()`
/// which blocked startup by 5–10 seconds for 10k keys.
/// Post-PR-4.19 the listen port binds immediately and
/// PR-4.17's lazy-load path covers any keys that aren't
/// yet in the cache.
pub fn spawn_load_keys(&self) -> tokio::task::JoinHandle<Result<usize>> {
    let keys = Arc::clone(&self.keys);
    let repo = self.repo.clone();
    tokio::spawn(async move {
        let metas = repo.list_all_tenants(None, None).await?;
        let mut loaded = 0usize;
        for meta in metas {
            let encrypted = match repo.find_encrypted_material(&meta.id).await? {
                Some(b) => b,
                None => {
                    tracing::warn!(
                        "Key {} found in DB but has no encrypted material. \
                        It may have been created before persistence was enabled.",
                        meta.id
                    );
                    continue;
                }
            };
            let material = match Self::decrypt_material_static(&meta.id, &encrypted, ...) {
                Ok(m) => m,
                Err(e) => {
                    tracing::error!(
                        "Failed to decrypt key {} from database: {}. \
                            This may indicate the KEK has changed.",
                        meta.id, e
                    );
                    continue;
                }
            };
            keys.insert_with_eviction(meta.id, KeyEntry {
                meta: meta.clone(),
                material: Zeroizing::new(material),
            });
            loaded += 1;
        }
        Ok(loaded)
    })
}
```

**关键设计**：
- 返回 `JoinHandle<Result<usize>>` — `usize` 是成功 preload 的密钥数（便于日志 / metrics）
- 用 `Arc::clone(&self.keys)` 让 spawned task 操作同一份 cache
- KEK decrypt 失败时**跳过**而不是 abort（保持 `load_keys()` 现有 best-effort 语义）
- 复用 `Self::decrypt_material`（但需要把 `self.kek` clone 或重构成 static；见 §2.3）

### 2.2 重构 `decrypt_material` 为静态方法

Pre-PR-4.19: `fn decrypt_material(&self, ...)` 借用 `self.kek`。

PR-4.19: 抽出 `fn decrypt_material_static(kek: &[u8; 32], key_id, encrypted)` + `fn decrypt_material(&self, ...)` thin wrapper。

```rust
fn decrypt_material(&self, key_id: &Uuid, encrypted: &[u8]) -> Result<Vec<u8>> {
    Self::decrypt_material_static(&self.kek, key_id, encrypted)
}

fn decrypt_material_static(
    kek: &[u8; 32],
    key_id: &Uuid,
    encrypted: &[u8],
) -> Result<Vec<u8>> {
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    // ... same body, taking `kek` instead of `self.kek.as_ref()`
}
```

### 2.3 server.rs 调用点切换

```rust
// Before:
match pg_keystore.load_keys().await {
    Ok(()) => tracing::info!("Loaded keys from PostgreSQL"),
    Err(e) => tracing::warn!("Failed to load keys from PostgreSQL: {e}"),
}
Arc::new(pg_keystore)

// After:
let preload_handle = pg_keystore.spawn_load_keys();
tokio::spawn(async move {
    match preload_handle.await {
        Ok(Ok(n)) => tracing::info!("Loaded {n} keys from PostgreSQL (background)"),
        Ok(Err(e)) => tracing::warn!("Failed to load keys from PostgreSQL: {e}"),
        Err(join_err) => tracing::error!("preload task panicked: {join_err}"),
    }
});
Arc::new(pg_keystore)
```

### 2.4 公共 API 兼容

- `load_keys()` 行为完全保留（仍可用，仍阻塞；用于测试 / 一次性 init script）
- 新增 `spawn_load_keys()`（opt-in）
- `decrypt_material` 行为完全保留（thin wrapper）
- 新增 `decrypt_material_static`（pub(crate)，供 spawned task 使用）

### 2.5 版本

`kms-core` / `kms-keystore` workspace version：**patch bump**（行为兼容；新 API；server.rs 调用点从 blocking 切换为 background — 这是 caller-side 行为改进，但**公共 API** 没有 breaking change）。

---

## 3. Tests

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr419_spawn_load_keys_returns_join_handle` | 构造 keystore，调用 `spawn_load_keys()`，断言返回 `JoinHandle<Result<usize>>`；await 完成后 `Ok(0)` 或 `Ok(n)` |
| T2 | `pr419_load_keys_and_spawn_have_same_outcome` | `#[ignore]` DB test：先 `load_keys().await` 计数 N；再 `spawn_load_keys()` await 计数 N；两者应相等 |
| T3 | `pr419_spawn_load_keys_does_not_block_caller` | 单元测试不需要 DB，验证 `spawn_load_keys()` **立即**返回（不 await DB）。可用一个缓慢的 mock 实现，或者断言函数返回耗时 < 100ms |
| T4 | `pr419_decrypt_material_static_matches_decrypt_material` | 用同样的 KEK + payload 同时调用 `decrypt_material()` 和 `decrypt_material_static()`，结果一致 |

### 3.1 测试策略说明

T2 是 `#[ignore]` DB 测试（与现有 pr417_* 一致）。T3 通过**不依赖真实 DB** 实现：构造一个 keystore 但不连接 DB，调用 `spawn_load_keys()`，spawn 后立刻断言 handle 已 ready（poll_once）。这要求 `list_all_tenants` 在 mocked repo 上被调用 — 但 repo 是 concrete type。T3 退化为**存在性 + 立即返回断言**：仅证明调用 `spawn_load_keys()` 在 < 100ms 内返回（不阻塞）。

---

## 4. 验证矩阵

```
cargo +1.88 fmt --all -- --check
cargo +1.88 clippy --workspace --all-targets -- -D warnings
cargo +1.88 test -p kms-keystore --lib pr419_
cargo +1.88 test --workspace --lib   # 全量回归
```

CI 含 Security Audit / Build Docker / OWASP ZAP。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| `self.repo` 不是 `Clone`（sqlx pool）| 抽 trait 或重新构造；实测 `sqlx::PgPool` 是 `Clone`（内部 `Arc`）— 已确认 |
| `self.kek` 不是 `Send` (Zeroizing 不是 Send 的字段) | Zeroizing<[u8; 32]> 本身 Send；static 方法只借用 `&[u8; 32]` 无问题 |
| preload 期间 cap=0 用户立刻发请求 | PR-4.17 lazy-load 已处理；首次 cache miss → DB lookup → 成功 |
| spawned task panic 没人知道 | JoinHandle await 时检查 `JoinError`，log error（§2.3） |
| preload 与 generate_key race | spawn 后 `keys.insert_with_eviction` 与 `generate_key` 的 `insert_with_eviction` 是同一方法，并发安全（BoundedKeyCache 内部 RwLock + Mutex 保证） |
| `repo.clone()` 是否 deep clone 整个 PgPool | sqlx::PgPool 是 `Arc<...>` 包装，clone 仅 bump refcount；零成本 |

---

## 6. Out of Scope

- **取消正在运行的 preload task**：暂不提供 `cancel()` API；目前 task 是 best-effort 一次性
- **进度回调**：每次成功 insert 通知 caller 进度。PR-4.19 仅返回总数
- **pg_keystore 的 metrics counter**：preload 成功 / 失败计数；可在 PR-4.20+ 加

---

## 7. 后续 PR 候选

- **PR-4.20**：gm-tlcp 错误类型统一
- **PR-4.21**：gm-tls CRL grace period + session cache persistence
- **PR-4.22**：gm-kms preload metrics + per-tenant preload status
