# SPEC: PR-4.17 — gm-kms keystore 真正 lazy load (PR-4.15 follow-up)

- **目标编号**：PR-4.17（Batch 4 follow-up — gm-kms 工程完善）
- **触发**：[`docs/requirements/N8-keystore-in-memory-cap.md §7`](../requirements/N8-keystore-in-memory-cap.md) 明确声明 "PR-4.18: `PostgresKeystore` lazy load（按需 SELECT，PR-4.15 留的口子）"
- **范围**：`crates/kms-keystore/src/postgres.rs` 的 `verify_tenant` 增加 cache-miss lazy load + metrics
- **影响面**：纯增量；caller API 不变；现有 `load_keys()` 行为不变

---

## 1. 问题陈述

[`gm-kms/crates/kms-keystore/src/postgres.rs:683-694`](file:///Users/laozhang/Work/opensource/gm-kms/crates/kms-keystore/src/postgres.rs#L683)：

```rust
async fn get_key_metadata(&self, key_id: &Uuid) -> Result<KeyMeta> {
    // Try in-memory first
    if let Some(entry) = self.keys.get_cloned(key_id) {
        return Ok(entry.meta);
    }

    // Fall back to PostgreSQL
    self.repo
        .find_by_id(key_id)
        .await?
        .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))
}
```

[`gm-kms/crates/kms-keystore/src/postgres.rs:129-141`](file:///Users/laozhang/Work/opensource/gm-kms/crates/kms-keystore/src/postgres.rs#L129)：

```rust
async fn verify_tenant(&self, key_id: &Uuid, tenant_id: &str) -> Result<()> {
    let entry = self
        .keys
        .get_cloned(key_id)
        .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;
    if entry.meta.tenant_id != tenant_id {
        return Err(Error::KeyNotFound(key_id.to_string()));
    }
    Ok(())
}
```

后果：
- **metadata 已 lazy**：`get_key_metadata` 命中失败时回退 DB
- **material 不 lazy**：`verify_tenant`（被 encrypt/decrypt/sign/verify/destroy ... 轮询调用）在 cache miss 时**直接返回 KeyNotFound**，即使 DB 里有
- PR-4.15 引入 `with_in_memory_cap(n)` 之后，cap 之外的密钥会**永久**拿不到（除非重启重新 load_keys() 取前 n 个）
- 实际场景：1000 密钥，cap=100 → 901-1000 这 100 个密钥**完全无法使用**

### 1.1 改进建议依据

PR-4.15 SPEC §7：
> **PR-4.16**：`PostgresKeystore` lazy load（按需 SELECT，PR-4.15 留的口子）

PR-4.17 解决**material 维度**的 lazy load。

---

## 2. Fix 策略

### 2.1 新增 `load_entry_from_db` helper

```rust
/// PR-4.17: lazy-load a `KeyEntry` from PostgreSQL when the
/// in-memory cache misses. Fetches metadata + encrypted
/// material, decrypts with the KEK, and returns the entry
/// ready for `insert_with_eviction`.
///
/// Errors:
/// - `Error::KeyNotFound` if the key id is absent from DB
/// - `Error::Internal` if KEK decryption fails (KEK
///   rotation scenario; logged but not panicking)
async fn load_entry_from_db(&self, key_id: &Uuid) -> Result<KeyEntry> {
    let meta = self
        .repo
        .find_by_id(key_id)
        .await?
        .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;
    let encrypted = self
        .repo
        .find_encrypted_material(key_id)
        .await?
        .ok_or_else(|| Error::Internal(format!(
            "key {} found in DB but no encrypted material (may predate persistence)",
            key_id
        )))?;
    let material = self.decrypt_material(key_id, &encrypted).map_err(|e| {
        Error::Internal(format!(
            "lazy-load KEK decrypt failed for {}: {} \
             (this likely indicates the KEK has changed)",
            key_id, e
        ))
    })?;
    Ok(KeyEntry {
        meta,
        material: Zeroizing::new(material),
    })
}
```

### 2.2 `verify_tenant` 改为 cache-miss → lazy load

```rust
async fn verify_tenant(&self, key_id: &Uuid, tenant_id: &str) -> Result<()> {
    if let Some(entry) = self.keys.get_cloned(key_id) {
        if entry.meta.tenant_id != tenant_id {
            return Err(Error::KeyNotFound(key_id.to_string()));
        }
        return Ok(());
    }

    // PR-4.17: cache miss → try DB before declaring
    // KeyNotFound. This is the path that lets
    // `with_in_memory_cap(n)` work for keys beyond position
    // n: those keys live only in DB and are pulled in on
    // first access.
    let entry = match self.load_entry_from_db(key_id).await {
        Ok(entry) => {
            self.keys.insert_with_eviction(key_id, entry.clone());
            record_lazy_load();
            entry
        }
        Err(Error::KeyNotFound(_)) => return Err(Error::KeyNotFound(key_id.to_string())),
        Err(e) => return Err(e),
    };
    if entry.meta.tenant_id != tenant_id {
        return Err(Error::KeyNotFound(key_id.to_string()));
    }
    Ok(())
}
```

### 2.3 Metrics counter

新增 `kms_keystore_lazy_loads_total` Prometheus counter（自进程启动以来 lazy-load 次数）：

```rust
fn record_lazy_load() {
    use metrics::counter;
    counter!("kms_keystore_lazy_loads_total").increment(1);
}
```

`metrics` crate 已是 workspace 依赖。

### 2.4 公共 API 兼容

- `verify_tenant` 行为不变（cache hit 路径完全相同）
- cache miss 路径从"直接 Err"变为"lazy load → cache insert → verify" — caller 看不到差异
- `with_in_memory_cap(n)` 现在真正生效：cap 之外的密钥按需加载

### 2.5 版本

`kms-core` / `kms-keystore` workspace version：**patch bump**（行为兼容；新 metrics；无公共 API 变更）。

---

## 3. Tests

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr417_lazy_load_hits_db_when_cache_misses` | mock cache 空；`verify_tenant` → mock DB 返回 entry → cache 填充 + 验证通过 |
| T2 | `pr417_lazy_load_does_not_evict_when_under_cap` | cache cap=2；pre-populate 1 entry；access 第二个 DB-backed → cap=2 之后；无 eviction |
| T3 | `pr417_lazy_load_does_evict_when_over_cap` | cache cap=2；pre-populate 2 entries；access 第三个 DB-backed → cap=2；最老 evicted |
| T4 | `pr417_lazy_load_returns_key_not_found_for_missing_key` | mock DB 返回 None → `Err(KeyNotFound)` |
| T5 | `pr417_lazy_load_returns_error_on_kek_decrypt_failure` | mock DB 返回 encrypted material 但 KEK decrypt 失败 → `Err(Internal)` |
| T6 | `pr417_verify_tenant_uses_cache_when_present` | cache 已 hit；DB 不被查询（mock 不应收到 `find_by_id` 调用） |

T1-T6 需要 mock `PostgresKeyRepository` + `BoundedKeyCache` fixture。考虑抽出一个 `mock_key_repo!` 宏。

---

## 4. 验证矩阵

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy --workspace --all-targets -- -D warnings
cargo +1.88 test -p kms-keystore --all-targets pr417_
cargo +1.88 test --workspace --all-targets   # 全量回归
```

CI 含 Security Audit / Build Docker / OWASP ZAP / Container Security Scan。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| 每次 cache miss 都要 2 次 DB query (find_by_id + find_encrypted_material) | 实测单 query < 1ms；最坏情况每次访问多 1ms；可后续 batch |
| KEK 变更后 lazy-load 失败 → 错误传播 | 已在 `load_entry_from_db` 中显式包装为 `Error::Internal` 并附 KEK-rotation 提示，与现有 `load_keys` 行为一致 |
| 攻击者用大量 cache miss → DB 放大 | 受 `with_in_memory_cap` 约束 + DB 连接池大小约束；不在本 PR scope |
| caller 假设 cache miss 一定 → KeyNotFound | 不可能：pre-PR-4.17 caller 已经在 cache miss 时收到 `KeyNotFound`；post-PR-4.17 caller 在 DB 中存在的密钥**也**得到正确响应（行为更宽容） |
| Material 与 metadata 解密后未 zeroize | 现有 `decrypt_material` 已返回 `Zeroizing<Vec<u8>>`；新 helper 同样使用 |

---

## 6. Out of Scope

- **Metadata-only lazy load 优化**：`get_key_metadata` 已经是 lazy 的，但 fetch 时未插回缓存（因为 metadata 没 material，无需 cache）
- **批量 prefetch**：检测 access pattern 预热 cache（PR-4.18+ 议题）
- **per-tenant rate limit on lazy loads**：本 PR 只关心功能正确性
- **`load_keys` 改成 background task**：可作为后续 PR — 让启动更快，但 lazy load 已解决根本问题

---

## 7. 后续 PR 候选

- **PR-4.18**：gm-tls 全面 typed error 化（包括 `HandshakeFailed` 内部细分）
- **PR-4.19**：`PostgresKeystore::load_keys()` 改为可选后台 task
- **PR-4.20**：gm-tlcp 错误类型统一
