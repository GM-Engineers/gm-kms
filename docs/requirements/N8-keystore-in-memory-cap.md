# SPEC: PR-4.15 — gm-kms keystore in-memory 容量上限 + FIFO eviction (P2-10)

- **目标编号**：PR-4.15（Batch 4 — gm-kms 工程完善）
- **触发**：[`gm与gm-kms源码级改进建议.md §四 P2-10`](file:///Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md#L165)：所有密钥常驻内存 HashMap、无冷热分层/容量上限，建议加惰性加载与内存上限
- **范围**：`crates/kms-keystore/src/postgres.rs` 的 `keys` HashMap 加上 opt-in 容量上限 + FIFO eviction + metrics
- **影响面**：纯增量；默认行为（无上限）保持不变；仅启用 cap 的 operator 看到 eviction

---

## 1. 问题陈述

[`gm-kms/crates/kms-keystore/src/postgres.rs:34-44`](file:///Users/laozhang/Work/opensource/gm-kms/crates/kms-keystore/src/postgres.rs#L34)：

```rust
pub struct PostgresKeystore {
    /// In-memory key material storage
    keys: Arc<RwLock<std::collections::HashMap<Uuid, KeyEntry>>>,
    repo: PostgresKeyRepository,
    kek: Zeroizing<[u8; 32]>,
}
```

后果：
- **无容量上限**：每条 create/rotate/import 的密钥都常驻内存；生产环境 10000 密钥 → 数百 MB RAM 占用
- **没有冷热分层**：极少使用的"老"密钥与热密钥竞争内存 → cache 命中失效
- **没有 metrics**：运维既看不到当前在内存的密钥数，也看不到 eviction（如果有的话）
- **启动负载问题**：`load_keys()` 启动时全量加载所有密钥 → 启动延迟随密钥量线性增长 → 容器扩容时间爆炸

### 1.1 改进建议依据（master plan §四 P2-10）

> `gm-kms/crates/kms-keystore/src/postgres.rs:34-42` | 所有密钥常驻内存 HashMap、无冷热分层/容量上限，建议加惰性加载与内存上限

PR-4.15 解决**内存上限 + eviction** 部分；**惰性加载**留作后续 PR（涉及读路径较大改动，本 PR 先把 capacity 闭环）。

---

## 2. Fix 策略

### 2.1 新增 `BoundedKeyCache` 类型

封装在 `crates/kms-keystore/src/bounded_cache.rs`（新文件）：

```rust
pub struct BoundedKeyCache {
    /// Bounded key map. capacity = `None` means unbounded
    /// (pre-PR-4.15 behavior preserved).
    map: RwLock<HashMap<Uuid, KeyEntry>>,
    /// FIFO insertion-order queue (front = oldest, back = newest).
    /// Maintained alongside `map` so eviction is O(1).
    order: Mutex<VecDeque<Uuid>>,
    /// Optional capacity cap. When `Some(n)` and `map.len() > n`,
    /// `insert_with_eviction` evicts oldest entries until len = n.
    capacity: Option<usize>,
    /// Metrics: total evictions since process start.
    evictions: AtomicU64,
}

impl BoundedKeyCache {
    pub fn new(capacity: Option<usize>) -> Self { ... }
    pub fn get_cloned(&self, key: &Uuid) -> Option<KeyEntry> { ... }
    pub fn insert_with_eviction(&self, key: Uuid, entry: KeyEntry) { ... }
    pub fn len(&self) -> usize { ... }
    pub fn capacity(&self) -> Option<usize> { ... }
    pub fn evictions_total(&self) -> u64 { ... }
}
```

### 2.2 FIFO eviction 策略

选 FIFO 而非 LRU：
- **更简单**：只需 `VecDeque<Uuid>`，无需双向链表 + Rc/Weak 模式
- **符合 master plan 语义**："内存上限"未指定 LRU vs FIFO；FIFO 实现简单
- **开销最小**：每次 insert O(1) push 到 back；每次 evict O(1) pop_front
- **生产场景适用**：密钥使用模式通常是"近期签发的更活跃"，FIFO 仍能淘汰老密钥

后续 PR-可升级到 LRU（增加 `lru` crate 依赖）。

### 2.3 `PostgresKeystore` 集成

```rust
pub struct PostgresKeystore {
    keys: Arc<BoundedKeyCache>,
    repo: PostgresKeyRepository,
    kek: Zeroizing<[u8; 32]>,
    /// Default-capacity config; populated at construction.
    in_memory_cap: Option<usize>,
}

impl PostgresKeystore {
    pub fn with_in_memory_cap(mut self, n: usize) -> Self {
        self.in_memory_cap = Some(n);
        // Rebuild cache with capacity. Existing entries are dropped;
        // they will be lazily re-loaded from DB on demand.
        self.keys = Arc::new(BoundedKeyCache::new(Some(n)));
        self
    }
}
```

### 2.4 `load_keys()` 调用点更新

当前 `load_keys()` 启动时全量加载。如果 operator 设置了 cap，**不能**一次性插入超过 cap 的条目（会触发全部 eviction，违背预期）。改为：
- cap = None → 保持现状（全部加载）
- cap = Some(n) → 启动时只加载 metadata（key id + name + tenant），material **不**预加载到内存 cache，而是按需加载

PR-4.15 **第一步只解决 cap**：保持 `load_keys()` 行为（启动全部加载），但**当 cap 被设置时限制为 cap 条目**：
```rust
pub async fn load_keys(&self) -> Result<()> {
    let keys = self.repo.list_all_tenants(None, None).await?;
    let limit = self.in_memory_cap.unwrap_or(usize::MAX);
    for meta in keys.into_iter().take(limit) {
        // ... existing decrypt + insert logic ...
    }
    Ok(())
}
```

行为：
- cap=None → 全量加载（不变）
- cap=Some(n) → 只加载前 n 条（其他密钥按需 lazy load — 但本 PR 不实现 lazy load，仅限制 startup load）

真正的 lazy load 留作后续 PR。

### 2.5 Metrics

新增 3 个 Prometheus 计数器/仪表：
- `kms_keystore_in_memory_entries` (Gauge): 当前 in-memory cache 容量
- `kms_keystore_evictions_total` (Counter): 自进程启动以来 FIFO 驱逐次数
- `kms_keystore_in_memory_cap` (Gauge): 配置上限（None = unbounded 时输出 0）

通过 `metrics` crate（已依赖）暴露，无需新增 crate。

### 2.6 公共 API 兼容

- `PostgresKeystore::new()` 行为不变（无 cap，eager load）
- `PostgresKeystore::with_in_memory_cap(n)` 是新的 builder
- 现有 caller 不需要修改

### 2.7 版本

`kms-core` / `kms-keystore` workspace version：**patch bump**（opt-in 配置；现有路径行为不变）。

---

## 3. Tests

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr415_unbounded_cache_never_evicts` | `BoundedKeyCache::new(None)`；插入 1000 条；`len() == 1000`；`evictions_total() == 0` |
| T2 | `pr415_bounded_cache_evicts_oldest_when_over_cap` | cap=3；插入 A/B/C/D → C/D 留下；A 被驱逐 |
| T3 | `pr415_bounded_cache_keeps_recently_inserted_under_cap` | cap=3；插入 A/B/C → 全部留下；`evictions_total() == 0` |
| T4 | `pr415_bounded_cache_get_cloned_returns_none_for_missing` | 空 cache；`get_cloned(Uuid::new_v4())` 返回 None |
| T5 | `pr415_bounded_cache_len_reflects_inserts_and_evictions` | cap=2；插入 4 条 → `len() == 2`；`evictions_total() == 2` |
| T6 | `pr415_postgres_keystore_builder_with_in_memory_cap` | `new(repo)` → 无 cap；`.with_in_memory_cap(10)` → cap=10 |
| T7 | `pr415_postgres_keystore_load_keys_respects_cap` | repo 有 100 条 metadata；`load_keys()` + cap=10 → cache 内 10 条 |

T7 需要 Postgres test fixture。参考现有 `tests/` 目录。

---

## 4. 验证矩阵

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy --workspace --all-targets -- -D warnings
cargo +1.88 test -p kms-keystore --all-targets pr415_
cargo +1.88 test --workspace --all-targets   # 全量回归
```

CI 含 Security Audit / Build Docker / OWASP ZAP / Container Security Scan。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| FIFO 策略可能淘汰热门密钥 | 文档明确这是 FIFO，**不是** LRU；operator 可选小 cap 让冷数据溢到 DB（按需 lazy load） |
| 启动时 O(n) load 仍占用内存峰值 | cap=Some(n) 时 `load_keys()` 只取前 n 条；其他密钥下次访问时按需加载（实际 lazy load 由后续 PR 实现） |
| 现有 test 假设 cache 全量 in-memory | 不变；T1 验证 unbounded 路径 |
| `RwLock` 嵌套 `Mutex` 死锁风险 | `order: Mutex<VecDeque<Uuid>>` 与 `map: RwLock<HashMap>` 是 **分离** 的锁；insert 永远先 map.write 再 order.lock；无嵌套 |

---

## 6. Out of Scope

- **真正的 lazy load**：把 `get_key_metadata()` 改成"cache 命中 → 立即返回；未命中 → SELECT FROM DB + INSERT into cache"。本 PR 仅在 `load_keys()` 上加 cap
- **LRU**：FIFO 实现简单；后续 PR 可升级
- **`lru` crate**：避免新增依赖
- **Redis-backed tier**：Redis 已经用作外部缓存；本 PR 不改造 Redis 路径

---

## 7. 后续 PR 候选

- **PR-4.16**：`PostgresKeystore` lazy load（按需 SELECT，PR-4.15 留的口子）
- **PR-4.17**：LRU 升级（替换 FIFO）
- **PR-4.18**：TlsError 重构为 typed error enum
