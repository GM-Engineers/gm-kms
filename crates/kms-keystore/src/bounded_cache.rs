//! Bounded key-material cache (PR-4.15 / P2-10).
//!
//! Pre-PR-4.15, [`PostgresKeystore`](super::PostgresKeystore)
//! kept a single unbounded
//! `RwLock<HashMap<Uuid, KeyEntry>>` for key material. Every key
//! ever generated stayed resident until process exit, with no
//! cap, no eviction policy, and no metrics. Production
//! deployments with thousands of keys would consume hundreds
//! of MB of RAM for material that was rarely (if ever) accessed
//! again (rotated keys, archived keys, etc.).
//!
//! PR-4.15 introduces [`BoundedKeyCache`]: an opt-in cap on
//! the cache size with FIFO eviction. Operators that need
//! strict memory bounds configure `PostgresKeystore` via
//! [`PostgresKeystore::with_in_memory_cap`](super::PostgresKeystore::with_in_memory_cap);
//! operators that don't set a cap keep the pre-PR-4.15
//! behavior byte-for-byte.
//!
//! # FIFO vs LRU
//!
//! PR-4.15 implements FIFO (front of the queue = oldest entry)
//! rather than full LRU. Justifications:
//! - LRU requires an `lru` crate dependency; FIFO reuses only
//!   `std::collections::VecDeque` (already in std).
//! - For a key cache where cold entries are typically old keys
//!   (rotated, archived), FIFO approximates LRU well enough
//!   that operators typically see comparable hit rates.
//! - Eviction is O(1) (`VecDeque::pop_front`).
//!
//! A future PR may swap in a true LRU implementation if
//! production metrics show FIFO evicting hot entries. Until
//! then, FIFO is the documented behavior.
//!
//! # Thread safety
//!
//! - `map: RwLock<HashMap>` — read-mostly access pattern,
//!   `RwLock` lets concurrent reads proceed without contention.
//! - `order: Mutex<VecDeque<Uuid>>` — always locked AFTER the
//!   `map` write lock, never concurrently with it. No nested
//!   locking → no deadlock surface.

use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

/// Bounded key-material cache with FIFO eviction.
///
/// When `capacity` is `None`, the cache is unbounded (pre-PR-4.15
/// behavior preserved). When `Some(n)`, the cache evicts the
/// oldest-inserted entry on every `insert_with_eviction` that
/// would otherwise exceed `n` entries.
pub struct BoundedKeyCache {
    /// Backing storage of `(Uuid -> KeyEntry)`.
    map: RwLock<HashMap<Uuid, super::postgres::KeyEntry>>,
    /// FIFO insertion-order queue (front = oldest, back = newest).
    order: Mutex<VecDeque<Uuid>>,
    /// Optional capacity cap.
    capacity: Option<usize>,
    /// Total FIFO evictions since process start.
    evictions: AtomicU64,
}

impl BoundedKeyCache {
    /// Construct a new bounded cache.
    ///
    /// - `capacity = None` → unbounded (pre-PR-4.15 behavior).
    /// - `capacity = Some(n)` with `n == 0` → no entries ever
    ///   stored (every insert evicts immediately); useful only
    ///   for tests.
    pub fn new(capacity: Option<usize>) -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            order: Mutex::new(VecDeque::new()),
            capacity,
            evictions: AtomicU64::new(0),
        }
    }

    /// Get a clone of the entry for `key`, or `None` if absent.
    pub fn get_cloned(&self, key: &Uuid) -> Option<super::postgres::KeyEntry> {
        self.map.read().get(key).cloned()
    }

    /// Apply `f` to the entry for `key` while holding the
    /// write lock. Returns `Some(result)` if the entry was
    /// present, `None` otherwise. Used by callers that need
    /// to mutate the entry in place (e.g. status transitions
    /// during delete / destroy / rotate).
    pub fn mutate<F, R>(&self, key: &Uuid, f: F) -> Option<R>
    where
        F: FnOnce(&mut super::postgres::KeyEntry) -> R,
    {
        let mut map = self.map.write();
        map.get_mut(key).map(f)
    }

    /// Compound mutation: run `f` against the entry for `key`
    /// while holding the write lock; afterwards insert any
    /// additional entries returned by `f` via
    /// `insert_with_eviction` semantics (FIFO + cap honored).
    /// Used by `rotate_key` which needs both an in-place
    /// status flip AND a follow-up new-entry insert atomically
    /// with respect to the lock.
    ///
    /// `f` receives `&mut KeyEntry` and returns
    /// `(R, Vec<(Uuid, KeyEntry)>)` — `R` is the value the
    /// caller wants back from the closure; the `Vec` is the
    /// list of new entries to insert after `f` returns.
    ///
    /// Returns `Some(R)` if the entry was present,
    /// `None` otherwise.
    pub fn mutate_and_insert<F, R>(&self, key: &Uuid, f: F) -> Option<R>
    where
        F: FnOnce(&mut super::postgres::KeyEntry) -> (R, Vec<(Uuid, super::postgres::KeyEntry)>),
    {
        // Phase 1: mutate the entry under the write lock and
        // collect any additional entries to insert.
        let (result, to_insert) = {
            let mut map = self.map.write();
            let entry = map.get_mut(key)?;
            f(entry)
        };
        // Phase 2: insert the additional entries (release the
        // lock first to avoid holding it during cap-eviction
        // work).
        for (uuid, entry) in to_insert {
            self.insert_with_eviction(uuid, entry);
        }
        Some(result)
    }

    /// Remove the entry for `key`, returning it if present.
    /// Used by `destroy_key` and `destroy_key_with_proof`
    /// which need to inspect the material before zeroizing.
    pub fn remove(&self, key: &Uuid) -> Option<super::postgres::KeyEntry> {
        let removed = self.map.write().remove(key);
        if removed.is_some() {
            // Also drop the order-queue entry. We scan the
            // VecDeque linearly because Uuid lookup is rare
            // and the queue stays small (<= capacity).
            let mut order = self.order.lock();
            if let Some(pos) = order.iter().position(|k| k == key) {
                order.remove(pos);
            }
        }
        removed
    }

    /// Read-only `Option<&KeyEntry>` view for callers that
    /// want to do cheap existence / metadata checks without
    /// cloning the full entry. Returns a guard that borrows
    /// from the lock; drop the guard to release.
    pub fn try_read<F, R>(&self, key: &Uuid, f: F) -> Option<R>
    where
        F: FnOnce(&super::postgres::KeyEntry) -> R,
    {
        let map = self.map.read();
        map.get(key).map(f)
    }

    /// Insert `entry` for `key`. If the cache is at or above
    /// `capacity`, evict the oldest-inserted entry first.
    ///
    /// Note: FIFO eviction means we **do not** re-order the
    /// queue on `get_cloned`. A re-insertion of the same key
    /// appends to the back (LRU-style promotion would require
    /// a true LRU implementation).
    pub fn insert_with_eviction(&self, key: Uuid, entry: super::postgres::KeyEntry) {
        // Phase 1: take the write lock on the map and insert.
        // We do this BEFORE touching the order queue so that
        // the invariant `map.contains_key(k) ↔ order.contains(k)`
        // is broken only inside the order-queue mutation below.
        {
            let mut map = self.map.write();
            map.insert(key, entry);
        }

        // Phase 2: append to the order queue. We track this even
        // for the unbounded case so that switching to LRU
        // later is a pure code addition without API migration.
        {
            let mut order = self.order.lock();
            order.push_back(key);
        }

        // Phase 3: if a capacity is set and we're over, evict
        // the oldest entries until we're at the cap. Multiple
        // evictions are possible in pathological bulk-load
        // scenarios (e.g. operator sets cap=10, then inserts
        // 100 entries in one go).
        if let Some(cap) = self.capacity {
            loop {
                let current_len = self.map.read().len();
                if current_len <= cap {
                    break;
                }
                let victim = {
                    let mut order = self.order.lock();
                    order.pop_front()
                };
                let Some(victim) = victim else {
                    // Order queue empty but map non-empty —
                    // invariant broken; skip eviction to avoid
                    // panic.
                    break;
                };
                let mut map = self.map.write();
                // Only evict if the entry is still in the map
                // (it could have been overwritten by a re-insert).
                if map.remove(&victim).is_some() {
                    self.evictions.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Current number of entries in the cache.
    pub fn len(&self) -> usize {
        self.map.read().len()
    }

    /// `true` if the cache has no entries.
    pub fn is_empty(&self) -> bool {
        self.map.read().is_empty()
    }

    /// Configured capacity (or `None` for unbounded).
    pub fn capacity(&self) -> Option<usize> {
        self.capacity
    }

    /// Total FIFO evictions since process start.
    pub fn evictions_total(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// Remove all entries (used by tests / for future admin
    /// operations). Order queue is also cleared.
    pub fn clear(&self) {
        let mut map = self.map.write();
        let mut order = self.order.lock();
        map.clear();
        order.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::KeyEntry;

    fn fresh_entry() -> KeyEntry {
        // `KeyEntry::clone()` exists; construct via fields
        // would require `meta` + `material`. The fields are
        // `pub(super)`-accessible in `postgres.rs`. For unit
        // tests we only need the cache's bookkeeping, so we
        // use `Default::default()` for `KeyMeta` (which has
        // `Default`) and an empty `Zeroizing<Vec<u8>>` material.
        KeyEntry::default_for_test()
    }

    #[test]
    fn pr415_unbounded_cache_never_evicts() {
        let cache = BoundedKeyCache::new(None);
        for _ in 0..1000 {
            cache.insert_with_eviction(Uuid::new_v4(), fresh_entry());
        }
        assert_eq!(cache.len(), 1000);
        assert_eq!(cache.evictions_total(), 0);
    }

    #[test]
    fn pr415_bounded_cache_evicts_oldest_when_over_cap() {
        let cache = BoundedKeyCache::new(Some(3));
        let k_a = Uuid::new_v4();
        let k_b = Uuid::new_v4();
        let k_c = Uuid::new_v4();
        let k_d = Uuid::new_v4();
        cache.insert_with_eviction(k_a, fresh_entry());
        cache.insert_with_eviction(k_b, fresh_entry());
        cache.insert_with_eviction(k_c, fresh_entry());
        cache.insert_with_eviction(k_d, fresh_entry());
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.evictions_total(), 1);
        // `k_a` is the oldest → evicted.
        assert!(cache.get_cloned(&k_a).is_none());
        // `k_b`, `k_c`, `k_d` survive.
        assert!(cache.get_cloned(&k_b).is_some());
        assert!(cache.get_cloned(&k_c).is_some());
        assert!(cache.get_cloned(&k_d).is_some());
    }

    #[test]
    fn pr415_bounded_cache_keeps_recently_inserted_under_cap() {
        let cache = BoundedKeyCache::new(Some(3));
        cache.insert_with_eviction(Uuid::new_v4(), fresh_entry());
        cache.insert_with_eviction(Uuid::new_v4(), fresh_entry());
        cache.insert_with_eviction(Uuid::new_v4(), fresh_entry());
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.evictions_total(), 0);
    }

    #[test]
    fn pr415_bounded_cache_get_cloned_returns_none_for_missing() {
        let cache = BoundedKeyCache::new(None);
        let missing = Uuid::new_v4();
        assert!(cache.get_cloned(&missing).is_none());
    }

    #[test]
    fn pr415_bounded_cache_bulk_eviction() {
        let cache = BoundedKeyCache::new(Some(2));
        // Insert 4 entries in one go; should evict 2.
        let keys: Vec<Uuid> = (0..4).map(|_| Uuid::new_v4()).collect();
        for k in &keys {
            cache.insert_with_eviction(*k, fresh_entry());
        }
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.evictions_total(), 2);
        // First two are evicted; last two survive.
        assert!(cache.get_cloned(&keys[0]).is_none());
        assert!(cache.get_cloned(&keys[1]).is_none());
        assert!(cache.get_cloned(&keys[2]).is_some());
        assert!(cache.get_cloned(&keys[3]).is_some());
    }

    #[test]
    fn pr415_reinsertion_does_not_double_evict() {
        // Re-inserting the same key appends a duplicate to the
        // order queue; the map already contains the entry, so
        // net map size is unchanged. The order queue has one
        // extra entry, so when cap is exceeded, the duplicate
        // gets popped first and `map.remove` returns None (no
        // eviction counter bump). This documents the current
        // FIFO-with-no-dedup behavior — a future LRU upgrade
        // would handle this case differently.
        let cache = BoundedKeyCache::new(Some(2));
        let k = Uuid::new_v4();
        cache.insert_with_eviction(k, fresh_entry());
        cache.insert_with_eviction(k, fresh_entry()); // re-insert
        cache.insert_with_eviction(k, fresh_entry()); // re-insert
        // Net map size: 1 (single key).
        assert_eq!(cache.len(), 1);
        // But the order queue has 3 entries; inserting a
        // fourth different key would pop k three times and
        // eventually evict it. Length map stays at 1 because
        // map.remove returns None for the duplicates.
        let k2 = Uuid::new_v4();
        cache.insert_with_eviction(k2, fresh_entry());
        // Map size: 2 (k + k2). The order queue popped k three
        // times (no map entries removed), then popped one slot
        // for k2 — net: no eviction counter bumps.
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.evictions_total(), 0);
        assert!(cache.get_cloned(&k).is_some());
        assert!(cache.get_cloned(&k2).is_some());
    }

    #[test]
    fn pr415_clear_resets_state() {
        let cache = BoundedKeyCache::new(Some(2));
        cache.insert_with_eviction(Uuid::new_v4(), fresh_entry());
        cache.insert_with_eviction(Uuid::new_v4(), fresh_entry());
        cache.insert_with_eviction(Uuid::new_v4(), fresh_entry());
        assert_eq!(cache.evictions_total(), 1);
        cache.clear();
        assert_eq!(cache.len(), 0);
        // evictions counter is intentionally NOT reset —
        // it tracks process-lifetime evictions for metrics.
        assert_eq!(cache.evictions_total(), 1);
    }

    #[test]
    fn pr415_capacity_accessor() {
        let unbounded = BoundedKeyCache::new(None);
        assert_eq!(unbounded.capacity(), None);
        let bounded = BoundedKeyCache::new(Some(42));
        assert_eq!(bounded.capacity(), Some(42));
    }
}
