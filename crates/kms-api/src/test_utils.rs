//! Shared test utilities for kms-api tests.
//!
//! This module is only compiled when testing (`#[cfg(test)]`).

use crate::rotation::OperationCounter;
use std::collections::HashMap;
use parking_lot::Mutex;
use uuid::Uuid;

/// An in-memory [`OperationCounter`] for testing, backed by a `HashMap`.
pub(crate) struct MockOperationCounter {
    counts: Mutex<HashMap<Uuid, u64>>,
}

impl MockOperationCounter {
    pub(crate) fn new() -> Self {
        Self {
            counts: Mutex::new(HashMap::new()),
        }
    }

    /// Synchronous convenience wrapper for get_count
    pub(crate) fn get(&self, key_id: &Uuid) -> u64 {
        self.counts
            .lock()
            .get(key_id)
            .copied()
            .unwrap_or(0)
    }
}

#[async_trait::async_trait]
impl OperationCounter for MockOperationCounter {
    async fn increment(&self, key_id: &Uuid) -> u64 {
        let mut map = self.counts.lock();
        let count = map.entry(*key_id).or_insert(0);
        *count += 1;
        *count
    }

    async fn get_count(&self, key_id: &Uuid) -> u64 {
        self.counts
            .lock()
            .get(key_id)
            .copied()
            .unwrap_or(0)
    }
}
