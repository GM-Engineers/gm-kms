//! KMS metrics for observability
//!
//! Provides metrics for monitoring KMS operations.
//!
//! This is a simple in-memory metrics implementation. For production use,
//! consider integrating with Prometheus client library.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

/// KMS metrics collector
#[derive(Debug, Clone)]
pub struct KmsMetrics {
    // Key operation counters
    pub key_operations_total: Counter,
    pub key_create_total: Counter,
    pub key_encrypt_total: Counter,
    pub key_decrypt_total: Counter,
    pub key_sign_total: Counter,
    pub key_verify_total: Counter,
    pub key_rotate_total: Counter,
    pub key_delete_total: Counter,
    pub key_export_total: Counter,

    // Error counters
    pub key_errors_total: Counter,

    // Active tenants gauge
    pub active_tenants: Counter,

    // Rate limit hits
    pub rate_limit_hits_total: Counter,

    // Quota exceeded hits
    pub quota_exceeded_total: Counter,

    // Audit backlog depth gauge
    pub audit_backlog_depth: AtomicGauge,

    // TSA observability (Phase 1 #13)
    pub tsa_requests_total: Counter,
    pub tsa_successes_total: Counter,
    pub tsa_failures_total: Counter,
    pub tsa_time_drift_seconds: Counter,

    // PBAC counters (Phase 1 #33)
    pub pbac_policy_count_total: Counter,
    pub pbac_evaluation_allow_total: Counter,
    pub pbac_evaluation_deny_total: Counter,

    // Key lifecycle (Phase 2 #3)
    pub keys_by_status_active: Counter,
    pub keys_by_status_pending_deletion: Counter,
    pub keys_by_status_obsolete: Counter,
    pub keys_by_status_destroyed: Counter,
    pub key_destroyed_total: Counter,
    pub key_expiry_soon_total: Counter,

    // Rotation (Phase 2 #5)
    pub rotation_attempts_total: Counter,
    pub rotation_failures_total: Counter,

    // MFA (Phase 2 #39)
    pub mfa_attempts_total: Counter,
    pub mfa_failures_total: Counter,
    pub mfa_lockouts_total: Counter,

    // Memory protection (Phase 2 #26)
    pub mlock_failures_total: Counter,

    // TPM health (Phase 2 #25)
    pub tpm_health_status: AtomicGauge,

    // SM9 KGC (Phase 2 #44)
    pub kgc_key_generation_total: Counter,
    pub kgc_master_key_loaded: AtomicGauge,

    // Feature flag verification (Phase 2 #22)
    pub feature_config_mismatch: AtomicGauge,

    // Aggregated health (Phase 2 #20+#43)
    pub health_status: AtomicGauge,

    // Client clock skew (Phase 2 #31)
    pub client_clock_skew_seconds: Counter,

    // Per-tenant rate limit hits (Phase 2 #32, internal only)
    #[allow(dead_code)]
    per_tenant_rate_limit_hits: Arc<Mutex<HashMap<String, u64>>>,

    // ── #4 Key access distribution ──
    /// Internal per-key access counts (not exposed directly)
    per_key_access_counts: Arc<Mutex<HashMap<Uuid, u64>>>,
    pub key_access_bucket_0: Counter,
    pub key_access_bucket_1_10: Counter,
    pub key_access_bucket_11_100: Counter,
    pub key_access_bucket_100_plus: Counter,

    // ── #6 Encrypt/decrypt ratio ──
    pub encrypt_decrypt_ratio: AtomicGauge,

    // ── #14 Crypto algorithm distribution ──
    pub aes_encrypt_total: Counter,
    pub aes_decrypt_total: Counter,
    pub sm4_encrypt_total: Counter,
    pub sm4_decrypt_total: Counter,
    pub sm2_sign_total: Counter,
    pub sm2_verify_total: Counter,
    pub ed25519_sign_total: Counter,
    pub ed25519_verify_total: Counter,
    pub sm9_sign_total: Counter,
    pub sm9_verify_total: Counter,
    pub sm9_encrypt_total: Counter,
    pub sm9_decrypt_total: Counter,
    pub ecdsa_p256_sign_total: Counter,
    pub ecdsa_p384_sign_total: Counter,

    // ── #15+#42 Backup/restore drill ──
    pub backup_attempts_total: Counter,
    pub backup_successes_total: Counter,
    pub backup_failures_total: Counter,
    pub backup_last_success_timestamp: AtomicGauge,

    // ── #19 Key storage capacity ──
    pub key_storage_bytes_estimated: AtomicGauge,
    pub key_count_total: AtomicGauge,

    // ── #38 Approval chain duration ──
    pub approval_chain_duration_seconds: Counter,
}

/// Simple atomic counter
#[derive(Debug, Clone, Default)]
pub struct Counter {
    count: Arc<AtomicU64>,
}

impl Counter {
    pub fn new() -> Self {
        Self {
            count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Create a counter from an existing Arc<AtomicU64>.
    /// Used to share the same underlying counter between KmsMetrics and
    /// other components (e.g., TimestampedAuditLogger's background TSA task).
    pub fn from_arc(arc: Arc<AtomicU64>) -> Self {
        Self { count: arc }
    }

    pub fn inc(&self) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn set(&self, value: u64) {
        self.count.store(value, Ordering::Relaxed);
    }

    pub fn reset(&self) {
        self.count.store(0, Ordering::Relaxed);
    }

    /// Return the inner Arc for sharing with other components
    pub fn inner_arc(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.count)
    }
}

/// Simple atomic gauge (value can go up and down)
#[derive(Debug, Clone, Default)]
pub struct AtomicGauge {
    value: Arc<AtomicU64>,
}

impl AtomicGauge {
    pub fn new() -> Self {
        Self {
            value: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn set(&self, v: u64) {
        self.value.store(v, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

impl KmsMetrics {
    pub fn new() -> Self {
        Self {
            key_operations_total: Counter::new(),
            key_create_total: Counter::new(),
            key_encrypt_total: Counter::new(),
            key_decrypt_total: Counter::new(),
            key_sign_total: Counter::new(),
            key_verify_total: Counter::new(),
            key_rotate_total: Counter::new(),
            key_delete_total: Counter::new(),
            key_export_total: Counter::new(),
            key_errors_total: Counter::new(),
            active_tenants: Counter::new(),
            rate_limit_hits_total: Counter::new(),
            quota_exceeded_total: Counter::new(),
            audit_backlog_depth: AtomicGauge::new(),
            tsa_requests_total: Counter::new(),
            tsa_successes_total: Counter::new(),
            tsa_failures_total: Counter::new(),
            tsa_time_drift_seconds: Counter::new(),
            pbac_policy_count_total: Counter::new(),
            pbac_evaluation_allow_total: Counter::new(),
            pbac_evaluation_deny_total: Counter::new(),
            keys_by_status_active: Counter::new(),
            keys_by_status_pending_deletion: Counter::new(),
            keys_by_status_obsolete: Counter::new(),
            keys_by_status_destroyed: Counter::new(),
            key_destroyed_total: Counter::new(),
            key_expiry_soon_total: Counter::new(),
            rotation_attempts_total: Counter::new(),
            rotation_failures_total: Counter::new(),
            mfa_attempts_total: Counter::new(),
            mfa_failures_total: Counter::new(),
            mfa_lockouts_total: Counter::new(),
            mlock_failures_total: Counter::new(),
            tpm_health_status: AtomicGauge::new(),
            kgc_key_generation_total: Counter::new(),
            kgc_master_key_loaded: AtomicGauge::new(),
            feature_config_mismatch: AtomicGauge::new(),
            health_status: AtomicGauge::new(),
            client_clock_skew_seconds: Counter::new(),
            per_tenant_rate_limit_hits: Arc::new(Mutex::new(HashMap::new())),

            // #4
            per_key_access_counts: Arc::new(Mutex::new(HashMap::new())),
            key_access_bucket_0: Counter::new(),
            key_access_bucket_1_10: Counter::new(),
            key_access_bucket_11_100: Counter::new(),
            key_access_bucket_100_plus: Counter::new(),

            // #6
            encrypt_decrypt_ratio: AtomicGauge::new(),

            // #14
            aes_encrypt_total: Counter::new(),
            aes_decrypt_total: Counter::new(),
            sm4_encrypt_total: Counter::new(),
            sm4_decrypt_total: Counter::new(),
            sm2_sign_total: Counter::new(),
            sm2_verify_total: Counter::new(),
            ed25519_sign_total: Counter::new(),
            ed25519_verify_total: Counter::new(),
            sm9_sign_total: Counter::new(),
            sm9_verify_total: Counter::new(),
            sm9_encrypt_total: Counter::new(),
            sm9_decrypt_total: Counter::new(),
            ecdsa_p256_sign_total: Counter::new(),
            ecdsa_p384_sign_total: Counter::new(),

            // #15+#42
            backup_attempts_total: Counter::new(),
            backup_successes_total: Counter::new(),
            backup_failures_total: Counter::new(),
            backup_last_success_timestamp: AtomicGauge::new(),

            // #19
            key_storage_bytes_estimated: AtomicGauge::new(),
            key_count_total: AtomicGauge::new(),

            // #38
            approval_chain_duration_seconds: Counter::new(),
        }
    }

    /// Create KmsMetrics with shared TSA counters.
    ///
    /// The `tsa_*` Arc<AtomicU64> values are shared with the
    /// TimestampedAuditLogger's background TSA task.
    pub fn with_tsa_counters(
        tsa_requests: Arc<AtomicU64>,
        tsa_successes: Arc<AtomicU64>,
        tsa_failures: Arc<AtomicU64>,
    ) -> Self {
        let mut m = Self::new();
        m.tsa_requests_total = Counter::from_arc(tsa_requests);
        m.tsa_successes_total = Counter::from_arc(tsa_successes);
        m.tsa_failures_total = Counter::from_arc(tsa_failures);
        m
    }

    /// Record a key operation
    pub fn record_key_op(&self, operation: &str) {
        self.key_operations_total.inc();
        match operation {
            "create" => self.key_create_total.inc(),
            "encrypt" => self.key_encrypt_total.inc(),
            "decrypt" => self.key_decrypt_total.inc(),
            "sign" => self.key_sign_total.inc(),
            "verify" => self.key_verify_total.inc(),
            "rotate" => self.key_rotate_total.inc(),
            "delete" => self.key_delete_total.inc(),
            "export" => self.key_export_total.inc(),
            _ => {}
        }
    }

    /// Record a key error
    pub fn record_error(&self) {
        self.key_errors_total.inc();
    }

    /// Record rate limit hit
    pub fn record_rate_limit_hit(&self) {
        self.rate_limit_hits_total.inc();
    }

    /// Record quota exceeded
    pub fn record_quota_exceeded(&self) {
        self.quota_exceeded_total.inc();
    }

    /// Record active tenant
    pub fn record_active_tenant(&self) {
        self.active_tenants.inc();
    }

    /// Record a key export operation
    pub fn record_key_export(&self) {
        self.record_key_op("export");
    }

    /// Set the audit backlog depth
    pub fn set_audit_backlog(&self, depth: usize) {
        self.audit_backlog_depth.set(depth as u64);
    }

    /// Record a TSA request
    pub fn record_tsa_request(&self) {
        self.tsa_requests_total.inc();
    }

    /// Record a TSA success
    pub fn record_tsa_success(&self) {
        self.tsa_successes_total.inc();
    }

    /// Record a TSA failure
    pub fn record_tsa_failure(&self) {
        self.tsa_failures_total.inc();
    }

    /// Set TSA time drift in seconds
    pub fn set_tsa_time_drift(&self, drift_secs: i64) {
        self.tsa_time_drift_seconds.set(drift_secs.unsigned_abs());
    }

    /// Record PBAC policy creation
    pub fn record_policy_create(&self) {
        self.pbac_policy_count_total.inc();
    }

    /// Record PBAC policy deletion
    pub fn record_policy_delete(&self) {
        self.pbac_policy_count_total.dec();
    }

    /// Record PBAC evaluation result
    pub fn record_pbac_evaluation(&self, allowed: bool) {
        if allowed {
            self.pbac_evaluation_allow_total.inc();
        } else {
            self.pbac_evaluation_deny_total.inc();
        }
    }

    // --- Key lifecycle (Phase 2 #3, #5, #27) ---

    /// Record a key creation (increment active count)
    pub fn record_key_created(&self) {
        self.keys_by_status_active.inc();
    }

    /// Record a key soft-deletion (active → pending_deletion)
    pub fn record_key_deleted(&self) {
        if self.keys_by_status_active.get() > 0 {
            self.keys_by_status_active.dec();
        }
        self.keys_by_status_pending_deletion.inc();
    }

    /// Record a key becoming obsolete (active → obsolete)
    pub fn record_key_obsoleted(&self) {
        if self.keys_by_status_active.get() > 0 {
            self.keys_by_status_active.dec();
        }
        self.keys_by_status_obsolete.inc();
    }

    /// Record a key being permanently destroyed
    pub fn record_key_destroyed(&self) {
        if self.keys_by_status_pending_deletion.get() > 0 {
            self.keys_by_status_pending_deletion.dec();
        }
        self.keys_by_status_destroyed.inc();
        self.key_destroyed_total.inc();
    }

    /// Record a key nearing expiration (< 7 days)
    pub fn record_key_expiry_soon(&self) {
        self.key_expiry_soon_total.inc();
    }

    // --- Rotation (Phase 2 #5) ---

    /// Record a rotation attempt
    pub fn record_rotation_attempt(&self) {
        self.rotation_attempts_total.inc();
    }

    /// Record a rotation failure
    pub fn record_rotation_failure(&self) {
        self.rotation_failures_total.inc();
    }

    // --- MFA (Phase 2 #39) ---

    /// Record an MFA verification attempt
    pub fn record_mfa_attempt(&self) {
        self.mfa_attempts_total.inc();
    }

    /// Record an MFA verification failure
    pub fn record_mfa_failure(&self) {
        self.mfa_failures_total.inc();
    }

    /// Record an MFA lockout event
    pub fn record_mfa_lockout(&self) {
        self.mfa_lockouts_total.inc();
    }

    // --- Memory protection (Phase 2 #26) ---

    /// Record an mlock failure
    pub fn record_mlock_failure(&self) {
        self.mlock_failures_total.inc();
    }

    // --- TPM health (Phase 2 #25) ---

    /// Set TPM health status (0=Healthy, 1=Degraded, 2=Unhealthy, 3=Unknown)
    pub fn set_tpm_health(&self, status: u8) {
        self.tpm_health_status.set(status as u64);
    }

    // --- SM9 KGC (Phase 2 #44) ---

    /// Record an SM9 KGC user key generation
    pub fn record_kgc_key_generation(&self) {
        self.kgc_key_generation_total.inc();
    }

    /// Set SM9 KGC master key loaded status (0=not loaded, 1=loaded)
    pub fn set_kgc_master_key_loaded(&self, loaded: bool) {
        self.kgc_master_key_loaded.set(if loaded { 1 } else { 0 });
    }

    // --- Feature flag verification (Phase 2 #22) ---

    /// Set feature/config mismatch gauge to 1
    pub fn set_feature_config_mismatch(&self) {
        self.feature_config_mismatch.set(1);
    }

    // --- Aggregated health (Phase 2 #20+#43) ---

    /// Set aggregated health status (0=Healthy, 1=Degraded, 2=Unhealthy, 3=Unknown)
    pub fn set_health_status(&self, status: u8) {
        self.health_status.set(status as u64);
    }

    // --- Client clock skew (Phase 2 #31) ---

    /// Set client clock skew in seconds (absolute value)
    pub fn set_client_clock_skew(&self, skew_secs: i64) {
        self.client_clock_skew_seconds.set(skew_secs.unsigned_abs());
    }

    // --- Per-tenant rate limiting (Phase 2 #32, internal only) ---

    /// Record a rate limit hit for a specific tenant (internal, not exposed in /v1/metrics)
    pub fn record_rate_limit_hit_for_tenant(&self, tenant: &str) {
        self.rate_limit_hits_total.inc();
        let mut map = self.per_tenant_rate_limit_hits.lock();
        let count = map.entry(tenant.to_string()).or_insert(0);
        *count += 1;
        if *count >= 100 && *count % 100 == 0 {
            tracing::warn!("Tenant '{}' has hit rate limit {} times", tenant, count);
        }
    }

    // ── #4 Key access distribution ──

    /// Record a key access for the access distribution histogram.
    pub fn record_key_access(&self, key_id: &Uuid) {
        let mut map = self.per_key_access_counts.lock();
        *map.entry(*key_id).or_insert(0) += 1;
    }

    /// Compute access distribution buckets and reset per-key counts.
    pub fn refresh_key_access_distribution(&self) {
        let mut map = self.per_key_access_counts.lock();
        let mut b0 = 0u64;
        let mut b1_10 = 0u64;
        let mut b11_100 = 0u64;
        let mut b100p = 0u64;
        for count in map.values() {
            match *count {
                0 => b0 += 1,
                1..=10 => b1_10 += 1,
                11..=100 => b11_100 += 1,
                101.. => b100p += 1,
            }
        }
        map.clear();
        drop(map);
        self.key_access_bucket_0.set(b0);
        self.key_access_bucket_1_10.set(b1_10);
        self.key_access_bucket_11_100.set(b11_100);
        self.key_access_bucket_100_plus.set(b100p);
    }

    // ── #6 Encrypt/decrypt ratio ──

    /// Update the encrypt/decrypt ratio gauge (permille, ×1000).
    pub fn refresh_encrypt_decrypt_ratio(&self) {
        let enc = self.key_encrypt_total.get();
        let dec = self.key_decrypt_total.get();
        let ratio = (enc * 1000).checked_div(dec).unwrap_or(0);
        self.encrypt_decrypt_ratio.set(ratio);
    }

    // ── #14 Crypto algorithm distribution ──

    /// Record a key operation with algorithm awareness.
    pub fn record_key_op_with_spec(&self, operation: &str, spec: &kms_core::key::KeySpec) {
        self.record_key_op(operation);
        match (operation, spec) {
            ("encrypt", kms_core::key::KeySpec::Aes256Gcm) => self.aes_encrypt_total.inc(),
            ("decrypt", kms_core::key::KeySpec::Aes256Gcm) => self.aes_decrypt_total.inc(),
            ("encrypt", kms_core::key::KeySpec::Sm4) => self.sm4_encrypt_total.inc(),
            ("decrypt", kms_core::key::KeySpec::Sm4) => self.sm4_decrypt_total.inc(),
            ("sign", kms_core::key::KeySpec::Sm2) => self.sm2_sign_total.inc(),
            ("verify", kms_core::key::KeySpec::Sm2) => self.sm2_verify_total.inc(),
            ("sign", kms_core::key::KeySpec::Ed25519) => self.ed25519_sign_total.inc(),
            ("verify", kms_core::key::KeySpec::Ed25519) => self.ed25519_verify_total.inc(),
            ("sign", kms_core::key::KeySpec::Sm9Signing) => self.sm9_sign_total.inc(),
            ("verify", kms_core::key::KeySpec::Sm9Signing) => self.sm9_verify_total.inc(),
            ("encrypt", kms_core::key::KeySpec::Sm9Encryption) => self.sm9_encrypt_total.inc(),
            ("decrypt", kms_core::key::KeySpec::Sm9Encryption) => self.sm9_decrypt_total.inc(),
            ("sign", kms_core::key::KeySpec::EcdsaP256) => self.ecdsa_p256_sign_total.inc(),
            ("sign", kms_core::key::KeySpec::EcdsaP384) => self.ecdsa_p384_sign_total.inc(),
            _ => {}
        }
    }

    // ── #15+#42 Backup/restore drill ──

    pub fn record_backup_attempt(&self) {
        self.backup_attempts_total.inc();
    }

    pub fn record_backup_success(&self) {
        self.backup_successes_total.inc();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.backup_last_success_timestamp.set(now);
    }

    pub fn record_backup_failure(&self) {
        self.backup_failures_total.inc();
    }

    // ── #19 Key storage capacity ──

    pub fn set_key_storage_bytes(&self, bytes: u64) {
        self.key_storage_bytes_estimated.set(bytes);
    }

    pub fn set_key_count(&self, count: u64) {
        self.key_count_total.set(count);
    }

    // ── #38 Approval chain duration ──

    /// Record the cumulative duration of an approval chain in seconds.
    pub fn record_approval_chain_duration(&self, duration_secs: u64) {
        self.approval_chain_duration_seconds.set(
            self.approval_chain_duration_seconds
                .get()
                .saturating_add(duration_secs),
        );
    }
}

impl Default for KmsMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter() {
        let counter = Counter::new();
        assert_eq!(counter.get(), 0);
        counter.inc();
        assert_eq!(counter.get(), 1);
        counter.inc();
        assert_eq!(counter.get(), 2);
    }

    #[test]
    fn test_counter_from_arc() {
        let arc = Arc::new(AtomicU64::new(42));
        let counter = Counter::from_arc(Arc::clone(&arc));
        assert_eq!(counter.get(), 42);
        counter.inc();
        assert_eq!(arc.load(Ordering::Relaxed), 43);
    }

    #[test]
    fn test_gauge() {
        let gauge = AtomicGauge::new();
        assert_eq!(gauge.get(), 0);
        gauge.set(5);
        assert_eq!(gauge.get(), 5);
        gauge.set(3);
        assert_eq!(gauge.get(), 3);
    }

    #[test]
    fn test_metrics_record() {
        let metrics = KmsMetrics::new();
        metrics.record_key_op("create");
        metrics.record_key_op("encrypt");
        metrics.record_key_op("decrypt");
        assert_eq!(metrics.key_operations_total.get(), 3);
        assert_eq!(metrics.key_create_total.get(), 1);
        assert_eq!(metrics.key_encrypt_total.get(), 1);
        assert_eq!(metrics.key_decrypt_total.get(), 1);
    }

    #[test]
    fn test_metrics_record_tenant() {
        let metrics = KmsMetrics::new();
        metrics.record_active_tenant();
        assert_eq!(metrics.active_tenants.get(), 1);
    }

    #[test]
    fn test_metrics_export_counter() {
        let metrics = KmsMetrics::new();
        metrics.record_key_export();
        assert_eq!(metrics.key_export_total.get(), 1);
    }

    #[test]
    fn test_metrics_audit_backlog() {
        let metrics = KmsMetrics::new();
        metrics.set_audit_backlog(42);
        assert_eq!(metrics.audit_backlog_depth.get(), 42);
    }

    #[test]
    fn test_metrics_tsa_counters() {
        let metrics = KmsMetrics::new();
        metrics.record_tsa_request();
        metrics.record_tsa_success();
        metrics.record_tsa_failure();
        metrics.record_tsa_failure();
        assert_eq!(metrics.tsa_requests_total.get(), 1);
        assert_eq!(metrics.tsa_successes_total.get(), 1);
        assert_eq!(metrics.tsa_failures_total.get(), 2);
    }

    #[test]
    fn test_metrics_tsa_drift() {
        let metrics = KmsMetrics::new();
        metrics.set_tsa_time_drift(5);
        assert_eq!(metrics.tsa_time_drift_seconds.get(), 5);
        metrics.set_tsa_time_drift(-3);
        assert_eq!(metrics.tsa_time_drift_seconds.get(), 3);
    }

    #[test]
    fn test_metrics_pbac_counters() {
        let metrics = KmsMetrics::new();
        metrics.record_policy_create();
        metrics.record_policy_create();
        assert_eq!(metrics.pbac_policy_count_total.get(), 2);
        metrics.record_policy_delete();
        assert_eq!(metrics.pbac_policy_count_total.get(), 1);
        metrics.record_pbac_evaluation(true);
        metrics.record_pbac_evaluation(false);
        assert_eq!(metrics.pbac_evaluation_allow_total.get(), 1);
        assert_eq!(metrics.pbac_evaluation_deny_total.get(), 1);
    }

    #[test]
    fn test_metrics_with_tsa_counters() {
        let req = Arc::new(AtomicU64::new(0));
        let ok = Arc::new(AtomicU64::new(0));
        let fail = Arc::new(AtomicU64::new(0));
        let metrics =
            KmsMetrics::with_tsa_counters(Arc::clone(&req), Arc::clone(&ok), Arc::clone(&fail));
        metrics.record_tsa_request();
        metrics.record_tsa_success();
        assert_eq!(req.load(Ordering::Relaxed), 1);
        assert_eq!(ok.load(Ordering::Relaxed), 1);
        assert_eq!(fail.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_key_lifecycle_metrics() {
        let m = KmsMetrics::new();
        m.record_key_created();
        m.record_key_created();
        assert_eq!(m.keys_by_status_active.get(), 2);
        m.record_key_deleted();
        assert_eq!(m.keys_by_status_active.get(), 1);
        assert_eq!(m.keys_by_status_pending_deletion.get(), 1);
        m.record_key_destroyed();
        assert_eq!(m.keys_by_status_pending_deletion.get(), 0);
        assert_eq!(m.keys_by_status_destroyed.get(), 1);
        assert_eq!(m.key_destroyed_total.get(), 1);
    }

    #[test]
    fn test_rotation_metrics() {
        let m = KmsMetrics::new();
        m.record_rotation_attempt();
        m.record_rotation_attempt();
        m.record_rotation_failure();
        assert_eq!(m.rotation_attempts_total.get(), 2);
        assert_eq!(m.rotation_failures_total.get(), 1);
    }

    #[test]
    fn test_mfa_metrics() {
        let m = KmsMetrics::new();
        m.record_mfa_attempt();
        m.record_mfa_attempt();
        m.record_mfa_failure();
        m.record_mfa_lockout();
        assert_eq!(m.mfa_attempts_total.get(), 2);
        assert_eq!(m.mfa_failures_total.get(), 1);
        assert_eq!(m.mfa_lockouts_total.get(), 1);
    }

    #[test]
    fn test_health_gauges() {
        let m = KmsMetrics::new();
        m.set_health_status(0);
        assert_eq!(m.health_status.get(), 0);
        m.set_health_status(1);
        assert_eq!(m.health_status.get(), 1);
        m.set_tpm_health(2);
        assert_eq!(m.tpm_health_status.get(), 2);
    }

    #[test]
    fn test_kgc_metrics() {
        let m = KmsMetrics::new();
        m.set_kgc_master_key_loaded(true);
        assert_eq!(m.kgc_master_key_loaded.get(), 1);
        m.record_kgc_key_generation();
        m.record_kgc_key_generation();
        assert_eq!(m.kgc_key_generation_total.get(), 2);
    }

    #[test]
    fn test_feature_mismatch_gauge() {
        let m = KmsMetrics::new();
        assert_eq!(m.feature_config_mismatch.get(), 0);
        m.set_feature_config_mismatch();
        assert_eq!(m.feature_config_mismatch.get(), 1);
    }

    #[test]
    fn test_clock_skew() {
        let m = KmsMetrics::new();
        m.set_client_clock_skew(30);
        assert_eq!(m.client_clock_skew_seconds.get(), 30);
        m.set_client_clock_skew(-5);
        assert_eq!(m.client_clock_skew_seconds.get(), 5);
    }

    #[test]
    fn test_mlock_failure() {
        let m = KmsMetrics::new();
        m.record_mlock_failure();
        m.record_mlock_failure();
        assert_eq!(m.mlock_failures_total.get(), 2);
    }

    #[test]
    fn test_key_expiry_soon() {
        let m = KmsMetrics::new();
        m.record_key_expiry_soon();
        m.record_key_expiry_soon();
        assert_eq!(m.key_expiry_soon_total.get(), 2);
    }

    #[test]
    fn test_per_tenant_rate_limit_internal() {
        let m = KmsMetrics::new();
        m.record_rate_limit_hit_for_tenant("tenant-a");
        m.record_rate_limit_hit_for_tenant("tenant-a");
        m.record_rate_limit_hit_for_tenant("tenant-b");
        assert_eq!(m.rate_limit_hits_total.get(), 3);
        let map = m.per_tenant_rate_limit_hits.lock();
        assert_eq!(map.get("tenant-a"), Some(&2));
        assert_eq!(map.get("tenant-b"), Some(&1));
    }

    #[test]
    fn test_key_obsoleted_transition() {
        let m = KmsMetrics::new();
        m.record_key_created();
        assert_eq!(m.keys_by_status_active.get(), 1);
        m.record_key_obsoleted();
        assert_eq!(m.keys_by_status_active.get(), 0);
        assert_eq!(m.keys_by_status_obsolete.get(), 1);
    }

    // ── Phase 3 tests ──

    #[test]
    fn test_key_access_distribution() {
        let m = KmsMetrics::new();
        let k1 = Uuid::new_v4();
        let k2 = Uuid::new_v4();
        // k1: 5 accesses → bucket 1-10
        for _ in 0..5 {
            m.record_key_access(&k1);
        }
        // k2: 50 accesses → bucket 11-100
        for _ in 0..50 {
            m.record_key_access(&k2);
        }
        m.refresh_key_access_distribution();
        assert_eq!(m.key_access_bucket_0.get(), 0); // no keys with 0 accesses tracked
        assert_eq!(m.key_access_bucket_1_10.get(), 1); // k1
        assert_eq!(m.key_access_bucket_11_100.get(), 1); // k2
        assert_eq!(m.key_access_bucket_100_plus.get(), 0);
        // Map is cleared after refresh
        let map = m.per_key_access_counts.lock();
        assert!(map.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_ratio() {
        let m = KmsMetrics::new();
        m.key_encrypt_total.inc();
        m.key_encrypt_total.inc();
        m.key_encrypt_total.inc(); // 3 encrypts
        m.key_decrypt_total.inc(); // 1 decrypt
        m.refresh_encrypt_decrypt_ratio();
        assert_eq!(m.encrypt_decrypt_ratio.get(), 3000); // 3/1 * 1000
    }

    #[test]
    fn test_encrypt_decrypt_ratio_zero_decrypts() {
        let m = KmsMetrics::new();
        m.key_encrypt_total.inc();
        m.refresh_encrypt_decrypt_ratio();
        assert_eq!(m.encrypt_decrypt_ratio.get(), 0);
    }

    #[test]
    fn test_algorithm_aware_metrics() {
        use kms_core::key::KeySpec;
        let m = KmsMetrics::new();
        m.record_key_op_with_spec("encrypt", &KeySpec::Aes256Gcm);
        m.record_key_op_with_spec("sign", &KeySpec::Sm2);
        assert_eq!(m.aes_encrypt_total.get(), 1);
        assert_eq!(m.sm2_sign_total.get(), 1);
        assert_eq!(m.key_encrypt_total.get(), 1);
        assert_eq!(m.key_sign_total.get(), 1);
    }

    #[test]
    fn test_backup_metrics() {
        let m = KmsMetrics::new();
        m.record_backup_attempt();
        m.record_backup_success();
        m.record_backup_attempt();
        m.record_backup_failure();
        assert_eq!(m.backup_attempts_total.get(), 2);
        assert_eq!(m.backup_successes_total.get(), 1);
        assert_eq!(m.backup_failures_total.get(), 1);
        assert!(m.backup_last_success_timestamp.get() > 0);
    }

    #[test]
    fn test_key_storage_capacity() {
        let m = KmsMetrics::new();
        m.set_key_storage_bytes(1024);
        m.set_key_count(42);
        assert_eq!(m.key_storage_bytes_estimated.get(), 1024);
        assert_eq!(m.key_count_total.get(), 42);
    }

    #[test]
    fn test_approval_chain_duration() {
        let m = KmsMetrics::new();
        m.record_approval_chain_duration(120);
        m.record_approval_chain_duration(300);
        assert_eq!(m.approval_chain_duration_seconds.get(), 420);
    }
}
