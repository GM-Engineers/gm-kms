//! Health Checker for aggregated dependency health (#20+#43)
//!
//! Probes all KMS dependencies and computes an aggregate health status.
//! Updates the `health_status` and `tpm_health_status` metrics gauges.

use crate::KmsMetrics;
use kms_core::types::HealthStatus;
use std::sync::Arc;

/// Aggregated health checker for KMS dependencies.
///
/// Probes the keystore, audit logger, and TPM health, then maps
/// results to an aggregate `HealthStatus` and updates metrics gauges.
pub struct HealthChecker {
    pub keystore: Arc<dyn kms_keystore::KeystoreBackend>,
    pub audit_logger: Arc<dyn kms_audit::AuditLog>,
    pub metrics: KmsMetrics,
}

impl HealthChecker {
    /// Create a new health checker.
    pub fn new(
        keystore: Arc<dyn kms_keystore::KeystoreBackend>,
        audit_logger: Arc<dyn kms_audit::AuditLog>,
        metrics: KmsMetrics,
    ) -> Self {
        Self {
            keystore,
            audit_logger,
            metrics,
        }
    }

    /// Run a full health check and return the aggregate status.
    ///
    /// Probing order:
    /// 1. Keystore health (direct probe)
    /// 2. Audit backlog depth
    ///
    /// The aggregate is the worst of all dependency statuses:
    /// - Any `Unhealthy` → aggregate is `Unhealthy`
    /// - Any `Degraded` → aggregate is `Degraded`
    /// - Otherwise → `Healthy`
    pub async fn check(&self) -> HealthStatus {
        let keystore_health = match self.keystore.health().await {
            Ok(status) => status,
            Err(e) => {
                tracing::error!("Keystore health check failed: {}", e);
                HealthStatus::Unhealthy
            }
        };

        let audit_backlog = self.audit_logger.backlog_depth().await;

        // Update TPM health gauge based on keystore backend type
        if self.keystore.backend_type() == kms_core::BackendType::Tpm {
            let tpm_val: u8 = match keystore_health {
                HealthStatus::Healthy => 0,
                HealthStatus::Degraded => 1,
                HealthStatus::Unhealthy => 2,
                HealthStatus::Unknown => 3,
            };
            self.metrics.set_tpm_health(tpm_val);
        }

        // Update audit backlog gauge
        self.metrics.set_audit_backlog(audit_backlog);

        // Compute aggregate: any Unhealthy → Unhealthy, any Degraded → Degraded
        let aggregate = if keystore_health == HealthStatus::Unhealthy {
            HealthStatus::Unhealthy
        } else if keystore_health == HealthStatus::Degraded {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        // Update the aggregated health gauge
        let agg_val: u8 = match aggregate {
            HealthStatus::Healthy => 0,
            HealthStatus::Degraded => 1,
            HealthStatus::Unhealthy => 2,
            HealthStatus::Unknown => 3,
        };
        self.metrics.set_health_status(agg_val);

        tracing::info!(
            "Health check: aggregate={:?}, keystore={:?}, audit_backlog={}",
            aggregate,
            keystore_health,
            audit_backlog
        );

        aggregate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kms_core::key::{KeyFilter, KeyMeta, KeySpec};
    use uuid::Uuid;

    /// A keystore that always returns Healthy.
    struct HealthyKeystore;
    #[async_trait::async_trait]
    impl kms_keystore::KeystoreBackend for HealthyKeystore {
        fn backend_type(&self) -> kms_core::BackendType {
            kms_core::BackendType::Software
        }
        async fn generate_key(
            &self,
            _spec: &KeySpec,
            _name: &str,
            _tenant_id: &str,
        ) -> kms_core::Result<KeyMeta> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn get_key_metadata(&self, _key_id: &Uuid) -> kms_core::Result<KeyMeta> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn encrypt(
            &self,
            _key_id: &Uuid,
            _plaintext: &[u8],
            _aad: Option<&[u8]>,
            _tenant_id: &str,
        ) -> kms_core::Result<kms_core::key::Ciphertext> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn decrypt(
            &self,
            _key_id: &Uuid,
            _ciphertext: &kms_core::key::Ciphertext,
            _aad: Option<&[u8]>,
            _tenant_id: &str,
        ) -> kms_core::Result<Vec<u8>> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn sign(
            &self,
            _key_id: &Uuid,
            _data: &[u8],
            _tenant_id: &str,
        ) -> kms_core::Result<kms_core::key::Signature> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn verify(
            &self,
            _key_id: &Uuid,
            _data: &[u8],
            _signature: &kms_core::key::Signature,
            _tenant_id: &str,
        ) -> kms_core::Result<bool> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn rotate_key(&self, _key_id: &Uuid, _tenant_id: &str) -> kms_core::Result<KeyMeta> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn delete_key(&self, _key_id: &Uuid, _tenant_id: &str) -> kms_core::Result<()> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn destroy_key(&self, _key_id: &Uuid) -> kms_core::Result<()> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn destroy_key_with_proof(
            &self,
            _key_id: &Uuid,
        ) -> kms_core::Result<kms_core::DestructionProof> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn list_keys(&self, _filter: &KeyFilter) -> kms_core::Result<Vec<KeyMeta>> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn health(&self) -> kms_core::Result<HealthStatus> {
            Ok(HealthStatus::Healthy)
        }
        async fn import_key_material(
            &self,
            _spec: &KeySpec,
            _name: &str,
            _tenant_id: &str,
            _material: Vec<u8>,
        ) -> kms_core::Result<KeyMeta> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn export_key_material(
            &self,
            _key_id: &Uuid,
            _tenant_id: &str,
        ) -> kms_core::Result<Vec<u8>> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn get_key_material(
            &self,
            _key_id: &Uuid,
            _tenant_id: &str,
        ) -> kms_core::Result<Vec<u8>> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn derive_shared_secret(
            &self,
            _key_id: &Uuid,
            _peer_public_key: &[u8],
            _algorithm: kms_core::dh::DhAlgorithm,
        ) -> kms_core::Result<kms_core::dh::SharedSecret> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
    }

    #[tokio::test]
    async fn test_health_check_healthy() {
        let metrics = KmsMetrics::new();
        let keystore = Arc::new(HealthyKeystore);
        let logger = Arc::new(kms_audit::AuditLogger::with_stdout());

        let checker = HealthChecker::new(keystore, logger, metrics.clone());
        let status = checker.check().await;

        assert_eq!(status, HealthStatus::Healthy);
        assert_eq!(metrics.health_status.get(), 0); // Healthy=0
    }

    #[tokio::test]
    async fn test_health_check_updates_gauges() {
        let metrics = KmsMetrics::new();
        let keystore = Arc::new(HealthyKeystore);
        let logger = Arc::new(kms_audit::AuditLogger::with_stdout());

        let checker = HealthChecker::new(keystore, logger, metrics.clone());
        let _ = checker.check().await;

        // After check, health_status gauge should be set
        let health_val = metrics.health_status.get();
        assert!(health_val < 4); // Valid range 0-3
    }

    /// A keystore that returns Degraded.
    struct DegradedKeystore;
    #[async_trait::async_trait]
    impl kms_keystore::KeystoreBackend for DegradedKeystore {
        fn backend_type(&self) -> kms_core::BackendType {
            kms_core::BackendType::Software
        }
        async fn health(&self) -> kms_core::Result<HealthStatus> {
            Ok(HealthStatus::Degraded)
        }
        // Minimal stubs
        async fn generate_key(&self, _: &KeySpec, _: &str, _: &str) -> kms_core::Result<KeyMeta> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn get_key_metadata(&self, _: &Uuid) -> kms_core::Result<KeyMeta> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn encrypt(
            &self,
            _: &Uuid,
            _: &[u8],
            _: Option<&[u8]>,
            _: &str,
        ) -> kms_core::Result<kms_core::key::Ciphertext> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn decrypt(
            &self,
            _: &Uuid,
            _: &kms_core::key::Ciphertext,
            _: Option<&[u8]>,
            _: &str,
        ) -> kms_core::Result<Vec<u8>> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn sign(
            &self,
            _: &Uuid,
            _: &[u8],
            _: &str,
        ) -> kms_core::Result<kms_core::key::Signature> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn verify(
            &self,
            _: &Uuid,
            _: &[u8],
            _: &kms_core::key::Signature,
            _: &str,
        ) -> kms_core::Result<bool> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn rotate_key(&self, _: &Uuid, _: &str) -> kms_core::Result<KeyMeta> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn delete_key(&self, _: &Uuid, _: &str) -> kms_core::Result<()> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn destroy_key(&self, _: &Uuid) -> kms_core::Result<()> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn destroy_key_with_proof(
            &self,
            _: &Uuid,
        ) -> kms_core::Result<kms_core::DestructionProof> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn list_keys(&self, _: &KeyFilter) -> kms_core::Result<Vec<KeyMeta>> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn import_key_material(
            &self,
            _: &KeySpec,
            _: &str,
            _: &str,
            _: Vec<u8>,
        ) -> kms_core::Result<KeyMeta> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn export_key_material(&self, _: &Uuid, _: &str) -> kms_core::Result<Vec<u8>> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn get_key_material(&self, _: &Uuid, _: &str) -> kms_core::Result<Vec<u8>> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn derive_shared_secret(
            &self,
            _: &Uuid,
            _: &[u8],
            _: kms_core::dh::DhAlgorithm,
        ) -> kms_core::Result<kms_core::dh::SharedSecret> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
    }

    /// A keystore that returns Unhealthy.
    struct UnhealthyKeystore;
    #[async_trait::async_trait]
    impl kms_keystore::KeystoreBackend for UnhealthyKeystore {
        fn backend_type(&self) -> kms_core::BackendType {
            kms_core::BackendType::Software
        }
        async fn health(&self) -> kms_core::Result<HealthStatus> {
            Ok(HealthStatus::Unhealthy)
        }
        // Minimal stubs
        async fn generate_key(&self, _: &KeySpec, _: &str, _: &str) -> kms_core::Result<KeyMeta> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn get_key_metadata(&self, _: &Uuid) -> kms_core::Result<KeyMeta> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn encrypt(
            &self,
            _: &Uuid,
            _: &[u8],
            _: Option<&[u8]>,
            _: &str,
        ) -> kms_core::Result<kms_core::key::Ciphertext> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn decrypt(
            &self,
            _: &Uuid,
            _: &kms_core::key::Ciphertext,
            _: Option<&[u8]>,
            _: &str,
        ) -> kms_core::Result<Vec<u8>> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn sign(
            &self,
            _: &Uuid,
            _: &[u8],
            _: &str,
        ) -> kms_core::Result<kms_core::key::Signature> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn verify(
            &self,
            _: &Uuid,
            _: &[u8],
            _: &kms_core::key::Signature,
            _: &str,
        ) -> kms_core::Result<bool> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn rotate_key(&self, _: &Uuid, _: &str) -> kms_core::Result<KeyMeta> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn delete_key(&self, _: &Uuid, _: &str) -> kms_core::Result<()> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn destroy_key(&self, _: &Uuid) -> kms_core::Result<()> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn destroy_key_with_proof(
            &self,
            _: &Uuid,
        ) -> kms_core::Result<kms_core::DestructionProof> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn list_keys(&self, _: &KeyFilter) -> kms_core::Result<Vec<KeyMeta>> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn import_key_material(
            &self,
            _: &KeySpec,
            _: &str,
            _: &str,
            _: Vec<u8>,
        ) -> kms_core::Result<KeyMeta> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn export_key_material(&self, _: &Uuid, _: &str) -> kms_core::Result<Vec<u8>> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn get_key_material(&self, _: &Uuid, _: &str) -> kms_core::Result<Vec<u8>> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
        async fn derive_shared_secret(
            &self,
            _: &Uuid,
            _: &[u8],
            _: kms_core::dh::DhAlgorithm,
        ) -> kms_core::Result<kms_core::dh::SharedSecret> {
            Err(kms_core::Error::NotImplemented("mock stub".into()))
        }
    }

    #[tokio::test]
    async fn test_health_check_degraded() {
        let metrics = KmsMetrics::new();
        let keystore = Arc::new(DegradedKeystore);
        let logger = Arc::new(kms_audit::AuditLogger::with_stdout());

        let checker = HealthChecker::new(keystore, logger, metrics.clone());
        let status = checker.check().await;

        assert_eq!(status, HealthStatus::Degraded);
        assert_eq!(metrics.health_status.get(), 1); // Degraded=1
    }

    #[tokio::test]
    async fn test_health_check_unhealthy() {
        let metrics = KmsMetrics::new();
        let keystore = Arc::new(UnhealthyKeystore);
        let logger = Arc::new(kms_audit::AuditLogger::with_stdout());

        let checker = HealthChecker::new(keystore, logger, metrics.clone());
        let status = checker.check().await;

        assert_eq!(status, HealthStatus::Unhealthy);
        assert_eq!(metrics.health_status.get(), 2); // Unhealthy=2
    }

    /// Health checker sets audit_backlog_depth gauge
    #[tokio::test]
    async fn test_health_check_updates_audit_backlog() {
        let metrics = KmsMetrics::new();
        let keystore = Arc::new(HealthyKeystore);
        let logger = Arc::new(kms_audit::AuditLogger::with_stdout());

        let checker = HealthChecker::new(keystore, logger, metrics.clone());
        let _ = checker.check().await;

        // Audit backlog should be set (0 for fresh logger)
        let backlog = metrics.audit_backlog_depth.get();
        assert_eq!(backlog, 0);
    }
}
