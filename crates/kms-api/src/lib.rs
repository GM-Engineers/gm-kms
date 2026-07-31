//! kms-api - REST and gRPC API layer for KMS

pub use sqlx;

pub mod anomaly;
pub mod approval;
pub mod auth;
pub mod cache;
pub mod chaos;
pub mod error;
pub mod fault_wrapper;
pub mod grpc;
pub mod health;
pub mod metrics;
pub mod mfa;
pub mod quota;
pub mod ratelimit;
pub mod rest;
pub mod rotation;
pub mod security_headers;
pub mod service;
pub mod state;
pub mod tracing;
pub mod validation;

#[cfg(test)]
mod proptests;

#[cfg(test)]
pub(crate) mod test_utils;

pub use approval::{
    ApprovalManager, ApprovalRequestResponse, ApproveRequest, CancelRequest, CreateApprovalRequest,
    RejectRequest,
};
pub use auth::ApiKey;
pub use auth::ApiKeyConfig;
pub use auth::{ApiKeyPermission, Permission};
pub use error::{ApiError, Result};
pub use metrics::KmsMetrics;
pub use mfa::{MfaManager, MfaStatusResponse};
pub use quota::{QuotaConfig, QuotaExceeded, TenantQuotaTracker};
pub use ratelimit::{RateLimitConfig, TenantRateLimiter};
pub use rotation::{
    OperationCounter, RedisOperationCounter, RotationCheckResult, RotationPolicy, RotationReason,
    RotationService,
};
pub use tracing::{TRACE_ID_HEADER, extract_trace_id, generate_trace_id};

use async_trait::async_trait;
use std::sync::Arc;
use parking_lot::RwLock;

/// KMS service state shared across REST and gRPC
#[derive(Clone)]
pub struct KmsState {
    pub keystore: Arc<dyn kms_keystore::KeystoreBackend>,
    pub policy_engine: Arc<kms_policy::PBACEngine>,
    pub audit_logger: Arc<dyn kms_audit::AuditLog>,
    pub sm9_state: Arc<Sm9State>,
    pub rate_limiter: Option<Arc<TenantRateLimiter>>,
    pub quota_tracker: Option<Arc<TenantQuotaTracker>>,
    pub op_counter: Option<Arc<dyn OperationCounter>>,
    pub mfa_manager: Arc<MfaManager>,
    pub approval_manager: Arc<RwLock<ApprovalManager>>,
    pub metrics: Arc<KmsMetrics>,
    pub backup_service: Option<Arc<kms_core::KeyBackupService>>,
}

/// SM9 state containing KGC master key
///
/// # Security Notice
///
/// ## In-Memory Mode (default)
/// The master_key is stored in memory without HSM/TPM protection.
/// In production deployments, this key MUST be stored in an HSM or TPM.
/// Memory dumps, swap files, or compromised processes could expose this key.
///
/// ## Persistent Mode (with KEK)
/// When SM9_KEK environment variable is set, the master key is encrypted
/// with AES-256-GCM using the KEK before being stored in PostgreSQL.
/// The KEK should be stored in an HSM/TPM or secure configuration management.
///
/// # Architecture (Persistent Mode)
/// ```text
/// +------------------+     +------------------+
/// |   KgcMasterKey   | --> |  PostgreSQL      |
/// |   (in-memory)   |     |  (encrypted)     |
/// +--------+--------+     +--------+---------+
///          |                       ^
///          | encrypt               | decrypt
///          v                       |
/// +------------------+     +------------------+
/// |      KEK         | <-- |  EnvVar/HSM     |
/// | (32 bytes)       |     |  (never stored) |
/// +------------------+     +------------------+
/// ```
#[derive(Clone)]
pub struct Sm9State {
    /// The KGC master key (in-memory, plaintext)
    pub master_key: gm_sm9_rs::KgcMasterKey,
    /// Optional repository for persistent storage (None = in-memory only)
    pub repository: Option<Arc<dyn crate::Sm9MasterKeyRepository>>,
}

/// Trait for SM9 master key repository (re-export from kms-core for API layer)
#[async_trait]
pub trait Sm9MasterKeyRepository: Send + Sync {
    /// Store the master key (will be encrypted before storage via KEK)
    async fn store(&self, key: &[u8], version: u32) -> crate::Result<()>;
    /// Load the master key (will be decrypted after retrieval via KEK)
    async fn load(&self) -> crate::Result<Vec<u8>>;
    /// Get current version of stored master key
    async fn get_version(&self) -> crate::Result<Option<u32>>;
    /// Check if a master key exists
    async fn exists(&self) -> crate::Result<bool>;
}

impl Sm9State {
    /// Create from an existing master key (in-memory mode)
    pub fn from_key(master_key: gm_sm9_rs::KgcMasterKey) -> Self {
        Self {
            master_key,
            repository: None,
        }
    }

    /// Load from repository (persistent mode)
    ///
    /// This method loads the master key from PostgreSQL (encrypted with KEK).
    /// Returns error if no master key is stored or if decryption fails.
    pub async fn load_from_repository(
        repo: &Arc<dyn Sm9MasterKeyRepository>,
    ) -> crate::Result<Self> {
        if !repo.exists().await? {
            return Err(crate::ApiError::Internal(
                "No SM9 master key found in repository".to_string(),
            ));
        }

        let bytes = repo.load().await?;
        let master_key = gm_sm9_rs::KgcMasterKey::from_bytes(&bytes).map_err(|e| {
            crate::ApiError::Internal(format!("failed to deserialize master key: {}", e))
        })?;

        Ok(Self {
            master_key,
            repository: Some(repo.clone()),
        })
    }

    /// Store to repository (persistent mode)
    pub async fn store_to_repository(
        &self,
        repo: &Arc<dyn Sm9MasterKeyRepository>,
    ) -> crate::Result<()> {
        // Serialize the master key using gm_sm9_rs's serialization
        let master_key_bytes = self.master_key.to_bytes()?;
        let version = repo.get_version().await?.unwrap_or(0) + 1;
        repo.store(&master_key_bytes, version).await
    }
}

impl KmsState {
    pub fn new(
        keystore: Arc<dyn kms_keystore::KeystoreBackend>,
        policy_engine: kms_policy::PBACEngine,
        audit_logger: Arc<dyn kms_audit::AuditLog>,
        sm9_state: Sm9State,
        metrics: KmsMetrics,
    ) -> Self {
        Self {
            keystore,
            policy_engine: Arc::new(policy_engine),
            audit_logger,
            sm9_state: Arc::new(sm9_state),
            rate_limiter: None,
            quota_tracker: None,
            op_counter: None,
            mfa_manager: Arc::new(MfaManager::new_in_memory().with_metrics(metrics.clone())),
            approval_manager: Arc::new(RwLock::new(ApprovalManager::new(Arc::new(
                metrics.clone(),
            )))),
            metrics: Arc::new(metrics),
            backup_service: None,
        }
    }

    /// Set the rate limiter
    pub fn with_rate_limiter(mut self, limiter: TenantRateLimiter) -> Self {
        self.rate_limiter = Some(Arc::new(limiter));
        self
    }

    /// Create with a database-backed MfaManager (production path)
    pub fn new_with_mfa(
        keystore: Arc<dyn kms_keystore::KeystoreBackend>,
        policy_engine: kms_policy::PBACEngine,
        audit_logger: Arc<dyn kms_audit::AuditLog>,
        sm9_state: Sm9State,
        metrics: KmsMetrics,
        mfa_manager: MfaManager,
    ) -> Self {
        Self {
            keystore,
            policy_engine: Arc::new(policy_engine),
            audit_logger,
            sm9_state: Arc::new(sm9_state),
            rate_limiter: None,
            quota_tracker: None,
            op_counter: None,
            mfa_manager: Arc::new(mfa_manager),
            approval_manager: Arc::new(RwLock::new(ApprovalManager::new(Arc::new(
                metrics.clone(),
            )))),
            metrics: Arc::new(metrics),
            backup_service: None,
        }
    }

    /// Set the quota tracker
    pub fn with_quota_tracker(mut self, tracker: TenantQuotaTracker) -> Self {
        self.quota_tracker = Some(Arc::new(tracker));
        self
    }

    /// Set the operation counter for usage-based key rotation
    pub fn with_op_counter(mut self, counter: Arc<dyn OperationCounter>) -> Self {
        self.op_counter = Some(counter);
        self
    }

    pub fn with_backup_service(mut self, backup_service: Arc<kms_core::KeyBackupService>) -> Self {
        self.backup_service = Some(backup_service);
        self
    }

    /// Create a CryptoService from this state
    pub fn crypto_service(&self) -> crate::service::CryptoService {
        crate::service::CryptoService::new(self)
    }

    /// Create a KeyService from this state
    pub fn key_service(&self) -> crate::service::KeyService {
        crate::service::KeyService::new(self)
    }
}
