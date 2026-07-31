//! kms-keystore - Key storage backend abstraction and implementations
//!
//! Provides KeystoreBackend trait and SoftwareKeystore implementation.

pub mod backend;
pub mod cache;
pub mod postgres;
pub mod rate_limiter;
pub mod repository;
pub mod sm2_kex_session;
pub mod sm9_master_key;
pub mod software;
pub mod validation;

pub use backend::{HealthStatus, KeyFilter, KeystoreBackend};
pub use cache::RedisCachedKeystore;
pub use postgres::PostgresKeystore;
pub use rate_limiter::{
    ClusterRateLimiter, RateLimitConfig, RateLimitResult, SlidingWindowRateLimiter,
};
pub use repository::PostgresKeyRepository;
pub use sm2_kex_session::Sm2KexSessionManager;
pub use sm9_master_key::PostgresSm9MasterKeyRepository;
pub use software::SoftwareKeystore;
pub use validation::{KeyMetadata, KeyValidationResult, validate_key_material};
