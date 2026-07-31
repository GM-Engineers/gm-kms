//! Server command - runs REST and gRPC servers

use anyhow::Result;
use async_trait::async_trait;
use kms_api::{
    KmsMetrics, KmsState, Sm9State,
    auth::{ApiKeyConfig, AuthError},
    grpc::pb::kms_service_server::KmsServiceServer,
    grpc::{GrpcAuthInterceptor, KmsGrpcService},
    health::HealthChecker,
    quota::TenantQuotaTracker,
    ratelimit::{RateLimitConfig, TenantRateLimiter},
    rest::create_routes,
};
use kms_audit::{AuditConfig, AuditLogger, TimestampedAuditConfig, TimestampedAuditLogger};
use kms_hsm::create_tpm_keystore;
use kms_keystore::{KeystoreBackend, PostgresKeyRepository, PostgresKeystore, RedisCachedKeystore, SoftwareKeystore};
use kms_policy::PBACEngine;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::signal;
use tokio::sync::oneshot;
use tonic_health::{ServingStatus, server as health_server};
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::cmd::config::TlsConfig;

// TLS imports for REST (using axum_server for TLS support)
use axum_server::tls_rustls::RustlsConfig;

// Database (PostgreSQL for MFA persistence)

/// Backend type selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendType {
    /// Software keystore (in-memory with optional Redis cache)
    Software,
    /// TPM 2.0 simulator backend
    Tpm,
}

// ============================================================================
// KMS State Builder - Reduces code duplication in state creation
// ============================================================================

/// Create a rate limiter if enabled, using a separate Redis connection
async fn maybe_create_rate_limiter(
    redis_url: &str,
    enabled: bool,
    requests_per_second: u64,
    requests_per_minute: u64,
    burst_size: u64,
) -> Option<TenantRateLimiter> {
    if !enabled {
        return None;
    }

    let rate_config = RateLimitConfig {
        requests_per_second,
        requests_per_minute,
        burst_size,
        fail_mode: kms_api::ratelimit::RateLimitFailMode::FailClosed,
    };

    tracing::info!(
        "Rate limiting enabled: {} req/s per tenant",
        requests_per_second
    );

    match redis::aio::ConnectionManager::new(
        redis::Client::open(redis_url).expect("Failed to create Redis client for rate limiter"),
    )
    .await
    {
        Ok(conn) => {
            let tls_config = kms_core::BackendTlsConfig::from_env();
            if tls_config.is_tls_enabled() {
                tracing::info!(mode = %tls_config.mode, "Redis rate limiter using TLS");
            }
            Some(TenantRateLimiter::new(conn, rate_config))
        }
        Err(e) => {
            tracing::warn!("Redis connection failed for rate limiter: {}", e);
            None
        }
    }
}

/// Create a quota tracker if enabled, using a separate Redis connection
async fn maybe_create_quota_tracker(
    redis_url: &str,
    enabled: bool,
    max_keys: u64,
    max_requests_per_minute: u64,
    max_requests_per_day: u64,
) -> Option<TenantQuotaTracker> {
    if !enabled {
        return None;
    }

    let quota_config = kms_api::quota::QuotaConfig {
        max_keys,
        max_requests_per_minute,
        max_requests_per_day,
    };

    tracing::info!("Quota tracking enabled: max {} keys per tenant", max_keys);

    match redis::aio::ConnectionManager::new(
        redis::Client::open(redis_url).expect("Failed to create Redis client for quota tracker"),
    )
    .await
    {
        Ok(conn) => {
            let tls_config = kms_core::BackendTlsConfig::from_env();
            if tls_config.is_tls_enabled() {
                tracing::info!(mode = %tls_config.mode, "Redis quota tracker using TLS");
            }
            Some(TenantQuotaTracker::new(conn, quota_config))
        }
        Err(e) => {
            tracing::warn!("Redis connection failed for quota tracker: {}", e);
            None
        }
    }
}

/// Create a PgPool from the database configuration if available.
/// Returns None if the database is not configured or connection fails.
async fn maybe_create_mfa_pool(
    database_config: &crate::cmd::config::DatabaseConfig,
) -> Option<kms_api::sqlx::PgPool> {
    let url = database_config.connection_url();
    let tls_config = kms_core::BackendTlsConfig::from_env();
    let url = tls_config.build_postgres_url(&url);

    if tls_config.is_tls_enabled() {
        tracing::info!(mode = %tls_config.mode, "Connecting to PostgreSQL for MFA with TLS");
    } else {
        tracing::info!(
            "Connecting to PostgreSQL for MFA persistence: host={}",
            database_config.host
        );
    }

    match kms_api::sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
    {
        Ok(pool) => {
            tracing::info!("PostgreSQL connected for MFA persistence");
            Some(pool)
        }
        Err(e) => {
            tracing::warn!(
                "PostgreSQL connection for MFA failed ({}), MFA will use in-memory fallback (lockouts will NOT survive restarts)",
                e
            );
            None
        }
    }
}

/// Build a KmsState with optional rate limiter, quota tracker, and metrics.
#[allow(clippy::too_many_arguments)]
fn build_kms_state(
    keystore: Arc<dyn KeystoreBackend + Send + Sync>,
    policy_engine: PBACEngine,
    audit_logger: Arc<dyn kms_audit::AuditLog>,
    sm9_state: Sm9State,
    rate_limiter: Option<TenantRateLimiter>,
    quota_tracker: Option<TenantQuotaTracker>,
    metrics: KmsMetrics,
    mfa_pool: Option<kms_api::sqlx::PgPool>,
    backup_service: Option<Arc<kms_core::KeyBackupService>>,
) -> Arc<KmsState> {
    let mut state = if let Some(pool) = mfa_pool {
        let mfa = kms_api::MfaManager::new(pool).with_metrics(metrics.clone());
        // Run migrations synchronously (we're in startup)
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(mfa.migrate()))
            .unwrap_or_else(|e| {
                tracing::error!("MFA database migration failed: {}", e);
            });
        KmsState::new_with_mfa(
            keystore,
            policy_engine,
            audit_logger,
            sm9_state,
            metrics,
            mfa,
        )
    } else {
        KmsState::new(keystore, policy_engine, audit_logger, sm9_state, metrics)
    };
    if let Some(limiter) = rate_limiter {
        state = state.with_rate_limiter(limiter);
    }
    if let Some(tracker) = quota_tracker {
        state = state.with_quota_tracker(tracker);
    }
    if let Some(bs) = backup_service {
        state = state.with_backup_service(bs);
    }
    Arc::new(state)
}

/// Build CORS layer from configuration
fn build_cors_layer(cors_config: &crate::cmd::config::CorsConfig) -> CorsLayer {
    use axum::http::HeaderValue;

    // If no origins are configured, return a restrictive layer that denies all
    if cors_config.allowed_origins.is_empty() {
        tracing::warn!(
            "CORS allowed_origins not configured - CORS will deny all cross-origin requests"
        );
        return CorsLayer::new();
    }

    let origin_header_values: Vec<HeaderValue> = cors_config
        .allowed_origins
        .split(',')
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                HeaderValue::from_str(trimmed).ok()
            }
        })
        .collect();

    if origin_header_values.is_empty() {
        tracing::warn!("No valid CORS origins found in config");
        return CorsLayer::new();
    }

    tracing::info!("CORS allowed origins: {}", cors_config.allowed_origins);
    CorsLayer::new()
        .allow_origin(origin_header_values)
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_credentials(cors_config.allow_credentials)
}

pub async fn run(config_path: &str, rest_port: u16, grpc_port: u16) -> Result<()> {
    // Load configuration from file and environment
    let config = crate::cmd::config::Config::load(config_path)?;
    let rest_port = if rest_port != 8080 {
        rest_port
    } else {
        config.server.rest_port
    };
    let grpc_port = if grpc_port != 9090 {
        grpc_port
    } else {
        config.server.grpc_port
    };

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("Starting KMS server...");

    // Initialize memory protection (core dump disable, mlock availability)
    // This must be called early, before any key material is loaded
    if let Err(e) = kms_core::init_memory_protection() {
        tracing::warn!(
            "Memory protection initialization failed: {}. Continuing anyway.",
            e
        );
    }

    // GB/T 37092-2018 §7.10: run cryptographic KAT self-test at startup
    tracing::info!("Running cryptographic KAT self-test (GB/T 37092-2018 §7.10)...");
    let tester = kms_core::self_test::SelfTester::new();
    let results = tester.run_all_tests().await;
    if !results.all_passed() {
        tracing::error!("KAT failed: {:?}", results.failures());
        return Err(anyhow::anyhow!(
            "Cryptographic self-test failed: {}/{} passed",
            results.passed_count(),
            results.total_count()
        ));
    }
    tracing::info!(
        "KAT passed: {}/{}",
        results.passed_count(),
        results.total_count()
    );

    // Initialize components
    let policy_engine = PBACEngine::new();

    // TSA counters — created here so they can be shared between TimestampedAuditLogger
    // background task and KmsMetrics (for /v1/metrics endpoint).
    let tsa_req_counter = Arc::new(AtomicU64::new(0));
    let tsa_ok_counter = Arc::new(AtomicU64::new(0));
    let tsa_fail_counter = Arc::new(AtomicU64::new(0));
    let has_tsa: bool;

    // Initialize audit logger with config (optionally with TSA)
    let audit_logger: Arc<dyn kms_audit::AuditLog> = {
        let audit_config = AuditConfig {
            output_path: std::path::PathBuf::from(&config.audit.output_path),
            flush_interval_secs: config.audit.flush_interval_secs,
            buffer_size: config.audit.buffer_size,
            kafka_brokers: config.audit.kafka_brokers.clone(),
            kafka_topic: config.audit.kafka_topic.clone(),
        };

        if let Some(ref tsa_cfg) = config.audit.tsa {
            if tsa_cfg.enabled && !tsa_cfg.endpoints.is_empty() {
                use kms_audit::{SignedAuditConfig, TimestampHashAlgorithm, TsaClientConfig};

                let hash_algorithm = match tsa_cfg.hash_algorithm.as_str() {
                    "sm3" => TimestampHashAlgorithm::Sm3,
                    _ => TimestampHashAlgorithm::Sha256,
                };

                let tsa_client_config = TsaClientConfig {
                    endpoints: tsa_cfg.endpoints.clone(),
                    timeout_secs: tsa_cfg.timeout_secs,
                    username: tsa_cfg.username.clone(),
                    password: tsa_cfg.password.clone(),
                    hash_algorithm,
                    ca_path: tsa_cfg.ca_path.as_ref().map(std::path::PathBuf::from),
                };

                let signed_config = SignedAuditConfig::new(audit_config.clone(), 0);
                let ts_config = TimestampedAuditConfig {
                    signed_config,
                    tsa_config: Some(tsa_client_config),
                    tsa_interval_secs: tsa_cfg.interval_secs,
                    require_tsa: tsa_cfg.require_tsa,
                };

                let tsa_start = std::time::Instant::now();
                tracing::info!(
                    "Audit logger: TimestampedAuditLogger with TSA (endpoints={}, interval={}s, require_tsa={})",
                    tsa_cfg.endpoints.join(","),
                    tsa_cfg.interval_secs,
                    tsa_cfg.require_tsa,
                );

                match TimestampedAuditLogger::new(
                    ts_config,
                    Some((
                        Arc::clone(&tsa_req_counter),
                        Arc::clone(&tsa_ok_counter),
                        Arc::clone(&tsa_fail_counter),
                    )),
                ) {
                    Ok(logger) => {
                        has_tsa = true;
                        let elapsed = tsa_start.elapsed();
                        tracing::info!("TSA initialization completed in {}ms", elapsed.as_millis());
                        Arc::new(logger) as Arc<dyn kms_audit::AuditLog>
                    }
                    Err(e) => {
                        has_tsa = false;
                        tracing::error!(
                            "Failed to create TimestampedAuditLogger: {}, falling back to plain audit logger",
                            e
                        );
                        Arc::new(AuditLogger::new(audit_config))
                    }
                }
            } else {
                has_tsa = false;
                tracing::info!(
                    "Audit logger: standard (TSA configured but not enabled or no endpoints)"
                );
                Arc::new(AuditLogger::new(audit_config))
            }
        } else {
            has_tsa = false;
            tracing::info!("Audit logger: standard");
            Arc::new(AuditLogger::new(audit_config))
        }
    };

    // Log audit configuration
    tracing::info!("Audit logger: output={}", config.audit.output_path);
    if config.audit.kafka_brokers.is_some() {
        tracing::info!(
            "Audit Kafka: enabled (topic={})",
            config
                .audit
                .kafka_topic
                .as_ref()
                .unwrap_or(&"<unset>".to_string())
        );
    }

    // Verify audit log integrity at startup (tamper detection)
    {
        let audit_path = std::path::PathBuf::from(&config.audit.output_path);
        if audit_path.exists() {
            match kms_audit::startup_verify_chain(&audit_path).await {
                Ok(report) if report.valid => {
                    tracing::info!(
                        "Audit chain verified: {} entries, all valid",
                        report.entries_checked
                    );
                }
                Ok(report) => {
                    tracing::error!(
                        "AUDIT CHAIN TAMPERED: {} entries checked, first invalid at index {:?}: {}",
                        report.entries_checked,
                        report.first_invalid_index,
                        report.error.as_deref().unwrap_or("unknown"),
                    );
                    // Don't abort — log the finding but let operations continue
                    // Compliance frameworks may require abort-on-tamper
                }
                Err(e) => {
                    tracing::warn!(
                        "Audit chain verification skipped (could not read log files): {}", e
                    );
                }
            }
        } else {
            tracing::info!("Audit chain verification: no existing log files (fresh start)");
        }
    }

    // Initialize metrics (with shared TSA counters if TSA is enabled)
    let metrics = if has_tsa {
        KmsMetrics::with_tsa_counters(
            Arc::clone(&tsa_req_counter),
            Arc::clone(&tsa_ok_counter),
            Arc::clone(&tsa_fail_counter),
        )
    } else {
        KmsMetrics::new()
    };

    // Wire mlock failure bridge (#26)
    kms_core::memory_protection::set_mlock_failure_counter(
        metrics.mlock_failures_total.inner_arc(),
    );

    // Feature flag check (#22): verify config matches compile-time features
    if cfg!(feature = "tpm2-tss") {
        tracing::info!("Compile-time feature `tpm2-tss` is enabled");
    } else if config.backend.backend_type == "tpm" {
        metrics.set_feature_config_mismatch();
        tracing::error!(
            "FEATURE CONFIG MISMATCH: config.backend.backend_type is \"tpm\" \
             but `tpm2-tss` feature is not enabled at compile time. \
             TPM operations will use the simulator instead."
        );
    }

    // Create PostgreSQL connection pool for MFA + SM9 persistence
    let mfa_pool = maybe_create_mfa_pool(&config.database).await;

    // Initialize SM9 KGC master key with persistence support

    let sm9_state = {
        let sm9_pool = match &mfa_pool {
            Some(pool) => Some(pool.clone()),
            None => maybe_create_mfa_pool(&config.database).await,
        };

        // Try loading from database first
        if let Some(pool) = sm9_pool {
            let kek_store = Arc::new(kms_core::sm9_master_key::EnvVarKekStore::new("KMS_KEK"));
            let pg_repo = Arc::new(
                kms_keystore::PostgresSm9MasterKeyRepository::new(pool, kek_store),
            );

            // Initialize the table
            if let Err(e) = pg_repo.init().await {
                tracing::error!("SM9 master key table init failed: {}, falling back to in-memory", e);
                let sm9_master_key = gm_sm9_rs::KgcMasterKey::generate()
                    .map_err(|e| anyhow::anyhow!("Failed to generate SM9 master key: {}", e))?;
                Sm9State::from_key(sm9_master_key)
            } else {
                // Bridge adapter: wraps kms_keystore Sm9MasterKeyRepository and
                // implements kms_api Sm9MasterKeyRepository
                let adapter: Arc<dyn kms_api::Sm9MasterKeyRepository> =
                    Arc::new(Sm9RepoAdapter { inner: pg_repo });

                match Sm9State::load_from_repository(&adapter).await {
                    Ok(state) => {
                        tracing::info!("SM9 KGC master key loaded from PostgreSQL (KEK-encrypted)");
                        metrics.record_kgc_key_generation();
                        state
                    }
                    Err(_) => {
                        // No key found or deserialization failed — generate and store
                        let sm9_master_key = gm_sm9_rs::KgcMasterKey::generate()
                            .map_err(|e| anyhow::anyhow!("Failed to generate SM9 master key: {}", e))?;
                        let state = Sm9State::from_key(sm9_master_key);
                        if let Err(e) = state.store_to_repository(&adapter).await {
                            tracing::error!("Failed to persist SM9 master key: {}", e);
                        } else {
                            tracing::info!("SM9 KGC master key generated and stored to PostgreSQL");
                        }
                        state
                    }
                }
            }
        } else {
            // No PostgreSQL available — in-memory only
            let sm9_master_key = gm_sm9_rs::KgcMasterKey::generate()
                .map_err(|e| anyhow::anyhow!("Failed to generate SM9 master key: {}", e))?;
            Sm9State::from_key(sm9_master_key)
        }
    };

    // SM9 KGC metrics (#44)
    metrics.set_kgc_master_key_loaded(true);
    metrics.record_kgc_key_generation();

    // P0-7: Warn if TPM/HSM feature not enabled — master key in plain memory
    #[cfg(not(feature = "tpm2-tss"))]
    {
        tracing::warn!(
            "SM9 master key loaded into unprotected memory (no --features kms-hsm/tpm2-tss). \
            NOT for production use. Use HSM/TPM for 等保三级 compliance (M-4)."
        );
    }
    #[cfg(feature = "tpm2-tss")]
    tracing::info!("SM9 master key protected by HSM/TPM");

    // Backend type selection
    let backend_type = match config.backend.backend_type.as_str() {
        "tpm" => BackendType::Tpm,
        _ => BackendType::Software,
    };
    tracing::info!("Selected backend: {:?}", backend_type);

    // mfa_pool is already created above (before SM9 initialization)

    // Create shared state with direct keystore (Redis caching optional)
    let redis_url = config.redis.url.clone();

    // Rate limiter setup - will be created inside branches where needed
    let rate_limit_enabled = config.redis.enabled && config.rate_limit.enabled;
    let quota_enabled = config.redis.enabled && config.quota.enabled;

    /// Helper: create a software keystore with PostgreSQL persistence if available
    async fn create_software_keystore(
        mfa_pool: &Option<kms_api::sqlx::PgPool>,
    ) -> Arc<dyn KeystoreBackend + Send + Sync> {
        if let Some(pool) = mfa_pool {
            tracing::info!("Using PostgreSQL-backed software keystore (keys survive restarts)");
            let repo = PostgresKeyRepository::new(pool.clone());
            match PostgresKeystore::new(repo).await {
                Ok(pg_keystore) => {
                    match pg_keystore.load_keys().await {
                        Ok(()) => {
                            tracing::info!("Loaded keys from PostgreSQL");
                        }
                        Err(e) => {
                            tracing::warn!("Failed to load keys from PostgreSQL: {}", e);
                        }
                    }
                    Arc::new(pg_keystore)
                }
                Err(e) => {
                    tracing::error!(
                        "PostgreSQL keystore init failed: {}. Falling back to in-memory keystore (keys WILL be lost on restart!)", e
                    );
                    Arc::new(SoftwareKeystore::new())
                }
            }
        } else {
            tracing::warn!(
                "No PostgreSQL configured — using in-memory keystore. \
                 Keys WILL be lost on restart! Set database config for persistence."
            );
            Arc::new(SoftwareKeystore::new())
        }
    }

    // Build state: wrap with Redis cache if available, otherwise use keystore directly

    /// Helper: create software keystore wrapped with Redis cache if PG is available.
    /// Falls back to in-memory SoftwareKeystore (F-2).
    async fn create_software_keystore_inner(
        mfa_pool: &Option<kms_api::sqlx::PgPool>,
        redis_conn: redis::aio::ConnectionManager,
    ) -> Arc<dyn KeystoreBackend + Send + Sync> {
        if let Some(pool) = mfa_pool {
            let repo = PostgresKeyRepository::new(pool.clone());
            match PostgresKeystore::new(repo).await {
                Ok(pg_keystore) => {
                    let _ = pg_keystore.load_keys().await;
                    tracing::info!(
                        "PostgreSQL-backed keystore with Redis cache (keys survive restarts)"
                    );
                    Arc::new(RedisCachedKeystore::new(pg_keystore, redis_conn))
                }
                Err(e) => {
                    tracing::error!(
                        "PostgreSQL keystore init failed: {} — using Redis-cached in-memory \
                         keystore (keys WILL be lost on restart!)",
                        e
                    );
                    Arc::new(RedisCachedKeystore::new(SoftwareKeystore::new(), redis_conn))
                }
            }
        } else {
            tracing::warn!(
                "No PostgreSQL — using Redis-cached in-memory keystore. \
                 Keys WILL be lost on restart!"
            );
            Arc::new(RedisCachedKeystore::new(SoftwareKeystore::new(), redis_conn))
        }
    }

    // Backup service — needs config and metrics, no state dependency
    let backup_service: Option<Arc<kms_core::KeyBackupService>> = if config.backup.enabled {
        match kms_core::MasterKey::generate() {
            Ok(master_key) => {
                let backup_config = kms_core::BackupConfig {
                    enabled: config.backup.enabled,
                    backup_path: config.backup.backup_path.clone(),
                    retention_count: config.backup.retention_count,
                    retention_days: config.backup.retention_days,
                    kdf_iterations: config.backup.kdf_iterations,
                };
                let svc = Arc::new(kms_core::KeyBackupService::new(backup_config, master_key));
                tracing::info!(
                    "Backup service enabled: path={}, retention={}d",
                    config.backup.backup_path,
                    config.backup.retention_days
                );
                Some(svc)
            }
            Err(e) => {
                tracing::warn!("Failed to initialize backup service: {}", e);
                None
            }
        }
    } else {
        tracing::info!("Backup service: disabled");
        None
    };

    let state = if config.redis.enabled {
        match redis::Client::open(redis_url.as_str()) {
            Ok(client) => match redis::aio::ConnectionManager::new(client).await {
                Ok(redis_conn) => {
                    tracing::info!("Redis connected, enabling key metadata caching");

                    let rate_limiter = maybe_create_rate_limiter(
                        redis_url.as_str(),
                        rate_limit_enabled,
                        config.rate_limit.requests_per_second,
                        config.rate_limit.requests_per_minute,
                        config.rate_limit.burst_size,
                    )
                    .await;

                    let quota_tracker = maybe_create_quota_tracker(
                        redis_url.as_str(),
                        quota_enabled,
                        config.quota.max_keys,
                        config.quota.max_requests_per_minute,
                        config.quota.max_requests_per_day,
                    )
                    .await;

                    match backend_type {
                        BackendType::Software => {
                            let keystore = create_software_keystore_inner(
                                &mfa_pool,
                                redis_conn,
                            )
                            .await;
                            build_kms_state(
                                keystore,
                                policy_engine,
                                audit_logger,
                                sm9_state.clone(),
                                rate_limiter,
                                quota_tracker,
                                metrics.clone(),
                                mfa_pool.clone(),
                                backup_service.clone(),
                            )
                        }
                        BackendType::Tpm => {
                            tracing::warn!(
                                "Redis caching not supported for TPM backend, using keystore directly"
                            );
                            let tpm_keystore =
                                create_tpm_keystore(&config.backend.tpm_backend)
                                    .map_err(|e| anyhow::anyhow!("Failed to create TPM keystore: {}", e))?;
                            build_kms_state(
                                tpm_keystore,
                                policy_engine,
                                audit_logger,
                                sm9_state.clone(),
                                rate_limiter,
                                quota_tracker,
                                metrics.clone(),
                                mfa_pool.clone(),
                                backup_service.clone(),
                            )
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Redis connection failed ({}), running without cache", e);

                    // Create rate limiter and quota tracker without Redis caching
                    let rate_limiter = maybe_create_rate_limiter(
                        redis_url.as_str(),
                        rate_limit_enabled,
                        config.rate_limit.requests_per_second,
                        config.rate_limit.requests_per_minute,
                        config.rate_limit.burst_size,
                    )
                    .await;

                    let quota_tracker = maybe_create_quota_tracker(
                        redis_url.as_str(),
                        quota_enabled,
                        config.quota.max_keys,
                        config.quota.max_requests_per_minute,
                        config.quota.max_requests_per_day,
                    )
                    .await;

                    build_kms_state(
                        create_software_keystore(&mfa_pool).await,
                        policy_engine,
                        audit_logger,
                        sm9_state.clone(),
                        rate_limiter,
                        quota_tracker,
                        metrics.clone(),
                        mfa_pool.clone(),
                        backup_service.clone(),
                    )
                }
            },
            Err(e) => {
                tracing::warn!(
                    "Failed to create Redis client ({}), running without cache",
                    e
                );

                // Create rate limiter and quota tracker without Redis caching
                let rate_limiter = maybe_create_rate_limiter(
                    redis_url.as_str(),
                    rate_limit_enabled,
                    config.rate_limit.requests_per_second,
                    config.rate_limit.requests_per_minute,
                    config.rate_limit.burst_size,
                )
                .await;

                let quota_tracker = maybe_create_quota_tracker(
                    redis_url.as_str(),
                    quota_enabled,
                    config.quota.max_keys,
                    config.quota.max_requests_per_minute,
                    config.quota.max_requests_per_day,
                )
                .await;

                build_kms_state(
                    create_software_keystore(&mfa_pool).await,
                    policy_engine,
                    audit_logger,
                    sm9_state.clone(),
                    rate_limiter,
                    quota_tracker,
                    metrics.clone(),
                    mfa_pool.clone(),
                    backup_service.clone(),
                )
            }
        }
    } else {
        tracing::info!("Redis caching disabled by configuration");

        // Rate limiter still available without Redis caching
        let rate_limiter = maybe_create_rate_limiter(
            redis_url.as_str(),
            rate_limit_enabled,
            config.rate_limit.requests_per_second,
            config.rate_limit.requests_per_minute,
            config.rate_limit.burst_size,
        )
        .await;

        // Quota tracker requires Redis, so it's None when Redis is disabled
        let quota_tracker = maybe_create_quota_tracker(
            redis_url.as_str(),
            false, // quota disabled when Redis is disabled
            config.quota.max_keys,
            config.quota.max_requests_per_minute,
            config.quota.max_requests_per_day,
        )
        .await;

        build_kms_state(
            create_software_keystore(&mfa_pool).await,
            policy_engine,
            audit_logger,
            sm9_state.clone(),
            rate_limiter,
            quota_tracker,
            metrics.clone(),
            mfa_pool.clone(),
            backup_service.clone(),
        )
    };

    tracing::info!("State created successfully");

    // Key lifecycle scan (#3): count keys by status and set gauges
    {
        let filter = kms_core::key::KeyFilter::default();
        match state.keystore.list_keys(&filter).await {
            Ok(keys) => {
                let mut active = 0u64;
                let mut pending_deletion = 0u64;
                let mut obsolete = 0u64;
                let mut destroyed = 0u64;
                for k in &keys {
                    match k.status {
                        kms_core::key::KeyStatus::Active => active += 1,
                        kms_core::key::KeyStatus::PendingDeletion => pending_deletion += 1,
                        kms_core::key::KeyStatus::Obsolete => obsolete += 1,
                        kms_core::key::KeyStatus::Destroyed => destroyed += 1,
                    }
                }
                metrics.keys_by_status_active.set(active);
                metrics
                    .keys_by_status_pending_deletion
                    .set(pending_deletion);
                metrics.keys_by_status_obsolete.set(obsolete);
                metrics.keys_by_status_destroyed.set(destroyed);
                tracing::info!(
                    "Key lifecycle scan: active={}, pending_deletion={}, obsolete={}, destroyed={}",
                    active,
                    pending_deletion,
                    obsolete,
                    destroyed
                );
            }
            Err(e) => {
                tracing::warn!("Key lifecycle scan failed: {}", e);
            }
        }
    }

    // Initial health check (#20+#43)
    let health_checker = Arc::new(HealthChecker::new(
        state.keystore.clone(),
        state.audit_logger.clone(),
        metrics.clone(),
    ));
    let initial_health = health_checker.check().await;
    tracing::info!("Initial health check: {:?}", initial_health);

    // Periodic health check every 60 seconds
    let hc_clone = health_checker.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let status = hc_clone.check().await;
            if status != kms_core::types::HealthStatus::Healthy {
                tracing::warn!("Health check: {:?}", status);
            }
        }
    });

    // ── Phase 3 periodic tasks ──

    // #4 Key access distribution refresh every 60s
    let m = metrics.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            m.refresh_key_access_distribution();
        }
    });

    // #6 Encrypt/decrypt ratio refresh every 60s
    let m = metrics.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            m.refresh_encrypt_decrypt_ratio();
        }
    });

    // #7 Signature anomaly detection every 60s
    let m = metrics.clone();
    let mut prev_sign_total: u64 = 0;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let current = m.key_sign_total.get();
            let delta = current.saturating_sub(prev_sign_total);
            prev_sign_total = current;
            if delta > 1000 {
                tracing::warn!(
                    "Signature anomaly detected: {} sign operations in last 60s (threshold: 1000)",
                    delta
                );
            }
        }
    });

    // #19 Key storage capacity scan every 300s
    {
        let keystore = state.keystore.clone();
        let m = metrics.clone();
        tokio::spawn(async move {
            let key_size_by_spec = |spec: &kms_core::key::KeySpec| -> u64 {
                match spec {
                    kms_core::key::KeySpec::Aes256Gcm => 32,
                    kms_core::key::KeySpec::Rsa4096 => 2048,
                    kms_core::key::KeySpec::EcdsaP256 => 32,
                    kms_core::key::KeySpec::EcdsaP384 => 48,
                    kms_core::key::KeySpec::Ed25519 => 32,
                    kms_core::key::KeySpec::Ed448 => 57,
                    kms_core::key::KeySpec::HmacSha256 => 32,
                    kms_core::key::KeySpec::Sm2 => 32,
                    kms_core::key::KeySpec::Sm4 => 16,
                    kms_core::key::KeySpec::Sm9Signing => 160,
                    kms_core::key::KeySpec::Sm9Encryption => 160,
                }
            };
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                match keystore
                    .list_keys(&kms_core::key::KeyFilter::default())
                    .await
                {
                    Ok(keys) => {
                        let total_bytes: u64 = keys.iter().map(|k| key_size_by_spec(&k.spec)).sum();
                        m.set_key_storage_bytes(total_bytes);
                        m.set_key_count(keys.len() as u64);
                    }
                    Err(e) => {
                        tracing::warn!("Key storage capacity scan failed: {}", e);
                    }
                }
            }
        });
    }

    // Daily backup cleanup task
    if let Some(ref bs) = backup_service {
        let svc_clone = bs.clone();
        let m = metrics.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
            loop {
                interval.tick().await;
                m.record_backup_attempt();
                match svc_clone.cleanup_old_backups() {
                    Ok(count) => {
                        m.record_backup_success();
                        tracing::info!(
                            "Backup cleanup completed: {} old backups removed",
                            count
                        );
                    }
                    Err(e) => {
                        m.record_backup_failure();
                        tracing::warn!("Backup cleanup failed: {}", e);
                    }
                }
            }
        });
    }

    // Log rate limiting status
    if rate_limit_enabled {
        tracing::info!(
            "Rate limiting: enabled ({} req/s per tenant)",
            config.rate_limit.requests_per_second
        );
    } else {
        tracing::info!("Rate limiting: disabled");
    }

    // Log quota tracking status
    if quota_enabled {
        tracing::info!(
            "Quota tracking: enabled (max {} keys per tenant)",
            config.quota.max_keys
        );
    } else {
        tracing::info!("Quota tracking: disabled");
    }

    // Load API key configuration for REST
    let api_key_config = ApiKeyConfig::from_env("X-API-Key", "KMS_API_KEY")
        .map_err(|e: AuthError| anyhow::anyhow!("{}", e))?;
    let api_key_config_arc = std::sync::Arc::new(api_key_config.clone());
    tracing::info!("REST API authentication: API Key configured");

    // Load TLS configuration for gRPC (optional mTLS)
    // Use config file TLS settings if available, otherwise try env vars
    let tls_config = config.tls.clone().or_else(TlsConfig::from_env);
    if let Some(ref tls) = tls_config {
        tracing::info!(
            "gRPC mTLS configured: require_client_cert={}",
            tls.require_client_cert
        );
    } else {
        tracing::warn!(
            "gRPC running without TLS - set TLS_CERT_PATH, TLS_KEY_PATH, TLS_CA_PATH to enable"
        );
    }

    // REST server
    let rest_addr: SocketAddr = ([0, 0, 0, 0], rest_port).into();
    let rest_state = state.clone();
    let cors_config = config.cors.clone();
    let rest_tls_config = config.rest_tls.clone();

    let (rest_shutdown_tx, rest_shutdown_rx) = oneshot::channel::<()>();
    let rest_handle = tokio::spawn(async move {
        // Build CORS layer based on configuration
        let cors = build_cors_layer(&cors_config);

        let app = create_routes(rest_state, api_key_config.clone()).layer(cors);

        let listener = tokio::net::TcpListener::bind(rest_addr)
            .await
            .expect("Failed to bind REST port");

        match rest_tls_config {
            Some(ref tls) if tls.enabled && tls.backend == "gm" => {
                // REST with GM/TLS (国密 TLS)
                tracing::info!("REST API listening on gm-tls://{}", rest_addr);

                let ca_path = tls.ca_path.as_deref().unwrap_or("");
                if ca_path.is_empty() {
                    anyhow::bail!("GM/TLS requires ca_path to be set in [rest_tls] config");
                }

                let gm_config =
                    gm_tls::TlsConfig::load(tls.cert_path.as_str(), tls.key_path.as_str(), ca_path)
                        .map(|cfg| cfg.with_require_client_auth(tls.require_client_auth))
                        .map_err(|e| anyhow::anyhow!("Failed to load GM/TLS config: {}", e))
                        .expect("GM/TLS config load failed");

                let gm_listener =
                    crate::cmd::gm_listener::GmTlsListener::bind(rest_addr, gm_config)
                        .await
                        .expect("Failed to bind GM/TLS REST listener");

                axum::serve(gm_listener, app)
                    .with_graceful_shutdown(async {
                        rest_shutdown_rx.await.ok();
                    })
                    .await
                    .expect("GM/TLS REST server error");
            }
            Some(ref tls) if tls.enabled => {
                // REST with TLS using axum_server
                tracing::info!("REST API listening on https://{}", rest_addr);

                let tls_config = RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path)
                    .await
                    .expect("Failed to load REST TLS certificates");

                let handle = axum_server::Handle::new();
                let shutdown_handle = handle.clone();

                // Spawn server task
                tokio::spawn(async move {
                    axum_server::bind_rustls(rest_addr, tls_config)
                        .handle(handle)
                        .serve(app.into_make_service())
                        .await
                        .expect("REST TLS server error");
                });

                // Wait for shutdown signal and trigger graceful shutdown
                rest_shutdown_rx.await.ok();
                tracing::info!("Initiating REST TLS server graceful shutdown...");
                shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
            }
            _ => {
                // REST without TLS
                tracing::info!("REST API listening on http://{}", rest_addr);

                axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        rest_shutdown_rx.await.ok();
                    })
                    .await
                    .expect("REST server error");
            }
        }
    });

    // gRPC server
    let grpc_addr: SocketAddr = ([0, 0, 0, 0], grpc_port).into();
    let grpc_state = state.clone();
    let grpc_auth = api_key_config_arc.clone();
    let tls_config_clone = tls_config.clone();

    let (grpc_shutdown_tx, grpc_shutdown_rx) = oneshot::channel::<()>();
    tracing::info!("Spawning gRPC server with API key authentication...");

    let grpc_handle = tokio::spawn(async move {
        let auth_interceptor = GrpcAuthInterceptor::new(grpc_auth);
        let service =
            KmsServiceServer::with_interceptor(KmsGrpcService::new(grpc_state), auth_interceptor);

        // Set up gRPC health check
        #[allow(unused_mut)]
        let (mut health_reporter, health_service) = health_server::health_reporter();
        health_reporter
            .set_service_status("kms.api.v1.KMSService", ServingStatus::Serving)
            .await;

        match tls_config_clone {
            Some(ref tls) => {
                // mTLS mode using gm-tls
                tracing::info!(
                    "gRPC mTLS: loading certificates from {}, {}, {}",
                    tls.cert_path,
                    tls.key_path,
                    tls.ca_path
                );

                let gm_config = tls.to_gm_config().expect("Failed to create gm-tls config");
                let acceptor =
                    gm_tls::TlsAcceptor::new(gm_config).expect("Failed to create gm-tls acceptor");

                let listener = tokio::net::TcpListener::bind(grpc_addr)
                    .await
                    .expect("Failed to bind gRPC port");
                let incoming = gm_tls::grpc::GmTlsIncoming::new(listener, acceptor);

                tracing::info!("gRPC mTLS API listening on {} (ALPN: h2)", grpc_addr);

                tonic::transport::Server::builder()
                    .add_service(health_service)
                    .add_service(service)
                    .serve_with_incoming(incoming)
                    .await
                    .expect("gRPC mTLS server error");
            }
            None => {
                // No TLS mode
                tracing::info!("gRPC API listening on {}", grpc_addr);

                // Set up gRPC health check
                #[allow(unused_mut)]
                let (mut health_reporter, health_service) = health_server::health_reporter();
                health_reporter
                    .set_service_status("kms.api.v1.KMSService", ServingStatus::Serving)
                    .await;

                tonic::transport::Server::builder()
                    .add_service(health_service)
                    .add_service(service)
                    .serve_with_shutdown(grpc_addr, async {
                        grpc_shutdown_rx.await.ok();
                    })
                    .await
                    .expect("gRPC server error");
            }
        }
    });

    tracing::info!("KMS server started successfully");
    tracing::info!(
        "  REST: http://0.0.0.0:{}/v1/keys (API Key auth)",
        rest_port
    );
    tracing::info!("  gRPC: 0.0.0.0:{} (API Key auth)", grpc_port);
    if tls_config.is_some() {
        tracing::info!("  TLS: Enabled (mTLS)");
    } else {
        tracing::warn!("  TLS: Disabled");
    }

    // Wait for shutdown signal (SIGINT or SIGTERM)
    let ctrl_c = async { signal::ctrl_c().await.expect("failed to listen for SIGINT") };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received SIGINT, shutting down..."),
        _ = terminate => tracing::info!("Received SIGTERM, shutting down..."),
    }

    // Send shutdown signals
    let _ = rest_shutdown_tx.send(());
    let _ = grpc_shutdown_tx.send(());

    // Wait for servers to finish
    let _ = tokio::join!(rest_handle, grpc_handle);

    tracing::info!("Server shutdown complete");

    Ok(())
}

// ============================================================================
// SM9 Master Key Repository Bridge Adapter
// ============================================================================
//
// Bridges kms_keystore::Sm9MasterKeyRepository (uses kms_core::Error) to
// kms_api::Sm9MasterKeyRepository (uses kms_api::ApiError).
//
// Both traits define the same methods; this adapter delegates each call and
// converts the error type.

/// Adapter that wraps a `kms_keystore::Sm9MasterKeyRepository` and implements
/// `kms_api::Sm9MasterKeyRepository` for use with `Sm9State` persistence methods.
struct Sm9RepoAdapter {
    inner: Arc<dyn kms_keystore::sm9_master_key::Sm9MasterKeyRepository>,
}

#[async_trait]
impl kms_api::Sm9MasterKeyRepository for Sm9RepoAdapter {
    async fn store(&self, key: &[u8], version: u32) -> kms_api::Result<()> {
        self.inner
            .store(key, version)
            .await
            .map_err(|e| kms_api::ApiError::Internal(format!("SM9 repo store: {e}")))
    }

    async fn load(&self) -> kms_api::Result<Vec<u8>> {
        self.inner
            .load()
            .await
            .map_err(|e| kms_api::ApiError::Internal(format!("SM9 repo load: {e}")))
    }

    async fn get_version(&self) -> kms_api::Result<Option<u32>> {
        self.inner
            .get_version()
            .await
            .map_err(|e| kms_api::ApiError::Internal(format!("SM9 repo get_version: {e}")))
    }

    async fn exists(&self) -> kms_api::Result<bool> {
        self.inner
            .exists()
            .await
            .map_err(|e| kms_api::ApiError::Internal(format!("SM9 repo exists: {e}")))
    }
}
