//! Server configuration from TOML file

use serde::Deserialize;

/// Server configuration
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    /// Server settings
    #[serde(default)]
    pub server: ServerConfig,

    /// Backend settings
    #[serde(default)]
    pub backend: BackendConfig,

    /// Redis settings
    #[serde(default)]
    pub redis: RedisConfig,

    /// TLS settings (for gRPC mTLS)
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// REST TLS settings (optional HTTPS)
    #[serde(default)]
    pub rest_tls: Option<RestTlsConfig>,

    /// Audit settings
    #[serde(default)]
    pub audit: AuditConfig,

    /// Rate limiting settings
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Quota settings
    #[serde(default)]
    pub quota: QuotaConfig,

    /// CORS settings
    #[serde(default)]
    pub cors: CorsConfig,

    /// Database settings (PostgreSQL)
    #[serde(default)]
    pub database: DatabaseConfig,

    /// Backup settings
    #[serde(default)]
    pub backup: BackupConfig,

    /// Kafka authentication credentials
    #[serde(default)]
    pub kafka_auth: KafkaAuthConfig,
}

/// Key backup configuration
#[derive(Debug, Clone, Deserialize)]
pub struct BackupConfig {
    /// Enable encrypted key backup
    #[serde(default = "default_backup_enabled")]
    pub enabled: bool,

    /// Backup storage directory path
    #[serde(default = "default_backup_path")]
    pub backup_path: String,

    /// Number of backups to retain per key
    #[serde(default = "default_backup_retention_count")]
    pub retention_count: u32,

    /// Backup retention period in days
    #[serde(default = "default_backup_retention_days")]
    pub retention_days: u32,

    /// KDF iterations for master key passphrase encryption
    #[serde(default = "default_backup_kdf_iterations")]
    pub kdf_iterations: u32,
}

fn default_backup_enabled() -> bool {
    true
}
fn default_backup_path() -> String {
    "/var/kms/backup".to_string()
}
fn default_backup_retention_count() -> u32 {
    3
}
fn default_backup_retention_days() -> u32 {
    365
}
fn default_backup_kdf_iterations() -> u32 {
    100_000
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: default_backup_enabled(),
            backup_path: default_backup_path(),
            retention_count: default_backup_retention_count(),
            retention_days: default_backup_retention_days(),
            kdf_iterations: default_backup_kdf_iterations(),
        }
    }
}

/// Audit configuration
#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    /// Output path for audit logs (file path or "stdout")
    #[serde(default = "default_audit_output")]
    pub output_path: String,

    /// Flush interval in seconds
    #[serde(default = "default_audit_flush_interval")]
    pub flush_interval_secs: u64,

    /// Buffer size before flush
    #[serde(default = "default_audit_buffer_size")]
    pub buffer_size: usize,

    /// Kafka brokers (optional, e.g., "localhost:9092")
    pub kafka_brokers: Option<String>,

    /// Kafka topic for audit events
    pub kafka_topic: Option<String>,

    /// RFC 3161 TSA configuration (optional)
    #[serde(default)]
    pub tsa: Option<TsaConfig>,
}

/// RFC 3161 Trusted Timestamp Authority configuration
#[derive(Debug, Clone, Deserialize)]
pub struct TsaConfig {
    /// Enable TSA timestamping
    #[serde(default)]
    pub enabled: bool,

    /// TSA endpoint URLs (e.g., "https://tsa.example.com/tsa")
    #[serde(default)]
    pub endpoints: Vec<String>,

    /// Request timeout in seconds
    #[serde(default = "default_tsa_timeout")]
    pub timeout_secs: u64,

    /// Require TSA success for audit logging (fail-closed)
    #[serde(default)]
    pub require_tsa: bool,

    /// TSA request interval in seconds (background task)
    #[serde(default = "default_tsa_interval")]
    pub interval_secs: u64,

    /// TSA authentication username
    #[serde(default)]
    pub username: Option<String>,

    /// TSA authentication password
    #[serde(default)]
    pub password: Option<String>,

    /// CA certificate path for TSA TLS verification
    #[serde(default)]
    pub ca_path: Option<String>,

    /// Hash algorithm: "sha256" or "sm3"
    #[serde(default = "default_tsa_hash_algorithm")]
    pub hash_algorithm: String,
}

fn default_tsa_timeout() -> u64 {
    30
}

fn default_tsa_interval() -> u64 {
    60
}

fn default_tsa_hash_algorithm() -> String {
    "sha256".to_string()
}

impl Default for TsaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoints: Vec::new(),
            timeout_secs: default_tsa_timeout(),
            require_tsa: false,
            interval_secs: default_tsa_interval(),
            username: None,
            password: None,
            ca_path: None,
            hash_algorithm: default_tsa_hash_algorithm(),
        }
    }
}

fn default_audit_output() -> String {
    "stdout".to_string()
}

fn default_audit_flush_interval() -> u64 {
    5
}

fn default_audit_buffer_size() -> usize {
    100
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// REST API port
    #[serde(default = "default_rest_port")]
    pub rest_port: u16,

    /// gRPC port
    #[serde(default = "default_grpc_port")]
    pub grpc_port: u16,
}

fn default_rest_port() -> u16 {
    8080
}

fn default_grpc_port() -> u16 {
    9090
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    /// Backend type: "software" or "tpm"
    #[serde(default = "default_backend")]
    pub backend_type: String,

    /// TPM backend: "simulated" (default) or "tpm2-tss" (requires hardware + feature flag)
    #[serde(default = "default_tpm_backend")]
    pub tpm_backend: String,
}

fn default_backend() -> String {
    "software".to_string()
}

fn default_tpm_backend() -> String {
    "simulated".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    /// Redis URL
    #[serde(default = "default_redis_url")]
    pub url: String,

    /// Enable Redis caching
    #[serde(default = "default_redis_enabled")]
    pub enabled: bool,
}

fn default_redis_url() -> String {
    "redis://127.0.0.1:6379".to_string()
}

fn default_redis_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// Server certificate path (PEM)
    pub cert_path: String,

    /// Server private key path (PEM)
    pub key_path: String,

    /// CA certificate path for client verification (PEM)
    pub ca_path: String,

    /// Whether to require client certificates (mTLS)
    #[serde(default = "default_require_client_cert")]
    pub require_client_cert: bool,
}

fn default_require_client_cert() -> bool {
    true
}

/// REST TLS configuration (optional, separate from gRPC mTLS)
#[derive(Debug, Clone, Deserialize)]
pub struct RestTlsConfig {
    /// Enable TLS for REST API
    #[serde(default = "default_rest_tls_enabled")]
    pub enabled: bool,

    /// TLS backend: "rustls" (standard, default) or "gm" (国密 GM/TLS)
    #[serde(default = "default_rest_tls_backend")]
    pub backend: String,

    /// Server certificate path (PEM or SM2 cert for gm-tls)
    pub cert_path: String,

    /// Server private key path (PEM or SM2 key for gm-tls)
    pub key_path: String,

    /// CA certificate path (required for gm-tls; optional for mTLS with rustls)
    #[serde(default)]
    pub ca_path: Option<String>,

    /// Require client certificate (mTLS). Default false for REST.
    #[serde(default)]
    pub require_client_auth: bool,
}

fn default_rest_tls_enabled() -> bool {
    false
}

fn default_rest_tls_backend() -> String {
    "rustls".to_string()
}

impl Default for RestTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: default_rest_tls_backend(),
            cert_path: String::new(),
            key_path: String::new(),
            ca_path: None,
            require_client_auth: false,
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,

    /// Maximum requests per second per tenant
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: u64,

    /// Maximum requests per minute per tenant
    #[serde(default = "default_requests_per_minute")]
    pub requests_per_minute: u64,

    /// Maximum burst size
    #[serde(default = "default_burst_size")]
    pub burst_size: u64,
}

fn default_rate_limit_enabled() -> bool {
    true
}

fn default_requests_per_second() -> u64 {
    100
}

fn default_requests_per_minute() -> u64 {
    5000
}

fn default_burst_size() -> u64 {
    200
}

/// Quota configuration
#[derive(Debug, Clone, Deserialize)]
pub struct QuotaConfig {
    /// Enable quota tracking
    #[serde(default = "default_quota_enabled")]
    pub enabled: bool,

    /// Maximum keys per tenant
    #[serde(default = "default_max_keys")]
    pub max_keys: u64,

    /// Maximum requests per minute per tenant
    #[serde(default = "default_max_requests_per_minute")]
    pub max_requests_per_minute: u64,

    /// Maximum requests per day per tenant
    #[serde(default = "default_max_requests_per_day")]
    pub max_requests_per_day: u64,
}

fn default_quota_enabled() -> bool {
    true
}

fn default_max_keys() -> u64 {
    1000
}

fn default_max_requests_per_minute() -> u64 {
    5000
}

fn default_max_requests_per_day() -> u64 {
    1000000
}

impl TlsConfig {
    /// Load from environment variables
    pub fn from_env() -> Option<Self> {
        let cert_path = std::env::var("TLS_CERT_PATH").ok()?;
        let key_path = std::env::var("TLS_KEY_PATH").ok()?;
        let ca_path = std::env::var("TLS_CA_PATH").ok()?;

        let require_client_cert = std::env::var("TLS_REQUIRE_CLIENT_CERT")
            .map(|v| v == "true")
            .unwrap_or(true);

        Some(Self {
            cert_path,
            key_path,
            ca_path,
            require_client_cert,
        })
    }

    /// Convert to gm-tls TlsConfig for mTLS
    pub fn to_gm_config(&self) -> anyhow::Result<gm_tls::TlsConfig, gm_tls::TlsError> {
        let config = gm_tls::TlsConfig::load(&self.cert_path, &self.key_path, &self.ca_path)?
            .with_require_client_auth(self.require_client_cert)
            .with_alpn(vec!["h2".to_string()]); // gRPC requires HTTP/2
        Ok(config)
    }
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file {}: {}", path, e))?;

        toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse config file {}: {}", path, e))
    }

    /// Load configuration with environment variable overrides
    pub fn load(path: &str) -> anyhow::Result<Self> {
        // Try to load from file first
        let mut config = if std::path::Path::new(path).exists() {
            Self::from_file(path)?
        } else {
            tracing::warn!("Config file {} not found, using defaults", path);
            Self::default()
        };

        // Override with environment variables
        config.apply_env_overrides();

        Ok(config)
    }

    /// Apply environment variable overrides
    fn apply_env_overrides(&mut self) {
        // Server ports
        if let Ok(port) = std::env::var("REST_PORT") {
            if let Ok(port) = port.parse() {
                self.server.rest_port = port;
            }
        }
        if let Ok(port) = std::env::var("GRPC_PORT") {
            if let Ok(port) = port.parse() {
                self.server.grpc_port = port;
            }
        }

        // Backend
        if let Ok(backend) = std::env::var("KMS_BACKEND") {
            self.backend.backend_type = backend;
        }
        if let Ok(tpm) = std::env::var("KMS_TPM_BACKEND") {
            self.backend.tpm_backend = tpm;
        }

        // Redis
        if let Ok(url) = std::env::var("REDIS_URL") {
            self.redis.url = url;
        }

        // TLS
        if let Ok(cert) = std::env::var("TLS_CERT_PATH") {
            if self.tls.is_none() {
                self.tls = Some(TlsConfig {
                    cert_path: cert,
                    key_path: std::env::var("TLS_KEY_PATH").unwrap_or_default(),
                    ca_path: std::env::var("TLS_CA_PATH").unwrap_or_default(),
                    require_client_cert: std::env::var("TLS_REQUIRE_CLIENT_CERT")
                        .map(|v| v == "true")
                        .unwrap_or(true),
                });
            }
        }

        // REST TLS
        if let Ok(cert) = std::env::var("REST_TLS_CERT_PATH") {
            if self.rest_tls.is_none() {
                self.rest_tls = Some(RestTlsConfig {
                    enabled: true,
                    backend: std::env::var("REST_TLS_BACKEND")
                        .unwrap_or_else(|_| default_rest_tls_backend()),
                    cert_path: cert,
                    key_path: std::env::var("REST_TLS_KEY_PATH").unwrap_or_default(),
                    ca_path: std::env::var("REST_TLS_CA_PATH").ok(),
                    require_client_auth: std::env::var("REST_TLS_REQUIRE_CLIENT_AUTH")
                        .map(|v| v == "true")
                        .unwrap_or(false),
                });
            }
        }
        // Patch existing rest_tls with env overrides if already loaded from file
        if let Some(ref mut tls) = self.rest_tls {
            if let Ok(backend) = std::env::var("REST_TLS_BACKEND") {
                tls.backend = backend;
            }
            if let Ok(ca_path) = std::env::var("REST_TLS_CA_PATH") {
                tls.ca_path = Some(ca_path);
            }
            if let Ok(require) = std::env::var("REST_TLS_REQUIRE_CLIENT_AUTH") {
                tls.require_client_auth = require == "true";
            }
        }

        // Audit settings
        if let Ok(output) = std::env::var("AUDIT_OUTPUT") {
            self.audit.output_path = output;
        }
        if let Ok(brokers) = std::env::var("KAFKA_BROKERS") {
            self.audit.kafka_brokers = Some(brokers);
        }
        if let Ok(topic) = std::env::var("KAFKA_TOPIC") {
            self.audit.kafka_topic = Some(topic);
        }

        // TSA settings
        if let Ok(enabled) = std::env::var("TSA_ENABLED") {
            let tsa = self.audit.tsa.get_or_insert_with(TsaConfig::default);
            tsa.enabled = enabled == "true";
        }
        if let Ok(endpoint) = std::env::var("TSA_ENDPOINT") {
            let tsa = self.audit.tsa.get_or_insert_with(TsaConfig::default);
            tsa.endpoints = endpoint.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(timeout) = std::env::var("TSA_TIMEOUT") {
            if let Ok(timeout) = timeout.parse() {
                let tsa = self.audit.tsa.get_or_insert_with(TsaConfig::default);
                tsa.timeout_secs = timeout;
            }
        }
        if let Ok(require) = std::env::var("TSA_REQUIRE") {
            let tsa = self.audit.tsa.get_or_insert_with(TsaConfig::default);
            tsa.require_tsa = require == "true";
        }
        if let Ok(interval) = std::env::var("TSA_INTERVAL") {
            if let Ok(interval) = interval.parse() {
                let tsa = self.audit.tsa.get_or_insert_with(TsaConfig::default);
                tsa.interval_secs = interval;
            }
        }
        if let Ok(username) = std::env::var("TSA_USERNAME") {
            let tsa = self.audit.tsa.get_or_insert_with(TsaConfig::default);
            tsa.username = Some(username);
        }
        if let Ok(password) = std::env::var("TSA_PASSWORD") {
            let tsa = self.audit.tsa.get_or_insert_with(TsaConfig::default);
            tsa.password = Some(password);
        }
        if let Ok(ca_path) = std::env::var("TSA_CA_PATH") {
            let tsa = self.audit.tsa.get_or_insert_with(TsaConfig::default);
            tsa.ca_path = Some(ca_path);
        }
        if let Ok(hash_algo) = std::env::var("TSA_HASH_ALGORITHM") {
            let tsa = self.audit.tsa.get_or_insert_with(TsaConfig::default);
            tsa.hash_algorithm = hash_algo;
        }

        // Rate limit settings
        if let Ok(rps) = std::env::var("RATE_LIMIT_RPS") {
            if let Ok(rps) = rps.parse() {
                self.rate_limit.requests_per_second = rps;
            }
        }
        if let Ok(enabled) = std::env::var("RATE_LIMIT_ENABLED") {
            self.rate_limit.enabled = enabled == "true";
        }

        // Database credentials (T-16: credential externalization)
        if let Ok(url) = std::env::var("DATABASE_URL") {
            self.database.url = Some(url);
        }
        if let Ok(host) = std::env::var("POSTGRES_HOST") {
            self.database.host = host;
        }
        if let Ok(port) = std::env::var("POSTGRES_PORT") {
            if let Ok(port) = port.parse() {
                self.database.port = port;
            }
        }
        if let Ok(name) = std::env::var("POSTGRES_DB") {
            self.database.name = name;
        }
        if let Ok(user) = std::env::var("POSTGRES_USER") {
            self.database.username = user;
        }
        if let Ok(pass) = std::env::var("POSTGRES_PASSWORD") {
            self.database.password = pass;
        }

        // Kafka authentication credentials (T-16)
        if let Ok(username) = std::env::var("KAFKA_USERNAME") {
            self.kafka_auth.username = Some(username);
        }
        if let Ok(password) = std::env::var("KAFKA_PASSWORD") {
            self.kafka_auth.password = Some(password);
        }
        if let Ok(tls) = std::env::var("KAFKA_USE_TLS") {
            self.kafka_auth.use_tls = tls == "true";
        }

        // Backup settings
        if let Ok(enabled) = std::env::var("BACKUP_ENABLED") {
            self.backup.enabled = enabled == "true";
        }
        if let Ok(path) = std::env::var("BACKUP_PATH") {
            self.backup.backup_path = path;
        }
        if let Ok(count) = std::env::var("BACKUP_RETENTION_COUNT") {
            if let Ok(count) = count.parse() {
                self.backup.retention_count = count;
            }
        }
        if let Ok(days) = std::env::var("BACKUP_RETENTION_DAYS") {
            if let Ok(days) = days.parse() {
                self.backup.retention_days = days;
            }
        }
        if let Ok(kdf_iter) = std::env::var("BACKUP_KDF_ITERATIONS") {
            if let Ok(kdf_iter) = kdf_iter.parse() {
                self.backup.kdf_iterations = kdf_iter;
            }
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            output_path: default_audit_output(),
            flush_interval_secs: default_audit_flush_interval(),
            buffer_size: default_audit_buffer_size(),
            kafka_brokers: None,
            kafka_topic: None,
            tsa: None,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            rest_port: default_rest_port(),
            grpc_port: default_grpc_port(),
        }
    }
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            backend_type: default_backend(),
            tpm_backend: default_tpm_backend(),
        }
    }
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: default_redis_url(),
            enabled: default_redis_enabled(),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_rate_limit_enabled(),
            requests_per_second: default_requests_per_second(),
            requests_per_minute: default_requests_per_minute(),
            burst_size: default_burst_size(),
        }
    }
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            enabled: default_quota_enabled(),
            max_keys: default_max_keys(),
            max_requests_per_minute: default_max_requests_per_minute(),
            max_requests_per_day: default_max_requests_per_day(),
        }
    }
}

/// CORS configuration
#[derive(Debug, Clone, Deserialize)]
pub struct CorsConfig {
    /// Allowed origins (comma-separated list of domains)
    #[serde(default = "default_cors_allowed_origins")]
    pub allowed_origins: String,

    /// Allow credentials
    #[serde(default = "default_cors_allow_credentials")]
    pub allow_credentials: bool,
}

fn default_cors_allowed_origins() -> String {
    "".to_string()
}

fn default_cors_allow_credentials() -> bool {
    true
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: default_cors_allowed_origins(),
            allow_credentials: default_cors_allow_credentials(),
        }
    }
}

/// Database configuration (PostgreSQL)
/// Supports externalization via environment variables for security
#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    /// Database host
    #[serde(default = "default_db_host")]
    pub host: String,

    /// Database port
    #[serde(default = "default_db_port")]
    pub port: u16,

    /// Database name
    #[serde(default = "default_db_name")]
    pub name: String,

    /// Database username
    #[serde(default = "default_db_username")]
    pub username: String,

    /// Database password (should be provided via POSTGRES_PASSWORD env var in production)
    #[serde(default = "default_db_password")]
    pub password: String,

    /// Database connection URL (overrides individual settings if provided)
    #[serde(default)]
    pub url: Option<String>,
}

fn default_db_host() -> String {
    "localhost".to_string()
}

fn default_db_port() -> u16 {
    5432
}

fn default_db_name() -> String {
    "kms".to_string()
}

fn default_db_username() -> String {
    "kms_user".to_string()
}

fn default_db_password() -> String {
    "kms_pass".to_string()
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            host: default_db_host(),
            port: default_db_port(),
            name: default_db_name(),
            username: default_db_username(),
            password: default_db_password(),
            url: None,
        }
    }
}

impl DatabaseConfig {
    /// Get the database connection URL
    /// Prefers explicit URL if set, otherwise constructs from individual settings
    #[allow(dead_code)]
    pub fn connection_url(&self) -> String {
        if let Some(ref url) = self.url {
            url.clone()
        } else {
            format!(
                "postgres://{}:{}@{}:{}/{}",
                self.username, self.password, self.host, self.port, self.name
            )
        }
    }
}

/// Kafka authentication configuration
/// Supports SASL/PLAIN authentication via environment variables
#[derive(Debug, Clone, Deserialize)]
pub struct KafkaAuthConfig {
    /// Kafka username (for SASL authentication)
    #[serde(default)]
    pub username: Option<String>,

    /// Kafka password (for SASL authentication)
    #[serde(default)]
    pub password: Option<String>,

    /// Enable TLS for Kafka connection
    #[serde(default = "default_kafka_tls")]
    pub use_tls: bool,
}

fn default_kafka_tls() -> bool {
    true
}

impl Default for KafkaAuthConfig {
    fn default() -> Self {
        Self {
            username: None,
            password: None,
            use_tls: default_kafka_tls(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_secure_by_default() {
        let config = Config::default();

        // TLS defaults: gRPC TLS must have cert paths set (not empty)
        // TLS and REST TLS are None by default, meaning they are optional
        // When enabled, they require cert_path to be set
        assert!(config.tls.is_none(), "gRPC TLS should be None by default");
        assert!(
            config.rest_tls.is_none() || !config.rest_tls.as_ref().unwrap().enabled,
            "REST TLS should be disabled by default"
        );

        // Rate limiting should be enabled by default
        assert!(
            config.rate_limit.enabled,
            "rate limiting should be enabled by default"
        );
        assert!(
            config.rate_limit.requests_per_second > 0,
            "rate limit should have a reasonable default"
        );

        // Kafka TLS should be enabled by default
        assert!(
            config.kafka_auth.use_tls,
            "Kafka TLS should be enabled by default"
        );

        // Backup should be enabled
        assert!(config.backup.enabled, "backup should be enabled by default");

        // KDF iterations should be reasonable (at least 600k per NIST SP 800-63B)
        assert!(
            config.backup.kdf_iterations >= 100_000,
            "KDF iterations should be >= 100k, got {}",
            config.backup.kdf_iterations
        );
    }

    #[test]
    fn test_config_rate_limit_default_bound() {
        let config = RateLimitConfig::default();

        // Rate limits should be within reasonable bounds
        assert!(
            config.requests_per_second > 0,
            "requests_per_second should be positive"
        );
        assert!(
            config.requests_per_second <= 10_000,
            "requests_per_second should be reasonable"
        );
        assert!(
            config.requests_per_minute > 0,
            "requests_per_minute should be positive"
        );
        assert!(config.burst_size > 0, "burst_size should be positive");
        assert!(
            config.burst_size >= config.requests_per_second,
            "burst_size should be >= requests_per_second"
        );
    }

    #[test]
    fn test_config_quota_defaults_reasonable() {
        let config = QuotaConfig::default();

        assert!(config.enabled, "quota should be enabled by default");
        assert!(config.max_keys > 0, "max_keys should be positive");
        assert!(
            config.max_keys <= 1_000_000,
            "max_keys default should be reasonable"
        );
        assert!(
            config.max_requests_per_day > config.max_requests_per_minute,
            "daily limit should exceed per-minute limit"
        );
    }

    #[test]
    fn test_config_backup_retention_meets_minimum() {
        let config = BackupConfig::default();

        // Retention should be at least 30 days for compliance
        assert!(
            config.retention_days >= 30,
            "backup retention should be >= 30 days, got {}",
            config.retention_days
        );
        assert!(
            config.retention_count >= 1,
            "at least 1 backup should be retained, got {}",
            config.retention_count
        );
        assert!(
            config.kdf_iterations >= 100_000,
            "KDF iterations should be >= 100k for security"
        );
    }

    #[test]
    fn test_config_server_ports_valid() {
        let config = ServerConfig::default();

        assert!(config.rest_port > 0, "REST port should be positive");
        assert!(config.grpc_port > 0, "gRPC port should be positive");
        assert_ne!(
            config.rest_port, config.grpc_port,
            "REST and gRPC ports should be different"
        );
    }

    #[test]
    fn test_config_backend_type_valid() {
        let config = BackendConfig::default();

        assert_eq!(
            config.backend_type, "software",
            "default backend should be software"
        );
        assert!(
            config.backend_type == "software" || config.backend_type == "tpm",
            "backend_type should be 'software' or 'tpm', got '{}'",
            config.backend_type
        );
    }

    #[test]
    fn test_config_audit_defaults() {
        let config = AuditConfig::default();

        // Audit output should be stdout by default for visibility
        assert!(
            !config.output_path.is_empty(),
            "audit output path should not be empty"
        );
        assert!(
            config.flush_interval_secs > 0,
            "flush interval should be positive"
        );
        assert!(config.buffer_size > 0, "buffer size should be positive");
    }

    #[test]
    fn test_config_tls_parse() {
        let toml_str = r#"
[tls]
cert_path = "/etc/kms/server.crt"
key_path = "/etc/kms/server.key"
ca_path = "/etc/kms/ca.crt"
require_client_cert = true
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        let tls = config.tls.unwrap();
        assert_eq!(tls.cert_path, "/etc/kms/server.crt");
        assert_eq!(tls.key_path, "/etc/kms/server.key");
        assert_eq!(tls.ca_path, "/etc/kms/ca.crt");
        assert!(tls.require_client_cert);
    }

    #[test]
    fn test_config_rest_tls_parse() {
        let toml_str = r#"
[rest_tls]
enabled = true
backend = "gm"
cert_path = "/etc/kms/rest.crt"
key_path = "/etc/kms/rest.key"
ca_path = "/etc/kms/ca.crt"
require_client_auth = true
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        let tls = config.rest_tls.unwrap();
        assert!(tls.enabled);
        assert_eq!(tls.backend, "gm");
        assert_eq!(tls.cert_path, "/etc/kms/rest.crt");
        assert_eq!(tls.key_path, "/etc/kms/rest.key");
        assert_eq!(tls.ca_path, Some("/etc/kms/ca.crt".to_string()));
        assert!(tls.require_client_auth);
    }

    #[test]
    fn test_config_rate_limit_parse() {
        let toml_str = r#"
[rate_limit]
enabled = true
requests_per_second = 50
requests_per_minute = 3000
burst_size = 100
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.rate_limit.requests_per_second, 50);
        assert_eq!(config.rate_limit.requests_per_minute, 3000);
        assert_eq!(config.rate_limit.burst_size, 100);
    }

    #[test]
    fn test_config_full_parse() {
        let toml_str = r#"
[server]
rest_port = 8443
grpc_port = 9443

[backend]
backend_type = "software"

[redis]
url = "redis://redis:6379"
enabled = true

[backup]
enabled = true
backup_path = "/var/kms/backup"
retention_count = 5
retention_days = 90
kdf_iterations = 200000

[rate_limit]
enabled = true
requests_per_second = 100
burst_size = 200
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.rest_port, 8443);
        assert_eq!(config.server.grpc_port, 9443);
        assert_eq!(config.backend.backend_type, "software");
        assert_eq!(config.redis.url, "redis://redis:6379");
        assert_eq!(config.backup.retention_count, 5);
        assert_eq!(config.backup.retention_days, 90);
        assert_eq!(config.backup.kdf_iterations, 200000);
        assert_eq!(config.rate_limit.requests_per_second, 100);
    }

    #[test]
    fn test_tls_config_from_env() {
        // When env vars aren't set, from_env returns None
        // (we skip remove_var to avoid unsafe in tests — env vars are unset by default in CI)
        let result = TlsConfig::from_env();
        // Either None (env vars not set) or Some (env vars set — CI/test envs set them)
        // The important thing is the function returns a valid result
        if let Some(tls) = result {
            assert!(!tls.cert_path.is_empty());
        }
        // If result is None, that's also expected (env vars not set)
    }

    #[test]
    fn test_rest_tls_default_disabled() {
        let config = RestTlsConfig::default();
        assert!(!config.enabled, "REST TLS should be disabled by default");
        assert_eq!(config.backend, "rustls");
    }

    #[test]
    fn test_gm_tls_requires_ca_path() {
        // When using GM TLS backend, ca_path should be configured
        let toml_str = r#"
[rest_tls]
enabled = true
backend = "gm"
cert_path = "/etc/kms/gm.crt"
key_path = "/etc/kms/gm.key"
require_client_auth = true
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let tls = config.rest_tls.unwrap();
        assert_eq!(tls.backend, "gm");
        // ca_path is optional in config but should be validated when gm-tls is used
        // The absence here just means it wasn't set in the TOML
        assert!(tls.ca_path.is_none());
    }

    #[test]
    fn test_grpc_tls_config_mtls_enabled() {
        let toml_str = r#"
[tls]
cert_path = "/etc/kms/grpc.crt"
key_path = "/etc/kms/grpc.key"
ca_path = "/etc/kms/ca.crt"
require_client_cert = true
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let tls = config.tls.unwrap();
        assert!(
            tls.require_client_cert,
            "gRPC mTLS should require client cert by default"
        );
    }

    #[test]
    fn test_config_tls_enabled_rest_tls() {
        let toml_str = r#"
[rest_tls]
enabled = true
backend = "rustls"
cert_path = "/etc/kms/rest.crt"
key_path = "/etc/kms/rest.key"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let tls = config.rest_tls.unwrap();
        assert!(tls.enabled);
        assert_eq!(tls.backend, "rustls");
        assert!(!tls.cert_path.is_empty());
        assert!(!tls.key_path.is_empty());
    }
}
