//! REST API implementation using Axum

use crate::auth::{ApiKeyConfig, CallerId};
use crate::mfa::{MAX_BACKUP_CODE_USES, MAX_TOTP_ATTEMPTS, MfaStatusResponse, TOTP_LOCKOUT_SECS};
use crate::validation::{
    validate_create_key_request, validate_decrypt_request, validate_encrypt_request,
};
use crate::{ApiError, KmsState, Result, service::KeyService};
use axum::{
    Json, Router,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    middleware::{from_fn, from_fn_with_state},
    routing::{delete, get, post},
};
use kms_approval::{OperationType, Role};
use kms_core::key::{KeyFilter, KeyMeta};
use kms_mfa::{TotpConfig, TotpGenerator};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

// OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    info(
        title = "gm-kms REST API",
        version = "0.1.0",
        description = "GM/KMS - Enterprise Key Management System with support for symmetric keys (AES-256-GCM, SM4), asymmetric keys (Ed25519, SM2), and SM9 identity-based cryptography. Features include multi-tenancy, PBAC policy engine, MFA authentication, and approval workflows."
    ),
    tags(
        { name = "Keys", description = "Key lifecycle management - create, rotate, delete, encrypt, decrypt, sign, verify" },
        { name = "Hash", description = "Cryptographic hash operations (SM3, SHA-256)" },
        { name = "Policies", description = "PBAC policy management for access control" },
        { name = "Audit", description = "Audit event querying and log retrieval" },
        { name = "SM9", description = "Identity-based cryptography operations using SM9 algorithm" },
        { name = "MFA", description = "Multi-factor authentication setup and verification (TOTP)" },
        { name = "Approvals", description = "Approval workflow for sensitive operations" },
        { name = "Envelope", description = "Envelope encryption using DEK/KEK两层加密架构" },
        { name = "Import/Export", description = "Secure key import and export with key wrapping" }
    ),
    components(schemas(CreateKeyRequest, KeyResponse, EncryptRequest, EncryptResponse,
                      DecryptRequest, DecryptResponse, SignRequest, SignResponse,
                      VerifyRequest, VerifyResponse, HashRequest, HashResponse,
                      MfaSetupResponse, MfaStatusResponse,
                      CreateApprovalReq, ApproveReq, RejectReq, CancelReq,
                      CreatePolicyRequest, PolicyResponse, HealthResponse,
                      EnvelopeEncryptRequest, EnvelopeEncryptResponse,
                      EnvelopeDecryptRequest, EnvelopeDecryptResponse,
                      ImportKeyRequest, ImportKeyResponse,
                      ExportKeyRequest, ExportKeyResponse))
)]
pub struct ApiDoc;

// Request/Response types

/// Create a new cryptographic key
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateKeyRequest {
    /// Unique name for the key within the tenant
    #[schema(example = "my-key")]
    pub name: String,
    /// Key specification: "aes-256-gcm", "ed25519", "ecdsa-p256", "sm4", "sm2", "sm9-signing", "sm9-encryption"
    #[schema(example = "aes-256-gcm")]
    pub spec: String,
    /// Tenant ID for multi-tenancy isolation
    #[serde(default = "default_tenant_id")]
    #[schema(example = "default")]
    pub tenant_id: String,
}

fn default_tenant_id() -> String {
    static WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    WARNED.get_or_init(|| {
        tracing::warn!(
            "SECURITY: Using default tenant_id='default'. \
             Configure explicit tenant isolation for production deployments."
        );
    });
    "default".to_string()
}

#[derive(Debug, Serialize, ToSchema)]
pub struct KeyResponse {
    /// Unique key identifier (UUID)
    pub id: Uuid,
    /// Tenant ID this key belongs to
    pub tenant_id: String,
    /// Human-readable key name
    pub name: String,
    /// Key specification (e.g., "Aes256Gcm", "Ed25519")
    pub spec: String,
    /// Current key status ("Active", "PendingDeletion", etc.)
    pub status: String,
    /// Current version number for key rotation
    pub version: u32,
    /// ISO 8601 creation timestamp
    pub created_at: String,
}

impl From<KeyMeta> for KeyResponse {
    fn from(meta: KeyMeta) -> Self {
        Self {
            id: meta.id,
            tenant_id: meta.tenant_id,
            name: meta.name,
            spec: format!("{:?}", meta.spec),
            status: format!("{:?}", meta.status),
            version: meta.version,
            created_at: meta.created_at.to_rfc3339(),
        }
    }
}

/// Encrypt plaintext using a key (AES-256-GCM or SM4)
#[derive(Debug, Deserialize, ToSchema)]
pub struct EncryptRequest {
    /// Base64-encoded plaintext data to encrypt
    pub plaintext: String,
    /// Optional additional authenticated data (AAD) for AEAD ciphers
    #[serde(default)]
    pub aad: Option<String>,
}

/// Encryption response with ciphertext and nonce
#[derive(Debug, Serialize, ToSchema)]
pub struct EncryptResponse {
    /// Base64-encoded ciphertext
    pub ciphertext: String,
    /// Base64-encoded nonce/IV
    pub nonce: String,
    /// Base64-encoded authentication tag
    pub tag: String,
}

/// Decrypt ciphertext using a key
#[derive(Debug, Deserialize, ToSchema)]
pub struct DecryptRequest {
    /// Base64-encoded ciphertext to decrypt
    pub ciphertext: String,
    /// Base64-encoded nonce/IV used during encryption
    pub nonce: String,
    /// Base64-encoded authentication tag
    pub tag: String,
    /// Optional additional authenticated data (AAD) - must match encryption
    #[serde(default)]
    pub aad: Option<String>,
}

/// Decryption response with plaintext
#[derive(Debug, Serialize, ToSchema)]
pub struct DecryptResponse {
    /// Base64-encoded decrypted plaintext
    pub plaintext: String,
}

/// Sign data using an asymmetric key (Ed25519 or SM2)
#[derive(Debug, Deserialize, ToSchema)]
pub struct SignRequest {
    /// Base64-encoded data to sign
    pub data: String,
}

/// Signature response
#[derive(Debug, Serialize, ToSchema)]
pub struct SignResponse {
    /// Base64-encoded signature
    pub signature: String,
    /// Version of the key used for signing
    pub version: u32,
}

/// Verify a signature
#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyRequest {
    /// Base64-encoded data that was signed
    pub data: String,
    /// Base64-encoded signature to verify
    pub signature: String,
}

/// Verification response
#[derive(Debug, Serialize, ToSchema)]
pub struct VerifyResponse {
    /// Whether the signature is valid
    pub valid: bool,
}

/// Compute cryptographic hash of data
#[derive(Debug, Deserialize, ToSchema)]
pub struct HashRequest {
    /// Base64-encoded data to hash
    pub data: String,
    /// Hash algorithm: "sm3" (GM standard) or "sha256"
    pub algorithm: String,
}

/// Hash computation response
#[derive(Debug, Serialize, ToSchema)]
pub struct HashResponse {
    /// Hex-encoded hash output
    pub hash: String,
    /// Algorithm used for hashing
    pub algorithm: String,
}

// Policy types

/// Create a PBAC policy for access control
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePolicyRequest {
    /// Unique policy name
    pub name: String,
    /// Policy effect: "allow" or "deny"
    pub effect: String,
    /// JSON-encoded condition expression (e.g., {"ip_eq": ["10.0.0.0/8"]})
    pub condition: serde_json::Value,
    /// List of resource patterns (e.g., ["keys/*", "policies/*"])
    pub resources: Vec<String>,
    /// List of subject patterns (e.g., ["user:*", "service:api"])
    pub subjects: Vec<String>,
    /// Whether the policy is active
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Serialize, ToSchema)]
/// PBAC policy response
pub struct PolicyResponse {
    /// Unique policy identifier (UUID)
    pub id: String,
    /// Human-readable policy name
    pub name: String,
    /// Policy effect: "allow" or "deny"
    pub effect: String,
    /// JSON-encoded condition expression
    pub condition: serde_json::Value,
    /// List of resource patterns
    pub resources: Vec<String>,
    /// List of subject patterns
    pub subjects: Vec<String>,
    /// Whether the policy is active
    pub enabled: bool,
}

// SM9 Identity-Based Cryptography types
#[derive(Debug, Deserialize, ToSchema)]
pub struct Sm9SignRequest {
    pub identity: String, // User identity (e.g., "user@example.com")
    pub data: String,     // base64 encoded data to sign
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Sm9SignResponse {
    pub w: String, // base64 encoded first signature component
    pub h: String, // hex encoded second component
    pub s: String, // base64 encoded third signature component
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct Sm9VerifyRequest {
    pub identity: String, // Signer identity
    pub data: String,     // base64 encoded original data
    pub w: String,        // base64 encoded first signature component
    pub h: String,        // hex encoded second component
    pub s: String,        // base64 encoded third signature component
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Sm9VerifyResponse {
    pub valid: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct Sm9EncryptRequest {
    pub identity: String,  // Recipient identity
    pub plaintext: String, // base64 encoded plaintext
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Sm9EncryptResponse {
    pub c1: String, // base64 encoded ciphertext component 1
    pub c2: String, // base64 encoded ciphertext component 2
    pub c3: String, // hex encoded ciphertext component 3
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct Sm9DecryptRequest {
    pub identity: String, // Recipient identity
    pub c1: String,       // base64 encoded ciphertext component 1
    pub c2: String,       // base64 encoded ciphertext component 2
    pub c3: String,       // hex encoded ciphertext component 3
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Sm9DecryptResponse {
    pub plaintext: String, // base64 encoded decrypted plaintext
}

// Tenant query parameter for request tracking
#[derive(Debug, Deserialize, ToSchema)]
pub struct TenantQuery {
    #[serde(default = "default_tenant_id")]
    pub tenant_id: String,
    /// Approval request ID (required for key deletion per GM/T 0028-2014 dual-control)
    #[serde(default)]
    pub approval_id: Option<String>,
}

// Envelope encryption types

/// Envelope encryption request - encrypts data using DEK wrapped with KEK
#[derive(Debug, Deserialize, ToSchema)]
pub struct EnvelopeEncryptRequest {
    /// Base64-encoded plaintext data to encrypt
    pub plaintext: String,
    /// KEK key ID for wrapping DEK
    pub kek_id: String,
    /// Optional: custom DEK length in bytes (default 32 for AES-256)
    #[serde(default)]
    pub dek_length: Option<usize>,
    /// Tenant ID for multi-tenant key isolation
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// Envelope encryption response
#[derive(Debug, Serialize, ToSchema)]
pub struct EnvelopeEncryptResponse {
    /// Base64-encoded wrapped DEK (DEK encrypted with KEK)
    pub wrapped_dek: String,
    /// Base64-encoded DEK nonce
    pub dek_nonce: String,
    /// Base64-encoded ciphertext (data encrypted with DEK)
    pub ciphertext: String,
    /// Base64-encoded data nonce
    pub data_nonce: String,
    /// Base64-encoded authentication tag
    pub tag: String,
    /// KEK version used
    pub kek_version: u32,
}

/// Envelope decryption request
#[derive(Debug, Deserialize, ToSchema)]
pub struct EnvelopeDecryptRequest {
    /// Base64-encoded wrapped DEK
    pub wrapped_dek: String,
    /// Base64-encoded DEK nonce
    pub dek_nonce: String,
    /// Base64-encoded ciphertext
    pub ciphertext: String,
    /// Base64-encoded data nonce
    pub data_nonce: String,
    /// Base64-encoded authentication tag
    pub tag: String,
    /// KEK key ID for unwrapping DEK
    pub kek_id: String,
    /// KEK version used for encryption (to ensure correct KEK version is used)
    pub kek_version: u32,
    /// Tenant ID for multi-tenant key isolation
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// Envelope decryption response
#[derive(Debug, Serialize, ToSchema)]
pub struct EnvelopeDecryptResponse {
    /// Base64-encoded decrypted plaintext
    pub plaintext: String,
}

/// DEK rewrap request (migrate DEK from old KEK version to current)
#[derive(Debug, Deserialize, ToSchema)]
pub struct EnvelopeRewrapRequest {
    /// Base64-encoded wrapped DEK (encrypted with old KEK version)
    pub wrapped_dek: String,
    /// Base64-encoded DEK nonce (from original encryption)
    pub dek_nonce: String,
    /// KEK key ID
    pub kek_id: String,
    /// Old KEK version used when DEK was originally wrapped
    pub old_kek_version: u32,
    /// Tenant ID for multi-tenant key isolation
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// DEK rewrap response
#[derive(Debug, Serialize, ToSchema)]
pub struct EnvelopeRewrapResponse {
    /// Base64-encoded rewrapped DEK (encrypted with current KEK version)
    pub wrapped_dek: String,
    /// Base64-encoded new DEK nonce
    pub dek_nonce: String,
    /// Current KEK version used for rewrapping
    pub kek_version: u32,
    /// Old KEK version from which the DEK was migrated
    pub old_kek_version: u32,
}

/// DH key derivation request
#[derive(Debug, Deserialize, ToSchema)]
pub struct DhDeriveRequest {
    /// Key ID of our private key to use for DH
    pub key_id: String,
    /// DH algorithm: "ECDH-P256", "ECDH-P384", "X25519", "SM2-KEX"
    pub algorithm: String,
    /// Base64-encoded peer's public key
    pub peer_public_key: String,
}

/// DH key derivation response
#[derive(Debug, Serialize, ToSchema)]
pub struct DhDeriveResponse {
    /// Base64-encoded derived shared secret
    pub shared_secret: String,
    /// Key derivation function used
    pub kdf: String,
}

/// SM2-KEX session role
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Sm2KexRole {
    /// Initiator (Party A)
    Initiator,
    /// Responder (Party B)
    Responder,
}

/// Create a new SM2-KEX session
#[derive(Debug, Deserialize, ToSchema)]
pub struct Sm2KexCreateSessionRequest {
    /// Key ID of our SM2 private key
    pub key_id: String,
    /// Our user ID (up to 16 bytes)
    pub user_id: String,
    /// Session role: "initiator" or "responder"
    pub role: Sm2KexRole,
    /// For responder: Base64-encoded first message from initiator (msg1)
    #[serde(default)]
    pub initiator_message: Option<String>,
    /// For responder: Base64-encoded peer's (initiator's) long-term public key for signature verification
    #[serde(default)]
    pub peer_public_key: Option<String>,
}

/// SM2-KEX message structure
#[derive(Debug, Serialize, ToSchema)]
pub struct Sm2KexMessageResponse {
    /// Session ID
    pub session_id: String,
    /// Message type: 1 (initiator→responder), 2 (responder→initiator), 3 (initiator→responder confirmation)
    pub msg_type: u8,
    /// Sender user ID (hex encoded)
    pub sender_id: String,
    /// Ephemeral public key R (Base64 encoded, 64 bytes for msg_type 1 and 2)
    pub r_pub: String,
    /// Signature (Base64 encoded, 64 bytes, for msg_type 2 only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Confirmation value SA/SB (Base64 encoded, 32 bytes, for msg_type 3 only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<String>,
}

/// SM2-KEX session result
#[derive(Debug, Serialize, ToSchema)]
pub struct Sm2KexResultResponse {
    /// Session ID
    pub session_id: String,
    /// Shared secret K (32 bytes, Base64 encoded)
    pub shared_secret: String,
    /// Session key for subsequent communication (32 bytes, Base64 encoded)
    pub session_key: String,
    /// Confirmation value S (32 bytes, Base64 encoded)
    pub s: String,
}

// Key import/export types

/// Import an external key into the KMS
#[derive(Debug, Deserialize, ToSchema)]
pub struct ImportKeyRequest {
    /// Unique name for the key within the tenant
    pub name: String,
    /// Key specification: "aes-256-gcm", "ed25519", "sm2", "sm4"
    pub spec: String,
    /// Key format: "pkcs8", "jwk", "raw"
    #[serde(default = "default_key_format")]
    pub format: String,
    /// Base64-encoded wrapped key (key material encrypted with transport key)
    pub wrapped_key: String,
    /// Base64-encoded encrypted transport key (transport key encrypted with KMS public key)
    pub encrypted_transport_key: String,
    /// SHA-256 fingerprint of source key for integrity verification
    pub source_fingerprint: String,
    /// Tenant ID for multi-tenancy isolation
    #[serde(default = "default_tenant_id")]
    pub tenant_id: String,
}

fn default_key_format() -> String {
    "pkcs8".to_string()
}

/// Response after successfully importing a key
#[derive(Debug, Serialize, ToSchema)]
pub struct ImportKeyResponse {
    /// Unique key identifier (UUID)
    pub id: String,
    /// Key specification
    pub spec: String,
    /// Whether the key was imported (true) or generated (false)
    pub imported: bool,
    /// Source fingerprint for audit trail
    pub source_fingerprint: String,
}

/// Request to export a key (requires approval in production)
#[derive(Debug, Deserialize, ToSchema)]
pub struct ExportKeyRequest {
    /// Target system identifier for audit
    pub target_system: String,
    /// Base64-encoded target system's public key for encrypting transport key
    pub target_public_key: String,
    /// Purpose of the export (migration, backup, etc.)
    pub purpose: String,
    /// ID of a pre-approved approval request for this key export.
    /// Key export requires an approved `KeyExport` approval request.
    pub approval_id: Option<String>,
}

/// Response containing wrapped key for secure export
#[derive(Debug, Serialize, ToSchema)]
pub struct ExportKeyResponse {
    /// Base64-encoded wrapped key (key encrypted with transport key)
    pub wrapped_key: String,
    /// Base64-encoded encrypted transport key
    pub encrypted_transport_key: String,
    /// SHA-256 fingerprint of the key
    pub key_fingerprint: String,
    /// Unique export identifier
    pub export_id: String,
    /// ISO 8601 expiration timestamp
    pub expires_at: String,
}

// ── Permission middleware helpers ──────────────────────────────────────

use crate::auth::Permission;

macro_rules! auth_layer {
    ($perm:expr) => {
        axum::middleware::from_fn(|req, next| async move {
            crate::auth::require_permission($perm, req, next).await
        })
    };
}

// REST routes with per-route permission enforcement (三员分立)
pub fn create_routes(state: Arc<KmsState>, api_key_config: ApiKeyConfig) -> Router {
    let config = Extension(Arc::new(api_key_config));

    // Read routes: any role with LIST_KEYS
    let read_routes = Router::new()
        .route("/v1/keys", get(list_keys))
        .route("/v1/keys/{id}", get(get_key))
        .route_layer(auth_layer!(Permission::LIST_KEYS));

    // Crypto routes: roles with ENCRYPT (Operator, KeyAdmin)
    // Note: all roles that have any crypto perm have ALL crypto perms
    let crypto_routes = Router::new()
        .route("/v1/keys/{id}/encrypt", post(encrypt))
        .route("/v1/keys/{id}/decrypt", post(decrypt))
        .route("/v1/keys/{id}/sign", post(sign))
        .route("/v1/keys/{id}/verify", post(verify))
        .route("/v1/hash", post(hash))
        .route("/v1/sm9/sign", post(sm9_sign))
        .route("/v1/sm9/verify", post(sm9_verify))
        .route("/v1/sm9/encrypt", post(sm9_encrypt))
        .route("/v1/sm9/decrypt", post(sm9_decrypt))
        .route("/v1/envelope/encrypt", post(envelope_encrypt))
        .route("/v1/envelope/decrypt", post(envelope_decrypt))
        .route("/v1/envelope/rewrap", post(envelope_rewrap))
        .route("/v1/dh/derive", post(dh_derive))
        .route_layer(auth_layer!(Permission::ENCRYPT));

    // Key lifecycle routes: KeyAdmin only
    let key_lifecycle_routes = Router::new()
        .route("/v1/keys", post(create_key))
        .route("/v1/keys/{id}/rotate", post(rotate_key))
        .route("/v1/keys/{id}", delete(delete_key))
        .route("/v1/keys/import", post(import_key))
        .route("/v1/keys/export/{id}", post(export_key))
        .route_layer(auth_layer!(Permission::CREATE_KEY));

    // Policy routes: SecurityOfficer only
    let policy_routes = Router::new()
        .route("/v1/policies", post(create_policy))
        .route("/v1/policies", get(list_policies))
        .route("/v1/policies/{id}", get(get_policy))
        .route_layer(auth_layer!(Permission::MANAGE_POLICY));

    // Audit routes: SecurityOfficer or AuditAdmin
    let audit_routes = Router::new()
        .route("/v1/audit/events", get(query_audit_events))
        .route_layer(auth_layer!(Permission::VIEW_AUDIT));

    // MFA routes: SecurityOfficer only
    let mfa_routes = Router::new()
        .route("/v1/mfa/setup/{user_id}", post(mfa_setup))
        .route("/v1/mfa/verify/{user_id}", post(mfa_verify))
        .route("/v1/mfa/backup/{user_id}", post(mfa_verify_backup))
        .route("/v1/mfa/status/{user_id}", get(mfa_status))
        .route_layer(auth_layer!(Permission::MANAGE_MFA));

    // Approval admin routes: SecurityOfficer only
    let approval_admin_routes = Router::new()
        .route(
            "/v1/approvals/pending/{tenant_id}",
            get(list_pending_approvals),
        )
        .route("/v1/approvals/{request_id}/approve", post(approve_request))
        .route("/v1/approvals/{request_id}/reject", post(reject_request))
        .route_layer(auth_layer!(Permission::APPROVE_ACTION));

    // Approval user routes: any authenticated role
    let approval_user_routes = Router::new()
        .route("/v1/approvals", post(create_approval_request))
        .route("/v1/approvals/{request_id}", get(get_approval_request))
        .route("/v1/approvals/{request_id}/cancel", post(cancel_request))
        .route_layer(auth_layer!(Permission::AUTHENTICATED));

    // Metrics routes: any valid API key (Permission::empty() short-circuits to true)
    let metrics_routes = Router::new()
        .route("/v1/metrics", get(metrics))
        .route_layer(auth_layer!(Permission::empty()));

    // Merge all protected routes
    let mut protected = Router::new()
        .merge(read_routes)
        .merge(crypto_routes)
        .merge(key_lifecycle_routes)
        .merge(policy_routes)
        .merge(audit_routes)
        .merge(mfa_routes)
        .merge(approval_admin_routes)
        .merge(approval_user_routes)
        .merge(metrics_routes)
        .layer(from_fn(
            crate::security_headers::security_headers_middleware,
        ))
        .layer(config);

    // Apply rate limiting if available
    if let Some(ref limiter) = state.rate_limiter {
        let rate_limit =
            from_fn_with_state(limiter.clone(), crate::ratelimit::rate_limit_middleware);
        protected = protected.layer(rate_limit);
    }

    // Tenant extraction middleware — runs first (innermost), before rate limiter and auth.
    // Extracts tenant_id from query params and sets TenantId in request extensions.
    protected = protected.layer(from_fn(crate::ratelimit::tenant_extraction_middleware));

    // Public routes - no auth required
    let swagger = SwaggerUi::new("/swagger-ui").url("/swagger/openapi.json", ApiDoc::openapi());

    let public = Router::new()
        .route("/v1/health", get(health_check))
        // Kubernetes probe endpoints
        .route("/healthz", get(liveness_probe))
        .route("/readyz", get(readiness_probe))
        .merge(swagger);

    protected.merge(public).with_state(state)
}

async fn create_key(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Json(req): Json<CreateKeyRequest>,
) -> Result<(StatusCode, Json<KeyResponse>)> {
    // Validate input
    if let Err(e) = validate_create_key_request(&req.name, &req.spec, &req.tenant_id) {
        return Err(ApiError::InvalidRequest(e.message()));
    }

    // PBAC evaluation
    use crate::auth::check_rest_pbac;
    check_rest_pbac(&state.policy_engine, &caller_id, "create_key", &req.name)
        .await
        .map_err(|_| ApiError::PermissionDenied)?;

    let spec = KeyService::parse_spec(&req.spec)?;

    let key_svc = state.key_service();
    let meta = key_svc
        .create_key(spec, &req.name, &req.tenant_id, &caller_id)
        .await?;

    state.metrics.record_key_created();

    // Backup key material (best-effort, failure is logged but not returned)
    if let Some(ref bs) = state.backup_service {
        match state
            .keystore
            .get_key_material(&meta.id, &req.tenant_id)
            .await
        {
            Ok(material) => {
                if let Err(e) = bs.backup_key(&meta, &material, Some(req.name.clone())) {
                    tracing::error!("Failed to backup key {}: {}", meta.id, e);
                } else {
                    tracing::info!("Key material backed up: {}", meta.id);
                }
            }
            Err(e) => {
                tracing::error!(
                    "Failed to retrieve key material for backup {}: {}",
                    meta.id,
                    e
                );
            }
        }
    }

    // Log audit event
    let event = kms_core::event::Event::key_created(&meta.id, &caller_id, &req.spec);
    state.audit_logger.log_event(&event).await;

    Ok((StatusCode::CREATED, Json(KeyResponse::from(meta))))
}

async fn get_key(
    State(state): State<Arc<KmsState>>,
    Path(id): Path<Uuid>,
    Query(tenant_query): Query<TenantQuery>,
) -> Result<Json<KeyResponse>> {
    let tenant_id = &tenant_query.tenant_id;
    let key_svc = state.key_service();
    let meta = key_svc.get_key(&id, tenant_id).await?;

    Ok(Json(KeyResponse::from(meta)))
}

async fn list_keys(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Query(tenant_query): Query<TenantQuery>,
) -> Result<Json<Vec<KeyResponse>>> {
    // PBAC evaluation
    use crate::auth::check_rest_pbac;
    check_rest_pbac(&state.policy_engine, &caller_id, "list_keys", "keys")
        .await
        .map_err(|_| ApiError::PermissionDenied)?;
    let tenant_id = &tenant_query.tenant_id;
    let key_svc = state.key_service();
    let keys = key_svc.list_keys(KeyFilter::default(), tenant_id).await?;

    let response: Vec<KeyResponse> = keys.into_iter().map(KeyResponse::from).collect();
    Ok(Json(response))
}

async fn encrypt(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Path(id): Path<Uuid>,
    Query(tenant_query): Query<TenantQuery>,
    Json(req): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    // PBAC evaluation
    use crate::auth::check_rest_pbac;
    check_rest_pbac(&state.policy_engine, &caller_id, "encrypt", &id.to_string())
        .await
        .map_err(|_| ApiError::PermissionDenied)?;

    let tenant_id = &tenant_query.tenant_id;

    // Validate input
    if let Err(e) = validate_encrypt_request(&req.plaintext, &req.aad) {
        return Err(ApiError::InvalidRequest(e.message()));
    }

    let plaintext = STANDARD
        .decode(&req.plaintext)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 plaintext".to_string()))?;

    // Use CryptoService for encryption
    let crypto = state.crypto_service();
    let ciphertext = crypto
        .encrypt(
            &id,
            &plaintext,
            req.aad.as_ref().map(|s| s.as_bytes()),
            tenant_id,
            &caller_id,
        )
        .await?;

    // Log audit event
    let event = kms_core::event::Event::key_encrypted(&id, &caller_id, plaintext.len());
    state.audit_logger.log_event(&event).await;

    Ok(Json(EncryptResponse {
        ciphertext: STANDARD.encode(&ciphertext.ciphertext),
        nonce: STANDARD.encode(&ciphertext.nonce),
        tag: STANDARD.encode(&ciphertext.tag),
    }))
}

async fn decrypt(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Path(id): Path<Uuid>,
    Query(tenant_query): Query<TenantQuery>,
    Json(req): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    // PBAC evaluation
    use crate::auth::check_rest_pbac;
    check_rest_pbac(&state.policy_engine, &caller_id, "decrypt", &id.to_string())
        .await
        .map_err(|_| ApiError::PermissionDenied)?;

    let tenant_id = &tenant_query.tenant_id;

    // Validate input
    if let Err(e) = validate_decrypt_request(&req.ciphertext, &req.nonce, &req.tag, &req.aad) {
        return Err(ApiError::InvalidRequest(e.message()));
    }

    let ciphertext = kms_core::key::Ciphertext {
        key_id: id,
        version: 1,
        format_version: 0, // Legacy format
        nonce: STANDARD
            .decode(&req.nonce)
            .map_err(|_| ApiError::InvalidRequest("invalid base64 nonce".to_string()))?,
        ciphertext: STANDARD
            .decode(&req.ciphertext)
            .map_err(|_| ApiError::InvalidRequest("invalid base64 ciphertext".to_string()))?,
        tag: STANDARD
            .decode(&req.tag)
            .map_err(|_| ApiError::InvalidRequest("invalid base64 tag".to_string()))?,
    };

    let crypto = state.crypto_service();
    let plaintext = crypto
        .decrypt(
            &id,
            &ciphertext,
            req.aad.as_ref().map(|s| s.as_bytes()),
            tenant_id,
            &caller_id,
        )
        .await?;

    // Log audit event
    let event = kms_core::event::Event::key_decrypted(&id, &caller_id, plaintext.len());
    state.audit_logger.log_event(&event).await;

    Ok(Json(DecryptResponse {
        plaintext: STANDARD.encode(&plaintext),
    }))
}

async fn rotate_key(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Path(id): Path<Uuid>,
    Query(tenant_query): Query<TenantQuery>,
) -> Result<Json<KeyResponse>> {
    // PBAC evaluation
    use crate::auth::check_rest_pbac;
    check_rest_pbac(
        &state.policy_engine,
        &caller_id,
        "rotate_key",
        &id.to_string(),
    )
    .await
    .map_err(|_| ApiError::PermissionDenied)?;

    let tenant_id = &tenant_query.tenant_id;

    let key_svc = state.key_service();
    let meta = key_svc.rotate_key(&id, tenant_id, &caller_id).await?;

    state.metrics.record_key_obsoleted();

    // Log audit event
    let event = kms_core::event::Event::key_rotated(&id, &caller_id);
    state.audit_logger.log_event(&event).await;

    Ok(Json(KeyResponse::from(meta)))
}

async fn delete_key(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Path(id): Path<Uuid>,
    Query(tenant_query): Query<TenantQuery>,
) -> Result<StatusCode> {
    // PBAC evaluation
    use crate::auth::check_rest_pbac;
    check_rest_pbac(
        &state.policy_engine,
        &caller_id,
        "delete_key",
        &id.to_string(),
    )
    .await
    .map_err(|_| ApiError::PermissionDenied)?;

    // Security: enforce dual-control approval for key deletion
    use kms_approval::OperationType;
    let approval_id = match &tenant_query.approval_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            tracing::warn!(key_id = %id, caller = %caller_id, "key deletion rejected: no approval_id");
            return Err(ApiError::InvalidRequest(
                "key deletion requires an approved DeleteKey request. Create one via POST /v1/approvals first".to_string(),
            ));
        }
    };
    let approval_uuid = uuid::Uuid::parse_str(&approval_id)
        .map_err(|_| ApiError::InvalidRequest("invalid approval_id format".to_string()))?;
    {
        let guard = state.approval_manager.read();
        if !guard.is_approved(approval_uuid, OperationType::KeyDelete) {
            tracing::warn!(
                key_id = %id,
                approval_id = %approval_id,
                "key deletion rejected: approval not found or not fully approved"
            );
            return Err(ApiError::InvalidRequest(
                "key deletion requires a fully approved DeleteKey request".to_string(),
            ));
        }
    }

    let tenant_id = &tenant_query.tenant_id;

    let key_svc = state.key_service();
    key_svc.delete_key(&id, tenant_id, &caller_id).await?;

    state.metrics.record_key_deleted();

    // Log audit event
    let event = kms_core::event::Event::key_deleted(&id, &caller_id);
    state.audit_logger.log_event(&event).await;

    Ok(StatusCode::NO_CONTENT)
}

async fn sign(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Path(id): Path<Uuid>,
    Query(tenant_query): Query<TenantQuery>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let tenant_id = &tenant_query.tenant_id;

    let data = STANDARD
        .decode(&req.data)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 data".to_string()))?;

    let crypto = state.crypto_service();
    let signature = crypto.sign(&id, &data, tenant_id, &caller_id).await?;

    // Log audit event
    let event = kms_core::event::Event::key_signed(&id, &caller_id);
    state.audit_logger.log_event(&event).await;

    Ok(Json(SignResponse {
        signature: STANDARD.encode(&signature.signature),
        version: signature.version,
    }))
}

async fn verify(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Path(id): Path<Uuid>,
    Query(tenant_query): Query<TenantQuery>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let tenant_id = &tenant_query.tenant_id;

    let data = STANDARD
        .decode(&req.data)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 data".to_string()))?;

    let signature_bytes = STANDARD
        .decode(&req.signature)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 signature".to_string()))?;

    let signature = kms_core::key::Signature {
        key_id: id,
        version: 1,
        signature: signature_bytes,
    };

    let crypto = state.crypto_service();
    let valid = crypto.verify(&id, &data, &signature, tenant_id).await?;

    // Log audit event
    let event = kms_core::event::Event::key_verified(&id, &caller_id, valid);
    state.audit_logger.log_event(&event).await;

    Ok(Json(VerifyResponse { valid }))
}

async fn hash(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Json(req): Json<HashRequest>,
) -> Result<Json<HashResponse>> {
    use crate::auth::check_rest_pbac;
    check_rest_pbac(&state.policy_engine, &caller_id, "hash", "hash")
        .await
        .map_err(|_| ApiError::PermissionDenied)?;

    use base64::{Engine, engine::general_purpose::STANDARD};

    let data = STANDARD
        .decode(&req.data)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 data".to_string()))?;

    let hash_hex = match req.algorithm.to_lowercase().as_str() {
        "sm3" => {
            use gm_crypto::sm3::Sm3Hasher;
            let hash_result = Sm3Hasher::hash(&data)
                .map_err(|e: gm_crypto::CryptoError| ApiError::Internal(e.to_string()))?;
            hex::encode(hash_result)
        }
        "sha256" => {
            use ring::digest;
            hex::encode(digest::digest(&digest::SHA256, &data).as_ref())
        }
        _ => {
            return Err(ApiError::InvalidRequest(format!(
                "unsupported hash algorithm: {}",
                req.algorithm
            )));
        }
    };

    // Log audit event
    let event = kms_core::event::Event::new(
        kms_core::event::EventType::KeyAccessed,
        &caller_id,
        "user",
        "hash",
        "crypto",
        None,
        "success",
    );
    state.audit_logger.log_event(&event).await;

    Ok(Json(HashResponse {
        hash: hash_hex,
        algorithm: req.algorithm.to_lowercase(),
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub components: ComponentHealth,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ComponentHealth {
    pub keystore: String,
    pub audit: String,
}

async fn health_check(State(state): State<Arc<KmsState>>) -> Result<Json<HealthResponse>> {
    let keystore_status = match state.keystore.health().await {
        Ok(kms_core::types::HealthStatus::Healthy) => "healthy".to_string(),
        Ok(kms_core::types::HealthStatus::Degraded) => "degraded".to_string(),
        Ok(kms_core::types::HealthStatus::Unhealthy) => "unhealthy".to_string(),
        Ok(kms_core::types::HealthStatus::Unknown) => "unknown".to_string(),
        Err(_) => "error".to_string(),
    };

    // Audit logger is always healthy if server is running
    let audit_status = "healthy".to_string();

    let overall_status = if keystore_status == "healthy" && audit_status == "healthy" {
        "ok"
    } else if keystore_status == "degraded" || audit_status == "error" {
        "degraded"
    } else {
        "error"
    };

    Ok(Json(HealthResponse {
        status: overall_status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        components: ComponentHealth {
            keystore: keystore_status,
            audit: audit_status,
        },
    }))
}

/// Kubernetes liveness probe endpoint
///
/// Returns 200 OK if the service is alive.
/// This is used by Kubernetes to determine if the container should be restarted.
async fn liveness_probe() -> StatusCode {
    StatusCode::OK
}

/// Kubernetes readiness probe endpoint
///
/// Returns 200 OK if the service is ready to handle traffic.
/// Checks keystore health as a proxy for overall service readiness.
async fn readiness_probe(State(state): State<Arc<KmsState>>) -> StatusCode {
    // Check if keystore is healthy
    match state.keystore.health().await {
        Ok(kms_core::types::HealthStatus::Healthy) => StatusCode::OK,
        Ok(kms_core::types::HealthStatus::Degraded) => {
            // Degraded is still ready (can handle traffic with limited functionality)
            StatusCode::OK
        }
        Ok(kms_core::types::HealthStatus::Unhealthy) => {
            // Unhealthy - not ready
            StatusCode::SERVICE_UNAVAILABLE
        }
        Ok(kms_core::types::HealthStatus::Unknown) => {
            // Unknown - assume not ready
            StatusCode::SERVICE_UNAVAILABLE
        }
        Err(_) => {
            // Error - not ready
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

/// Prometheus metrics endpoint
///
/// Returns metrics in Prometheus text format for scraping.
/// Metrics include key operations counters, error rates, audit backlog,
/// TSA status, and PBAC counters.
///
/// Requires a valid API key (any permission level).
/// Each access is logged as an audit event.
async fn metrics(State(state): State<Arc<KmsState>>) -> String {
    // Log metrics access for audit trail
    let event = kms_core::event::Event::new(
        kms_core::event::EventType::KeyAccessed,
        "metrics",
        "system",
        "metrics_accessed",
        "observability",
        None,
        "success",
    );
    state.audit_logger.log_event(&event).await;

    // Collect audit backlog depth (live query from the audit logger buffer)
    let backlog = state.audit_logger.backlog_depth().await;
    state.metrics.set_audit_backlog(backlog);

    let m = state.metrics.as_ref();

    format!(
        r#"# HELP kms_key_operations_total Total number of key operations
# TYPE kms_key_operations_total counter
kms_key_operations_total {}

# HELP kms_key_create_total Number of keys created
# TYPE kms_key_create_total counter
kms_key_create_total {}

# HELP kms_key_encrypt_total Number of encrypt operations
# TYPE kms_key_encrypt_total counter
kms_key_encrypt_total {}

# HELP kms_key_decrypt_total Number of decrypt operations
# TYPE kms_key_decrypt_total counter
kms_key_decrypt_total {}

# HELP kms_key_sign_total Number of sign operations
# TYPE kms_key_sign_total counter
kms_key_sign_total {}

# HELP kms_key_verify_total Number of verify operations
# TYPE kms_key_verify_total counter
kms_key_verify_total {}

# HELP kms_key_rotate_total Number of key rotations
# TYPE kms_key_rotate_total counter
kms_key_rotate_total {}

# HELP kms_key_delete_total Number of key deletions
# TYPE kms_key_delete_total counter
kms_key_delete_total {}

# HELP kms_key_export_total Number of key export operations
# TYPE kms_key_export_total counter
kms_key_export_total {}

# HELP kms_key_errors_total Total number of key operation errors
# TYPE kms_key_errors_total counter
kms_key_errors_total {}

# HELP kms_rate_limit_hits_total Total number of rate limit hits
# TYPE kms_rate_limit_hits_total counter
kms_rate_limit_hits_total {}

# HELP kms_quota_exceeded_total Total number of quota exceeded events
# TYPE kms_quota_exceeded_total counter
kms_quota_exceeded_total {}

# HELP kms_active_tenants_total Total number of active tenants
# TYPE kms_active_tenants_total counter
kms_active_tenants_total {}

# HELP kms_audit_backlog_depth Current audit log buffer depth (un-flushed events)
# TYPE kms_audit_backlog_depth gauge
kms_audit_backlog_depth {}

# HELP kms_tsa_requests_total Total number of TSA requests
# TYPE kms_tsa_requests_total counter
kms_tsa_requests_total {}

# HELP kms_tsa_successes_total Total number of successful TSA requests
# TYPE kms_tsa_successes_total counter
kms_tsa_successes_total {}

# HELP kms_tsa_failures_total Total number of failed TSA requests
# TYPE kms_tsa_failures_total counter
kms_tsa_failures_total {}

# HELP kms_tsa_time_drift_seconds Time drift between local clock and TSA (seconds)
# TYPE kms_tsa_time_drift_seconds gauge
kms_tsa_time_drift_seconds {}

# HELP kms_pbac_policy_count_total Total number of configured PBAC policies
# TYPE kms_pbac_policy_count_total gauge
kms_pbac_policy_count_total {}

# HELP kms_pbac_evaluation_allow_total PBAC evaluations resulting in allow
# TYPE kms_pbac_evaluation_allow_total counter
kms_pbac_evaluation_allow_total {}

# HELP kms_pbac_evaluation_deny_total PBAC evaluations resulting in deny
# TYPE kms_pbac_evaluation_deny_total counter
kms_pbac_evaluation_deny_total {}

# HELP kms_keys_by_status_active Number of keys currently active
# TYPE kms_keys_by_status_active gauge
kms_keys_by_status_active {}

# HELP kms_keys_by_status_pending_deletion Number of keys pending deletion
# TYPE kms_keys_by_status_pending_deletion gauge
kms_keys_by_status_pending_deletion {}

# HELP kms_keys_by_status_obsolete Number of obsoleted keys
# TYPE kms_keys_by_status_obsolete gauge
kms_keys_by_status_obsolete {}

# HELP kms_keys_by_status_destroyed Number of destroyed keys
# TYPE kms_keys_by_status_destroyed gauge
kms_keys_by_status_destroyed {}

# HELP kms_key_destroyed_total Total number of key destructions
# TYPE kms_key_destroyed_total counter
kms_key_destroyed_total {}

# HELP kms_key_expiry_soon_total Number of keys expiring within 7 days
# TYPE kms_key_expiry_soon_total counter
kms_key_expiry_soon_total {}

# HELP kms_rotation_attempts_total Total rotation check attempts
# TYPE kms_rotation_attempts_total counter
kms_rotation_attempts_total {}

# HELP kms_rotation_failures_total Total rotation failures
# TYPE kms_rotation_failures_total counter
kms_rotation_failures_total {}

# HELP kms_mfa_attempts_total Total MFA verification attempts
# TYPE kms_mfa_attempts_total counter
kms_mfa_attempts_total {}

# HELP kms_mfa_failures_total Total MFA verification failures
# TYPE kms_mfa_failures_total counter
kms_mfa_failures_total {}

# HELP kms_mfa_lockouts_total Total MFA lockout events
# TYPE kms_mfa_lockouts_total counter
kms_mfa_lockouts_total {}

# HELP kms_mlock_failures_total Total mlock failures (memory protection)
# TYPE kms_mlock_failures_total counter
kms_mlock_failures_total {}

# HELP kms_tpm_health_status TPM health: 0=healthy 1=degraded 2=unhealthy 3=unknown
# TYPE kms_tpm_health_status gauge
kms_tpm_health_status {}

# HELP kms_kgc_key_generation_total Total KGC key generations
# TYPE kms_kgc_key_generation_total counter
kms_kgc_key_generation_total {}

# HELP kms_kgc_master_key_loaded Whether KGC master key is loaded (1=true, 0=false)
# TYPE kms_kgc_master_key_loaded gauge
kms_kgc_master_key_loaded {}

# HELP kms_feature_config_mismatch Feature flag/config mismatch detected
# TYPE kms_feature_config_mismatch gauge
kms_feature_config_mismatch {}

# HELP kms_health_status Aggregated health: 0=healthy 1=degraded 2=unhealthy 3=unknown
# TYPE kms_health_status gauge
kms_health_status {}

# HELP kms_client_clock_skew_seconds Client clock skew in seconds
# TYPE kms_client_clock_skew_seconds counter
kms_client_clock_skew_seconds {}

# HELP kms_key_access_bucket_0 Number of keys with 0 accesses in last interval
# TYPE kms_key_access_bucket_0 gauge
kms_key_access_bucket_0 {}

# HELP kms_key_access_bucket_1_10 Number of keys with 1-10 accesses in last interval
# TYPE kms_key_access_bucket_1_10 gauge
kms_key_access_bucket_1_10 {}

# HELP kms_key_access_bucket_11_100 Number of keys with 11-100 accesses in last interval
# TYPE kms_key_access_bucket_11_100 gauge
kms_key_access_bucket_11_100 {}

# HELP kms_key_access_bucket_100_plus Number of keys with 100+ accesses in last interval
# TYPE kms_key_access_bucket_100_plus gauge
kms_key_access_bucket_100_plus {}

# HELP kms_encrypt_decrypt_ratio Permille ratio of encrypt to decrypt operations (x1000)
# TYPE kms_encrypt_decrypt_ratio gauge
kms_encrypt_decrypt_ratio {}

# HELP kms_aes_encrypt_total Total AES-256-GCM encrypt operations
# TYPE kms_aes_encrypt_total counter
kms_aes_encrypt_total {}

# HELP kms_aes_decrypt_total Total AES-256-GCM decrypt operations
# TYPE kms_aes_decrypt_total counter
kms_aes_decrypt_total {}

# HELP kms_sm4_encrypt_total Total SM4 encrypt operations
# TYPE kms_sm4_encrypt_total counter
kms_sm4_encrypt_total {}

# HELP kms_sm4_decrypt_total Total SM4 decrypt operations
# TYPE kms_sm4_decrypt_total counter
kms_sm4_decrypt_total {}

# HELP kms_sm2_sign_total Total SM2 sign operations
# TYPE kms_sm2_sign_total counter
kms_sm2_sign_total {}

# HELP kms_sm2_verify_total Total SM2 verify operations
# TYPE kms_sm2_verify_total counter
kms_sm2_verify_total {}

# HELP kms_ed25519_sign_total Total Ed25519 sign operations
# TYPE kms_ed25519_sign_total counter
kms_ed25519_sign_total {}

# HELP kms_ed25519_verify_total Total Ed25519 verify operations
# TYPE kms_ed25519_verify_total counter
kms_ed25519_verify_total {}

# HELP gm_sm9_rs_sign_total Total SM9 sign operations
# TYPE gm_sm9_rs_sign_total counter
gm_sm9_rs_sign_total {}

# HELP gm_sm9_rs_verify_total Total SM9 verify operations
# TYPE gm_sm9_rs_verify_total counter
gm_sm9_rs_verify_total {}

# HELP gm_sm9_rs_encrypt_total Total SM9 encrypt operations
# TYPE gm_sm9_rs_encrypt_total counter
gm_sm9_rs_encrypt_total {}

# HELP gm_sm9_rs_decrypt_total Total SM9 decrypt operations
# TYPE gm_sm9_rs_decrypt_total counter
gm_sm9_rs_decrypt_total {}

# HELP kms_ecdsa_p256_sign_total Total ECDSA P-256 sign operations
# TYPE kms_ecdsa_p256_sign_total counter
kms_ecdsa_p256_sign_total {}

# HELP kms_ecdsa_p384_sign_total Total ECDSA P-384 sign operations
# TYPE kms_ecdsa_p384_sign_total counter
kms_ecdsa_p384_sign_total {}

# HELP kms_backup_attempts_total Total backup attempts
# TYPE kms_backup_attempts_total counter
kms_backup_attempts_total {}

# HELP kms_backup_successes_total Total successful backups
# TYPE kms_backup_successes_total counter
kms_backup_successes_total {}

# HELP kms_backup_failures_total Total failed backups
# TYPE kms_backup_failures_total counter
kms_backup_failures_total {}

# HELP kms_backup_last_success_timestamp Unix timestamp of last successful backup
# TYPE kms_backup_last_success_timestamp gauge
kms_backup_last_success_timestamp {}

# HELP kms_key_storage_bytes_estimated Estimated total key storage in bytes
# TYPE kms_key_storage_bytes_estimated gauge
kms_key_storage_bytes_estimated {}

# HELP kms_key_count_total Total number of keys
# TYPE kms_key_count_total gauge
kms_key_count_total {}

# HELP kms_approval_chain_duration_seconds Cumulative approval chain duration in seconds
# TYPE kms_approval_chain_duration_seconds counter
kms_approval_chain_duration_seconds {}
"#,
        m.key_operations_total.get(),
        m.key_create_total.get(),
        m.key_encrypt_total.get(),
        m.key_decrypt_total.get(),
        m.key_sign_total.get(),
        m.key_verify_total.get(),
        m.key_rotate_total.get(),
        m.key_delete_total.get(),
        m.key_export_total.get(),
        m.key_errors_total.get(),
        m.rate_limit_hits_total.get(),
        m.quota_exceeded_total.get(),
        m.active_tenants.get(),
        m.audit_backlog_depth.get(),
        m.tsa_requests_total.get(),
        m.tsa_successes_total.get(),
        m.tsa_failures_total.get(),
        m.tsa_time_drift_seconds.get(),
        m.pbac_policy_count_total.get(),
        m.pbac_evaluation_allow_total.get(),
        m.pbac_evaluation_deny_total.get(),
        m.keys_by_status_active.get(),
        m.keys_by_status_pending_deletion.get(),
        m.keys_by_status_obsolete.get(),
        m.keys_by_status_destroyed.get(),
        m.key_destroyed_total.get(),
        m.key_expiry_soon_total.get(),
        m.rotation_attempts_total.get(),
        m.rotation_failures_total.get(),
        m.mfa_attempts_total.get(),
        m.mfa_failures_total.get(),
        m.mfa_lockouts_total.get(),
        m.mlock_failures_total.get(),
        m.tpm_health_status.get(),
        m.kgc_key_generation_total.get(),
        m.kgc_master_key_loaded.get(),
        m.feature_config_mismatch.get(),
        m.health_status.get(),
        m.client_clock_skew_seconds.get(),
        m.key_access_bucket_0.get(),
        m.key_access_bucket_1_10.get(),
        m.key_access_bucket_11_100.get(),
        m.key_access_bucket_100_plus.get(),
        m.encrypt_decrypt_ratio.get(),
        m.aes_encrypt_total.get(),
        m.aes_decrypt_total.get(),
        m.sm4_encrypt_total.get(),
        m.sm4_decrypt_total.get(),
        m.sm2_sign_total.get(),
        m.sm2_verify_total.get(),
        m.ed25519_sign_total.get(),
        m.ed25519_verify_total.get(),
        m.sm9_sign_total.get(),
        m.sm9_verify_total.get(),
        m.sm9_encrypt_total.get(),
        m.sm9_decrypt_total.get(),
        m.ecdsa_p256_sign_total.get(),
        m.ecdsa_p384_sign_total.get(),
        m.backup_attempts_total.get(),
        m.backup_successes_total.get(),
        m.backup_failures_total.get(),
        m.backup_last_success_timestamp.get(),
        m.key_storage_bytes_estimated.get(),
        m.key_count_total.get(),
        m.approval_chain_duration_seconds.get(),
    )
}

// =============================================================================
// MFA Handlers
// =============================================================================

#[derive(Debug, Serialize, ToSchema)]
struct MfaSetupResponse {
    secret: String,
    provisioning_uri: String,
    backup_codes: Vec<String>,
}

async fn mfa_setup(
    State(state): State<Arc<KmsState>>,
    Path(user_id): Path<String>,
) -> Result<Json<MfaSetupResponse>> {
    // Generate secret
    let secret = TotpGenerator::generate_secret().map_err(|e| ApiError::Internal(e.to_string()))?;

    let config = TotpConfig {
        secret: secret.clone(),
        time_step: 30,
        digits: 6,
        algorithm: kms_mfa::totp::TotpAlgorithm::Sha1,
        window: 1,
    };

    let generator =
        TotpGenerator::new(config.clone()).map_err(|e| ApiError::Internal(e.to_string()))?;

    let provisioning_uri = generator.get_provisioning_uri(&user_id, "gm-kms");

    // Generate backup codes using OsRng (CSPRNG, not rand::random)
    let backup_codes: Vec<String> = (0..8)
        .map(|_| {
            use rand::Rng;
            let mut buf = [0u8; 4];
            rand::rng().fill_bytes(&mut buf);
            let code = u32::from_be_bytes(buf) % 100_000_000;
            format!("{:08}", code)
        })
        .collect();

    let secret_b32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &secret);

    // Persist config (database + in-memory cache)
    state
        .mfa_manager
        .store_totp_config(&user_id, &config, &backup_codes)
        .await
        .map_err(ApiError::InvalidRequest)?;

    // Log audit event
    let event = kms_core::event::Event::mfa_setup(&user_id, "totp");
    state.audit_logger.log_event(&event).await;

    Ok(Json(MfaSetupResponse {
        secret: secret_b32,
        provisioning_uri,
        backup_codes,
    }))
}

#[derive(Debug, Deserialize)]
struct MfaVerifyRequest {
    code: String,
}

async fn mfa_verify(
    State(state): State<Arc<KmsState>>,
    Extension(caller_id): Extension<CallerId>,
    Extension(api_key_config): Extension<Arc<ApiKeyConfig>>,
    Path(user_id): Path<String>,
    Json(req): Json<MfaVerifyRequest>,
) -> Result<Json<serde_json::Value>> {
    enum MfaVerifyResult {
        Valid,
        Locked { remaining: u64 },
        Invalid { attempts_remaining: u32 },
    }

    let mfa = &state.mfa_manager;

    // Check if locked out
    if mfa.is_locked_out(&user_id).await {
        let remaining = mfa.lockout_remaining_secs(&user_id).await;
        return Err(ApiError::TooManyRequests(format!(
            "Account locked. Try again in {remaining} seconds")));
    }

    let config = mfa
        .load_totp_config(&user_id)
        .await
        .ok_or_else(|| ApiError::NotFound("MFA not configured for user".to_string()))?;

    let generator = TotpGenerator::with_secret(&config.secret)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let valid = generator
        .verify(&req.code)
        .map_err(|e| ApiError::InvalidArgument(e.to_string()))?;

    let result = if valid {
        mfa.clear_failed_attempts(&user_id).await;
        mfa.reset_backup_code_usage(&user_id).await;
        MfaVerifyResult::Valid
    } else {
        let locked = mfa.record_failed_totp_attempt(&user_id).await;
        if locked {
            // H-2: Link MFA lockout to API key lockout
            api_key_config.lock_key_by_id(&caller_id.key_id);
            MfaVerifyResult::Locked {
                remaining: TOTP_LOCKOUT_SECS,
            }
        } else {
            let attempts = mfa.failed_attempt_count(&user_id).await;
            MfaVerifyResult::Invalid {
                attempts_remaining: MAX_TOTP_ATTEMPTS.saturating_sub(attempts),
            }
        }
    };

    match result {
        MfaVerifyResult::Valid => {
            let event = kms_core::event::Event::mfa_verified(&user_id);
            state.audit_logger.log_event(&event).await;
            Ok(Json(serde_json::json!({ "valid": true })))
        }
        MfaVerifyResult::Locked { remaining } => {
            let event = kms_core::event::Event::mfa_failed(&user_id, "account_locked");
            state.audit_logger.log_event(&event).await;
            Err(ApiError::TooManyRequests(format!(
                "Too many failed attempts. Account locked for {remaining} seconds")))
        }
        MfaVerifyResult::Invalid { attempts_remaining } => {
            let event = kms_core::event::Event::mfa_failed(&user_id, "invalid_totp_code");
            state.audit_logger.log_event(&event).await;
            Ok(Json(serde_json::json!({
                "valid": false,
                "attempts_remaining": attempts_remaining
            })))
        }
    }
}

async fn mfa_verify_backup(
    State(state): State<Arc<KmsState>>,
    Extension(caller_id): Extension<CallerId>,
    Extension(api_key_config): Extension<Arc<ApiKeyConfig>>,
    Path(user_id): Path<String>,
    Json(req): Json<MfaVerifyRequest>,
) -> Result<Json<serde_json::Value>> {
    enum BackupResult {
        Valid,
        LimitExceeded,
        Invalid,
    }

    let mfa = &state.mfa_manager;

    // Check if user exceeded backup code usage limit
    if mfa.backup_code_usage_count(&user_id).await >= MAX_BACKUP_CODE_USES {
        return Err(ApiError::TooManyRequests(
            "Backup code usage limit exceeded. Please use TOTP or reset MFA".to_string(),
        ));
    }

    let backup_valid = mfa.consume_backup_code(&user_id, &req.code).await;

    let result = if backup_valid {
        mfa.reset_backup_code_usage(&user_id).await;
        BackupResult::Valid
    } else {
        let limit_exceeded = mfa.record_backup_code_usage(&user_id).await;
        if limit_exceeded {
            BackupResult::LimitExceeded
        } else {
            BackupResult::Invalid
        }
    };

    match result {
        BackupResult::Valid => {
            let event = kms_core::event::Event::mfa_backup_code_used(&user_id);
            state.audit_logger.log_event(&event).await;
            Ok(Json(
                serde_json::json!({ "valid": true, "backup_code_used": true }),
            ))
        }
        BackupResult::LimitExceeded => {
            // H-2: Link backup code abuse to API key lockout
            api_key_config.lock_key_by_id(&caller_id.key_id);
            let event = kms_core::event::Event::mfa_failed(&user_id, "backup_code_limit_exceeded");
            state.audit_logger.log_event(&event).await;
            Err(ApiError::TooManyRequests(
                "Backup code usage limit exceeded. Please use TOTP or reset MFA".to_string(),
            ))
        }
        BackupResult::Invalid => {
            let event = kms_core::event::Event::mfa_failed(&user_id, "invalid_backup_code");
            state.audit_logger.log_event(&event).await;
            Ok(Json(serde_json::json!({ "valid": false })))
        }
    }
}

async fn mfa_status(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Path(user_id): Path<String>,
) -> Result<Json<MfaStatusResponse>> {
    let enabled = state.mfa_manager.has_totp_config(&user_id).await;
    let backup_codes_remaining = state.mfa_manager.backup_codes_remaining(&user_id).await;

    // Log audit event
    let event = kms_core::event::Event::new(
        kms_core::event::EventType::MfaSetup,
        &caller_id,
        "user",
        "mfa_status",
        "mfa",
        None,
        "success",
    );
    state.audit_logger.log_event(&event).await;

    Ok(Json(MfaStatusResponse {
        enabled,
        mfa_type: "totp".to_string(),
        backup_codes_remaining,
    }))
}

// =============================================================================
// Approval Workflow Handlers
// =============================================================================

fn parse_operation(op: &str) -> Option<OperationType> {
    match op.to_lowercase().as_str() {
        "key_delete" => Some(OperationType::KeyDelete),
        "key_export" => Some(OperationType::KeyExport),
        "key_rotate" => Some(OperationType::KeyRotate),
        "policy_change" => Some(OperationType::PolicyChange),
        "high_value_key_create" => Some(OperationType::HighValueKeyCreate),
        "audit_access" => Some(OperationType::AuditAccess),
        "mfa_change" => Some(OperationType::MfaChange),
        "tenant_admin" => Some(OperationType::TenantAdmin),
        _ => None,
    }
}

fn parse_role(role: &str) -> Role {
    match role.to_lowercase().as_str() {
        "user" => Role::User,
        "operator" => Role::Operator,
        "manager" => Role::Manager,
        "admin" => Role::Admin,
        "security_officer" => Role::SecurityOfficer,
        _ => Role::User,
    }
}

#[derive(Debug, Deserialize, ToSchema)]
struct CreateApprovalReq {
    operation: String,
    resource_id: String,
    resource_type: String,
    tenant_id: String,
    requestor_id: String,
    justification: Option<String>,
}

async fn create_approval_request(
    State(state): State<Arc<KmsState>>,
    Json(req): Json<CreateApprovalReq>,
) -> Result<(StatusCode, Json<crate::approval::ApprovalRequestResponse>)> {
    let operation = parse_operation(&req.operation).ok_or_else(|| {
        ApiError::InvalidArgument(format!("Unknown operation: {}", req.operation))
    })?;

    let operation_name = req.operation.clone();
    let requestor = req.requestor_id.clone();

    let response = {
        let mut approval = state.approval_manager.write();

        approval
            .create_request(
                operation,
                &req.resource_id,
                &req.resource_type,
                &req.tenant_id,
                &requestor,
                req.justification,
                None,
            )
            .ok_or_else(|| ApiError::Internal("Failed to create approval request".to_string()))?
    }; // approval dropped here

    // Log audit event
    let request_uuid = uuid::Uuid::parse_str(&response.id).unwrap_or(uuid::Uuid::nil());
    let event =
        kms_core::event::Event::approval_requested(&request_uuid, &requestor, &operation_name);
    state.audit_logger.log_event(&event).await;

    Ok((StatusCode::CREATED, Json(response)))
}

async fn list_pending_approvals(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Path(tenant_id): Path<String>,
) -> Result<Json<Vec<crate::approval::ApprovalRequestResponse>>> {
    let requests = {
        let approval = state.approval_manager.read();
        approval.list_pending(&tenant_id)
    }; // approval dropped here

    // Log audit event
    let event = kms_core::event::Event::new(
        kms_core::event::EventType::ApprovalRequested,
        &caller_id,
        "user",
        "list_pending_approvals",
        "approval",
        None,
        "success",
    );
    state.audit_logger.log_event(&event).await;

    Ok(Json(requests))
}

async fn get_approval_request(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Path(request_id): Path<Uuid>,
) -> Result<Json<crate::approval::ApprovalRequestResponse>> {
    let response = {
        let approval = state.approval_manager.read();
        approval
            .get_request(request_id)
            .ok_or_else(|| ApiError::NotFound("Approval request not found".to_string()))?
    }; // approval dropped here

    // Log audit event
    let event = kms_core::event::Event::new(
        kms_core::event::EventType::ApprovalRequested,
        &caller_id,
        "user",
        "get_approval_request",
        "approval",
        Some(request_id.to_string()),
        "success",
    );
    state.audit_logger.log_event(&event).await;

    Ok(Json(response))
}

#[derive(Debug, Deserialize, ToSchema)]
struct ApproveReq {
    approver_id: String,
    approver_role: String,
    comment: Option<String>,
}

async fn approve_request(
    State(state): State<Arc<KmsState>>,
    Path(request_id): Path<Uuid>,
    Json(req): Json<ApproveReq>,
) -> Result<Json<crate::approval::ApprovalRequestResponse>> {
    let role = parse_role(&req.approver_role);
    let approver = req.approver_id.clone();

    let response = {
        let mut approval = state.approval_manager.write();
        approval
            .approve(request_id, &approver, role, req.comment)
            .ok_or_else(|| {
                ApiError::NotFound("Approval request not found or already completed".to_string())
            })?
    }; // approval dropped here

    // Log audit event
    let event = kms_core::event::Event::approval_granted(&request_id, &approver);
    state.audit_logger.log_event(&event).await;

    Ok(Json(response))
}

#[derive(Debug, Deserialize, ToSchema)]
struct RejectReq {
    rejector_id: String,
    rejector_role: String,
    reason: String,
}

async fn reject_request(
    State(state): State<Arc<KmsState>>,
    Path(request_id): Path<Uuid>,
    Json(req): Json<RejectReq>,
) -> Result<Json<crate::approval::ApprovalRequestResponse>> {
    let role = parse_role(&req.rejector_role);
    let rejector = req.rejector_id.clone();
    let reason = req.reason.clone();

    let response = {
        let mut approval = state.approval_manager.write();
        approval
            .reject(request_id, &rejector, role, req.reason)
            .ok_or_else(|| {
                ApiError::NotFound("Approval request not found or already completed".to_string())
            })?
    }; // approval dropped here

    // Log audit event
    let event = kms_core::event::Event::approval_denied(&request_id, &rejector, &reason);
    state.audit_logger.log_event(&event).await;

    Ok(Json(response))
}

#[derive(Debug, Deserialize, ToSchema)]
struct CancelReq {
    requestor_id: String,
}

async fn cancel_request(
    State(state): State<Arc<KmsState>>,
    Path(request_id): Path<Uuid>,
    Json(req): Json<CancelReq>,
) -> Result<Json<crate::approval::ApprovalRequestResponse>> {
    let requestor = req.requestor_id.clone();

    let response = {
        let mut approval = state.approval_manager.write();
        approval.cancel(request_id, &requestor).ok_or_else(|| {
            ApiError::NotFound("Approval request not found or not authorized".to_string())
        })?
    }; // approval dropped here

    // Log audit event
    let event = kms_core::event::Event::new(
        kms_core::event::EventType::ApprovalDenied,
        &requestor,
        "user",
        "cancel_request",
        "approval",
        Some(request_id.to_string()),
        "cancelled",
    );
    state.audit_logger.log_event(&event).await;

    Ok(Json(response))
}

// Envelope encryption handlers

/// Encrypt data using envelope encryption (DEK wrapped with KEK)
async fn envelope_encrypt(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Json(req): Json<EnvelopeEncryptRequest>,
) -> Result<Json<EnvelopeEncryptResponse>> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let kek_id = uuid::Uuid::parse_str(&req.kek_id)
        .map_err(|_| ApiError::InvalidRequest("invalid kek_id format".to_string()))?;

    let plaintext = STANDARD
        .decode(&req.plaintext)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 plaintext".to_string()))?;

    let tenant_id = req.tenant_id.as_deref().unwrap_or("default");

    let envelope_svc = crate::service::EnvelopeService::new(&state);
    let result = envelope_svc
        .encrypt(&kek_id, &plaintext, None, tenant_id, "envelope-user")
        .await?;

    // Log audit event
    let event = kms_core::event::Event::key_encrypted(&kek_id, &caller_id, plaintext.len());
    state.audit_logger.log_event(&event).await;

    Ok(Json(EnvelopeEncryptResponse {
        wrapped_dek: result.wrapped_dek,
        dek_nonce: result.dek_nonce,
        ciphertext: result.ciphertext,
        data_nonce: result.data_nonce,
        tag: result.tag,
        kek_version: result.kek_version,
    }))
}

/// Decrypt data using envelope encryption (unwrap DEK with KEK, then decrypt)
async fn envelope_decrypt(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Json(req): Json<EnvelopeDecryptRequest>,
) -> Result<Json<EnvelopeDecryptResponse>> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let kek_id = uuid::Uuid::parse_str(&req.kek_id)
        .map_err(|_| ApiError::InvalidRequest("invalid kek_id format".to_string()))?;

    // Use KEK version from request for version-aware decryption.
    // This allows decrypting data encrypted with an older KEK version after rotation.
    let kek_version = req.kek_version;
    let tenant_id = req.tenant_id.as_deref().unwrap_or("default");

    // Decode request fields
    let wrapped_dek = STANDARD
        .decode(&req.wrapped_dek)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 wrapped_dek".to_string()))?;
    let ciphertext = STANDARD
        .decode(&req.ciphertext)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 ciphertext".to_string()))?;
    let dek_nonce = STANDARD
        .decode(&req.dek_nonce)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 dek_nonce".to_string()))?;
    let data_nonce = STANDARD
        .decode(&req.data_nonce)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 data_nonce".to_string()))?;
    let tag = STANDARD
        .decode(&req.tag)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 tag".to_string()))?;

    let envelope_svc = crate::service::EnvelopeService::new(&state);
    let plaintext = envelope_svc
        .decrypt_with_kek_version(
            &kek_id,
            &ciphertext,
            &wrapped_dek,
            &dek_nonce,
            &data_nonce,
            &tag,
            None,
            tenant_id,
            "envelope-user",
            kek_version,
        )
        .await?;

    // Log audit event
    let event = kms_core::event::Event::key_decrypted(&kek_id, &caller_id, plaintext.len());
    state.audit_logger.log_event(&event).await;

    Ok(Json(EnvelopeDecryptResponse {
        plaintext: STANDARD.encode(&plaintext),
    }))
}

/// Rewrap a DEK from an old KEK version to the current KEK version.
///
/// After KEK rotation, existing envelope-encrypted data still references the old KEK
/// version. This endpoint re-wraps the DEK with the current KEK version, enabling
/// decryption with the new key without re-encrypting the underlying plaintext.
async fn envelope_rewrap(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Json(req): Json<EnvelopeRewrapRequest>,
) -> Result<Json<EnvelopeRewrapResponse>> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let kek_id = uuid::Uuid::parse_str(&req.kek_id)
        .map_err(|_| ApiError::InvalidRequest("invalid kek_id format".to_string()))?;

    let wrapped_dek = STANDARD
        .decode(&req.wrapped_dek)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 wrapped_dek".to_string()))?;
    let dek_nonce = STANDARD
        .decode(&req.dek_nonce)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 dek_nonce".to_string()))?;

    let tenant_id = req.tenant_id.as_deref().unwrap_or("default");

    let envelope_svc = crate::service::EnvelopeService::new(&state);
    let result = envelope_svc
        .rewrap_dek(
            &kek_id,
            &wrapped_dek,
            &dek_nonce,
            req.old_kek_version,
            tenant_id,
        )
        .await?;

    // Log audit event
    let event = kms_core::event::Event::key_rotated(&kek_id, &caller_id);
    state.audit_logger.log_event(&event).await;

    Ok(Json(EnvelopeRewrapResponse {
        wrapped_dek: result.wrapped_dek,
        dek_nonce: result.dek_nonce,
        kek_version: result.kek_version,
        old_kek_version: result.old_kek_version,
    }))
}

/// Derive a shared secret using Diffie-Hellman key exchange
async fn dh_derive(
    State(state): State<Arc<KmsState>>,
    Json(req): Json<DhDeriveRequest>,
) -> Result<Json<DhDeriveResponse>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use kms_core::dh::DhAlgorithm;

    // Parse key ID
    let key_id = uuid::Uuid::parse_str(&req.key_id)
        .map_err(|_| ApiError::InvalidRequest("invalid key_id format".to_string()))?;

    // Parse algorithm
    let algorithm = match req.algorithm.to_uppercase().as_str() {
        "ECDH-P256" | "P-256" => DhAlgorithm::EcdsaP256,
        "ECDH-P384" | "P-384" => DhAlgorithm::EcdsaP384,
        "X25519" | "CURVE25519" => DhAlgorithm::X25519,
        "SM2-KEX" | "SM2" => DhAlgorithm::Sm2Kex,
        _ => {
            return Err(ApiError::InvalidRequest(format!(
                "unsupported DH algorithm: {} (supported: ECDH-P256, ECDH-P384, X25519, SM2-KEX)",
                req.algorithm
            )));
        }
    };

    // Decode peer's public key
    let peer_public_key = STANDARD
        .decode(&req.peer_public_key)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 peer_public_key".to_string()))?;

    // Perform DH key exchange
    let shared_secret = state
        .keystore
        .derive_shared_secret(&key_id, &peer_public_key, algorithm)
        .await
        .map_err(|e| match e {
            kms_core::Error::KeyNotFound(_) => {
                ApiError::NotFound(format!("key {key_id} not found"))
            }
            kms_core::Error::NotImplemented(_) => ApiError::NotImplemented,
            kms_core::Error::KeyOperationNotAllowed(msg) => ApiError::InvalidRequest(msg),
            _ => ApiError::Internal(e.to_string()),
        })?;

    // Log audit event
    let event = kms_core::event::Event::new(
        kms_core::event::EventType::KeyAccessed,
        "dh-user",
        "user",
        "derive_shared_secret",
        "dh",
        Some(key_id.to_string()),
        "success",
    );
    state.audit_logger.log_event(&event).await;

    Ok(Json(DhDeriveResponse {
        shared_secret: STANDARD.encode(&shared_secret.secret),
        kdf: shared_secret.kdf.unwrap_or_else(|| "none".to_string()),
    }))
}

// Key import/export handlers

/// Import an external key into the KMS
async fn import_key(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Json(req): Json<ImportKeyRequest>,
) -> Result<(StatusCode, Json<ImportKeyResponse>)> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    use crate::auth::check_rest_pbac;
    check_rest_pbac(&state.policy_engine, &caller_id, "import_key", &req.name)
        .await
        .map_err(|_| ApiError::PermissionDenied)?;

    // Parse key spec using KeyService
    let spec = KeyService::parse_spec(&req.spec)?;

    // Decode wrapped_key (key material, encrypted with transport key)
    let wrapped_key_bytes = STANDARD
        .decode(&req.wrapped_key)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 wrapped_key".to_string()))?;

    // Decode encrypted_transport_key (transport key, encrypted with KMS public key)
    let encrypted_transport_key_bytes =
        STANDARD.decode(&req.encrypted_transport_key).map_err(|_| {
            ApiError::InvalidRequest("invalid base64 encrypted_transport_key".to_string())
        })?;

    let key_svc = state.key_service();
    let meta = key_svc
        .import_key(
            spec,
            &req.name,
            &req.format,
            &wrapped_key_bytes,
            &encrypted_transport_key_bytes,
            &req.source_fingerprint,
            &req.tenant_id,
            &caller_id,
        )
        .await?;

    // Log audit event
    let event = kms_core::event::Event::key_imported(&meta.id, &caller_id, &req.format);
    state.audit_logger.log_event(&event).await;

    Ok((
        StatusCode::CREATED,
        Json(ImportKeyResponse {
            id: meta.id.to_string(),
            spec: format!("{:?}", meta.spec),
            imported: true,
            source_fingerprint: req.source_fingerprint,
        }),
    ))
}

/// Export a key (wrapped with transport key)
///
/// **Security**: Key export requires an approved `KeyExport` approval request.
/// The caller must first create an approval request via `POST /v1/approvals`,
/// obtain the required approvals (Triple level — 3 approvers), then pass the
/// `approval_id` in this request. Export without approval is rejected.
async fn export_key(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Path(key_id): Path<Uuid>,
    Json(req): Json<ExportKeyRequest>,
) -> Result<Json<ExportKeyResponse>> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    // PBAC evaluation
    use crate::auth::check_rest_pbac;
    check_rest_pbac(
        &state.policy_engine,
        &caller_id,
        "export_key",
        &key_id.to_string(),
    )
    .await
    .map_err(|_| ApiError::PermissionDenied)?;

    // Enforce approval gate: KeyExport requires an approved request
    let approval_id = match &req.approval_id {
        Some(id) => id.clone(),
        None => {
            tracing::warn!(key_id = %key_id, "key export rejected: no approval_id provided");
            return Err(ApiError::InvalidRequest(
                "key export requires an approved KeyExport request. Create one via POST /v1/approvals first".to_string(),
            ));
        }
    };

    let approval_uuid = uuid::Uuid::parse_str(&approval_id)
        .map_err(|_| ApiError::InvalidRequest("invalid approval_id format".to_string()))?;

    // Check approval is valid and fully approved for KeyExport
    // (sync block — no .await inside the RwLockReadGuard scope)
    let approval_ok = {
        let guard = state.approval_manager.read();
        guard.is_approved(approval_uuid, OperationType::KeyExport)
    }; // guard dropped here, before any .await
    if !approval_ok {
        tracing::warn!(
            key_id = %key_id,
            approval_id = %approval_id,
            "key export rejected: approval not found, not for KeyExport, or not fully approved"
        );
        return Err(ApiError::InvalidRequest(
            "key export requires a fully approved KeyExport request".to_string(),
        ));
    }

    let target_pubkey = STANDARD
        .decode(&req.target_public_key)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 target_public_key".to_string()))?;

    let key_svc = state.key_service();
    let exported = key_svc
        .export_key(
            &key_id,
            &target_pubkey,
            &req.purpose,
            "", // tenant_id - not used in current implementation
            &caller_id,
        )
        .await?;

    // Record export metric
    state.metrics.record_key_export();

    // Log audit event for export request
    let export_request_event =
        kms_core::event::Event::key_export_requested(&key_id, &caller_id, &req.purpose);
    state.audit_logger.log_event(&export_request_event).await;

    // Log audit event
    let event = kms_core::event::Event::key_exported(&key_id, &caller_id, &req.purpose);
    state.audit_logger.log_event(&event).await;

    Ok(Json(ExportKeyResponse {
        wrapped_key: exported.wrapped_key,
        encrypted_transport_key: exported.encrypted_transport_key,
        key_fingerprint: exported.key_fingerprint,
        export_id: exported.export_id,
        expires_at: exported.expires_at,
    }))
}

async fn create_policy(
    State(state): State<Arc<KmsState>>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<(StatusCode, Json<PolicyResponse>)> {
    let effect = match req.effect.to_lowercase().as_str() {
        "allow" => kms_core::PolicyEffect::Allow,
        "deny" => kms_core::PolicyEffect::Deny,
        _ => {
            return Err(ApiError::InvalidRequest(format!(
                "invalid effect: {}, expected 'allow' or 'deny'",
                req.effect
            )));
        }
    };

    let policy = kms_policy::Policy {
        id: uuid::Uuid::new_v4(),
        name: req.name,
        effect,
        condition: req.condition,
        resources: req.resources,
        subjects: req.subjects,
        enabled: req.enabled,
    };

    state
        .policy_engine
        .add_policy(policy.clone())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Record PBAC policy creation metric
    state.metrics.record_policy_create();

    Ok((
        StatusCode::CREATED,
        Json(PolicyResponse {
            id: policy.id.to_string(),
            name: policy.name,
            effect: format!("{:?}", policy.effect),
            condition: policy.condition,
            resources: policy.resources,
            subjects: policy.subjects,
            enabled: policy.enabled,
        }),
    ))
}

async fn get_policy(
    State(state): State<Arc<KmsState>>,
    Path(id): Path<String>,
) -> Result<Json<PolicyResponse>> {
    let policy = state
        .policy_engine
        .get_policy(&id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("policy {id} not found")))?;

    Ok(Json(PolicyResponse {
        id: policy.id.to_string(),
        name: policy.name,
        effect: format!("{:?}", policy.effect),
        condition: policy.condition,
        resources: policy.resources,
        subjects: policy.subjects,
        enabled: policy.enabled,
    }))
}

async fn list_policies(State(state): State<Arc<KmsState>>) -> Result<Json<Vec<PolicyResponse>>> {
    let policies = state
        .policy_engine
        .list_policies()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let response: Vec<PolicyResponse> = policies
        .into_iter()
        .map(|p| PolicyResponse {
            id: p.id.to_string(),
            name: p.name,
            effect: format!("{:?}", p.effect),
            condition: p.condition,
            resources: p.resources,
            subjects: p.subjects,
            enabled: p.enabled,
        })
        .collect();

    Ok(Json(response))
}

async fn query_audit_events(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Query(filter): Query<kms_audit::AuditFilter>,
) -> Result<Json<Vec<kms_audit::AuditEvent>>> {
    // PBAC evaluation
    use crate::auth::check_rest_pbac;
    check_rest_pbac(
        &state.policy_engine,
        &caller_id,
        "query_audit_events",
        "audit",
    )
    .await
    .map_err(|_| ApiError::PermissionDenied)?;
    let events = state.audit_logger.query(filter).await;

    Ok(Json(events))
}

// SM9 Identity-Based Cryptography handlers

use gm_sm9_rs::{Decryptor, Encryptor, Signer, Verifier};

async fn sm9_sign(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Json(req): Json<Sm9SignRequest>,
) -> Result<Json<Sm9SignResponse>> {
    use crate::auth::check_rest_pbac;
    check_rest_pbac(&state.policy_engine, &caller_id, "sm9_sign", &req.identity)
        .await
        .map_err(|_| ApiError::PermissionDenied)?;

    use base64::{Engine, engine::general_purpose::STANDARD};

    let data = STANDARD
        .decode(&req.data)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 data".to_string()))?;

    // Derive signing key for this identity
    let sign_key = state
        .sm9_state
        .master_key
        .derive_signing_key(req.identity.as_bytes())
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let signer = Signer::new(sign_key);

    let signature = signer
        .sign(&data, &mut rand::rng())
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let signature_bytes = signature.to_bytes();

    // Log audit event
    let event = kms_core::event::Event::new(
        kms_core::event::EventType::KeyAccessed,
        &caller_id,
        "user",
        "sm9_sign",
        "sm9",
        None,
        "success",
    );
    state.audit_logger.log_event(&event).await;

    // GmSSL returns raw signature bytes
    Ok(Json(Sm9SignResponse {
        w: String::new(), // Deprecated field, signature is in raw bytes
        h: String::new(), // Deprecated field
        s: STANDARD.encode(&signature_bytes),
    }))
}

async fn sm9_verify(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Json(req): Json<Sm9VerifyRequest>,
) -> Result<Json<Sm9VerifyResponse>> {
    use crate::auth::check_rest_pbac;
    check_rest_pbac(
        &state.policy_engine,
        &caller_id,
        "sm9_verify",
        &req.identity,
    )
    .await
    .map_err(|_| ApiError::PermissionDenied)?;

    use base64::{Engine, engine::general_purpose::STANDARD};

    let data = STANDARD
        .decode(&req.data)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 data".to_string()))?;

    // Signature is in raw bytes (GmSSL format), passed via the 's' field
    let signature_bytes = STANDARD
        .decode(&req.s)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 s".to_string()))?;

    let signature = gm_sm9_rs::Signature::from_der(&signature_bytes)
        .or_else(|_| gm_sm9_rs::Signature::from_bytes(&signature_bytes))
        .map_err(|e| ApiError::InvalidRequest(format!("invalid signature format: {e}")))?;

    let verifier = Verifier::new(
        req.identity.as_bytes(),
        &state.sm9_state.master_key.sign_master().ppubs,
    );

    let valid = verifier
        .verify(&data, &signature)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Log audit event
    let event = kms_core::event::Event::new(
        kms_core::event::EventType::KeyAccessed,
        &caller_id,
        "user",
        "sm9_verify",
        "sm9",
        None,
        "success",
    );
    state.audit_logger.log_event(&event).await;

    Ok(Json(Sm9VerifyResponse { valid }))
}

async fn sm9_encrypt(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Json(req): Json<Sm9EncryptRequest>,
) -> Result<Json<Sm9EncryptResponse>> {
    use crate::auth::check_rest_pbac;
    check_rest_pbac(
        &state.policy_engine,
        &caller_id,
        "sm9_encrypt",
        &req.identity,
    )
    .await
    .map_err(|_| ApiError::PermissionDenied)?;

    use base64::{Engine, engine::general_purpose::STANDARD};

    let plaintext = STANDARD
        .decode(&req.plaintext)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 plaintext".to_string()))?;

    let encryptor = Encryptor::new(
        req.identity.as_bytes(),
        &state.sm9_state.master_key.enc_master().ppube,
    );

    let ciphertext = encryptor
        .encrypt(&plaintext, &mut rand::rng())
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let ciphertext_bytes = ciphertext.to_bytes();

    // Log audit event
    let event = kms_core::event::Event::new(
        kms_core::event::EventType::KeyAccessed,
        &caller_id,
        "user",
        "sm9_encrypt",
        "sm9",
        None,
        "success",
    );
    state.audit_logger.log_event(&event).await;

    // GmSSL returns raw ciphertext bytes
    Ok(Json(Sm9EncryptResponse {
        c1: STANDARD.encode(&ciphertext_bytes),
        c2: String::new(), // Deprecated, ciphertext is in c1
        c3: String::new(), // Deprecated, ciphertext is in c1
    }))
}

async fn sm9_decrypt(
    CallerId { key_id: caller_id }: CallerId,
    State(state): State<Arc<KmsState>>,
    Json(req): Json<Sm9DecryptRequest>,
) -> Result<Json<Sm9DecryptResponse>> {
    use crate::auth::check_rest_pbac;
    check_rest_pbac(
        &state.policy_engine,
        &caller_id,
        "sm9_decrypt",
        &req.identity,
    )
    .await
    .map_err(|_| ApiError::PermissionDenied)?;

    use base64::{Engine, engine::general_purpose::STANDARD};

    let ciphertext_bytes = STANDARD
        .decode(&req.c1)
        .map_err(|_| ApiError::InvalidRequest("invalid base64 ciphertext".to_string()))?;

    let ciphertext = gm_sm9_rs::Ciphertext::from_bytes(&ciphertext_bytes)
        .map_err(|e| ApiError::InvalidRequest(format!("invalid ciphertext: {e}")))?;

    // Derive decryption key for this identity
    let enc_key = state
        .sm9_state
        .master_key
        .derive_encryption_key(req.identity.as_bytes())
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let decryptor = Decryptor::new(enc_key);

    let plaintext = decryptor
        .decrypt(&ciphertext, req.identity.as_bytes())
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Log audit event
    let event = kms_core::event::Event::new(
        kms_core::event::EventType::KeyAccessed,
        &caller_id,
        "user",
        "sm9_decrypt",
        "sm9",
        None,
        "success",
    );
    state.audit_logger.log_event(&event).await;

    Ok(Json(Sm9DecryptResponse {
        plaintext: STANDARD.encode(&plaintext),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kms_core::key::KeySpec;

    // Test request/response type conversions
    #[test]
    fn test_key_response_from_key_meta() {
        let meta = KeyMeta {
            id: Uuid::new_v4(),
            tenant_id: "test-tenant".to_string(),
            name: "test-key".to_string(),
            spec: KeySpec::Aes256Gcm,
            status: kms_core::key::KeyStatus::Active,
            created_at: chrono::Utc::now(),
            rotated_at: None,
            version: 1,
            description: None,
            metadata: Default::default(),
        };

        let response: KeyResponse = meta.clone().into();
        assert_eq!(response.name, "test-key");
        assert_eq!(response.tenant_id, "test-tenant");
        assert_eq!(response.spec, "Aes256Gcm");
        assert_eq!(response.version, 1);
    }

    // Test spec parsing
    #[test]
    fn test_spec_parsing_aes256gcm() {
        let spec_str = "aes-256-gcm";
        let spec = match spec_str.to_lowercase().as_str() {
            "aes-256-gcm" => Ok(KeySpec::Aes256Gcm),
            "sm4" => Ok(KeySpec::Sm4),
            "sm2" => Ok(KeySpec::Sm2),
            "ed25519" => Ok(KeySpec::Ed25519),
            _ => Err("Unknown spec"),
        };
        assert!(spec.is_ok());
        assert!(matches!(spec.unwrap(), KeySpec::Aes256Gcm));
    }

    #[test]
    fn test_spec_parsing_sm4() {
        let spec_str = "sm4";
        let spec = match spec_str.to_lowercase().as_str() {
            "aes-256-gcm" => KeySpec::Aes256Gcm,
            "sm4" => KeySpec::Sm4,
            "sm2" => KeySpec::Sm2,
            "ed25519" => KeySpec::Ed25519,
            _ => panic!("Unknown spec"),
        };
        assert!(matches!(spec, KeySpec::Sm4));
    }

    // Test CreateKeyRequest defaults
    #[test]
    fn test_create_key_request_defaults() {
        let json = r#"{"name": "test-key", "spec": "aes-256-gcm"}"#;
        let req: CreateKeyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "test-key");
        assert_eq!(req.tenant_id, "default"); // Default tenant
    }

    // Test EncryptRequest parsing
    #[test]
    fn test_encrypt_request_parsing() {
        let json = r#"{"plaintext": "SGVsbG8=", "aad": null}"#;
        let req: EncryptRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.plaintext, "SGVsbG8=");
        assert!(req.aad.is_none());
    }

    // Test KeyFilter parsing
    #[test]
    fn test_key_filter_default() {
        let filter = KeyFilter::default();
        assert!(filter.tenant_id.is_none());
        assert!(filter.status.is_none());
        assert!(filter.limit.is_none());
    }

    // Test hash algorithm selection
    #[test]
    fn test_hash_algorithm_selection() {
        let algo = "sm3";
        let selected = match algo.to_lowercase().as_str() {
            "sm3" => "sm3",
            "sha256" => "sha256",
            _ => "unknown",
        };
        assert_eq!(selected, "sm3");
    }

    // Test policy effect parsing
    #[test]
    fn test_policy_effect_parsing() {
        let effect_str = "allow";
        let effect = match effect_str.to_lowercase().as_str() {
            "allow" => kms_core::PolicyEffect::Allow,
            "deny" => kms_core::PolicyEffect::Deny,
            _ => panic!("Invalid effect"),
        };
        assert!(matches!(effect, kms_core::PolicyEffect::Allow));
    }

    // Test sign request parsing
    #[test]
    fn test_sign_request_parsing() {
        let json = r#"{"data": "dGVzdCBkYXRh"}"#;
        let req: SignRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.data, "dGVzdCBkYXRh");
    }

    // Test verify request parsing
    #[test]
    fn test_verify_request_parsing() {
        let json = r#"{"data": "dGVzdCBkYXRh", "signature": "c2lnbmF0dXJl"}"#;
        let req: VerifyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.data, "dGVzdCBkYXRh");
        assert_eq!(req.signature, "c2lnbmF0dXJl");
    }
}
