//! gRPC API implementation using Tonic

use crate::{ApiError, ApiKeyConfig, ApiKeyPermission, KmsState, Permission};
use kms_approval::OperationType;
use std::sync::Arc;
use tonic::{Request, Response, Status, service::Interceptor};

// Include generated protobuf
pub mod pb {
    tonic::include_proto!("kms.v1");
}

use pb::{
    CreateKeyResponse, DeleteKeyResponse, EncryptResponse, GetKeyResponse, Key, ListKeysResponse,
    RotateKeyResponse, SignResponse, Sm9DecryptResponse, Sm9EncryptResponse, Sm9SignResponse,
    Sm9VerifyResponse, VerifyResponse, kms_service_server::KmsService,
};

pub struct KmsGrpcService {
    state: Arc<KmsState>,
}

impl KmsGrpcService {
    pub fn new(state: Arc<KmsState>) -> Self {
        Self { state }
    }

    /// Evaluate PBAC policy for an access request.
    /// Returns Ok(()) if allowed, Err(Status) if denied or on evaluation error.
    ///
    /// This is the gRPC counterpart of the REST PBAC middleware.
    /// Policy is evaluated ADDITIVELY: the API key role check (check_permission)
    /// is still required; PBAC can only FURTHER RESTRICT access, never grant it.
    async fn check_pbac(
        &self,
        subject_id: &str,
        action: &str,
        resource_id: &str,
    ) -> Result<(), Status> {
        let ctx = kms_policy::AccessContext::new(subject_id, action, resource_id);
        match self.state.policy_engine.evaluate(&ctx).await {
            Ok(kms_policy::Decision::Allow) => Ok(()),
            Ok(kms_policy::Decision::Deny) => {
                tracing::warn!(%subject_id, %action, %resource_id, "PBAC denied");
                Err(Status::permission_denied("access denied by policy"))
            }
            Err(e) => {
                tracing::error!(%subject_id, %action, %resource_id, error = %e, "PBAC evaluation error");
                Err(Status::internal("policy evaluation error"))
            }
        }
    }

    /// Shared approval gate for sensitive key-lifecycle operations (delete/export/rotate).
    /// Mirrors the REST `require_approved` helper so both channels enforce the same
    /// invariants (audit P1-2 resource binding, P2-8 expiry, P2-4 uniform
    /// `OperationType`-driven gate): the `approval_id` must reference a fully-approved,
    /// non-expired request of `operation` bound to `resource_id`.
    fn require_approved(
        &self,
        approval_id: &str,
        operation: OperationType,
        resource_id: &str,
        action: &str,
    ) -> Result<(), Status> {
        if approval_id.is_empty() {
            tracing::warn!(%resource_id, %action, "{action} rejected: no approval_id");
            return Err(Status::failed_precondition(format!(
                "{action} requires an approved request. Create one via the approvals API first"
            )));
        }
        let approval_uuid = uuid::Uuid::parse_str(approval_id)
            .map_err(|_| Status::invalid_argument("invalid approval_id format"))?;
        let approval_ok = {
            let guard = self.state.approval_manager.read();
            guard.is_approved(approval_uuid, operation, resource_id)
        };
        if !approval_ok {
            tracing::warn!(
                %resource_id,
                %approval_id,
                %action,
                "{action} rejected: approval not found, not bound to this resource/operation, not fully approved, or expired"
            );
            return Err(Status::permission_denied(format!(
                "{action} requires a fully approved request bound to this resource"
            )));
        }
        Ok(())
    }
}

/// Resolve the effective request tenant from the authenticated identity (audit P1-3).
///
/// - Bound key (`Some(b)`) => the bound tenant is AUTHORITATIVE; the request-reported
///   tenant is ignored (a mismatch is logged so spoofing attempts are observable).
/// - Unbound key + non-empty request tenant => honour the request tenant (compat).
/// - Unbound key + empty request tenant => FAIL explicitly. This removes the previous
///   silent `"default"` fallback, which masked misconfiguration and pooled untensored
///   requests into a shared bucket.
fn resolve_tenant(bound: Option<&str>, req_tenant: &str) -> Result<String, Status> {
    if let Some(b) = bound {
        if !req_tenant.is_empty() && req_tenant != b {
            tracing::warn!(
                bound_tenant = %b,
                reported_tenant = %req_tenant,
                "ignoring self-reported tenant: authenticated API key is bound to its own tenant"
            );
        }
        return Ok(b.to_string());
    }
    if req_tenant.is_empty() {
        tracing::warn!("gRPC request denied: unbound API key with empty tenant_id");
        return Err(Status::invalid_argument(
            "tenant_id is required: set it in the request or bind it to the API key",
        ));
    }
    Ok(req_tenant.to_string())
}

// ── gRPC Authentication Interceptor ──────────────────────────────────

/// gRPC interceptor that enforces API Key authentication.
///
/// Reuses the same `ApiKeyConfig` as the REST API, ensuring consistent auth
/// across both interfaces. This interceptor verifies that the caller provides
/// a valid (non-expired, non-revoked, non-locked) API key.
///
/// Fine-grained permission checks (e.g., CREATE_KEY vs ENCRYPT) are performed
/// inside each handler method via `check_permission()`, since the tonic
/// `Interceptor` trait only receives `Request<()>` without method path info.
pub struct GrpcAuthInterceptor {
    api_key_config: Arc<ApiKeyConfig>,
}

impl Clone for GrpcAuthInterceptor {
    fn clone(&self) -> Self {
        Self {
            api_key_config: Arc::clone(&self.api_key_config),
        }
    }
}

impl GrpcAuthInterceptor {
    pub fn new(api_key_config: Arc<ApiKeyConfig>) -> Self {
        Self { api_key_config }
    }
}

impl Interceptor for GrpcAuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        // Extract API key from metadata
        let api_key = request
            .metadata()
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .or_else(|| {
                // Also accept Authorization: Bearer <key>
                request
                    .metadata()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
            });

        match api_key {
            Some(key) => {
                if let Some((permission, key_id)) = self.api_key_config.validate_with_identity(key)
                {
                    // Server-side tenant binding (audit P1-3): derive the authoritative
                    // tenant from the authenticated key. Computed before the mutable
                    // borrow of `request` below to keep the `key` borrow region tight.
                    let tenant_id = self.api_key_config.lookup_tenant(key);
                    // Attach the caller's role + identity to request extensions for handler-level checks
                    request.extensions_mut().insert(GrpcCaller {
                        role: permission,
                        key_id,
                        tenant_id,
                    });
                    Ok(request)
                } else {
                    tracing::warn!("gRPC request denied: invalid or locked API key");
                    Err(Status::unauthenticated("invalid API key"))
                }
            }
            None => {
                tracing::warn!("gRPC request denied: missing API key");
                Err(Status::unauthenticated(
                    "API key required: set x-api-key metadata header",
                ))
            }
        }
    }
}

/// Authenticated caller context stored in gRPC request extensions.
#[derive(Debug, Clone)]
pub struct GrpcCaller {
    pub role: ApiKeyPermission,
    /// API key ID for audit trail (satisfies 等保三级 traceability requirement).
    pub key_id: String,
    /// Tenant bound to the authenticated API key (audit P1-3). `None` means unbound,
    /// so the handler falls back to the request-self-reported tenant.
    pub tenant_id: Option<String>,
}

/// Check that the caller has the required Permission.
/// Returns the caller's identity (role + key_id + bound tenant) on success, or a Status error.
fn check_permission<T>(
    request: &Request<T>,
    required: Permission,
) -> Result<(ApiKeyPermission, String, Option<String>), Status> {
    match request.extensions().get::<GrpcCaller>() {
        Some(caller) => {
            if caller.role.satisfies(required) {
                Ok((caller.role, caller.key_id.clone(), caller.tenant_id.clone()))
            } else {
                tracing::warn!(
                    role = %caller.role,
                    required = ?required,
                    "gRPC permission denied"
                );
                Err(Status::permission_denied(format!(
                    "insufficient permissions: {required:?} required"
                )))
            }
        }
        None => Err(Status::unauthenticated("no caller context")),
    }
}

/// Convert ApiError to tonic Status
fn api_error_to_status(e: ApiError) -> Status {
    match e {
        // Sanitized: log key ID server-side, return generic message to client
        ApiError::KeyNotFound(id) => {
            tracing::warn!(key_id = %id, "key not found");
            Status::not_found("key not found")
        }
        ApiError::InvalidRequest(msg) => Status::invalid_argument(msg),
        ApiError::Forbidden(msg) => Status::permission_denied(msg),
        ApiError::QuotaExceeded {
            resource,
            current,
            limit,
        } => {
            Status::resource_exhausted(format!("quota exceeded for {resource}: {current}/{limit}"))
        }
        // Sanitized: log full error server-side, return generic message to client
        ApiError::Internal(msg) => {
            tracing::error!(error = %msg, "internal server error");
            Status::internal("internal server error")
        }
        ApiError::NotFound(msg) => Status::not_found(msg),
        ApiError::InvalidArgument(msg) => Status::invalid_argument(msg),
        _ => Status::internal("internal server error"),
    }
}

#[tonic::async_trait]
impl KmsService for KmsGrpcService {
    async fn create_key(
        &self,
        request: Request<pb::CreateKeyRequest>,
    ) -> Result<Response<CreateKeyResponse>, Status> {
        let (_, caller_id, caller_tenant) = check_permission(&request, Permission::CREATE_KEY)?;
        let req = request.into_inner();

        // PBAC: evaluate policy for key creation
        self.check_pbac(&caller_id, "create_key", &req.name).await?;

        let spec =
            crate::service::KeyService::parse_spec(&req.spec).map_err(api_error_to_status)?;

        let tenant_id = resolve_tenant(caller_tenant.as_deref(), &req.tenant_id)?;

        let key_svc = self.state.key_service();
        let meta = key_svc
            .create_key(spec, &req.name, &tenant_id, &caller_id)
            .await
            .map_err(api_error_to_status)?;

        // Log audit event
        let event = kms_core::event::Event::key_created(&meta.id, &caller_id, &req.spec);
        self.state.audit_logger.log_event(&event).await;

        // Backup key material (best-effort, failure is logged but not returned)
        if let Some(ref bs) = self.state.backup_service {
            match self
                .state
                .keystore
                .get_key_material(&meta.id, &tenant_id)
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

        Ok(Response::new(CreateKeyResponse {
            key: Some(Key {
                id: meta.id.to_string(),
                tenant_id: meta.tenant_id,
                name: meta.name,
                spec: format!("{:?}", meta.spec),
                status: format!("{:?}", meta.status),
                version: meta.version,
                created_at: meta.created_at.to_rfc3339(),
            }),
        }))
    }

    async fn get_key(
        &self,
        request: Request<pb::GetKeyRequest>,
    ) -> Result<Response<GetKeyResponse>, Status> {
        let (_, caller_id, caller_tenant) = check_permission(&request, Permission::GET_KEY)?;
        let req = request.into_inner();
        let id = uuid::Uuid::parse_str(&req.id)
            .map_err(|_| Status::invalid_argument("invalid key id"))?;
        self.check_pbac(&caller_id, "get_key", &id.to_string())
            .await?;

        let tenant_id_owned = resolve_tenant(caller_tenant.as_deref(), &req.tenant_id)?;
        let tenant_id: &str = &tenant_id_owned;

        let key_svc = self.state.key_service();
        let meta = key_svc
            .get_key(&id, tenant_id)
            .await
            .map_err(api_error_to_status)?;

        // Log audit event
        let event = kms_core::event::Event::key_material_accessed(&id, &caller_id, "get");
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(GetKeyResponse {
            key: Some(Key {
                id: meta.id.to_string(),
                tenant_id: meta.tenant_id,
                name: meta.name,
                spec: format!("{:?}", meta.spec),
                status: format!("{:?}", meta.status),
                version: meta.version,
                created_at: meta.created_at.to_rfc3339(),
            }),
        }))
    }

    async fn encrypt(
        &self,
        request: Request<pb::EncryptRequest>,
    ) -> Result<Response<EncryptResponse>, Status> {
        let (_, caller_id, caller_tenant) = check_permission(&request, Permission::ENCRYPT)?;
        let req = request.into_inner();
        let id = uuid::Uuid::parse_str(&req.key_id)
            .map_err(|_| Status::invalid_argument("invalid key id"))?;
        self.check_pbac(&caller_id, "encrypt", &id.to_string())
            .await?;

        // plaintext is now bytes type in proto (not base64 encoded string)
        let plaintext = req.plaintext;

        let tenant_id_owned = resolve_tenant(caller_tenant.as_deref(), &req.tenant_id)?;
        let tenant_id: &str = &tenant_id_owned;

        let crypto = self.state.crypto_service();
        let ciphertext = crypto
            .encrypt(&id, &plaintext, None, tenant_id, &caller_id)
            .await
            .map_err(api_error_to_status)?;

        // Log audit event
        let event = kms_core::event::Event::key_encrypted(&id, &caller_id, plaintext.len());
        self.state.audit_logger.log_event(&event).await;

        use base64::{Engine, engine::general_purpose::STANDARD};
        Ok(Response::new(EncryptResponse {
            ciphertext: STANDARD.encode(&ciphertext.ciphertext),
            nonce: STANDARD.encode(&ciphertext.nonce),
            tag: STANDARD.encode(&ciphertext.tag),
            version: ciphertext.version,
            format_version: ciphertext.format_version as u32,
        }))
    }

    async fn decrypt(
        &self,
        request: Request<pb::DecryptRequest>,
    ) -> Result<Response<pb::DecryptResponse>, Status> {
        let (_, caller_id, caller_tenant) = check_permission(&request, Permission::DECRYPT)?;
        let req = request.into_inner();
        let id = uuid::Uuid::parse_str(&req.key_id)
            .map_err(|_| Status::invalid_argument("invalid key id"))?;
        self.check_pbac(&caller_id, "decrypt", &id.to_string())
            .await?;

        use base64::{Engine, engine::general_purpose::STANDARD};

        let ciphertext = kms_core::key::Ciphertext {
            key_id: id,
            version: req.version,
            // Echo the caller-supplied format so the keystore reproduces the
            // exact AAD used at encryption (format 2 binds AAD to
            // key_id/tenant/version); unset defaults to 2 (current production
            // format), legacy 0/1 by explicit echo from Encrypt.
            format_version: req.format_version.unwrap_or(2) as u8,
            nonce: STANDARD
                .decode(&req.nonce)
                .map_err(|_| Status::invalid_argument("invalid base64 nonce"))?,
            ciphertext: STANDARD
                .decode(&req.ciphertext)
                .map_err(|_| Status::invalid_argument("invalid base64 ciphertext"))?,
            tag: STANDARD
                .decode(&req.tag)
                .map_err(|_| Status::invalid_argument("invalid base64 tag"))?,
        };

        let tenant_id_owned = resolve_tenant(caller_tenant.as_deref(), &req.tenant_id)?;
        let tenant_id: &str = &tenant_id_owned;

        let crypto = self.state.crypto_service();
        let plaintext = crypto
            .decrypt(&id, &ciphertext, None, tenant_id, &caller_id)
            .await
            .map_err(api_error_to_status)?;

        // Log audit event
        let event = kms_core::event::Event::key_decrypted(&id, &caller_id, plaintext.len());
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(pb::DecryptResponse {
            plaintext: plaintext.to_vec(),
        }))
    }

    async fn rotate_key(
        &self,
        request: Request<pb::RotateKeyRequest>,
    ) -> Result<Response<RotateKeyResponse>, Status> {
        let (_, caller_id, caller_tenant) = check_permission(&request, Permission::ROTATE_KEY)?;
        let req = request.into_inner();
        let id = uuid::Uuid::parse_str(&req.id)
            .map_err(|_| Status::invalid_argument("invalid key id"))?;
        self.check_pbac(&caller_id, "rotate_key", &id.to_string())
            .await?;

        // Security: KeyRotate is a dual-approval operation (workflow.rs:
        // KeyRotate => ApprovalLevel::Double). Enforce it here too, bound to THIS
        // key, so the enum-declared level is actually required at the interface
        // (audit P2-4).
        self.require_approved(
            &req.approval_id,
            OperationType::KeyRotate,
            &id.to_string(),
            "key rotation",
        )?;

        let tenant_id_owned = resolve_tenant(caller_tenant.as_deref(), &req.tenant_id)?;
        let tenant_id: &str = &tenant_id_owned;

        let key_svc = self.state.key_service();
        let meta = key_svc
            .rotate_key(&id, tenant_id, &caller_id)
            .await
            .map_err(api_error_to_status)?;

        // Log audit event
        let event = kms_core::event::Event::key_rotated(&id, &caller_id);
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(RotateKeyResponse {
            key: Some(Key {
                id: meta.id.to_string(),
                tenant_id: meta.tenant_id,
                name: meta.name,
                spec: format!("{:?}", meta.spec),
                status: format!("{:?}", meta.status),
                version: meta.version,
                created_at: meta.created_at.to_rfc3339(),
            }),
        }))
    }

    async fn delete_key(
        &self,
        request: Request<pb::DeleteKeyRequest>,
    ) -> Result<Response<DeleteKeyResponse>, Status> {
        let (_, caller_id, caller_tenant) = check_permission(&request, Permission::DELETE_KEY)?;
        let req = request.into_inner();
        let id = uuid::Uuid::parse_str(&req.id)
            .map_err(|_| Status::invalid_argument("invalid key id"))?;
        self.check_pbac(&caller_id, "delete_key", &id.to_string())
            .await?;

        // Security: enforce dual-control approval bound to THIS key for deletion
        // GM/T 0028-2014 requires multi-party approval for destructive operations
        self.require_approved(
            &req.approval_id,
            OperationType::KeyDelete,
            &id.to_string(),
            "key deletion",
        )?;

        let tenant_id_owned = resolve_tenant(caller_tenant.as_deref(), &req.tenant_id)?;
        let tenant_id: &str = &tenant_id_owned;

        let key_svc = self.state.key_service();
        key_svc
            .delete_key(&id, tenant_id, &caller_id)
            .await
            .map_err(api_error_to_status)?;

        // Log audit event
        let event = kms_core::event::Event::key_deleted(&id, &caller_id);
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(DeleteKeyResponse {}))
    }

    async fn list_keys(
        &self,
        request: Request<pb::ListKeysRequest>,
    ) -> Result<Response<ListKeysResponse>, Status> {
        let (_, caller_id, caller_tenant) = check_permission(&request, Permission::LIST_KEYS)?;
        let req = request.into_inner();
        self.check_pbac(&caller_id, "list_keys", "keys").await?;

        let tenant_id_owned = resolve_tenant(caller_tenant.as_deref(), &req.tenant_id)?;
        let tenant_id: &str = &tenant_id_owned;

        let key_svc = self.state.key_service();
        let keys = key_svc
            .list_keys(kms_core::key::KeyFilter::default(), tenant_id)
            .await
            .map_err(api_error_to_status)?;

        // Log audit event
        let event = kms_core::event::Event::new(
            kms_core::event::EventType::KeyAccessed,
            &caller_id,
            "user",
            "list_keys",
            "keys",
            None,
            "success",
        );
        self.state.audit_logger.log_event(&event).await;

        let pb_keys: Vec<Key> = keys
            .into_iter()
            .map(|meta| Key {
                id: meta.id.to_string(),
                tenant_id: meta.tenant_id,
                name: meta.name,
                spec: format!("{:?}", meta.spec),
                status: format!("{:?}", meta.status),
                version: meta.version,
                created_at: meta.created_at.to_rfc3339(),
            })
            .collect();

        Ok(Response::new(ListKeysResponse { keys: pb_keys }))
    }

    async fn sign(
        &self,
        request: Request<pb::SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let (_, caller_id, caller_tenant) = check_permission(&request, Permission::SIGN)?;
        let req = request.into_inner();
        let id = uuid::Uuid::parse_str(&req.key_id)
            .map_err(|_| Status::invalid_argument("invalid key id"))?;
        self.check_pbac(&caller_id, "sign", &id.to_string()).await?;

        use base64::{Engine, engine::general_purpose::STANDARD};

        let data = STANDARD
            .decode(&req.data)
            .map_err(|_| Status::invalid_argument("invalid base64 data"))?;

        let tenant_id_owned = resolve_tenant(caller_tenant.as_deref(), &req.tenant_id)?;
        let tenant_id: &str = &tenant_id_owned;

        let crypto = self.state.crypto_service();
        let signature = crypto
            .sign(&id, &data, tenant_id, &caller_id)
            .await
            .map_err(api_error_to_status)?;

        // Log audit event
        let event = kms_core::event::Event::key_signed(&id, &caller_id);
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(SignResponse {
            signature: STANDARD.encode(&signature.signature),
            version: signature.version,
        }))
    }

    async fn verify(
        &self,
        request: Request<pb::VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let (_, caller_id, caller_tenant) = check_permission(&request, Permission::VERIFY)?;
        let req = request.into_inner();
        let id = uuid::Uuid::parse_str(&req.key_id)
            .map_err(|_| Status::invalid_argument("invalid key id"))?;
        self.check_pbac(&caller_id, "verify", &id.to_string())
            .await?;

        use base64::{Engine, engine::general_purpose::STANDARD};

        let data = STANDARD
            .decode(&req.data)
            .map_err(|_| Status::invalid_argument("invalid base64 data"))?;

        let signature_bytes = STANDARD
            .decode(&req.signature)
            .map_err(|_| Status::invalid_argument("invalid base64 signature"))?;

        let signature = kms_core::key::Signature {
            key_id: id,
            version: 1,
            signature: signature_bytes,
        };

        let tenant_id_owned = resolve_tenant(caller_tenant.as_deref(), &req.tenant_id)?;
        let tenant_id: &str = &tenant_id_owned;

        let crypto = self.state.crypto_service();
        let valid = crypto
            .verify(&id, &data, &signature, tenant_id)
            .await
            .map_err(api_error_to_status)?;

        // Log audit event
        let event = kms_core::event::Event::key_verified(&id, &caller_id, valid);
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(VerifyResponse { valid }))
    }

    async fn hmac(
        &self,
        request: Request<pb::HmacRequest>,
    ) -> Result<Response<pb::HmacResponse>, Status> {
        let (_, caller_id, caller_tenant) = check_permission(&request, Permission::ENCRYPT)?;
        let req = request.into_inner();
        let id = uuid::Uuid::parse_str(&req.key_id)
            .map_err(|_| Status::invalid_argument("invalid key id"))?;
        self.check_pbac(&caller_id, "hmac", &id.to_string()).await?;

        // data/aad are proto `bytes`, already Vec<u8> (no base64 on the gRPC channel).
        let aad = if req.aad.is_empty() {
            None
        } else {
            Some(req.aad.as_slice())
        };

        let tenant_id_owned = resolve_tenant(caller_tenant.as_deref(), &req.tenant_id)?;
        let tenant_id: &str = &tenant_id_owned;

        let crypto = self.state.crypto_service();
        let (mac, version) = crypto
            .hmac(&id, &req.data, aad, tenant_id, &caller_id)
            .await
            .map_err(api_error_to_status)?;

        // Log audit event (reuse the signing event type for MAC computation).
        let event = kms_core::event::Event::key_signed(&id, &caller_id);
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(pb::HmacResponse { mac, version }))
    }

    async fn hmac_verify(
        &self,
        request: Request<pb::HmacVerifyRequest>,
    ) -> Result<Response<pb::HmacVerifyResponse>, Status> {
        let (_, caller_id, caller_tenant) = check_permission(&request, Permission::ENCRYPT)?;
        let req = request.into_inner();
        let id = uuid::Uuid::parse_str(&req.key_id)
            .map_err(|_| Status::invalid_argument("invalid key id"))?;
        self.check_pbac(&caller_id, "hmac_verify", &id.to_string())
            .await?;

        let aad = if req.aad.is_empty() {
            None
        } else {
            Some(req.aad.as_slice())
        };

        let tenant_id_owned = resolve_tenant(caller_tenant.as_deref(), &req.tenant_id)?;
        let tenant_id: &str = &tenant_id_owned;

        let crypto = self.state.crypto_service();
        let valid = crypto
            .hmac_verify(&id, &req.data, aad, &req.mac, tenant_id, &caller_id)
            .await
            .map_err(api_error_to_status)?;

        // Log audit event (reuse the verify event type for MAC verification).
        let event = kms_core::event::Event::key_verified(&id, &caller_id, valid);
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(pb::HmacVerifyResponse { valid }))
    }

    async fn sm9_sign(
        &self,
        request: Request<pb::Sm9SignRequest>,
    ) -> Result<Response<Sm9SignResponse>, Status> {
        let (_, caller_id, _caller_tenant) = check_permission(&request, Permission::SIGN)?;
        let req = request.into_inner();
        self.check_pbac(&caller_id, "sm9_sign", &req.identity)
            .await?;
        use base64::{Engine, engine::general_purpose::STANDARD};

        let data = STANDARD
            .decode(&req.data)
            .map_err(|_| Status::invalid_argument("invalid base64 data"))?;

        let sign_key = self
            .state
            .sm9_state
            .master_key
            .derive_signing_key(req.identity.as_bytes())
            .map_err(|e| Status::internal(e.to_string()))?;
        let signer = gm_sm9_rs::Signer::new(sign_key);

        let signature = signer
            .sign(&data, &mut rand::rng())
            .map_err(|e| Status::internal(e.to_string()))?;
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
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(Sm9SignResponse {
            w: String::new(),
            h: String::new(),
            s: STANDARD.encode(&signature_bytes),
        }))
    }

    async fn sm9_verify(
        &self,
        request: Request<pb::Sm9VerifyRequest>,
    ) -> Result<Response<Sm9VerifyResponse>, Status> {
        let (_, caller_id, _caller_tenant) = check_permission(&request, Permission::VERIFY)?;
        let req = request.into_inner();
        self.check_pbac(&caller_id, "sm9_verify", &req.identity)
            .await?;
        use base64::{Engine, engine::general_purpose::STANDARD};

        let data = STANDARD
            .decode(&req.data)
            .map_err(|_| Status::invalid_argument("invalid base64 data"))?;

        let signature_bytes = STANDARD
            .decode(&req.s)
            .map_err(|_| Status::invalid_argument("invalid base64 s"))?;

        let signature = gm_sm9_rs::Signature::from_der(&signature_bytes)
            .or_else(|_| gm_sm9_rs::Signature::from_bytes(&signature_bytes))
            .map_err(|e| Status::invalid_argument(format!("invalid signature format: {e}")))?;

        let verifier = gm_sm9_rs::Verifier::new(
            req.identity.as_bytes(),
            &self.state.sm9_state.master_key.sign_master().ppubs,
        );

        let valid = verifier
            .verify(&data, &signature)
            .map_err(|e| Status::internal(e.to_string()))?;

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
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(Sm9VerifyResponse { valid }))
    }

    async fn sm9_encrypt(
        &self,
        request: Request<pb::Sm9EncryptRequest>,
    ) -> Result<Response<Sm9EncryptResponse>, Status> {
        let (_, caller_id, _caller_tenant) = check_permission(&request, Permission::ENCRYPT)?;
        let req = request.into_inner();
        self.check_pbac(&caller_id, "sm9_encrypt", &req.identity)
            .await?;
        use base64::{Engine, engine::general_purpose::STANDARD};

        let plaintext = req.plaintext;

        let encryptor = gm_sm9_rs::Encryptor::new(
            req.identity.as_bytes(),
            &self.state.sm9_state.master_key.enc_master().ppube,
        );

        let ciphertext = encryptor
            .encrypt(&plaintext, &mut rand::rng())
            .map_err(|e| Status::internal(e.to_string()))?;
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
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(Sm9EncryptResponse {
            c1: STANDARD.encode(&ciphertext_bytes),
            c2: String::new(),
            c3: String::new(),
        }))
    }

    async fn sm9_decrypt(
        &self,
        request: Request<pb::Sm9DecryptRequest>,
    ) -> Result<Response<Sm9DecryptResponse>, Status> {
        let (_, caller_id, _caller_tenant) = check_permission(&request, Permission::DECRYPT)?;
        let req = request.into_inner();
        self.check_pbac(&caller_id, "sm9_decrypt", &req.identity)
            .await?;
        use base64::{Engine, engine::general_purpose::STANDARD};

        let ciphertext_bytes = STANDARD
            .decode(&req.c1)
            .map_err(|_| Status::invalid_argument("invalid base64 ciphertext"))?;

        let enc_key = self
            .state
            .sm9_state
            .master_key
            .derive_encryption_key(req.identity.as_bytes())
            .map_err(|e| Status::internal(e.to_string()))?;
        let ciphertext = gm_sm9_rs::Ciphertext::from_bytes(&ciphertext_bytes)
            .map_err(|e| Status::invalid_argument(format!("invalid ciphertext: {e}")))?;

        let decryptor = gm_sm9_rs::Decryptor::new(enc_key);

        let plaintext = decryptor
            .decrypt(&ciphertext, req.identity.as_bytes())
            .map_err(|e| Status::internal(e.to_string()))?;

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
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(Sm9DecryptResponse {
            plaintext: plaintext.to_vec(),
        }))
    }

    async fn envelope_encrypt(
        &self,
        request: Request<pb::EnvelopeEncryptRequest>,
    ) -> Result<Response<pb::EnvelopeEncryptResponse>, Status> {
        let (_, caller_id, caller_tenant) = check_permission(&request, Permission::ENCRYPT)?;
        let req = request.into_inner();

        let kek_id = uuid::Uuid::parse_str(&req.kek_id)
            .map_err(|_| Status::invalid_argument("invalid kek_id format"))?;
        self.check_pbac(&caller_id, "envelope_encrypt", &kek_id.to_string())
            .await?;

        let tenant_id_owned = resolve_tenant(caller_tenant.as_deref(), &req.tenant_id)?;
        let tenant_id: &str = &tenant_id_owned;

        let envelope_svc = crate::service::EnvelopeService::new(&self.state);
        let result = envelope_svc
            .encrypt(&kek_id, &req.plaintext, None, tenant_id, &caller_id)
            .await
            .map_err(api_error_to_status)?;

        let event = kms_core::event::Event::key_encrypted(&kek_id, &caller_id, req.plaintext.len());
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(pb::EnvelopeEncryptResponse {
            wrapped_dek: result.wrapped_dek,
            dek_nonce: result.dek_nonce,
            ciphertext: result.ciphertext,
            data_nonce: result.data_nonce,
            tag: result.tag,
            kek_version: result.kek_version,
        }))
    }

    async fn envelope_decrypt(
        &self,
        request: Request<pb::EnvelopeDecryptRequest>,
    ) -> Result<Response<pb::EnvelopeDecryptResponse>, Status> {
        let (_, caller_id, caller_tenant) = check_permission(&request, Permission::DECRYPT)?;
        let req = request.into_inner();

        let kek_id = uuid::Uuid::parse_str(&req.kek_id)
            .map_err(|_| Status::invalid_argument("invalid kek_id format"))?;
        self.check_pbac(&caller_id, "envelope_decrypt", &kek_id.to_string())
            .await?;

        let tenant_id_owned = resolve_tenant(caller_tenant.as_deref(), &req.tenant_id)?;
        let tenant_id: &str = &tenant_id_owned;

        let envelope_svc = crate::service::EnvelopeService::new(&self.state);
        let plaintext = envelope_svc
            .decrypt_with_kek_version(
                &kek_id,
                &req.ciphertext,
                &req.wrapped_dek,
                &req.dek_nonce,
                &req.data_nonce,
                &req.tag,
                None,
                tenant_id,
                &caller_id,
                req.kek_version,
            )
            .await
            .map_err(api_error_to_status)?;

        let event = kms_core::event::Event::key_decrypted(&kek_id, &caller_id, plaintext.len());
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(pb::EnvelopeDecryptResponse {
            plaintext: plaintext.to_vec(),
        }))
    }

    async fn envelope_rewrap(
        &self,
        request: Request<pb::EnvelopeRewrapRequest>,
    ) -> Result<Response<pb::EnvelopeRewrapResponse>, Status> {
        let (_, caller_id, caller_tenant) = check_permission(&request, Permission::ENCRYPT)?;
        let req = request.into_inner();

        let kek_id = uuid::Uuid::parse_str(&req.kek_id)
            .map_err(|_| Status::invalid_argument("invalid kek_id format"))?;
        self.check_pbac(&caller_id, "envelope_rewrap", &kek_id.to_string())
            .await?;

        let tenant_id_owned = resolve_tenant(caller_tenant.as_deref(), &req.tenant_id)?;
        let tenant_id: &str = &tenant_id_owned;

        let envelope_svc = crate::service::EnvelopeService::new(&self.state);
        let result = envelope_svc
            .rewrap_dek(
                &kek_id,
                &req.wrapped_dek,
                &req.dek_nonce,
                req.old_kek_version,
                tenant_id,
            )
            .await
            .map_err(api_error_to_status)?;

        let event = kms_core::event::Event::key_rotated(&kek_id, &caller_id);
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(pb::EnvelopeRewrapResponse {
            wrapped_dek: result.wrapped_dek,
            dek_nonce: result.dek_nonce,
            kek_version: result.kek_version,
            old_kek_version: result.old_kek_version,
        }))
    }

    async fn import_key(
        &self,
        request: Request<pb::ImportKeyRequest>,
    ) -> Result<Response<pb::ImportKeyResponse>, Status> {
        let (_, caller_id, caller_tenant) = check_permission(&request, Permission::IMPORT_KEY)?;
        let req = request.into_inner();
        self.check_pbac(&caller_id, "import_key", &req.name).await?;

        let spec =
            crate::service::KeyService::parse_spec(&req.spec).map_err(api_error_to_status)?;

        let tenant_id_owned = resolve_tenant(caller_tenant.as_deref(), &req.tenant_id)?;
        let tenant_id: &str = &tenant_id_owned;

        let meta = self
            .state
            .keystore
            .import_key_material(&spec, &req.name, tenant_id, req.key_material.clone())
            .await
            .map_err(|e| match e {
                kms_core::Error::KeyNotFound(_) => Status::not_found("key not found"),
                _ => Status::internal(e.to_string()),
            })?;

        let event = kms_core::event::Event::key_imported(&meta.id, &caller_id, "raw");
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(pb::ImportKeyResponse {
            key: Some(Key {
                id: meta.id.to_string(),
                tenant_id: meta.tenant_id,
                name: meta.name,
                spec: format!("{:?}", meta.spec),
                status: format!("{:?}", meta.status),
                version: meta.version,
                created_at: meta.created_at.to_rfc3339(),
            }),
        }))
    }

    async fn export_key(
        &self,
        request: Request<pb::ExportKeyRequest>,
    ) -> Result<Response<pb::ExportKeyResponse>, Status> {
        let (_, caller_id, caller_tenant) = check_permission(&request, Permission::EXPORT_KEY)?;
        let req = request.into_inner();

        let key_id = uuid::Uuid::parse_str(&req.id)
            .map_err(|_| Status::invalid_argument("invalid key id format"))?;
        self.check_pbac(&caller_id, "export_key", &key_id.to_string())
            .await?;

        // Enforce approval gate: an approved, un-expired KeyExport request bound to
        // THIS key. Mirrors the REST API behaviour (see rest.rs export_key).
        self.require_approved(
            &req.approval_id,
            OperationType::KeyExport,
            &key_id.to_string(),
            "key export",
        )?;

        let tenant_id_owned = resolve_tenant(caller_tenant.as_deref(), &req.tenant_id)?;
        let tenant_id: &str = &tenant_id_owned;

        // Wrapped-export semantics (audit P2-5): converge gRPC onto the SAME service-layer
        // method REST uses, so raw key material is never returned over the wire. The caller
        // supplies its public key; the server returns wrapped_key + encrypted_transport_key.
        // The transport-key protection scheme (audit P2-6) mirrors REST.
        let protection =
            crate::service::ExportProtection::parse(Some(req.protection_scheme.as_str()))
                .map_err(api_error_to_status)?;
        let key_svc = self.state.key_service();
        let exported = key_svc
            .export_key(
                &key_id,
                &req.target_public_key,
                &req.purpose,
                tenant_id,
                &caller_id,
                crate::service::ExportOptions {
                    protection,
                    version: (req.version != 0).then_some(req.version),
                },
            )
            .await
            .map_err(api_error_to_status)?;

        let event = kms_core::event::Event::new(
            kms_core::event::EventType::KeyAccessed,
            &caller_id,
            "user",
            "export_key",
            "export",
            Some(key_id.to_string()),
            "success",
        );
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(pb::ExportKeyResponse {
            wrapped_key: exported.wrapped_key,
            encrypted_transport_key: exported.encrypted_transport_key,
            key_fingerprint: exported.key_fingerprint,
        }))
    }

    async fn hash(
        &self,
        request: Request<pb::HashRequest>,
    ) -> Result<Response<pb::HashResponse>, Status> {
        let (_, caller_id, _caller_tenant) = check_permission(&request, Permission::HASH)?;
        let req = request.into_inner();
        self.check_pbac(&caller_id, "hash", "hash").await?;

        let digest = match req.algorithm.to_lowercase().as_str() {
            "sm3" => {
                use gm_crypto::sm3::Sm3Hasher;
                Sm3Hasher::hash(&req.data)
                    .map_err(|e: gm_crypto::CryptoError| Status::internal(e.to_string()))?
                    .to_vec()
            }
            "sha256" => {
                use ring::digest;
                digest::digest(&digest::SHA256, &req.data).as_ref().to_vec()
            }
            _ => {
                return Err(Status::invalid_argument(format!(
                    "unsupported hash algorithm: {} (supported: sm3, sha256)",
                    req.algorithm
                )));
            }
        };

        Ok(Response::new(pb::HashResponse { digest }))
    }

    async fn dh_derive(
        &self,
        request: Request<pb::DhDeriveRequest>,
    ) -> Result<Response<pb::DhDeriveResponse>, Status> {
        let (_, caller_id, caller_tenant) = check_permission(&request, Permission::ENCRYPT)?;
        let req = request.into_inner();

        let key_id = uuid::Uuid::parse_str(&req.key_id)
            .map_err(|_| Status::invalid_argument("invalid key_id format"))?;
        self.check_pbac(&caller_id, "dh_derive", &key_id.to_string())
            .await?;

        // Tenant isolation (audit B7-b): the private key belongs to exactly one
        // tenant, so the derived secret must not be handed to a caller acting
        // for another one. The keystore enforces it too; the check here gives
        // the same sanitized NOT_FOUND answer as the other key operations.
        let tenant_id_owned = resolve_tenant(caller_tenant.as_deref(), &req.tenant_id)?;
        let tenant_id: &str = &tenant_id_owned;
        let meta = self
            .state
            .keystore
            .get_key_metadata(&key_id)
            .await
            .map_err(|_| Status::not_found("key not found"))?;
        if meta.tenant_id != tenant_id {
            return Err(Status::not_found("key not found"));
        }

        // Default to SM2-KEX for gm ecosystem
        let algorithm = kms_core::dh::DhAlgorithm::Sm2Kex;

        let shared_secret = self
            .state
            .keystore
            .derive_shared_secret(&key_id, &req.peer_public, algorithm, tenant_id)
            .await
            .map_err(|e| match e {
                kms_core::Error::KeyNotFound(_) => {
                    Status::not_found(format!("key {key_id} not found"))
                }
                _ => Status::internal(e.to_string()),
            })?;

        let event = kms_core::event::Event::new(
            kms_core::event::EventType::KeyAccessed,
            &caller_id,
            "user",
            "derive_shared_secret",
            "dh",
            Some(key_id.to_string()),
            "success",
        );
        self.state.audit_logger.log_event(&event).await;

        Ok(Response::new(pb::DhDeriveResponse {
            shared_secret: shared_secret.secret.to_vec(),
            public_key: Vec::new(), // peer provides their public key; our public is derived from key_id
        }))
    }

    async fn query_audit_events(
        &self,
        request: Request<pb::QueryAuditEventsRequest>,
    ) -> Result<Response<pb::QueryAuditEventsResponse>, Status> {
        let (_, caller_id, _caller_tenant) = check_permission(&request, Permission::VIEW_AUDIT)?;
        let req = request.into_inner();
        self.check_pbac(&caller_id, "query_audit_events", "audit")
            .await?;

        let event_types: Option<Vec<kms_core::event::EventType>> = if req.event_type.is_empty() {
            None
        } else {
            // Try to match by name; default to KeyAccessed if unknown
            let et = match req.event_type.to_lowercase().as_str() {
                "key_created" | "create" => kms_core::event::EventType::KeyCreated,
                "key_deleted" | "delete" => kms_core::event::EventType::KeyDeleted,
                "key_rotated" | "rotate" => kms_core::event::EventType::KeyRotated,
                "key_imported" | "import" => kms_core::event::EventType::KeyImported,
                "key_exported" | "export" => kms_core::event::EventType::KeyExported,
                "key_accessed" | "access" => kms_core::event::EventType::KeyAccessed,
                "key_encrypted" | "encrypt" => kms_core::event::EventType::KeyEncrypted,
                "key_decrypted" | "decrypt" => kms_core::event::EventType::KeyDecrypted,
                _ => kms_core::event::EventType::KeyAccessed,
            };
            Some(vec![et])
        };

        let filter = kms_audit::AuditFilter {
            event_types,
            actor_id: None,
            resource_id: if req.key_id.is_empty() {
                None
            } else {
                Some(req.key_id.clone())
            },
            start_time: if req.start_time.is_empty() {
                None
            } else {
                req.start_time.parse().ok()
            },
            end_time: if req.end_time.is_empty() {
                None
            } else {
                req.end_time.parse().ok()
            },
            limit: if req.limit == 0 {
                None
            } else {
                Some(req.limit as usize)
            },
            offset: if req.offset == 0 {
                None
            } else {
                Some(req.offset as usize)
            },
        };

        let events = self.state.audit_logger.query(filter).await;
        let total = events.len() as u32;

        let proto_events: Vec<pb::AuditEvent> = events
            .iter()
            .map(|e| pb::AuditEvent {
                id: e.event_id.to_string(),
                event_type: format!("{:?}", e.event_type),
                key_id: e.resource_id.clone().unwrap_or_default(),
                user_id: e.actor_id.clone(),
                tenant_id: String::new(), // audit events don't carry tenant_id directly
                timestamp: e.timestamp.to_rfc3339(),
                details: e
                    .metadata
                    .get("details")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
            .collect();

        Ok(Response::new(pb::QueryAuditEventsResponse {
            events: proto_events,
            total,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ApiKey;
    use tonic::metadata::MetadataValue;

    fn test_api_key_config() -> Arc<ApiKeyConfig> {
        let operator_key = ApiKey::operator("test-operator-key".to_string());
        let readonly_key = ApiKey::read_only("test-readonly-key".to_string());
        Arc::new(ApiKeyConfig::with_keys(vec![operator_key, readonly_key]))
    }

    #[test]
    fn test_interceptor_valid_key() {
        let config = test_api_key_config();
        let mut interceptor = GrpcAuthInterceptor::new(config);

        let mut req = Request::new(());
        req.metadata_mut()
            .insert("x-api-key", MetadataValue::from_static("test-operator-key"));

        let result = interceptor.call(req);
        assert!(result.is_ok(), "valid key should pass");
        let req = result.unwrap();
        let caller = req.extensions().get::<GrpcCaller>().unwrap();
        assert!(caller.role.satisfies(Permission::SIGN));
    }

    #[test]
    fn test_interceptor_bearer_token() {
        let config = test_api_key_config();
        let mut interceptor = GrpcAuthInterceptor::new(config);

        let mut req = Request::new(());
        req.metadata_mut().insert(
            "authorization",
            MetadataValue::from_static("Bearer test-readonly-key"),
        );

        let result = interceptor.call(req);
        assert!(result.is_ok(), "bearer token should pass");
    }

    #[test]
    fn test_interceptor_missing_key() {
        let config = test_api_key_config();
        let mut interceptor = GrpcAuthInterceptor::new(config);

        let req = Request::new(());
        let result = interceptor.call(req);
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn test_interceptor_invalid_key() {
        let config = test_api_key_config();
        let mut interceptor = GrpcAuthInterceptor::new(config);

        let mut req = Request::new(());
        req.metadata_mut()
            .insert("x-api-key", MetadataValue::from_static("wrong-key"));

        let result = interceptor.call(req);
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn test_check_permission_insufficient() {
        let _config = test_api_key_config();
        let mut req = Request::new(());
        req.extensions_mut().insert(GrpcCaller {
            role: ApiKeyPermission::ReadOnly,
            key_id: "test-key".to_string(),
            tenant_id: None,
        });

        let result = check_permission(&req, Permission::CREATE_KEY);
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn test_check_permission_sufficient() {
        let mut req = Request::new(());
        req.extensions_mut().insert(GrpcCaller {
            role: ApiKeyPermission::Operator,
            key_id: "test-key".to_string(),
            tenant_id: None,
        });

        let result = check_permission(&req, Permission::SIGN);
        assert!(result.is_ok());
    }

    // ── resolve_tenant (audit P1-3) ──────────────────────────────────

    #[test]
    fn test_resolve_tenant_bound_overrides_reported() {
        // bound tenant wins; self-reported value ignored (even on mismatch)
        assert_eq!(resolve_tenant(Some("acme"), "evil").unwrap(), "acme");
        assert_eq!(resolve_tenant(Some("acme"), "").unwrap(), "acme");
        assert_eq!(resolve_tenant(Some("acme"), "acme").unwrap(), "acme");
    }

    #[test]
    fn test_resolve_tenant_unbound_honours_reported() {
        assert_eq!(resolve_tenant(None, "tenant-a").unwrap(), "tenant-a");
    }

    #[test]
    fn test_resolve_tenant_unbound_empty_fails_explicitly() {
        // silent "default" fallback removed: unbound + empty must fail with InvalidArgument
        let err = resolve_tenant(None, "").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn test_interceptor_propagates_bound_tenant() {
        let bound_key = ApiKey::operator("bound-key".to_string()).with_tenant("acme".to_string());
        let unbound_key = ApiKey::operator("unbound-key".to_string());
        let config = Arc::new(ApiKeyConfig::with_keys(vec![bound_key, unbound_key]));
        let mut interceptor = GrpcAuthInterceptor::new(config);

        let mut req = Request::new(());
        req.metadata_mut()
            .insert("x-api-key", MetadataValue::from_static("bound-key"));
        let caller = interceptor
            .call(req)
            .unwrap()
            .extensions()
            .get::<GrpcCaller>()
            .unwrap()
            .clone();
        assert_eq!(caller.tenant_id.as_deref(), Some("acme"));

        let mut req2 = Request::new(());
        req2.metadata_mut()
            .insert("x-api-key", MetadataValue::from_static("unbound-key"));
        let caller2 = interceptor
            .call(req2)
            .unwrap()
            .extensions()
            .get::<GrpcCaller>()
            .unwrap()
            .clone();
        assert_eq!(caller2.tenant_id, None);
    }
}
