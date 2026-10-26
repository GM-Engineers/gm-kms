//! 接口层集成测试（真实 axum HTTP 服务器 + reqwest 客户端）。
//!
//! 现有 `integration_tests.rs` 全部在 keystore 层直接调用，**从未触达 HTTP/gRPC
//! 接口处理器**。本文件补齐接口层护栏，专门暴露只在接口层出现的缺陷，例如：
//!
//! - **CRITICAL-NEW**：REST `decrypt` 处理器把 `Ciphertext` 重建为
//!   `format_version: 0`（→ 空 AAD），而 `encrypt` 产出 `format_version: 2`
//!   （AAD 绑定 `key_id/tenant_id/version`）。于是 SM4 / AES-256-GCM 的
//!   加密→解密端到端往返必然 tag 校验失败。keystore 层单测绕过了接口重建，
//!   因此一直没抓到。
//!
//! 装配：`SoftwareKeystore` + 放行 PBAC 策略 + 默认 `AuditLogger` +
//! `Sm9State` + `KmsMetrics`；单个 KeyAdmin API Key 覆盖 create/encrypt/decrypt。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kms_api::auth::{ApiKey, ApiKeyConfig};
use kms_api::grpc::pb;
use kms_api::grpc::pb::kms_service_client::KmsServiceClient;
use kms_api::grpc::pb::kms_service_server::KmsServiceServer;
use kms_api::grpc::{GrpcAuthInterceptor, KmsGrpcService};
use kms_api::{KmsMetrics, KmsState, Sm9State, rest::create_routes};
use kms_audit::AuditLogger;
use kms_core::PolicyEffect;
use kms_keystore::SoftwareKeystore;
use kms_policy::{PBACEngine, Policy};
use serde_json::json;
use tokio::net::TcpListener;

const ADMIN_SECRET: &str = "integration-admin-key-secret";
const OFFICER_SECRET: &str = "integration-officer-key-secret";
const ACME_SECRET: &str = "integration-acme-key-secret";
const ADMIN_HEADER: &str = "x-api-key";

/// Distinct SecurityOfficer keys used as distinct approvers.
///
/// audit follow-up B7-a: the approver identity is derived from the
/// authenticated API key, so one key = one vote. A multi-party quorum
/// therefore requires several *different* keys, not one key replayed with
/// different body-supplied names.
const OFFICER_SECRETS: [&str; 3] = [
    "integration-officer-1-secret",
    "integration-officer-2-secret",
    "integration-officer-3-secret",
];

/// An Operator key: authority level `Double`, which is **below** the `Triple`
/// level a key export requires (audit follow-up B7-a).
const OPERATOR_SECRET: &str = "integration-operator-key-secret";

/// A TenantAdmin key: the only role that reaches the approval engine's `Admin`
/// level, which the `tenant_admin` operation requires (audit follow-up B7-g).
const TENANT_ADMIN_SECRET: &str = "integration-tenant-admin-key-secret";

/// A tenant-bound approver: holds the approve permission, but only within its
/// own tenant (audit follow-up B7-h).
const ACME_OFFICER_SECRET: &str = "integration-acme-officer-key-secret";

/// 起一个绑定随机 loopback 端口的 REST 服务器，返回 `http://addr` base URL 与
/// 服务器后台任务句柄（调用方负责 abort）。
async fn spawn_rest_server() -> (String, reqwest::Client, tokio::task::JoinHandle<()>) {
    spawn_rest_server_with_policies(Vec::new()).await
}

/// Same as [`spawn_rest_server`], plus extra PBAC policies.
///
/// Deny policies are evaluated before allow policies by the PBAC engine, so an
/// extra `Deny` policy can single out one action (audit B7-b).
async fn spawn_rest_server_with_policies(
    extra_policies: Vec<Policy>,
) -> (String, reqwest::Client, tokio::task::JoinHandle<()>) {
    let (base, client, handle, _state) =
        spawn_rest_server_with_policies_and_state(extra_policies).await;
    (base, client, handle)
}

/// Same as [`spawn_rest_server_with_policies`], but also hands back the
/// [`KmsState`] so a test can reach the approval engine directly.
async fn spawn_rest_server_with_policies_and_state(
    extra_policies: Vec<Policy>,
) -> (
    String,
    reqwest::Client,
    tokio::task::JoinHandle<()>,
    Arc<KmsState>,
) {
    // PBAC：注入一条放行全部 subject/resource/action 的策略。
    let engine = PBACEngine::new();
    engine
        .add_policy(Policy {
            id: uuid::Uuid::new_v4(),
            name: "allow-all-integration".to_string(),
            effect: PolicyEffect::Allow,
            condition: json!({ "operator": "always" }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            tenant: None,
            enabled: true,
        })
        .await
        .expect("add policy");
    for policy in extra_policies {
        engine.add_policy(policy).await.expect("add extra policy");
    }

    spawn_rest_server_with_engine_and_state(engine).await
}

/// Boot a REST server with the default allow-all policy and hand back the
/// [`KmsState`] as well (audit B8-d).
async fn spawn_rest_server_with_state() -> (
    String,
    reqwest::Client,
    tokio::task::JoinHandle<()>,
    Arc<KmsState>,
) {
    spawn_rest_server_with_policies_and_state(Vec::new()).await
}

/// Same as [`spawn_rest_server_with_policies`], but with **no** policy at all.
///
/// This mirrors a production deployment: the server starts with an empty PBAC
/// engine and never loads policies at startup (audit follow-up B7-g). Before
/// the fix, every protected endpoint answered 403 in this state, i.e. the KMS
/// was unusable out of the box.
async fn spawn_rest_server_without_policy() -> (String, reqwest::Client, tokio::task::JoinHandle<()>)
{
    spawn_rest_server_with_engine(PBACEngine::new()).await
}

/// Boot a REST server on top of the given PBAC engine.
async fn spawn_rest_server_with_engine(
    engine: PBACEngine,
) -> (String, reqwest::Client, tokio::task::JoinHandle<()>) {
    let (base, client, handle, _state) = spawn_rest_server_with_engine_and_state(engine).await;
    (base, client, handle)
}

/// Same as [`spawn_rest_server_with_engine`], but also hands back the
/// [`KmsState`] so a test can reach the approval engine directly.
///
/// Audit B8-d: an approval request that is *approved but already expired*
/// cannot be produced through the REST API (`create_request` always derives a
/// future `expires_at`), so the interface-level expiry guard needs this hook
/// to inject one.
async fn spawn_rest_server_with_engine_and_state(
    engine: PBACEngine,
) -> (
    String,
    reqwest::Client,
    tokio::task::JoinHandle<()>,
    Arc<KmsState>,
) {
    // keystore
    let keystore = Arc::new(SoftwareKeystore::new());

    let audit = Arc::new(AuditLogger::default());
    let sm9 = Sm9State::from_key(gm_sm9_rs::KgcMasterKey::generate().expect("sm9 master key"));
    let metrics = KmsMetrics::new();

    let state = Arc::new(KmsState::new(keystore, engine, audit, sm9, metrics));

    let api_key_config = ApiKeyConfig::with_keys(vec![
        ApiKey::key_admin(ADMIN_SECRET.to_string()).with_key_id("admin".to_string()),
        ApiKey::security_officer(OFFICER_SECRET.to_string()).with_key_id("officer".to_string()),
        // Distinct approver keys (audit follow-up B7-a): each key is one vote.
        ApiKey::security_officer(OFFICER_SECRETS[0].to_string())
            .with_key_id("officer-1".to_string()),
        ApiKey::security_officer(OFFICER_SECRETS[1].to_string())
            .with_key_id("officer-2".to_string()),
        ApiKey::security_officer(OFFICER_SECRETS[2].to_string())
            .with_key_id("officer-3".to_string()),
        // Lower authority: may not approve a Triple-level (key export) request.
        ApiKey::operator(OPERATOR_SECRET.to_string()).with_key_id("operator".to_string()),
        // Admin-level authority: the only role that can approve a
        // `tenant_admin` request (audit follow-up B7-g).
        ApiKey::tenant_admin(TENANT_ADMIN_SECRET.to_string())
            .with_key_id("tenant-admin".to_string()),
        // Tenant-bound admin key (audit P1-3): server derives tenant="acme" from this
        // identity and ignores any self-reported tenant.
        ApiKey::key_admin(ACME_SECRET.to_string())
            .with_key_id("acme".to_string())
            .with_tenant("acme".to_string()),
        // Tenant-bound approver: it may approve, but only within its own
        // tenant (audit follow-up B7-h).
        ApiKey::security_officer(ACME_OFFICER_SECRET.to_string())
            .with_key_id("acme-officer".to_string())
            .with_tenant("acme".to_string()),
    ]);

    let app = create_routes(Arc::clone(&state), api_key_config);

    let listener = TcpListener::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // 等待就绪：轮询公开健康端点直到 200（避免首次请求竞态）。
    for _ in 0..100 {
        if client
            .get(format!("{base}/v1/health"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    (base, client, handle, state)
}

/// 建一把密钥，返回其 id（字符串）。
async fn create_key(
    client: &reqwest::Client,
    base: &str,
    name: &str,
    spec: &str,
    tenant: &str,
) -> String {
    let resp = client
        .post(format!("{base}/v1/keys"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "name": name, "spec": spec, "tenant_id": tenant }))
        .send()
        .await
        .expect("create_key send");
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|_| json!({"__nonjson": true}));
    assert!(
        status.is_success(),
        "create_key({spec}) failed: {status} body={body}"
    );
    body["id"].as_str().expect("key id").to_string()
}

/// REST 加密，返回 (ciphertext, nonce, tag) 的 base64。
async fn encrypt(
    client: &reqwest::Client,
    base: &str,
    key_id: &str,
    tenant: &str,
    plaintext: &[u8],
) -> (String, String, String) {
    let resp = client
        .post(format!(
            "{base}/v1/keys/{key_id}/encrypt?tenant_id={tenant}"
        ))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "plaintext": STANDARD.encode(plaintext), "aad": null }))
        .send()
        .await
        .expect("encrypt send");
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|_| json!({"__nonjson": true}));
    assert!(status.is_success(), "encrypt failed: {status} body={body}");
    (
        body["ciphertext"].as_str().unwrap().to_string(),
        body["nonce"].as_str().unwrap().to_string(),
        body["tag"].as_str().unwrap().to_string(),
    )
}

/// REST 解密，返回 (status_success, plaintext_opt, body_value)。
async fn decrypt(
    client: &reqwest::Client,
    base: &str,
    key_id: &str,
    tenant: &str,
    ct: &str,
    nonce: &str,
    tag: &str,
) -> (bool, Option<Vec<u8>>, serde_json::Value) {
    let resp = client
        .post(format!(
            "{base}/v1/keys/{key_id}/decrypt?tenant_id={tenant}"
        ))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({
            "ciphertext": ct, "nonce": nonce, "tag": tag, "aad": null
        }))
        .send()
        .await
        .expect("decrypt send");
    let ok = resp.status().is_success();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|_| json!({"__nonjson": true}));
    let plaintext = if ok {
        body["plaintext"]
            .as_str()
            .map(|s| STANDARD.decode(s).expect("decode b64 plaintext"))
    } else {
        None
    };
    (ok, plaintext, body)
}

/// 加密→解密往返断言：明文必须原样回来。
///
/// 覆盖 **CRITICAL-NEW**：SM4 / AES-256-GCM 当前会失败（接口解密重建
/// `format_version:0` 空 AAD 与加密绑定 AAD 不一致）；SM2 作为对照应通过。
async fn assert_roundtrip(spec: &str, plaintext: &[u8]) {
    let (base, client, handle) = spawn_rest_server().await;
    let tenant = "tenant-a";
    let key_id = create_key(&client, &base, &format!("key-{spec}"), spec, tenant).await;

    let (ct, nonce, tag) = encrypt(&client, &base, &key_id, tenant, plaintext).await;
    let (ok, got, body) = decrypt(&client, &base, &key_id, tenant, &ct, &nonce, &tag).await;

    handle.abort();

    assert!(
        ok,
        "[{spec}] decrypt returned non-2xx while the same key just encrypted successfully \
         (CRITICAL-NEW interface format_version regression): body={body}"
    );
    assert_eq!(
        got.expect("plaintext"),
        plaintext,
        "[{spec}] round-trip plaintext mismatch"
    );
}

#[tokio::test]
async fn sm4_encrypt_decrypt_roundtrip_rest() {
    assert_roundtrip("sm4", b"country secret plaintext 123").await;
}

#[tokio::test]
async fn aes256gcm_encrypt_decrypt_roundtrip_rest() {
    assert_roundtrip("aes-256-gcm", b"roundtrip via rest interface").await;
}

#[tokio::test]
async fn sm2_encrypt_decrypt_roundtrip_rest() {
    // SM2 走 format_version:1、不绑定 AAD，作为对照用例（应通过）。
    assert_roundtrip("sm2", b"sm2 asymmetric control case").await;
}

// =============================================================================
// Batch 2: export usability (P1-1) + approval resource/expiry binding (P1-2/P2-8)
// + rotation approval gate (P2-4)
// =============================================================================

/// A valid RSA-2048 public key in PKCS#1 DER (base64), for the wrapped-export path.
const RSA_PUB_PKCS1_B64: &str = "MIIBCgKCAQEAutdoRksj77EXTbJUvB0nyAKtIEkEjbpt8Bnu9LsmrwV/UK4he6mT3NaySjOgYJ9NOew0QkGRzD3eyy13Cwam8sISDxlF+2tCOiSACNqDQCs8SY9nQZUwmhZPTrtuWzVeHhR9FDEou+d0FiFSR5zgHnVQ4XPXP9DuYGBkB+DVQweHFW37Qdpr6pCPeTNkUjfCny9N8wlM1qtNUtCDCkuhsEUrvTgZwOnS9pZ78ldPlZfqENjZrRRIZkGjIKMLPusJfgSSbB1wg2Ppb9eP+iSgySUG9IWybAoCWE0e4/uBm9xrgXUubGkBw+G9uj14e2do74lx11rTbNpGxHohSxkPOwIDAQAB";

/// Create a resource-bound approval request (KeyAdmin can, route is AUTHENTICATED).
async fn create_approval(
    client: &reqwest::Client,
    base: &str,
    operation: &str,
    resource_id: &str,
    tenant: &str,
) -> String {
    let resp = client
        .post(format!("{base}/v1/approvals"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({
            "operation": operation,
            "resource_id": resource_id,
            "resource_type": "key",
            "tenant_id": tenant,
            "requestor_id": "requestor-user",
            "justification": "integration test",
        }))
        .send()
        .await
        .expect("create_approval send");
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|_| json!({ "__nonjson": true }));
    assert!(
        status.is_success(),
        "create_approval failed: {status} body={body}"
    );
    body["id"].as_str().expect("approval id").to_string()
}

/// Approve with `n` **distinct** approver keys (audit follow-up B7-a).
///
/// The server derives the approver identity from the authenticated API key,
/// so every vote needs a *different* key; replaying one key with different
/// body-supplied names no longer counts.
async fn approve_n(client: &reqwest::Client, base: &str, approval_id: &str, n: usize) {
    for i in 0..n {
        let secret = OFFICER_SECRETS[i % OFFICER_SECRETS.len()];
        let (status, body) = approve_with(client, base, approval_id, secret, json!({})).await;
        assert!(
            status.is_success(),
            "approve[{i}] failed: {status} body={body}"
        );
    }
}

/// Approve with a specific API key and a specific request body.
///
/// Returns (status, body) so negative tests can assert on the exact outcome.
async fn approve_with(
    client: &reqwest::Client,
    base: &str,
    approval_id: &str,
    secret: &str,
    body: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = client
        .post(format!("{base}/v1/approvals/{approval_id}/approve"))
        .header(ADMIN_HEADER, secret)
        .json(&body)
        .send()
        .await
        .expect("approve send");
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|_| json!({ "__nonjson": true }));
    (status, body)
}

/// Create a resource-bound approval request with a specific API key.
///
/// `extra` is merged into the request body so a test can still send
/// client-supplied identity fields (which the server now ignores) and assert
/// that they cannot be used to impersonate anybody.
///
/// Returns (status, body) so negative tests can assert on the exact outcome.
#[allow(clippy::too_many_arguments)]
async fn create_approval_with(
    client: &reqwest::Client,
    base: &str,
    secret: &str,
    operation: &str,
    resource_id: &str,
    resource_type: &str,
    tenant: &str,
    extra: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let mut body = json!({
        "operation": operation,
        "resource_id": resource_id,
        "resource_type": resource_type,
        "tenant_id": tenant,
        "justification": "integration test",
    });
    if let (Some(obj), Some(extra_obj)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in extra_obj {
            obj.insert(k.clone(), v.clone());
        }
    }
    let resp = client
        .post(format!("{base}/v1/approvals"))
        .header(ADMIN_HEADER, secret)
        .json(&body)
        .send()
        .await
        .expect("create_approval send");
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|_| json!({ "__nonjson": true }));
    (status, body)
}

/// REST export; returns (status, body).
async fn export_key(
    client: &reqwest::Client,
    base: &str,
    key_id: &str,
    tenant: &str,
    approval_id: Option<&str>,
) -> (u16, serde_json::Value) {
    let mut body = json!({
        "target_system": "integration",
        "target_public_key": RSA_PUB_PKCS1_B64,
        "purpose": "migration",
    });
    body["approval_id"] = match approval_id {
        Some(id) => json!(id),
        None => json!(null),
    };
    let resp = client
        .post(format!("{base}/v1/keys/export/{key_id}?tenant_id={tenant}"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&body)
        .send()
        .await
        .expect("export send");
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|_| json!({ "__nonjson": true }));
    (status, body)
}

/// REST rotate; returns (status, body).
async fn rotate_key(
    client: &reqwest::Client,
    base: &str,
    key_id: &str,
    tenant: &str,
    approval_id: Option<&str>,
) -> (u16, serde_json::Value) {
    let url = match approval_id {
        Some(id) => format!("{base}/v1/keys/{key_id}/rotate?tenant_id={tenant}&approval_id={id}"),
        None => format!("{base}/v1/keys/{key_id}/rotate?tenant_id={tenant}"),
    };
    let resp = client
        .post(url)
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .send()
        .await
        .expect("rotate send");
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|_| json!({ "__nonjson": true }));
    (status, body)
}

/// P1-1: a properly approved, resource-bound export with the real tenant now succeeds
/// (previously the handler hardcoded `""` and every REST export returned 404).
#[tokio::test]
async fn export_key_rest_requires_bound_approval() {
    let (base, client, handle) = spawn_rest_server().await;
    let tenant = "tenant-a";
    let key_id = create_key(&client, &base, "export-ok", "sm4", tenant).await;

    let approval_id = create_approval(&client, &base, "key_export", &key_id, tenant).await;
    approve_n(&client, &base, &approval_id, 3).await; // Triple

    let (status, body) = export_key(&client, &base, &key_id, tenant, Some(&approval_id)).await;
    handle.abort();

    assert_eq!(
        status, 200,
        "export should succeed with bound approval: body={body}"
    );
    assert!(
        body["wrapped_key"].as_str().is_some_and(|s| !s.is_empty()),
        "export response must carry wrapped_key: body={body}"
    );
    assert!(
        body["encrypted_transport_key"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "export response must carry encrypted_transport_key: body={body}"
    );
    // audit P3-4: the misleading dead fields must no longer be present.
    assert!(
        body.get("export_id").is_none() && body.get("expires_at").is_none(),
        "export response must not advertise a non-existent pull-back flow: body={body}"
    );
}

/// P1-2: an approval bound to key A cannot unlock an export of key B.
#[tokio::test]
async fn export_key_rest_rejects_unbound_resource() {
    let (base, client, handle) = spawn_rest_server().await;
    let tenant = "tenant-a";
    let key_a = create_key(&client, &base, "key-a", "sm4", tenant).await;
    let key_b = create_key(&client, &base, "key-b", "sm4", tenant).await;

    // Approval bound to key_a, fully approved for KeyExport.
    let approval_id = create_approval(&client, &base, "key_export", &key_a, tenant).await;
    approve_n(&client, &base, &approval_id, 3).await;

    // Using that approval to export key_b must be rejected at the interface gate.
    let (status, body) = export_key(&client, &base, &key_b, tenant, Some(&approval_id)).await;
    handle.abort();

    // The approval gate answers with 403 (Forbidden) — the same code the gRPC
    // channel reports as PERMISSION_DENIED; assert the exact code so an
    // internal error (500) cannot satisfy this test.
    assert_eq!(
        status, 403,
        "cross-resource export must be rejected by the approval gate: body={body}"
    );
}

/// Audit B8-d: an approval request that is **approved but already expired**
/// must not unlock a key export at the interface level.
///
/// The engine's expiry rule (`is_approved`: `Utc::now() <= expires_at`) had
/// unit-level coverage only. The interface layer is where key material
/// actually leaves the KMS, so the guard needs its own case: a request that
/// was approved while valid and expired afterwards must stop authorizing the
/// export.
#[tokio::test]
async fn b8d_export_rejects_an_expired_approval() {
    let (base, client, handle, state) = spawn_rest_server_with_state().await;
    let tenant = "tenant-a";
    let key_id = create_key(&client, &base, "expired-approval", "sm4", tenant).await;

    // A fully approved (Triple quorum) KeyExport request bound to THIS key,
    // whose deadline has already passed.
    let approval_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    let request = kms_approval::ApprovalRequestEntity {
        id: approval_id,
        operation: kms_approval::OperationType::KeyExport,
        resource_id: key_id.clone(),
        resource_type: "key".to_string(),
        tenant_id: tenant.to_string(),
        requestor_id: "requestor-user".to_string(),
        justification: Some("interface-level expiry guard".to_string()),
        status: kms_approval::ApprovalStatus::Approved,
        required_level: kms_approval::ApprovalLevel::Triple,
        current_level: kms_approval::ApprovalLevel::Triple,
        approvals: (0..3)
            .map(|i| kms_approval::ApprovalRecord {
                approver_id: format!("officer-{i}"),
                level: kms_approval::ApprovalLevel::Triple,
                approved_at: now - chrono::Duration::hours(2),
                comment: None,
            })
            .collect(),
        rejections: Vec::new(),
        created_at: now - chrono::Duration::hours(3),
        expires_at: now - chrono::Duration::hours(1),
        completed_at: Some(now - chrono::Duration::hours(2)),
        metadata: serde_json::json!({}),
    };
    {
        let mut guard = state.approval_manager.write();
        guard
            .restore_request(request)
            .expect("the expired approval must be restorable");
    }

    let (status, body) = export_key(
        &client,
        &base,
        &key_id,
        tenant,
        Some(&approval_id.to_string()),
    )
    .await;
    handle.abort();

    assert_eq!(
        status, 403,
        "an expired approval must not unlock a key export: body={body}"
    );
    assert!(
        body.get("wrapped_key").is_none(),
        "no key material may leave the KMS with an expired approval: body={body}"
    );
}

/// P1-1 defense-in-depth: correct bound approval but wrong tenant => 404 (service-layer
// ownership check rejects cross-tenant).
#[tokio::test]
async fn export_key_rest_rejects_cross_tenant() {
    let (base, client, handle) = spawn_rest_server().await;
    let tenant = "tenant-a";
    let key_id = create_key(&client, &base, "xtenant", "sm4", tenant).await;

    let approval_id = create_approval(&client, &base, "key_export", &key_id, tenant).await;
    approve_n(&client, &base, &approval_id, 3).await;

    // Request export under a DIFFERENT tenant: gate passes (resource matches), then
    // the service-layer tenant-ownership check returns 404.
    let (status, body) = export_key(&client, &base, &key_id, "tenant-b", Some(&approval_id)).await;
    handle.abort();

    assert_eq!(status, 404, "cross-tenant export must be 404: body={body}");
}

/// P2-4: rotation now requires a resource-bound KeyRotate (Double) approval.
#[tokio::test]
async fn rotate_key_requires_approval() {
    let (base, client, handle) = spawn_rest_server().await;
    let tenant = "tenant-a";
    let key_id = create_key(&client, &base, "rotate-me", "sm4", tenant).await;

    // Without approval => rejected. A *missing* approval_id is a malformed
    // call (400 Bad Request); an approval that exists but is not (yet) valid
    // for this key is an authorization failure (403 Forbidden).
    let (no_appr_status, body1) = rotate_key(&client, &base, &key_id, tenant, None).await;
    assert_eq!(
        no_appr_status, 400,
        "rotate without approval must be rejected by the approval gate: body={body1}"
    );

    // With a bound, fully approved KeyRotate (Double => 2 approvers) => success.
    let approval_id = create_approval(&client, &base, "key_rotate", &key_id, tenant).await;
    approve_n(&client, &base, &approval_id, 2).await;
    let (ok_status, body2) = rotate_key(&client, &base, &key_id, tenant, Some(&approval_id)).await;
    handle.abort();

    assert_eq!(
        ok_status, 200,
        "rotate with bound approval should succeed: body={body2}"
    );
}

// =============================================================================
// Batch 3: multi-tenant identity binding (audit P1-3)
// =============================================================================

/// A key bound to tenant "acme" ignores the tenant self-reported in the request body:
/// the created key lands under the bound tenant, not the spoofed one.
#[tokio::test]
async fn bound_key_overrides_self_reported_body_tenant() {
    let (base, client, handle) = spawn_rest_server().await;

    let resp = client
        .post(format!("{base}/v1/keys"))
        .header(ADMIN_HEADER, ACME_SECRET)
        .json(&json!({ "name": "acme-key", "spec": "sm4", "tenant_id": "evil" }))
        .send()
        .await
        .expect("create send");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("json");
    handle.abort();

    assert!(
        status.is_success(),
        "create should succeed: {status} body={body}"
    );
    assert_eq!(
        body["tenant_id"].as_str(),
        Some("acme"),
        "bound key must be created under its own tenant, ignoring the spoofed body value: body={body}"
    );
}

/// A key bound to "acme" cannot read another tenant's key even when it reports that
/// tenant in the query: resolution forces "acme", so the foreign key is not found (404),
/// while the owning (unbound) admin key can still read it.
#[tokio::test]
async fn bound_key_confined_to_its_tenant() {
    let (base, client, handle) = spawn_rest_server().await;

    // Unbound admin creates a key under tenant "victim".
    let victim_key = create_key(&client, &base, "victim-key", "sm4", "victim").await;

    // Bound "acme" key reports tenant=victim => forced to "acme" => foreign key 404.
    let as_acme = client
        .get(format!("{base}/v1/keys/{victim_key}?tenant_id=victim"))
        .header(ADMIN_HEADER, ACME_SECRET)
        .send()
        .await
        .expect("acme get send");
    let acme_status = as_acme.status().as_u16();

    // Sanity: the owning (unbound) admin key reading the same tenant IS authorized.
    let as_admin = client
        .get(format!("{base}/v1/keys/{victim_key}?tenant_id=victim"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .send()
        .await
        .expect("admin get send");
    let admin_status = as_admin.status().as_u16();

    handle.abort();

    assert_eq!(
        admin_status, 200,
        "unbound owner should read its own tenant key"
    );
    assert_eq!(
        acme_status, 404,
        "bound key must not reach another tenant's key by reporting that tenant"
    );
}

// =============================================================================
// Batch 4: versioned export + interface decrypt version echo (audit P2-2/P2-3)
// =============================================================================

/// Encrypt via REST, returning (ciphertext, nonce, tag, format_version, key_version).
async fn encrypt_with_meta(
    client: &reqwest::Client,
    base: &str,
    key_id: &str,
    tenant: &str,
    plaintext: &[u8],
) -> (String, String, String, u8, u32) {
    let resp = client
        .post(format!(
            "{base}/v1/keys/{key_id}/encrypt?tenant_id={tenant}"
        ))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "plaintext": STANDARD.encode(plaintext), "aad": null }))
        .send()
        .await
        .expect("encrypt send");
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|_| json!({"__nonjson": true}));
    assert!(status.is_success(), "encrypt failed: {status} body={body}");
    (
        body["ciphertext"].as_str().unwrap().to_string(),
        body["nonce"].as_str().unwrap().to_string(),
        body["tag"].as_str().unwrap().to_string(),
        body["format_version"].as_u64().unwrap_or(2) as u8,
        body["version"].as_u64().unwrap_or(1) as u32,
    )
}

/// Decrypt via REST echoing the exact `format_version`/`version` from encryption.
#[allow(clippy::too_many_arguments)]
async fn decrypt_with_version(
    client: &reqwest::Client,
    base: &str,
    key_id: &str,
    tenant: &str,
    ct: &str,
    nonce: &str,
    tag: &str,
    format_version: u8,
    version: u32,
) -> (bool, Option<Vec<u8>>, serde_json::Value) {
    let resp = client
        .post(format!(
            "{base}/v1/keys/{key_id}/decrypt?tenant_id={tenant}"
        ))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({
            "ciphertext": ct,
            "nonce": nonce,
            "tag": tag,
            "aad": null,
            "format_version": format_version,
            "version": version,
        }))
        .send()
        .await
        .expect("decrypt send");
    let ok = resp.status().is_success();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|_| json!({"__nonjson": true}));
    let plaintext = if ok {
        body["plaintext"]
            .as_str()
            .map(|s| STANDARD.decode(s).expect("decode b64 plaintext"))
    } else {
        None
    };
    (ok, plaintext, body)
}

/// After a rotation the active key version bumps to 2. A ciphertext produced
/// post-rotation binds AAD to version 2; REST must echo that version to decrypt.
/// Before the audit P2-3 fix the handler hardcoded `version: 1`, so this failed.
#[tokio::test]
async fn decrypt_after_rotation_echoes_version_rest() {
    let (base, client, handle) = spawn_rest_server().await;
    let tenant = "tenant-a";
    let key_id = create_key(&client, &base, "rotate-decrypt", "aes-256-gcm", tenant).await;

    // Encrypt -> rotate (bound KeyRotate approval, Double => 2) -> encrypt again.
    let approval_id = create_approval(&client, &base, "key_rotate", &key_id, tenant).await;
    approve_n(&client, &base, &approval_id, 2).await;
    let (rot_status, rot_body) =
        rotate_key(&client, &base, &key_id, tenant, Some(&approval_id)).await;
    assert_eq!(
        rot_status, 200,
        "rotation should succeed with bound approval: body={rot_body}"
    );

    // New ciphertext now uses the bumped key version (2).
    let secret = b"post-rotation ciphertext must decrypt with echoed version";
    let (ct, nonce, tag, fmt, ver) =
        encrypt_with_meta(&client, &base, &key_id, tenant, secret).await;
    assert_eq!(fmt, 2, "AES-GCM should use format_version 2");
    assert_eq!(ver, 2, "post-rotation encryption should use key version 2");

    let (ok, got, body) =
        decrypt_with_version(&client, &base, &key_id, tenant, &ct, &nonce, &tag, fmt, ver).await;
    handle.abort();

    assert!(
        ok,
        "decrypting a version-2 ciphertext with echoed version must succeed (P2-3): body={body}"
    );
    assert_eq!(
        got.expect("plaintext"),
        secret,
        "round-trip plaintext mismatch"
    );
}

// =============================================================================
// Batch 5: managed HMAC-SM3 (audit P2-1)
// =============================================================================

/// REST compute+verify round-trip over the dedicated /hmac endpoints, and that
/// an AES key is rejected for HMAC (the MAC path is spec-gated, not a silent
/// fallback onto AES-GCM).
#[tokio::test]
async fn hmac_sm3_compute_verify_rest() {
    let (base, client, handle) = spawn_rest_server().await;
    let tenant = "tenant-a";
    let key_id = create_key(&client, &base, "mac-rest", "hmac-sm3", tenant).await;

    let payload = STANDARD.encode(b"the quick brown fox");

    // Compute
    let resp = client
        .post(format!("{base}/v1/keys/{key_id}/hmac?tenant_id={tenant}"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "data": payload, "aad": null }))
        .send()
        .await
        .expect("hmac send");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("hmac json");
    assert!(
        status.is_success(),
        "hmac compute should succeed: {status} body={body}"
    );
    let mac = body["mac"].as_str().expect("mac field").to_string();
    assert_eq!(
        STANDARD.decode(&mac).expect("decode mac").len(),
        32,
        "SM3 tag is 32 bytes"
    );
    assert_eq!(body["version"].as_u64(), Some(1), "fresh key version 1");

    // Verify (correct)
    let resp = client
        .post(format!(
            "{base}/v1/keys/{key_id}/hmac/verify?tenant_id={tenant}"
        ))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "data": payload, "mac": mac, "aad": null }))
        .send()
        .await
        .expect("hmac verify send");
    let vbody: serde_json::Value = resp.json().await.expect("hmac verify json");
    assert_eq!(
        vbody["valid"].as_bool(),
        Some(true),
        "valid MAC must verify"
    );

    // Verify (tampered data)
    let resp = client
        .post(format!(
            "{base}/v1/keys/{key_id}/hmac/verify?tenant_id={tenant}"
        ))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "data": STANDARD.encode(b"tampered"), "mac": mac, "aad": null }))
        .send()
        .await
        .expect("hmac verify tampered send");
    let tbody: serde_json::Value = resp.json().await.expect("hmac verify tampered json");
    assert_eq!(
        tbody["valid"].as_bool(),
        Some(false),
        "MAC must not verify over altered data"
    );

    // A non-HMAC key must be rejected (spec gate), not silently MAC'd via AES-GCM.
    let aes_id = create_key(&client, &base, "not-a-mac", "aes-256-gcm", tenant).await;
    let resp = client
        .post(format!("{base}/v1/keys/{aes_id}/hmac?tenant_id={tenant}"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "data": payload, "aad": null }))
        .send()
        .await
        .expect("hmac on aes send");
    handle.abort();
    assert!(
        !resp.status().is_success(),
        "HMAC over a non-SM3-HMAC key must be rejected: status={}",
        resp.status()
    );
}

// =============================================================================
// Batch 6 / P4-3: REST <-> gRPC cross-channel semantic consistency.
//
// Both channels converge on the SAME service layer (`KeyService`/`CryptoService`)
// and the SAME keystore. These tests boot a single shared `KmsState` behind both
// an axum REST router and a tonic gRPC server, then assert that the invariants
// documented in `docs/api-semantics.md` hold identically on both transports:
//   * an (key_id, tenant, version, format 2) ciphertext produced on one channel
//     decrypts on the other (AAD-binding convergence);
//   * not-found and cross-tenant access fail on both channels with the same
//     sanitized "not found" semantics.
// =============================================================================

/// Wrap a gRPC request with the `x-api-key` admin metadata so it passes the
/// server's `GrpcAuthInterceptor` (mirrors the REST `x-api-key` header).
fn admin_req<T>(msg: T) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.metadata_mut().insert(
        "x-api-key",
        tonic::metadata::MetadataValue::from_static(ADMIN_SECRET),
    );
    req
}

/// A REST + gRPC server pair sharing one keystore/state.
struct DualStack {
    base: String,
    client: reqwest::Client,
    grpc: KmsServiceClient<tonic::transport::Channel>,
    _handles: Vec<tokio::task::JoinHandle<()>>,
}

/// Boot REST (axum) + gRPC (tonic) over one shared `KmsState` on random loopback
/// ports. The `admin` key is unbound, so both channels honour the self-reported
/// tenant — letting a test drive the same tenant on both transports.
async fn spawn_dual_stack() -> DualStack {
    spawn_dual_stack_with_policies(Vec::new()).await
}

/// Same as [`spawn_dual_stack`], plus extra PBAC policies.
///
/// Both channels share one engine, so a policy that denies an action blocks
/// the REST *and* the gRPC endpoint of that action (audit follow-up B7-g).
async fn spawn_dual_stack_with_policies(extra_policies: Vec<Policy>) -> DualStack {
    let keystore = Arc::new(SoftwareKeystore::new());

    let engine = PBACEngine::new();
    engine
        .add_policy(Policy {
            id: uuid::Uuid::new_v4(),
            name: "allow-all-integration".to_string(),
            effect: PolicyEffect::Allow,
            condition: json!({ "operator": "always" }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            tenant: None,
            enabled: true,
        })
        .await
        .expect("add policy");
    for policy in extra_policies {
        engine.add_policy(policy).await.expect("add extra policy");
    }

    let audit = Arc::new(AuditLogger::default());
    let sm9 = Sm9State::from_key(gm_sm9_rs::KgcMasterKey::generate().expect("sm9 master key"));
    let metrics = KmsMetrics::new();
    let state = Arc::new(KmsState::new(keystore, engine, audit, sm9, metrics));

    let api_key_config = ApiKeyConfig::with_keys(vec![
        ApiKey::key_admin(ADMIN_SECRET.to_string()).with_key_id("admin".to_string()),
        ApiKey::security_officer(OFFICER_SECRET.to_string()).with_key_id("officer".to_string()),
    ]);

    // REST listener.
    let app = create_routes(state.clone(), api_key_config.clone());
    let rest_listener = TcpListener::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .expect("bind rest");
    let rest_addr = rest_listener.local_addr().expect("rest addr");
    let rest_handle = tokio::spawn(async move {
        axum::serve(rest_listener, app).await.expect("serve rest");
    });

    // gRPC listener sharing the same state + api keys.
    let grpc_listener = TcpListener::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .expect("bind grpc");
    let grpc_addr = grpc_listener.local_addr().expect("grpc addr");
    let service = KmsServiceServer::with_interceptor(
        KmsGrpcService::new(state.clone()),
        GrpcAuthInterceptor::new(Arc::new(api_key_config)),
    );
    let incoming: tonic::transport::server::TcpIncoming = grpc_listener.into();
    let incoming = incoming.with_nodelay(Some(true));
    let grpc_handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await
            .expect("serve grpc");
    });

    let client = reqwest::Client::new();
    let base = format!("http://{rest_addr}");

    // Wait for REST readiness via the public health endpoint.
    for _ in 0..100 {
        if client
            .get(format!("{base}/v1/health"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Connect the gRPC client (retry until the server task is accepting).
    let grpc_url = format!("http://{grpc_addr}");
    let mut grpc = None;
    for _ in 0..100 {
        match KmsServiceClient::connect(grpc_url.clone()).await {
            Ok(c) => {
                grpc = Some(c);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    let grpc = grpc.expect("grpc client connect");

    DualStack {
        base,
        client,
        grpc,
        _handles: vec![rest_handle, grpc_handle],
    }
}

/// gRPC encrypt: returns (ciphertext, nonce, tag) base64 + version + format_version.
async fn grpc_encrypt(
    grpc: &mut KmsServiceClient<tonic::transport::Channel>,
    key_id: &str,
    tenant: &str,
    plaintext: &[u8],
) -> (String, String, String, u32, u32) {
    let resp = grpc
        .encrypt(admin_req(pb::EncryptRequest {
            key_id: key_id.to_string(),
            plaintext: plaintext.to_vec(),
            aad: Vec::new(),
            tenant_id: tenant.to_string(),
        }))
        .await
        .expect("grpc encrypt")
        .into_inner();
    (
        resp.ciphertext,
        resp.nonce,
        resp.tag,
        resp.version,
        resp.format_version,
    )
}

/// gRPC decrypt: returns the Result-carrying Status so callers can assert errors.
async fn grpc_decrypt(
    grpc: &mut KmsServiceClient<tonic::transport::Channel>,
    key_id: &str,
    tenant: &str,
    ct: &str,
    nonce: &str,
    tag: &str,
    version: u32,
) -> Result<Vec<u8>, tonic::Status> {
    let resp = grpc
        .decrypt(admin_req(pb::DecryptRequest {
            key_id: key_id.to_string(),
            ciphertext: ct.to_string(),
            nonce: nonce.to_string(),
            tag: tag.to_string(),
            aad: Vec::new(),
            version,
            tenant_id: tenant.to_string(),
            format_version: None, // defaults to production format 2 (matches REST)
        }))
        .await?;
    Ok(resp.into_inner().plaintext)
}

#[tokio::test]
async fn p43_ciphertext_interops_across_rest_and_grpc() {
    // audit P4-3 invariant: AAD binding (key_id, tenant, version, format 2) is
    // computed identically on both channels, so a ciphertext sealed on one
    // decrypts on the other.
    let mut stack = spawn_dual_stack().await;
    let tenant = "tenant-a";
    let plaintext = b"cross-channel interop plaintext";
    let key_id = create_key(&stack.client, &stack.base, "key-p43", "sm4", tenant).await;

    // Seal on REST -> open on gRPC.
    let (ct, nonce, tag) = encrypt(&stack.client, &stack.base, &key_id, tenant, plaintext).await;
    let got = grpc_decrypt(&mut stack.grpc, &key_id, tenant, &ct, &nonce, &tag, 1)
        .await
        .expect("gRPC must decrypt a REST-produced ciphertext (shared AAD binding)");
    assert_eq!(got, plaintext, "REST->gRPC round-trip plaintext mismatch");

    // Seal on gRPC -> open on REST.
    let (ct2, nonce2, tag2, version2, fmt2) =
        grpc_encrypt(&mut stack.grpc, &key_id, tenant, plaintext).await;
    assert_eq!(fmt2, 2, "gRPC encrypt should use production format 2");
    assert_eq!(version2, 1, "fresh key version 1");
    let (ok, got2, body) = decrypt(
        &stack.client,
        &stack.base,
        &key_id,
        tenant,
        &ct2,
        &nonce2,
        &tag2,
    )
    .await;
    assert!(
        ok,
        "REST must decrypt a gRPC-produced ciphertext: body={body}"
    );
    assert_eq!(
        got2.expect("plaintext"),
        plaintext,
        "gRPC->REST round-trip mismatch"
    );
}

#[tokio::test]
async fn p43_not_found_maps_consistently_across_channels() {
    // audit P4-3 error-mapping invariant (the aligned KeyNotFound row): a missing
    // key yields REST 404 and gRPC NOT_FOUND on both channels.
    let mut stack = spawn_dual_stack().await;
    let tenant = "tenant-a";
    let missing = uuid::Uuid::new_v4().to_string();

    let resp = stack
        .client
        .post(format!(
            "{}/v1/keys/{missing}/encrypt?tenant_id={tenant}",
            stack.base
        ))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "plaintext": STANDARD.encode(b"x"), "aad": null }))
        .send()
        .await
        .expect("rest encrypt send");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "REST: missing key -> 404"
    );

    let err = stack
        .grpc
        .encrypt(admin_req(pb::EncryptRequest {
            key_id: missing.clone(),
            plaintext: b"x".to_vec(),
            aad: Vec::new(),
            tenant_id: tenant.to_string(),
        }))
        .await
        .expect_err("gRPC: missing key must error");
    assert_eq!(
        err.code(),
        tonic::Code::NotFound,
        "gRPC: missing key -> NOT_FOUND"
    );
}

#[tokio::test]
async fn p43_cross_tenant_denied_on_both_channels() {
    // audit P4-3 tenant-isolation invariant: a key owned by tenant-a is not usable
    // under tenant-b on either channel (both fail-closed with the sanitized
    // not-found semantics used to avoid cross-tenant enumeration).
    let mut stack = spawn_dual_stack().await;
    let key_id = create_key(&stack.client, &stack.base, "key-iso", "sm4", "tenant-a").await;

    // Same-tenant encrypt works on both channels (baseline).
    let _ = encrypt(&stack.client, &stack.base, &key_id, "tenant-a", b"ok").await;
    let _ = grpc_encrypt(&mut stack.grpc, &key_id, "tenant-a", b"ok").await;

    // Cross-tenant must fail on REST.
    let resp = stack
        .client
        .post(format!(
            "{}/v1/keys/{key_id}/encrypt?tenant_id=tenant-b",
            stack.base
        ))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "plaintext": STANDARD.encode(b"nope"), "aad": null }))
        .send()
        .await
        .expect("rest cross-tenant send");
    assert!(
        !resp.status().is_success(),
        "REST cross-tenant encrypt must be denied: status={}",
        resp.status()
    );

    // Cross-tenant must fail on gRPC too.
    let err = stack
        .grpc
        .encrypt(admin_req(pb::EncryptRequest {
            key_id: key_id.clone(),
            plaintext: b"nope".to_vec(),
            aad: Vec::new(),
            tenant_id: "tenant-b".to_string(),
        }))
        .await
        .expect_err("gRPC cross-tenant encrypt must be denied");
    assert_eq!(
        err.code(),
        tonic::Code::NotFound,
        "gRPC cross-tenant uses the sanitized NOT_FOUND semantics"
    );
}

// =============================================================================
// Batch 7 / B7-a: approval identity must come from the authenticated API key
//
// Before this fix the requestor, the approver and the approver's role were all
// taken from the request body. A single API key could therefore post three
// approvals with three different body-supplied names and satisfy the
// `Triple` quorum that a key export requires, and could cancel or reject
// requests raised by other principals. These tests pin the fixed behaviour.
// =============================================================================

/// The core regression: one key replayed with different body-supplied approver
/// names must NOT be able to forge a three-party quorum.
#[tokio::test]
async fn b7a_single_key_cannot_forge_multi_party_quorum() {
    let (base, client, handle) = spawn_rest_server().await;
    let tenant = "tenant-a";
    let key_id = create_key(&client, &base, "quorum-key", "sm4", tenant).await;

    let approval_id = create_approval(&client, &base, "key_export", &key_id, tenant).await;

    // First vote with the officer key: legitimate, succeeds.
    let (s1, b1) = approve_with(
        &client,
        &base,
        &approval_id,
        OFFICER_SECRETS[0],
        json!({ "approver_id": "alice", "approver_role": "admin" }),
    )
    .await;
    assert_eq!(s1, 200, "first approval must succeed: body={b1}");

    // Second and third votes with the SAME key but different claimed names:
    // the server derives the approver from the key, so the key has already
    // voted and cannot vote again.
    let (s2, b2) = approve_with(
        &client,
        &base,
        &approval_id,
        OFFICER_SECRETS[0],
        json!({ "approver_id": "bob", "approver_role": "admin" }),
    )
    .await;
    assert_eq!(
        s2, 400,
        "the same key must not be able to vote twice: body={b2}"
    );

    let (s3, b3) = approve_with(
        &client,
        &base,
        &approval_id,
        OFFICER_SECRETS[0],
        json!({ "approver_id": "carol", "approver_role": "admin" }),
    )
    .await;
    assert_eq!(
        s3, 400,
        "the same key must not be able to vote a third time: body={b3}"
    );

    // The quorum must therefore be incomplete: the export stays blocked.
    let (status, body) = export_key(&client, &base, &key_id, tenant, Some(&approval_id)).await;
    handle.abort();
    assert_eq!(
        status, 403,
        "export must stay blocked without a real three-party quorum: body={body}"
    );
}

/// The requestor is the authenticated key, so the same key cannot approve the
/// request it raised (the engine's self-approval guard becomes meaningful).
#[tokio::test]
async fn b7a_self_approval_rejected() {
    let (base, client, handle) = spawn_rest_server().await;
    let tenant = "tenant-a";
    let key_id = create_key(&client, &base, "self-approve-key", "sm4", tenant).await;

    // The officer key raises the request, claiming a *different* requestor in
    // the body...
    let (status, body) = create_approval_with(
        &client,
        &base,
        OFFICER_SECRETS[0],
        "key_export",
        &key_id,
        "key",
        tenant,
        json!({ "requestor_id": "alice" }),
    )
    .await;
    assert_eq!(status, 201, "approval request must be created: body={body}");
    let approval_id = body["id"].as_str().expect("approval id").to_string();

    // ...and then tries to approve it itself, claiming yet another name. The
    // server derives both identities from the key, so the requestor and the
    // approver are the same principal and the engine rejects the vote.
    let (s, b) = approve_with(
        &client,
        &base,
        &approval_id,
        OFFICER_SECRETS[0],
        json!({ "approver_id": "bob", "approver_role": "admin" }),
    )
    .await;
    handle.abort();
    assert_eq!(s, 403, "self-approval must be rejected with 403: body={b}");
}

/// An approver whose authority is below the level the operation requires must
/// not be able to contribute a vote.
///
/// A tenant-admin operation requires the `Admin` level; a SecurityOfficer key
/// maps to the `Manager` level, which is not enough. The approver *does* hold
/// the `APPROVE_ACTION` permission, so this exercises the level gate itself
/// and not the coarse route permission.
#[tokio::test]
async fn b7a_insufficient_authority_rejected() {
    let (base, client, handle) = spawn_rest_server().await;
    let tenant = "tenant-a";

    let (status, body) = create_approval_with(
        &client,
        &base,
        ADMIN_SECRET,
        "tenant_admin",
        "tenant-a-admin",
        "policy",
        tenant,
        json!({ "requestor_id": "admin" }),
    )
    .await;
    assert_eq!(status, 201, "approval request must be created: body={body}");
    let approval_id = body["id"].as_str().expect("approval id").to_string();

    // SecurityOfficer authority is `Manager`, below the required `Admin` level.
    let (s, b) = approve_with(
        &client,
        &base,
        &approval_id,
        OFFICER_SECRETS[0],
        json!({ "approver_id": "officer-1", "approver_role": "admin" }),
    )
    .await;
    handle.abort();
    assert_eq!(
        s, 403,
        "an approver below the required level must be rejected: body={b}"
    );
}

/// Only the principal that raised an approval request may cancel it.
#[tokio::test]
async fn b7a_other_principal_cannot_cancel_request() {
    let (base, client, handle) = spawn_rest_server().await;
    let tenant = "tenant-a";
    let key_id = create_key(&client, &base, "cancel-key", "sm4", tenant).await;

    // The admin raises the request; the body claims to be "admin" so a
    // body-driven implementation would let the attacker cancel it.
    let (status, body) = create_approval_with(
        &client,
        &base,
        ADMIN_SECRET,
        "key_export",
        &key_id,
        "key",
        tenant,
        json!({ "requestor_id": "admin" }),
    )
    .await;
    assert_eq!(status, 201, "approval request must be created: body={body}");
    let approval_id = body["id"].as_str().expect("approval id").to_string();

    // A different principal tries to cancel it while claiming to be the
    // requestor.
    let resp = client
        .post(format!("{base}/v1/approvals/{approval_id}/cancel"))
        .header(ADMIN_HEADER, OFFICER_SECRETS[0])
        .json(&json!({ "requestor_id": "admin" }))
        .send()
        .await
        .expect("cancel send");
    let status = resp.status();
    handle.abort();
    assert_eq!(
        status, 404,
        "a foreign principal must not be able to cancel the request"
    );
}

/// An approval request may not be raised for a key owned by another tenant.
#[tokio::test]
async fn b7a_approval_for_other_tenant_key_rejected() {
    let (base, client, handle) = spawn_rest_server().await;

    // A key owned by tenant-a...
    let key_id = create_key(&client, &base, "other-tenant-key", "sm4", "tenant-a").await;

    // ...cannot have an approval request raised for it by the tenant-bound
    // "acme" key, and the error must not disclose that the key exists.
    let (status, body) = create_approval_with(
        &client,
        &base,
        ACME_SECRET,
        "key_export",
        &key_id,
        "key",
        "acme",
        json!({ "requestor_id": "admin" }),
    )
    .await;
    handle.abort();
    assert_eq!(
        status, 404,
        "cross-tenant approval request must be rejected as not-found: body={body}"
    );
}

// =============================================================================
// Batch 7 / B7-b: REST/gRPC PBAC parity and DH tenant isolation
//
// The REST HMAC handlers skipped the PBAC check that the gRPC handlers
// perform, so attribute-based access control could be bypassed by switching
// protocol. The DH derive endpoint had neither a PBAC check nor any tenant
// check at all, which allowed deriving a shared secret with another tenant's
// private key.
// =============================================================================

/// A PBAC policy that denies one specific action.
fn deny_action_policy(action: &str) -> Policy {
    Policy {
        id: uuid::Uuid::new_v4(),
        name: format!("deny-{action}"),
        effect: PolicyEffect::Deny,
        condition: json!({ "operator": "eq", "attribute": "action", "value": action }),
        resources: vec!["*".to_string()],
        subjects: vec!["*".to_string()],
        tenant: None,
        enabled: true,
    }
}

/// The REST HMAC endpoint must honour the same PBAC decision as the gRPC one.
#[tokio::test]
async fn b7b_rest_hmac_respects_pbac_deny() {
    let (base, client, handle) =
        spawn_rest_server_with_policies(vec![deny_action_policy("hmac")]).await;
    let tenant = "tenant-a";
    let key_id = create_key(&client, &base, "pbac-mac-key", "hmac-sm3", tenant).await;

    let resp = client
        .post(format!("{base}/v1/keys/{key_id}/hmac?tenant_id={tenant}"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "data": STANDARD.encode(b"payload"), "aad": null }))
        .send()
        .await
        .expect("hmac send");
    let status = resp.status();
    handle.abort();

    assert_eq!(
        status, 403,
        "a PBAC deny on the hmac action must block the REST endpoint too"
    );
}

/// The REST HMAC verify endpoint must honour the same PBAC decision.
#[tokio::test]
async fn b7b_rest_hmac_verify_respects_pbac_deny() {
    let (base, client, handle) =
        spawn_rest_server_with_policies(vec![deny_action_policy("hmac_verify")]).await;
    let tenant = "tenant-a";
    let key_id = create_key(&client, &base, "pbac-mac-verify-key", "hmac-sm3", tenant).await;

    let resp = client
        .post(format!(
            "{base}/v1/keys/{key_id}/hmac/verify?tenant_id={tenant}"
        ))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({
            "data": STANDARD.encode(b"payload"),
            "mac": STANDARD.encode([0u8; 32]),
            "aad": null
        }))
        .send()
        .await
        .expect("hmac verify send");
    let status = resp.status();
    handle.abort();

    assert_eq!(
        status, 403,
        "a PBAC deny on the hmac_verify action must block the REST endpoint too"
    );
}

/// Deriving a shared secret with another tenant's private key must be denied
/// with the same sanitized "not found" answer the other key operations give.
#[tokio::test]
async fn b7b_dh_derive_cross_tenant_rejected() {
    let (base, client, handle) = spawn_rest_server().await;
    let key_id = create_key(&client, &base, "dh-key", "ed25519", "tenant-a").await;

    // Same tenant: allowed.
    let resp = client
        .post(format!("{base}/v1/dh/derive"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({
            "key_id": key_id,
            "algorithm": "X25519",
            "peer_public_key": STANDARD.encode([7u8; 32]),
            "tenant_id": "tenant-a",
        }))
        .send()
        .await
        .expect("dh derive send");
    let status = resp.status();
    assert_eq!(
        status, 200,
        "deriving with the owning tenant must succeed: status={status}"
    );

    // Another tenant: denied, and the answer must not disclose the key.
    let resp = client
        .post(format!("{base}/v1/dh/derive"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({
            "key_id": key_id,
            "algorithm": "X25519",
            "peer_public_key": STANDARD.encode([7u8; 32]),
            "tenant_id": "tenant-b",
        }))
        .send()
        .await
        .expect("dh derive cross-tenant send");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
    handle.abort();

    assert_eq!(
        status, 404,
        "cross-tenant DH derive must be rejected as not-found: body={body}"
    );
}

/// A tenant-bound key must not be usable to derive with another tenant's key.
#[tokio::test]
async fn b7b_dh_derive_bound_key_confined_to_its_tenant() {
    let (base, client, handle) = spawn_rest_server().await;
    let key_id = create_key(&client, &base, "dh-bound-key", "ed25519", "tenant-a").await;

    // The "acme" key is bound to tenant "acme", so it may not touch the
    // tenant-a key no matter which tenant it claims.
    let resp = client
        .post(format!("{base}/v1/dh/derive"))
        .header(ADMIN_HEADER, ACME_SECRET)
        .json(&json!({
            "key_id": key_id,
            "algorithm": "X25519",
            "peer_public_key": STANDARD.encode([7u8; 32]),
            "tenant_id": "tenant-a",
        }))
        .send()
        .await
        .expect("dh derive bound send");
    let status = resp.status();
    handle.abort();

    assert_eq!(
        status, 404,
        "a tenant-bound key must not derive with another tenant's key"
    );
}

// =============================================================================
// Batch 7 / B7-d: the gRPC `version` default must match the REST one
//
// proto3 cannot distinguish "unset" from 0, so an unset `DecryptRequest.version`
// arrived as 0, which the keystore could not resolve ("key version 0 not
// found"). The REST channel defaults to version 1; the gRPC handler now
// normalises 0 to the same value.
// =============================================================================

#[tokio::test]
async fn b7d_grpc_decrypt_without_version_uses_the_same_default_as_rest() {
    let mut stack = spawn_dual_stack().await;
    let tenant = "tenant-a";
    let plaintext = b"version default across channels";
    let key_id = create_key(&stack.client, &stack.base, "key-b7d", "sm4", tenant).await;

    // Seal on REST.
    let (ct, nonce, tag) = encrypt(&stack.client, &stack.base, &key_id, tenant, plaintext).await;

    // Open on gRPC with the version field left unset (proto3 default 0).
    let got = grpc_decrypt(&mut stack.grpc, &key_id, tenant, &ct, &nonce, &tag, 0)
        .await
        .expect("gRPC decrypt with an unset version must use the same default as REST");
    assert_eq!(got, plaintext, "plaintext mismatch");

    // The same ciphertext decrypts on REST (its default is version 1).
    let (ok, got2, body) = decrypt(
        &stack.client,
        &stack.base,
        &key_id,
        tenant,
        &ct,
        &nonce,
        &tag,
    )
    .await;
    assert!(ok, "REST decrypt must succeed: body={body}");
    assert_eq!(
        got2.expect("plaintext"),
        plaintext,
        "REST plaintext mismatch"
    );
}

// =============================================================================
// Batch 7 / B7-g: PBAC bootstrap semantics
//
// The PBAC engine denies every request that no policy covers. The server
// starts with an EMPTY engine and loads no policies at startup, so with the
// raw engine semantics every protected endpoint answered 403 — the KMS was
// unusable out of the box (audit follow-up B7-g).
//
// The fix: while no policy is configured, attribute-based control is inactive
// and the role-based check (the API key's permission bitmask) is the only
// gate. As soon as the first policy is installed the default-deny applies
// again.
// =============================================================================

/// With no policy configured the KMS must be usable: key creation and the
/// crypto endpoints are PBAC-guarded, so they answered 403 before the fix.
#[tokio::test]
async fn b7g1_server_without_any_policy_is_usable() {
    let (base, client, handle) = spawn_rest_server_without_policy().await;

    let resp = client
        .post(format!("{base}/v1/keys"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({
            "name": "key-b7g1",
            "spec": "sm4",
            "tenant_id": "tenant-a",
        }))
        .send()
        .await
        .expect("create_key send");
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|_| json!({"__nonjson": true}));

    assert_eq!(
        status, 201,
        "a deployment without PBAC policies must not lock every caller out: body={body}"
    );

    let key_id = body["id"].as_str().expect("key id").to_string();

    // The crypto endpoints are PBAC-guarded as well.
    let (ct, nonce, tag) = encrypt(&client, &base, &key_id, "tenant-a", b"out of the box").await;
    let (ok, plaintext, body) =
        decrypt(&client, &base, &key_id, "tenant-a", &ct, &nonce, &tag).await;
    assert!(ok, "decrypt must succeed without policies: body={body}");
    assert_eq!(plaintext.expect("plaintext"), b"out of the box");

    handle.abort();
}

/// The role-based check is still the gate when no policy is configured: a key
/// without the required permission is still refused.
#[tokio::test]
async fn b7g1_rbac_still_applies_without_any_policy() {
    let (base, client, handle) = spawn_rest_server_without_policy().await;

    // The security-officer key may not create keys (no CREATE_KEY bit).
    let resp = client
        .post(format!("{base}/v1/keys"))
        .header(ADMIN_HEADER, OFFICER_SECRET)
        .json(&json!({
            "name": "key-b7g1-rbac-denied",
            "spec": "sm4",
            "tenant_id": "tenant-a",
        }))
        .send()
        .await
        .expect("create_key send");
    let status = resp.status();
    handle.abort();

    assert_eq!(
        status, 403,
        "without policies the role-based check must still refuse the operation"
    );
}

/// Once a policy is installed the default-deny applies again: a request that
/// no policy covers is refused.
#[tokio::test]
async fn b7g1_installed_policy_restores_default_deny() {
    // A single policy that matches nothing: every request falls through to
    // the engine's default-deny.
    let engine = PBACEngine::new();
    engine
        .add_policy(Policy {
            id: uuid::Uuid::new_v4(),
            name: "matches-nothing".to_string(),
            effect: PolicyEffect::Allow,
            condition: json!({ "operator": "always" }),
            resources: vec!["no-such-resource".to_string()],
            subjects: vec!["no-such-subject".to_string()],
            tenant: None,
            enabled: true,
        })
        .await
        .expect("add policy");
    let (base, client, handle) = spawn_rest_server_with_engine(engine).await;

    let resp = client
        .post(format!("{base}/v1/keys"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({
            "name": "key-b7g1-denied",
            "spec": "sm4",
            "tenant_id": "tenant-a",
        }))
        .send()
        .await
        .expect("create_key send");
    let status = resp.status();
    handle.abort();

    assert_eq!(
        status, 403,
        "with a policy installed, requests that no policy covers must be denied"
    );
}

// =============================================================================
// Batch 7 / B7-g: REST must evaluate the same PBAC actions as gRPC
//
// The gRPC channel checked the attribute-based policy for every one of its 23
// methods, but six REST endpoints did not evaluate it at all. A client that
// was denied over gRPC could simply switch to REST and get through — the
// protocol-switchable PBAC bypass (audit follow-up B7-g).
//
// The action names below are the ones the gRPC handlers use, verbatim.
// =============================================================================

/// The REST sign endpoint must honour the PBAC decision for the `sign` action.
#[tokio::test]
async fn b7g2_rest_sign_respects_pbac_deny() {
    let (base, client, handle) =
        spawn_rest_server_with_policies(vec![deny_action_policy("sign")]).await;
    let tenant = "tenant-a";
    let key_id = create_key(&client, &base, "pbac-sign-key", "sm2", tenant).await;

    let resp = client
        .post(format!("{base}/v1/keys/{key_id}/sign?tenant_id={tenant}"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "data": STANDARD.encode(b"payload") }))
        .send()
        .await
        .expect("sign send");
    let status = resp.status();
    handle.abort();

    assert_eq!(
        status, 403,
        "a PBAC deny on the sign action must block the REST endpoint too"
    );
}

/// The REST verify endpoint must honour the PBAC decision for `verify`.
#[tokio::test]
async fn b7g2_rest_verify_respects_pbac_deny() {
    let (base, client, handle) =
        spawn_rest_server_with_policies(vec![deny_action_policy("verify")]).await;
    let tenant = "tenant-a";
    let key_id = create_key(&client, &base, "pbac-verify-key", "sm2", tenant).await;

    let resp = client
        .post(format!("{base}/v1/keys/{key_id}/verify?tenant_id={tenant}"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({
            "data": STANDARD.encode(b"payload"),
            "signature": STANDARD.encode([0u8; 64]),
        }))
        .send()
        .await
        .expect("verify send");
    let status = resp.status();
    handle.abort();

    assert_eq!(
        status, 403,
        "a PBAC deny on the verify action must block the REST endpoint too"
    );
}

/// The REST key-metadata endpoint must honour the PBAC decision for `get_key`.
#[tokio::test]
async fn b7g2_rest_get_key_respects_pbac_deny() {
    let (base, client, handle) =
        spawn_rest_server_with_policies(vec![deny_action_policy("get_key")]).await;
    let tenant = "tenant-a";
    let key_id = create_key(&client, &base, "pbac-get-key", "sm4", tenant).await;

    let resp = client
        .get(format!("{base}/v1/keys/{key_id}?tenant_id={tenant}"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .send()
        .await
        .expect("get_key send");
    let status = resp.status();
    handle.abort();

    assert_eq!(
        status, 403,
        "a PBAC deny on the get_key action must block the REST endpoint too"
    );
}

/// The REST envelope-encrypt endpoint must honour `envelope_encrypt`.
#[tokio::test]
async fn b7g2_rest_envelope_encrypt_respects_pbac_deny() {
    let (base, client, handle) =
        spawn_rest_server_with_policies(vec![deny_action_policy("envelope_encrypt")]).await;
    let tenant = "tenant-a";
    let kek_id = create_key(&client, &base, "pbac-envelope-kek", "sm4", tenant).await;

    let resp = client
        .post(format!("{base}/v1/envelope/encrypt"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({
            "kek_id": kek_id,
            "plaintext": STANDARD.encode(b"payload"),
            "tenant_id": tenant,
        }))
        .send()
        .await
        .expect("envelope encrypt send");
    let status = resp.status();
    handle.abort();

    assert_eq!(
        status, 403,
        "a PBAC deny on the envelope_encrypt action must block the REST endpoint too"
    );
}

/// The REST envelope-decrypt endpoint must honour `envelope_decrypt`.
#[tokio::test]
async fn b7g2_rest_envelope_decrypt_respects_pbac_deny() {
    let (base, client, handle) =
        spawn_rest_server_with_policies(vec![deny_action_policy("envelope_decrypt")]).await;
    let tenant = "tenant-a";
    let kek_id = create_key(&client, &base, "pbac-envelope-decrypt-kek", "sm4", tenant).await;

    let resp = client
        .post(format!("{base}/v1/envelope/decrypt"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({
            "kek_id": kek_id,
            "wrapped_dek": STANDARD.encode([0u8; 32]),
            "dek_nonce": STANDARD.encode([0u8; 12]),
            "ciphertext": STANDARD.encode([0u8; 32]),
            "data_nonce": STANDARD.encode([0u8; 12]),
            "tag": STANDARD.encode([0u8; 16]),
            "kek_version": 1,
            "tenant_id": tenant,
        }))
        .send()
        .await
        .expect("envelope decrypt send");
    let status = resp.status();
    handle.abort();

    assert_eq!(
        status, 403,
        "a PBAC deny on the envelope_decrypt action must block the REST endpoint too"
    );
}

/// The REST envelope-rewrap endpoint must honour `envelope_rewrap`.
#[tokio::test]
async fn b7g2_rest_envelope_rewrap_respects_pbac_deny() {
    let (base, client, handle) =
        spawn_rest_server_with_policies(vec![deny_action_policy("envelope_rewrap")]).await;
    let tenant = "tenant-a";
    let kek_id = create_key(&client, &base, "pbac-envelope-rewrap-kek", "sm4", tenant).await;

    let resp = client
        .post(format!("{base}/v1/envelope/rewrap"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({
            "kek_id": kek_id,
            "wrapped_dek": STANDARD.encode([0u8; 32]),
            "dek_nonce": STANDARD.encode([0u8; 12]),
            "old_kek_version": 1,
            "tenant_id": tenant,
        }))
        .send()
        .await
        .expect("envelope rewrap send");
    let status = resp.status();
    handle.abort();

    assert_eq!(
        status, 403,
        "a PBAC deny on the envelope_rewrap action must block the REST endpoint too"
    );
}

/// Switching protocol must not change the decision: one policy denies the
/// `sign` action on both channels.
#[tokio::test]
async fn b7g2_protocol_switch_cannot_bypass_pbac() {
    let mut stack = spawn_dual_stack_with_policies(vec![deny_action_policy("sign")]).await;
    let tenant = "tenant-a";
    let key_id = create_key(&stack.client, &stack.base, "pbac-parity-key", "sm2", tenant).await;

    // REST must refuse.
    let rest_url = format!("{}/v1/keys/{key_id}/sign?tenant_id={tenant}", stack.base);
    let resp = stack
        .client
        .post(rest_url)
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "data": STANDARD.encode(b"payload") }))
        .send()
        .await
        .expect("rest sign send");
    let rest_status = resp.status();

    // gRPC must refuse as well.
    let grpc_status = stack
        .grpc
        .sign(admin_req(pb::SignRequest {
            key_id: key_id.clone(),
            data: STANDARD.encode(b"payload"),
            tenant_id: tenant.to_string(),
        }))
        .await
        .expect_err("gRPC sign must be denied by the same policy");
    assert_eq!(
        grpc_status.code(),
        tonic::Code::PermissionDenied,
        "gRPC must refuse the denied action"
    );

    assert_eq!(
        rest_status, 403,
        "REST must refuse the denied action as well — switching protocol must not help"
    );
}

// =============================================================================
// Batch 7 / B7-g: approval-workflow hardening
//
//  * the resource type of an approval request is derived from its operation,
//    so the request body cannot decide whether the tenant-ownership check
//    runs;
//  * the `tenant_admin` operation needs the `Admin` approval level, which no
//    API key role could reach — the request could never be approved;
//  * `tenant_id` defaults to "default" instead of the empty string;
//  * the reject path reports the engine error instead of "not found";
//  * an approval request may only be read by its own tenant.
// =============================================================================

/// The resource type is derived from the operation, so labelling a key
/// resource as "policy" must not skip the tenant-ownership check.
#[tokio::test]
async fn b7g3_resource_type_cannot_be_forged_to_skip_tenant_check() {
    let (base, client, handle) = spawn_rest_server().await;

    // A key owned by tenant-a...
    let key_id = create_key(&client, &base, "forged-resource-type", "sm4", "tenant-a").await;

    // ...must not get an approval request from the tenant-bound "acme" key,
    // even when the request claims the resource is a policy, not a key.
    let (status, body) = create_approval_with(
        &client,
        &base,
        ACME_SECRET,
        "key_export",
        &key_id,
        "policy",
        "acme",
        json!({ "requestor_id": "admin" }),
    )
    .await;
    handle.abort();
    assert_eq!(
        status, 404,
        "the resource type must be derived from the operation, so the tenant check still runs: body={body}"
    );
}

/// A `tenant_admin` request must be approvable: the `Admin` approval level
/// has to be reachable from an API key.
#[tokio::test]
async fn b7g3_tenant_admin_request_can_be_approved() {
    let (base, client, handle) = spawn_rest_server().await;

    let (status, body) = create_approval_with(
        &client,
        &base,
        ADMIN_SECRET,
        "tenant_admin",
        "tenant-a",
        "tenant",
        "tenant-a",
        json!({}),
    )
    .await;
    assert_eq!(status, 201, "create request failed: body={body}");
    let approval_id = body["id"].as_str().expect("approval id").to_string();

    // The tenant-admin key holds the `Admin` level, so it may approve it.
    let (status, body) =
        approve_with(&client, &base, &approval_id, TENANT_ADMIN_SECRET, json!({})).await;
    handle.abort();
    assert_eq!(
        status, 200,
        "a tenant-admin request must be approvable by the tenant-admin key: body={body}"
    );
    assert_eq!(
        body["status"], "approved",
        "the request must reach the approved state: body={body}"
    );
}

/// A lower authority must not be able to approve a `tenant_admin` request.
#[tokio::test]
async fn b7g3_tenant_admin_request_rejects_lower_authority() {
    let (base, client, handle) = spawn_rest_server().await;

    let (status, body) = create_approval_with(
        &client,
        &base,
        ADMIN_SECRET,
        "tenant_admin",
        "tenant-a",
        "tenant",
        "tenant-a",
        json!({}),
    )
    .await;
    assert_eq!(status, 201, "create request failed: body={body}");
    let approval_id = body["id"].as_str().expect("approval id").to_string();

    // The security officer only reaches the `Manager` level.
    let (status, body) =
        approve_with(&client, &base, &approval_id, OFFICER_SECRET, json!({})).await;
    handle.abort();
    assert_eq!(
        status, 403,
        "an approver below the required level must be refused: body={body}"
    );
}

/// An approval request without an explicit tenant lands in "default".
#[tokio::test]
async fn b7g3_approval_request_tenant_defaults_to_default() {
    let (base, client, handle) = spawn_rest_server().await;

    // The key lives in the "default" tenant, so a request without an explicit
    // tenant must resolve to "default" for the ownership check to pass.
    let key_id = create_key(&client, &base, "default-tenant-key", "sm4", "default").await;

    let resp = client
        .post(format!("{base}/v1/approvals"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({
            "operation": "key_export",
            "resource_id": key_id,
            "resource_type": "key",
            "justification": "no tenant given",
        }))
        .send()
        .await
        .expect("create_approval send");
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|_| json!({"__nonjson": true}));
    handle.abort();

    assert_eq!(status, 201, "create request failed: body={body}");
    assert_eq!(
        body["tenant_id"], "default",
        "an approval request without a tenant must default to \"default\": body={body}"
    );
}

/// The reject path reports the engine error instead of flattening everything
/// into "not found": a requestor rejecting their own request is a 403.
#[tokio::test]
async fn b7g3_reject_reports_the_actual_error() {
    let (base, client, handle) = spawn_rest_server().await;
    let key_id = create_key(&client, &base, "reject-error-key", "sm4", "tenant-a").await;

    // The security officer holds the approve permission, so the reject route
    // is reachable for it — the requestor may then try to reject its own
    // request, which the engine refuses with `SelfApproval`.
    let (status, body) = create_approval_with(
        &client,
        &base,
        OFFICER_SECRET,
        "key_export",
        &key_id,
        "key",
        "tenant-a",
        json!({}),
    )
    .await;
    assert_eq!(status, 201, "create request failed: body={body}");
    let approval_id = body["id"].as_str().expect("approval id").to_string();

    // The requestor rejects their own request => self-rejection => 403.
    let resp = client
        .post(format!("{base}/v1/approvals/{approval_id}/reject"))
        .header(ADMIN_HEADER, OFFICER_SECRET)
        .json(&json!({ "reason": "changed my mind" }))
        .send()
        .await
        .expect("reject send");
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|_| json!({"__nonjson": true}));
    handle.abort();

    assert_eq!(
        status, 403,
        "a self-rejection must be reported as forbidden, not as \"not found\": body={body}"
    );
}

/// An approval request may only be read by the tenant that owns it.
#[tokio::test]
async fn b7g3_approval_request_is_not_readable_across_tenants() {
    let (base, client, handle) = spawn_rest_server().await;
    let key_id = create_key(&client, &base, "cross-tenant-read-key", "sm4", "tenant-a").await;

    let (status, body) = create_approval_with(
        &client,
        &base,
        ADMIN_SECRET,
        "key_export",
        &key_id,
        "key",
        "tenant-a",
        json!({}),
    )
    .await;
    assert_eq!(status, 201, "create request failed: body={body}");
    let approval_id = body["id"].as_str().expect("approval id").to_string();

    // The tenant-bound "acme" key must not read tenant-a's request.
    let resp = client
        .get(format!("{base}/v1/approvals/{approval_id}"))
        .header(ADMIN_HEADER, ACME_SECRET)
        .send()
        .await
        .expect("get approval send");
    let status = resp.status();
    handle.abort();

    assert_eq!(
        status, 404,
        "an approval request must not be readable across tenants: body={body}"
    );
}

// =============================================================================
// Batch 7 / B7-g: the configuration surface
//
// A declared API key whose secret environment variable is set but empty used
// to register an *empty* credential — an empty `x-api-key` header then
// authenticated. Duplicate secrets and duplicate key ids were accepted
// silently (audit follow-up B7-g).
//
// The corresponding startup validation lives in `src/cmd/server.rs`
// (`build_api_key_config`) and is covered by unit tests there.
// =============================================================================

/// A key without the approve permission must not be able to approve.
///
/// Note that the refusal comes from the **route's** permission layer
/// (`auth_layer!(Permission::APPROVE_ACTION)`), not from the handler: the
/// request never reaches it. This test therefore guards the route wiring.
/// The handler's own authority check (an approver whose level is below the
/// required one) is covered by
/// `b7g3_tenant_admin_request_rejects_lower_authority`.
#[tokio::test]
async fn b7g4_operator_cannot_approve() {
    let (base, client, handle) = spawn_rest_server().await;
    let key_id = create_key(&client, &base, "operator-approve-key", "sm4", "tenant-a").await;

    // The operator may raise a request (any authenticated key may)...
    let (status, body) = create_approval_with(
        &client,
        &base,
        OPERATOR_SECRET,
        "key_export",
        &key_id,
        "key",
        "tenant-a",
        json!({}),
    )
    .await;
    assert_eq!(status, 201, "create request failed: body={body}");
    let approval_id = body["id"].as_str().expect("approval id").to_string();

    // ...but it holds no APPROVE_ACTION, so the approval is refused.
    let (status, body) =
        approve_with(&client, &base, &approval_id, OPERATOR_SECRET, json!({})).await;
    handle.abort();
    assert_eq!(
        status, 403,
        "a key without the approve permission must not be able to approve: body={body}"
    );
}

// =============================================================================
// Batch 7 / B7-g: version semantics
//
//  * a missing key version is a missing resource (404), not an invalid
//    algorithm (400);
//  * the REST channel normalises an explicit `version: 0` to the same default
//    the gRPC channel uses, so both protocols behave identically.
// =============================================================================

/// A version that does not exist must be reported as "not found", not as an
/// invalid algorithm.
#[tokio::test]
async fn b7g5_unknown_key_version_is_not_found() {
    let (base, client, handle) = spawn_rest_server().await;
    let tenant = "tenant-a";
    let key_id = create_key(&client, &base, "key-b7g5-version", "sm4", tenant).await;

    let (ct, nonce, tag) = encrypt(&client, &base, &key_id, tenant, b"payload").await;

    // Version 99 was never created.
    let (ok, _, body) =
        decrypt_with_version(&client, &base, &key_id, tenant, &ct, &nonce, &tag, 2, 99).await;
    handle.abort();
    assert!(!ok, "an unknown version must not decrypt: body={body}");
    assert_eq!(
        body["error"], "key not found",
        "an unknown key version must be reported as not found: body={body}"
    );
}

/// An explicit `version: 0` means "unset" and must behave like the default
/// (version 1) — the same normalisation the gRPC channel performs.
#[tokio::test]
async fn b7g5_rest_version_zero_behaves_like_the_default() {
    let (base, client, handle) = spawn_rest_server().await;
    let tenant = "tenant-a";
    let key_id = create_key(&client, &base, "key-b7g5-zero", "sm4", tenant).await;

    let plaintext = b"version zero";
    let (ct, nonce, tag) = encrypt(&client, &base, &key_id, tenant, plaintext).await;

    // The default (the field absent) works...
    let (ok, got, body) =
        decrypt_with_version(&client, &base, &key_id, tenant, &ct, &nonce, &tag, 2, 1).await;
    assert!(ok, "decrypt with the default version failed: body={body}");
    assert_eq!(got.expect("plaintext"), plaintext);

    // ...and an explicit 0 must behave exactly the same.
    let (ok, got, body) =
        decrypt_with_version(&client, &base, &key_id, tenant, &ct, &nonce, &tag, 2, 0).await;
    handle.abort();
    assert!(
        ok,
        "an explicit version 0 must be normalised to the default, like the gRPC channel does: body={body}"
    );
    assert_eq!(got.expect("plaintext"), plaintext);
}

// =============================================================================
// Batch 7 / B7-h: findings of the second independent review
// =============================================================================

/// A disabled policy must not switch the engine into the default-deny mode:
/// it matches nothing, so counting it would lock every caller out with no
/// visible cause.
#[tokio::test]
async fn b7h_disabled_policy_does_not_lock_out_the_data_plane() {
    let engine = PBACEngine::new();
    engine
        .add_policy(Policy {
            id: uuid::Uuid::new_v4(),
            name: "disabled-policy".to_string(),
            effect: PolicyEffect::Allow,
            condition: json!({ "operator": "always" }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            tenant: None,
            enabled: false,
        })
        .await
        .expect("add policy");
    let (base, client, handle) = spawn_rest_server_with_engine(engine).await;

    let resp = client
        .post(format!("{base}/v1/keys"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({
            "name": "key-b7h-disabled",
            "spec": "sm4",
            "tenant_id": "tenant-a",
        }))
        .send()
        .await
        .expect("create_key send");
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|_| json!({"__nonjson": true}));
    handle.abort();

    assert_eq!(
        status, 201,
        "a disabled policy must not lock the data plane out: body={body}"
    );
}

/// A tenant-bound approver must not approve the request of another tenant.
#[tokio::test]
async fn b7h_approval_is_tenant_scoped() {
    let (base, client, handle) = spawn_rest_server().await;
    let key_id = create_key(&client, &base, "b7h-tenant-key", "sm4", "tenant-a").await;

    // A request owned by tenant-a...
    let (status, body) = create_approval_with(
        &client,
        &base,
        ADMIN_SECRET,
        "key_export",
        &key_id,
        "key",
        "tenant-a",
        json!({}),
    )
    .await;
    assert_eq!(status, 201, "create request failed: body={body}");
    let approval_id = body["id"].as_str().expect("approval id").to_string();

    // ...must not be approved by the tenant-bound "acme" approver.
    let (status, body) =
        approve_with(&client, &base, &approval_id, ACME_OFFICER_SECRET, json!({})).await;
    handle.abort();
    assert_eq!(
        status, 404,
        "a tenant-bound approver must not approve another tenant's request: body={body}"
    );
}

/// The same for the reject path.
#[tokio::test]
async fn b7h_rejection_is_tenant_scoped() {
    let (base, client, handle) = spawn_rest_server().await;
    let key_id = create_key(&client, &base, "b7h-reject-key", "sm4", "tenant-a").await;

    let (status, body) = create_approval_with(
        &client,
        &base,
        ADMIN_SECRET,
        "key_export",
        &key_id,
        "key",
        "tenant-a",
        json!({}),
    )
    .await;
    assert_eq!(status, 201, "create request failed: body={body}");
    let approval_id = body["id"].as_str().expect("approval id").to_string();

    let resp = client
        .post(format!("{base}/v1/approvals/{approval_id}/reject"))
        .header(ADMIN_HEADER, ACME_OFFICER_SECRET)
        .json(&json!({ "reason": "not mine" }))
        .send()
        .await
        .expect("reject send");
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or_else(|_| json!({"__nonjson": true}));
    handle.abort();

    assert_eq!(
        status, 404,
        "a tenant-bound rejector must not reject another tenant's request: body={body}"
    );
}

/// A `high_value_key_create` approval authorises the creation of a key that
/// does not exist yet, so it must not require an existing key.
#[tokio::test]
async fn b7h_high_value_key_create_approval_does_not_require_an_existing_key() {
    let (base, client, handle) = spawn_rest_server().await;

    let (status, body) = create_approval_with(
        &client,
        &base,
        ADMIN_SECRET,
        "high_value_key_create",
        "the-name-of-the-key-to-be-created",
        "key",
        "tenant-a",
        json!({}),
    )
    .await;
    handle.abort();
    assert_eq!(
        status, 201,
        "a high-value key creation must be approvable before the key exists: body={body}"
    );
}

// =============================================================================
// Batch 9 / B9-b: the PBAC tenant dimension
//
// A policy may be restricted to a tenant. The tenant it is matched against is
// the effective one — the tenant of the API key when it is bound to one, the
// self-reported tenant otherwise — so a tenant-scoped rule decides the
// requests of that tenant and of no other.
// =============================================================================

/// A PBAC policy that denies one action for one tenant only.
fn deny_action_policy_for_tenant(action: &str, tenant: &str) -> Policy {
    Policy {
        id: uuid::Uuid::new_v4(),
        name: format!("deny-{action}-{tenant}"),
        effect: PolicyEffect::Deny,
        condition: json!({ "operator": "eq", "attribute": "action", "value": action }),
        resources: vec!["*".to_string()],
        subjects: vec!["*".to_string()],
        tenant: Some(tenant.to_string()),
        enabled: true,
    }
}

/// A tenant-scoped deny must block the tenant it names and leave the other
/// tenants alone.
#[tokio::test]
async fn b9b_rest_tenant_scoped_deny_only_covers_its_tenant() {
    let (base, client, handle) =
        spawn_rest_server_with_policies(vec![deny_action_policy_for_tenant(
            "create_key",
            "tenant-a",
        )])
        .await;

    // The tenant the policy names is refused.
    let resp = client
        .post(format!("{base}/v1/keys"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "name": "denied-key", "spec": "Sm4", "tenant_id": "tenant-a" }))
        .send()
        .await
        .expect("create_key send");
    let denied_status = resp.status();

    // Another tenant is not covered by the policy and may create its key.
    let resp = client
        .post(format!("{base}/v1/keys"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "name": "allowed-key", "spec": "Sm4", "tenant_id": "tenant-b" }))
        .send()
        .await
        .expect("create_key send");
    let allowed_status = resp.status();
    handle.abort();

    assert_eq!(
        denied_status, 403,
        "a tenant-scoped deny must refuse the tenant it names"
    );
    assert_eq!(
        allowed_status, 201,
        "a tenant-scoped deny must not refuse another tenant"
    );
}

/// A request without a tenant reaches no tenant-scoped policy: the admin key
/// of the test harness is unbound, so the tenant comes from the request.
#[tokio::test]
async fn b9b_rest_request_without_a_tenant_reaches_no_tenant_scoped_policy() {
    let (base, client, handle) =
        spawn_rest_server_with_policies(vec![deny_action_policy_for_tenant(
            "create_key",
            "tenant-a",
        )])
        .await;

    // No tenant at all in the request.
    let resp = client
        .post(format!("{base}/v1/keys"))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "name": "tenantless-key", "spec": "Sm4" }))
        .send()
        .await
        .expect("create_key send");
    let status = resp.status();
    handle.abort();

    assert_ne!(
        status, 403,
        "a request without a tenant must not be caught by a tenant-scoped policy"
    );
}

/// Switching protocol must not change the decision: a tenant-scoped policy
/// denies the same tenant on both channels.
#[tokio::test]
async fn b9b_protocol_switch_cannot_bypass_a_tenant_scoped_policy() {
    let mut stack = spawn_dual_stack_with_policies(vec![deny_action_policy_for_tenant(
        "create_key",
        "tenant-a",
    )])
    .await;

    // REST must refuse the tenant the policy names.
    let resp = stack
        .client
        .post(format!("{}/v1/keys", stack.base))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "name": "rest-denied", "spec": "Sm4", "tenant_id": "tenant-a" }))
        .send()
        .await
        .expect("rest create_key send");
    let rest_status = resp.status();

    // gRPC must refuse it as well.
    let grpc_status = stack
        .grpc
        .create_key(admin_req(pb::CreateKeyRequest {
            name: "grpc-denied".to_string(),
            spec: "Sm4".to_string(),
            tenant_id: "tenant-a".to_string(),
        }))
        .await
        .expect_err("gRPC create_key must be denied by the same tenant-scoped policy");
    assert_eq!(
        grpc_status.code(),
        tonic::Code::PermissionDenied,
        "gRPC must refuse the denied tenant"
    );

    // And another tenant stays allowed on both channels.
    let resp = stack
        .client
        .post(format!("{}/v1/keys", stack.base))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "name": "rest-allowed", "spec": "Sm4", "tenant_id": "tenant-b" }))
        .send()
        .await
        .expect("rest create_key send");
    let rest_allowed = resp.status();

    let grpc_allowed = stack
        .grpc
        .create_key(admin_req(pb::CreateKeyRequest {
            name: "grpc-allowed".to_string(),
            spec: "Sm4".to_string(),
            tenant_id: "tenant-b".to_string(),
        }))
        .await
        .expect("gRPC create_key must stay allowed for the other tenant");

    assert_eq!(
        rest_status, 403,
        "REST must refuse the tenant the policy names — switching protocol must not help"
    );
    assert_eq!(
        rest_allowed, 201,
        "REST must allow the tenant the policy does not name"
    );
    assert!(
        grpc_allowed.into_inner().key.is_some(),
        "gRPC must allow the tenant the policy does not name"
    );
}
