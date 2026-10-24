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

/// 起一个绑定随机 loopback 端口的 REST 服务器，返回 `http://addr` base URL 与
/// 服务器后台任务句柄（调用方负责 abort）。
async fn spawn_rest_server() -> (String, reqwest::Client, tokio::task::JoinHandle<()>) {
    // keystore
    let keystore = Arc::new(SoftwareKeystore::new());

    // PBAC：默认 deny，注入一条放行全部 subject/resource/action 的策略。
    let engine = PBACEngine::new();
    engine
        .add_policy(Policy {
            id: uuid::Uuid::new_v4(),
            name: "allow-all-integration".to_string(),
            effect: PolicyEffect::Allow,
            condition: json!({ "operator": "always" }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            enabled: true,
        })
        .await
        .expect("add policy");

    let audit = Arc::new(AuditLogger::default());
    let sm9 = Sm9State::from_key(gm_sm9_rs::KgcMasterKey::generate().expect("sm9 master key"));
    let metrics = KmsMetrics::new();

    let state = Arc::new(KmsState::new(keystore, engine, audit, sm9, metrics));

    let api_key_config = ApiKeyConfig::with_keys(vec![
        ApiKey::key_admin(ADMIN_SECRET.to_string()).with_key_id("admin".to_string()),
        ApiKey::security_officer(OFFICER_SECRET.to_string()).with_key_id("officer".to_string()),
        // Tenant-bound admin key (audit P1-3): server derives tenant="acme" from this
        // identity and ignores any self-reported tenant.
        ApiKey::key_admin(ACME_SECRET.to_string())
            .with_key_id("acme".to_string())
            .with_tenant("acme".to_string()),
    ]);

    let app = create_routes(state, api_key_config);

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

    (base, client, handle)
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

/// Approve with `n` distinct approvers via the SecurityOfficer key (APPROVE_ACTION).
async fn approve_n(client: &reqwest::Client, base: &str, approval_id: &str, n: usize) {
    for i in 0..n {
        let resp = client
            .post(format!("{base}/v1/approvals/{approval_id}/approve"))
            .header(ADMIN_HEADER, OFFICER_SECRET)
            .json(&json!({
                "approver_id": format!("approver-{i}"),
                "approver_role": "manager",
                "comment": null,
            }))
            .send()
            .await
            .expect("approve send");
        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .unwrap_or_else(|_| json!({ "__nonjson": true }));
        assert!(
            status.is_success(),
            "approve[{i}] failed: {status} body={body}"
        );
    }
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

    assert!(
        !(200..300).contains(&status) && status != 404,
        "cross-resource export must be rejected by the approval gate (got {status}): body={body}"
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

    // Without approval => rejected.
    let (no_appr_status, body1) = rotate_key(&client, &base, &key_id, tenant, None).await;
    assert!(
        !(200..300).contains(&no_appr_status),
        "rotate without approval must be rejected: body={body1}"
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
