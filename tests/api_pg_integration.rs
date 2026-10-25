//! Interface-level security guards against the **PostgreSQL-backed** keystore
//! (audit B8-d / plan Batch 0 + Batch 2).
//!
//! `tests/api_integration.rs` exercises the interface guards against the
//! in-memory `SoftwareKeystore`. The guards themselves (approval expiry,
//! approval↔key binding, cross-tenant isolation) sit in the REST layer and are
//! therefore backend-independent — but the keystore *underneath* them is not:
//! the PostgreSQL backend resolves keys lazily from the database, keeps the
//! material encrypted with the KEK, and enforces the tenant ownership per
//! lookup. A guard that only ever runs against an in-memory keystore says
//! nothing about the deployment that actually runs in production.
//!
//! These cases are `#[ignore]`d and gated on `DATABASE_URL`, like the other
//! PostgreSQL-backed tests in this repository (see
//! `crates/kms-keystore/src/postgres.rs`).
//!
//! Run them against a real PostgreSQL with:
//!
//! ```text
//! export DATABASE_URL="postgres://kms:kms123@127.0.0.1:55432/kms"
//! export KMS_KEK="<64 hex characters>"
//! cargo test --test api_pg_integration -- --ignored --test-threads=1
//! ```
//!
//! `KMS_KEK` is mandatory: without it the keystore cannot decrypt the stored
//! material, and the production path deliberately refuses to continue (the
//! keystore would otherwise `exit(1)` the whole test binary without saying
//! why).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kms_api::auth::{ApiKey, ApiKeyConfig};
use kms_api::{KmsMetrics, KmsState, Sm9State, rest::create_routes};
use kms_audit::AuditLogger;
use kms_core::PolicyEffect;
use kms_keystore::{PostgresKeyRepository, PostgresKeystore};
use kms_policy::{PBACEngine, Policy};
use serde_json::json;
use tokio::net::TcpListener;

const ADMIN_SECRET: &str = "pg-integration-admin-key-secret";
const ADMIN_HEADER: &str = "x-api-key";

/// Distinct SecurityOfficer keys used as distinct approvers.
///
/// The server derives the approver identity from the authenticated API key,
/// so one key is one vote: a Triple-level quorum needs three *different*
/// keys (audit follow-up B7-a).
const OFFICER_SECRETS: [&str; 3] = [
    "pg-integration-officer-1-secret",
    "pg-integration-officer-2-secret",
    "pg-integration-officer-3-secret",
];

/// An RSA-1024 public key (PKCS#1, base64) — the transport key the exported
/// key material is wrapped for.
const RSA_PUB_PKCS1_B64: &str = "MIIBCgKCAQEAutdoRksj77EXTbJUvB0nyAKtIEkEjbpt8Bnu9LsmrwV/UK4he6mT3NaySjOgYJ9NOew0QkGRzD3eyy13Cwam8sISDxlF+2tCOiSACNqDQCs8SY9nQZUwmhZPTrtuWzVeHhR9FDEou+d0FiFSR5zgHnVQ4XPXP9DuYGBkB+DVQweHFW37Qdpr6pCPeTNkUjfCny9N8wlM1qtNUtCDCkuhsEUrvTgZwOnS9pZ78ldPlZfqENjZrRRIZkGjIKMLPusJfgSSbB1wg2Ppb9eP+iSgySUG9IWybAoCWE0e4/uBm9xrgXUubGkBw+G9uj14e2do74lx11rTbNpGxHohSxkPOwIDAQAB";

/// The PostgreSQL URL the tests run against.
fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://kms:kms123@localhost:5432/kms".to_string())
}

/// Fail with an actionable message instead of letting the keystore kill the
/// whole test binary.
fn require_kek() {
    let configured = std::env::var("KMS_KEK")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .is_some()
        || std::env::var("KMS_KEK_FILE")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some();
    assert!(
        configured,
        "KMS_KEK (or KMS_KEK_FILE) must be set: the PostgreSQL keystore encrypts the \
         key material with it and cannot read the stored rows without it"
    );
}

/// Boot a REST server on top of the **PostgreSQL** keystore.
///
/// The keystore is wired exactly like the production path
/// (`src/cmd/server.rs::create_software_keystore`): a `PostgresKeyRepository`
/// on a real connection pool, a `PostgresKeystore` with the KEK-encrypted
/// material, and the eager preload of the stored keys.
async fn spawn_pg_rest_server() -> (
    String,
    reqwest::Client,
    tokio::task::JoinHandle<()>,
    Arc<KmsState>,
) {
    require_kek();

    let pool = kms_api::sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url())
        .await
        .expect("DATABASE_URL must point at a reachable PostgreSQL");

    let repo = PostgresKeyRepository::new(pool);
    let keystore = PostgresKeystore::new(repo)
        .await
        .expect("the PostgreSQL keystore must be constructible");
    keystore
        .load_keys()
        .await
        .expect("the eager preload of the stored keys must succeed");

    // PBAC: allow everything, like the in-memory interface harness.
    let engine = PBACEngine::new();
    engine
        .add_policy(Policy {
            id: uuid::Uuid::new_v4(),
            name: "allow-all-pg-integration".to_string(),
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

    let state = Arc::new(KmsState::new(
        Arc::new(keystore),
        engine,
        audit,
        sm9,
        metrics,
    ));

    let api_key_config = ApiKeyConfig::with_keys(vec![
        ApiKey::key_admin(ADMIN_SECRET.to_string()).with_key_id("admin".to_string()),
        ApiKey::security_officer(OFFICER_SECRETS[0].to_string())
            .with_key_id("officer-1".to_string()),
        ApiKey::security_officer(OFFICER_SECRETS[1].to_string())
            .with_key_id("officer-2".to_string()),
        ApiKey::security_officer(OFFICER_SECRETS[2].to_string())
            .with_key_id("officer-3".to_string()),
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

    // Wait until the server answers.
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

/// Create a key in the given tenant; returns its id.
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
        .unwrap_or_else(|_| json!({ "__nonjson": true }));
    assert!(
        status.is_success(),
        "create_key failed: {status} body={body}"
    );
    body["id"].as_str().expect("key id").to_string()
}

/// Create a resource-bound approval request; returns its id.
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
            "justification": "pg integration test",
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

/// Approve with `n` distinct approver keys.
async fn approve_n(client: &reqwest::Client, base: &str, approval_id: &str, n: usize) {
    for i in 0..n {
        let secret = OFFICER_SECRETS[i % OFFICER_SECRETS.len()];
        let resp = client
            .post(format!("{base}/v1/approvals/{approval_id}/approve"))
            .header(ADMIN_HEADER, secret)
            .json(&json!({}))
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
        "target_system": "pg-integration",
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

/// The positive baseline: the PostgreSQL keystore serves a real roundtrip.
///
/// Without this case the negative results below would be worthless — a
/// harness that cannot even encrypt a key would "reject" everything for the
/// wrong reason.
#[tokio::test]
#[ignore] // Requires running server (PostgreSQL)
async fn b8d_pg_encrypt_decrypt_roundtrip() {
    let (base, client, handle, _state) = spawn_pg_rest_server().await;
    let tenant = "pg-roundtrip";
    let key_id = create_key(&client, &base, "pg-roundtrip-key", "sm4", tenant).await;

    let plaintext = b"postgres-backed roundtrip";
    let enc = client
        .post(format!(
            "{base}/v1/keys/{key_id}/encrypt?tenant_id={tenant}"
        ))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "plaintext": STANDARD.encode(plaintext) }))
        .send()
        .await
        .expect("encrypt send");
    let enc_status = enc.status();
    let enc_body: serde_json::Value = enc
        .json()
        .await
        .unwrap_or_else(|_| json!({ "__nonjson": true }));
    assert!(
        enc_status.is_success(),
        "encrypt failed: {enc_status} body={enc_body}"
    );
    let ciphertext = enc_body["ciphertext"]
        .as_str()
        .expect("ciphertext")
        .to_string();
    let nonce = enc_body["nonce"].as_str().expect("nonce").to_string();
    let tag = enc_body["tag"].as_str().expect("tag").to_string();

    let dec = client
        .post(format!(
            "{base}/v1/keys/{key_id}/decrypt?tenant_id={tenant}"
        ))
        .header(ADMIN_HEADER, ADMIN_SECRET)
        .json(&json!({ "ciphertext": ciphertext, "nonce": nonce, "tag": tag, "aad": null }))
        .send()
        .await
        .expect("decrypt send");
    let dec_status = dec.status();
    let dec_body: serde_json::Value = dec
        .json()
        .await
        .unwrap_or_else(|_| json!({ "__nonjson": true }));
    handle.abort();

    assert!(
        dec_status.is_success(),
        "decrypt failed: {dec_status} body={dec_body}"
    );
    assert_eq!(
        dec_body["plaintext"].as_str(),
        Some(STANDARD.encode(plaintext).as_str()),
        "the decrypted plaintext must match: body={dec_body}"
    );
}

/// The positive baseline for the export path: a fully approved, resource-bound
/// export succeeds and hands out the wrapped key material.
#[tokio::test]
#[ignore] // Requires running server (PostgreSQL)
async fn b8d_pg_export_succeeds_with_a_bound_approval() {
    let (base, client, handle, _state) = spawn_pg_rest_server().await;
    let tenant = "pg-export-ok";
    let key_id = create_key(&client, &base, "pg-export-ok-key", "sm4", tenant).await;

    let approval_id = create_approval(&client, &base, "key_export", &key_id, tenant).await;
    approve_n(&client, &base, &approval_id, 3).await; // Triple quorum

    let (status, body) = export_key(&client, &base, &key_id, tenant, Some(&approval_id)).await;
    handle.abort();

    assert_eq!(
        status, 200,
        "export should succeed with a bound approval: body={body}"
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
}

/// An approval that exists but was never fully approved must not unlock an
/// export (the quorum is not reached).
#[tokio::test]
#[ignore] // Requires running server (PostgreSQL)
async fn b8d_pg_export_rejects_an_incomplete_quorum() {
    let (base, client, handle, _state) = spawn_pg_rest_server().await;
    let tenant = "pg-export-quorum";
    let key_id = create_key(&client, &base, "pg-export-quorum-key", "sm4", tenant).await;

    let approval_id = create_approval(&client, &base, "key_export", &key_id, tenant).await;
    approve_n(&client, &base, &approval_id, 2).await; // one vote short of Triple

    let (status, body) = export_key(&client, &base, &key_id, tenant, Some(&approval_id)).await;
    handle.abort();

    assert_eq!(
        status, 403,
        "an incomplete quorum must not unlock an export: body={body}"
    );
    assert!(
        body.get("wrapped_key").is_none(),
        "no key material may leave the KMS without a full quorum: body={body}"
    );
}

/// An approval that is approved but **expired** must not unlock an export.
///
/// The engine's expiry rule (`is_approved`: `Utc::now() <= expires_at`) has
/// unit-level coverage only; the interface layer is where the key material
/// actually leaves the KMS.
#[tokio::test]
#[ignore] // Requires running server (PostgreSQL)
async fn b8d_pg_export_rejects_an_expired_approval() {
    let (base, client, handle, state) = spawn_pg_rest_server().await;
    let tenant = "pg-export-expired";
    let key_id = create_key(&client, &base, "pg-export-expired-key", "sm4", tenant).await;

    // A fully approved (Triple quorum) KeyExport request bound to THIS key,
    // whose deadline has already passed. It cannot be produced through the
    // REST API (`create_request` always derives a future `expires_at`), so the
    // approval engine's restore hook injects it.
    let approval_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    let request = kms_approval::ApprovalRequestEntity {
        id: approval_id,
        operation: kms_approval::OperationType::KeyExport,
        resource_id: key_id.clone(),
        resource_type: "key".to_string(),
        tenant_id: tenant.to_string(),
        requestor_id: "requestor-user".to_string(),
        justification: Some("pg interface-level expiry guard".to_string()),
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

/// An approval bound to key A must not unlock an export of key B.
#[tokio::test]
#[ignore] // Requires running server (PostgreSQL)
async fn b8d_pg_export_rejects_an_approval_bound_to_another_key() {
    let (base, client, handle, _state) = spawn_pg_rest_server().await;
    let tenant = "pg-export-binding";
    let key_a = create_key(&client, &base, "pg-export-binding-a", "sm4", tenant).await;
    let key_b = create_key(&client, &base, "pg-export-binding-b", "sm4", tenant).await;

    let approval_id = create_approval(&client, &base, "key_export", &key_a, tenant).await;
    approve_n(&client, &base, &approval_id, 3).await;

    let (status, body) = export_key(&client, &base, &key_b, tenant, Some(&approval_id)).await;
    handle.abort();

    assert_eq!(
        status, 403,
        "an approval bound to another key must not unlock an export: body={body}"
    );
    assert!(
        body.get("wrapped_key").is_none(),
        "no key material may leave the KMS with a foreign approval: body={body}"
    );
}

/// A valid approval for key A must not unlock an export of key A **under
/// another tenant**: the keystore enforces the ownership per lookup, and the
/// interface answers 404 (the keystore cannot distinguish "missing key" from
/// "wrong tenant").
#[tokio::test]
#[ignore] // Requires running server (PostgreSQL)
async fn b8d_pg_export_rejects_a_cross_tenant_request() {
    let (base, client, handle, _state) = spawn_pg_rest_server().await;
    let tenant = "pg-export-owner";
    let key_id = create_key(&client, &base, "pg-export-owner-key", "sm4", tenant).await;

    let approval_id = create_approval(&client, &base, "key_export", &key_id, tenant).await;
    approve_n(&client, &base, &approval_id, 3).await;

    // The gate passes (the resource matches), then the ownership check in the
    // keystore rejects the foreign tenant.
    let (status, body) = export_key(
        &client,
        &base,
        &key_id,
        "pg-export-other-tenant",
        Some(&approval_id),
    )
    .await;
    handle.abort();

    assert_eq!(
        status, 404,
        "a cross-tenant export must not return the key material: body={body}"
    );
    assert!(
        body.get("wrapped_key").is_none(),
        "no key material may leave the KMS for a foreign tenant: body={body}"
    );
}

/// An export without an approval id at all is a malformed call (400) — it
/// must never reach the key material.
#[tokio::test]
#[ignore] // Requires running server (PostgreSQL)
async fn b8d_pg_export_without_an_approval_is_rejected() {
    let (base, client, handle, _state) = spawn_pg_rest_server().await;
    let tenant = "pg-export-none";
    let key_id = create_key(&client, &base, "pg-export-none-key", "sm4", tenant).await;

    let (status, body) = export_key(&client, &base, &key_id, tenant, None).await;
    handle.abort();

    assert_eq!(
        status, 400,
        "an export without an approval must be rejected: body={body}"
    );
    assert!(
        body.get("wrapped_key").is_none(),
        "no key material may leave the KMS without an approval: body={body}"
    );
}
