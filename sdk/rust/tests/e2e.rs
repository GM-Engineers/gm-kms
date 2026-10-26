//! The end-to-end companion of the drift guard: the SDK against a real server.
//!
//! `tests/contract.rs` proves that the SDK and the server agree about the
//! *shape* of the wire. This file proves that they agree about the
//! *meaning*: a real `kms-api` server is booted on a loopback port and the SDK
//! walks the whole life of a key through it —
//!
//! ```text
//! create → encrypt → decrypt → hmac → hmac/verify → approve → export
//! ```
//!
//! and the refusals that matter are checked through the SDK as well: an
//! export without an approval, and an export unlocked by an approval that has
//! expired (audit B8-d).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use gm_kms_sdk::{
    ApprovalOperation, Client, CreateApprovalRequest, CreateKeyRequest, CreatePolicyRequest,
    EncryptRequest, ExportKeyRequest, HmacRequest, HmacVerifyRequest, KeySpec, KmsError,
};
use kms_api::auth::{ApiKey, ApiKeyConfig};
use kms_api::{KmsMetrics, KmsState, Sm9State, rest::create_routes};
use kms_audit::AuditLogger;
use kms_core::PolicyEffect;
use kms_keystore::SoftwareKeystore;
use kms_policy::{PBACEngine, Policy};
use serde_json::json;
use tokio::net::TcpListener;

/// A key administrator: it may create keys and raise approval requests.
const ADMIN_SECRET: &str = "e2e-admin-key-secret";

/// Three distinct approvers. The approver identity comes from the API key
/// (audit follow-up B7-a), so a quorum needs three *different* keys.
const OFFICER_SECRETS: [&str; 3] = [
    "e2e-officer-1-secret",
    "e2e-officer-2-secret",
    "e2e-officer-3-secret",
];

const TENANT: &str = "tenant-a";

/// A valid RSA-2048 public key in PKCS#1 DER (base64): the target of the
/// wrapped export.
const RSA_PUB_PKCS1_B64: &str = "MIIBCgKCAQEAutdoRksj77EXTbJUvB0nyAKtIEkEjbpt8Bnu9LsmrwV/UK4he6mT3NaySjOgYJ9NOew0QkGRzD3eyy13Cwam8sISDxlF+2tCOiSACNqDQCs8SY9nQZUwmhZPTrtuWzVeHhR9FDEou+d0FiFSR5zgHnVQ4XPXP9DuYGBkB+DVQweHFW37Qdpr6pCPeTNkUjfCny9N8wlM1qtNUtCDCkuhsEUrvTgZwOnS9pZ78ldPlZfqENjZrRRIZkGjIKMLPusJfgSSbB1wg2Ppb9eP+iSgySUG9IWybAoCWE0e4/uBm9xrgXUubGkBw+G9uj14e2do74lx11rTbNpGxHohSxkPOwIDAQAB";

/// Boot a REST server on a loopback port and hand back its base URL, its
/// state (so a test can reach the approval engine) and its task handle.
async fn spawn_server() -> (String, Arc<KmsState>, tokio::task::JoinHandle<()>) {
    // A PBAC engine with one allow-all policy, as a deployment would have.
    let engine = PBACEngine::new();
    engine
        .add_policy(Policy {
            id: uuid::Uuid::new_v4(),
            name: "allow-all-e2e".to_string(),
            effect: PolicyEffect::Allow,
            condition: json!({ "operator": "always" }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            tenant: None,
            enabled: true,
        })
        .await
        .expect("add the allow-all policy");

    let keystore = Arc::new(SoftwareKeystore::new());
    let audit = Arc::new(AuditLogger::default());
    let sm9 = Sm9State::from_key(gm_sm9_rs::KgcMasterKey::generate().expect("sm9 master key"));
    let metrics = KmsMetrics::new();
    let state = Arc::new(KmsState::new(keystore, engine, audit, sm9, metrics));

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

    let base = format!("http://{addr}");

    // Wait for the server to answer before the first request.
    let probe = reqwest::Client::new();
    for _ in 0..100 {
        if probe
            .get(format!("{base}/v1/health"))
            .send()
            .await
            .map(|response| response.status().is_success())
            .unwrap_or(false)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    (base, state, handle)
}

/// A client that acts in [`TENANT`] as the key administrator.
fn admin_client(base: &str) -> Client {
    Client::builder(base)
        .api_key(ADMIN_SECRET)
        .tenant(TENANT)
        .build()
        .expect("build the client")
}

/// A client that acts in [`TENANT`] as one of the approvers.
fn officer_client(base: &str, secret: &str) -> Client {
    Client::builder(base)
        .api_key(secret)
        .tenant(TENANT)
        .build()
        .expect("build the client")
}

/// The SDK walks the whole life of a key through a real server.
#[tokio::test]
async fn the_sdk_walks_the_whole_life_of_a_key() {
    let (base, _state, handle) = spawn_server().await;
    let kms = admin_client(&base);

    // ── Create ──────────────────────────────────────────────────────────
    let key = kms
        .create_key(&CreateKeyRequest {
            name: "orders".to_string(),
            spec: KeySpec::Sm4,
            tenant_id: None,
        })
        .await
        .expect("create the key");
    assert_eq!(key.name, "orders");
    assert_eq!(key.tenant_id, TENANT);
    // The server answers with the Debug spelling of its own enum; the SDK
    // turns it back into the typed specification.
    assert_eq!(key.spec, KeySpec::Sm4);
    assert_eq!(key.version, 1);

    // The key is listed under the tenant it was created in.
    let listed = kms.list_keys(None).await.expect("list the keys");
    assert!(
        listed.iter().any(|listed| listed.id == key.id),
        "the new key must be listed"
    );

    // ── Encrypt and decrypt ─────────────────────────────────────────────
    let plaintext = "订单 42".as_bytes();
    let sealed = kms
        .encrypt(
            &key.id,
            &EncryptRequest {
                plaintext: plaintext.to_vec(),
                aad: None,
            },
            None,
        )
        .await
        .expect("encrypt");
    assert!(!sealed.ciphertext.is_empty());
    assert!(!sealed.nonce.is_empty());
    assert!(!sealed.tag.is_empty());

    let opened = kms
        .decrypt(&key.id, &sealed.to_decrypt_request(), None)
        .await
        .expect("decrypt");
    assert_eq!(opened, plaintext);

    // ── HMAC and HMAC verification ──────────────────────────────────────
    let mac_key = kms
        .create_key(&CreateKeyRequest {
            name: "orders-mac".to_string(),
            spec: KeySpec::Sm3Hmac,
            tenant_id: None,
        })
        .await
        .expect("create the mac key");
    assert_eq!(mac_key.spec, KeySpec::Sm3Hmac);

    let tag = kms
        .hmac(
            &mac_key.id,
            &HmacRequest {
                data: plaintext.to_vec(),
                aad: None,
            },
            None,
        )
        .await
        .expect("hmac");
    assert!(!tag.mac.is_empty());

    let verified = kms
        .hmac_verify(
            &mac_key.id,
            &HmacVerifyRequest {
                data: plaintext.to_vec(),
                mac: tag.mac.clone(),
                aad: None,
            },
            None,
        )
        .await
        .expect("hmac verify");
    assert!(verified, "the tag must verify");

    // A tampered tag must not verify.
    let tampered = kms
        .hmac_verify(
            &mac_key.id,
            &HmacVerifyRequest {
                data: plaintext.to_vec(),
                mac: vec![tag.mac[0] ^ 0xff; tag.mac.len()],
                aad: None,
            },
            None,
        )
        .await
        .expect("hmac verify of a tampered tag");
    assert!(!tampered, "a tampered tag must not verify");

    // ── Approve and export ──────────────────────────────────────────────
    let approval = kms
        .create_approval(&CreateApprovalRequest {
            operation: ApprovalOperation::KeyExport,
            resource_id: key.id.to_string(),
            justification: Some("quarterly migration".to_string()),
            tenant_id: None,
        })
        .await
        .expect("raise the approval request");
    assert_eq!(approval.operation, "key_export");
    assert_eq!(approval.resource_id, key.id.to_string());
    assert_eq!(approval.tenant_id, TENANT);

    // Three distinct approvers: one key is one vote (audit follow-up B7-a).
    for secret in OFFICER_SECRETS {
        let officer = officer_client(&base, secret);
        let approved = officer
            .approve(&approval.id, Some("looks good"))
            .await
            .expect("approve");
        assert_eq!(approved.id, approval.id);
    }

    let exported = kms
        .export_key(&ExportKeyRequest {
            key_id: key.id,
            target_system: "e2e".to_string(),
            target_public_key: RSA_PUB_PKCS1_B64.to_string(),
            purpose: "migration".to_string(),
            approval_id: Some(approval.id.clone()),
            protection_scheme: None,
            version: None,
            tenant_id: None,
        })
        .await
        .expect("export the key");
    assert!(!exported.wrapped_key.is_empty());
    assert!(!exported.encrypted_transport_key.is_empty());
    assert!(!exported.key_fingerprint.is_empty());

    handle.abort();
}

/// An export without an approval is a *malformed request* (400), while an
/// export whose approval does not authorize it is a *refusal* (403).
///
/// The distinction matters to a caller: a 400 says "fix your request", a 403
/// says "you are not allowed" (audit B8-d, `docs/api-semantics.md` §8.5).
#[tokio::test]
async fn an_export_without_an_approval_is_a_malformed_request() {
    let (base, _state, handle) = spawn_server().await;
    let kms = admin_client(&base);

    let key = kms
        .create_key(&CreateKeyRequest {
            name: "unapproved".to_string(),
            spec: KeySpec::Sm4,
            tenant_id: None,
        })
        .await
        .expect("create the key");

    let error = kms
        .export_key(&ExportKeyRequest {
            key_id: key.id,
            target_system: "e2e".to_string(),
            target_public_key: RSA_PUB_PKCS1_B64.to_string(),
            purpose: "migration".to_string(),
            approval_id: None,
            protection_scheme: None,
            version: None,
            tenant_id: None,
        })
        .await
        .expect_err("an export without an approval must be refused");

    handle.abort();

    assert_eq!(
        error.status(),
        Some(400),
        "a missing approval is a malformed request: {error}"
    );
    assert!(
        !error.is_forbidden(),
        "a missing approval must not be reported as a refusal: {error}"
    );
    let message = error.message().unwrap_or_default();
    assert!(
        message.contains("requires an approved request"),
        "the message must say what is missing: {message}"
    );
}

/// An approval id that is not even an id is a malformed request too.
#[tokio::test]
async fn an_export_with_a_malformed_approval_id_is_a_malformed_request() {
    let (base, _state, handle) = spawn_server().await;
    let kms = admin_client(&base);

    let key = kms
        .create_key(&CreateKeyRequest {
            name: "malformed-approval".to_string(),
            spec: KeySpec::Sm4,
            tenant_id: None,
        })
        .await
        .expect("create the key");

    let error = kms
        .export_key(&ExportKeyRequest {
            key_id: key.id,
            target_system: "e2e".to_string(),
            target_public_key: RSA_PUB_PKCS1_B64.to_string(),
            purpose: "migration".to_string(),
            approval_id: Some("not-a-uuid".to_string()),
            protection_scheme: None,
            version: None,
            tenant_id: None,
        })
        .await
        .expect_err("an export with a malformed approval id must be refused");

    handle.abort();

    assert_eq!(
        error.status(),
        Some(400),
        "a malformed approval id is a malformed request: {error}"
    );
    let message = error.message().unwrap_or_default();
    assert!(
        message.contains("invalid approval_id"),
        "the message must say what is wrong: {message}"
    );
}

/// An approval that has expired authorizes nothing, even though it was
/// approved while it was valid (audit B8-d).
#[tokio::test]
async fn an_expired_approval_does_not_unlock_an_export() {
    let (base, state, handle) = spawn_server().await;
    let kms = admin_client(&base);

    let key = kms
        .create_key(&CreateKeyRequest {
            name: "expired".to_string(),
            spec: KeySpec::Sm4,
            tenant_id: None,
        })
        .await
        .expect("create the key");

    // A fully approved (Triple quorum) KeyExport request bound to THIS key,
    // whose deadline has already passed. Such a request cannot be produced
    // through the REST API (`create_request` always derives a future
    // `expires_at`), so it is injected into the engine directly.
    let approval_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    let request = kms_approval::ApprovalRequestEntity {
        id: approval_id,
        operation: kms_approval::OperationType::KeyExport,
        resource_id: key.id.to_string(),
        resource_type: "key".to_string(),
        tenant_id: TENANT.to_string(),
        requestor_id: "requestor-user".to_string(),
        justification: Some("expired approval".to_string()),
        status: kms_approval::ApprovalStatus::Approved,
        required_level: kms_approval::ApprovalLevel::Triple,
        current_level: kms_approval::ApprovalLevel::Triple,
        approvals: (0..3)
            .map(|index| kms_approval::ApprovalRecord {
                approver_id: format!("officer-{index}"),
                level: kms_approval::ApprovalLevel::Triple,
                approved_at: now - chrono::Duration::hours(2),
                comment: None,
            })
            .collect(),
        rejections: Vec::new(),
        created_at: now - chrono::Duration::hours(3),
        expires_at: now - chrono::Duration::hours(1),
        completed_at: Some(now - chrono::Duration::hours(2)),
        metadata: json!({}),
    };
    {
        let mut guard = state.approval_manager.write();
        guard
            .restore_request(request)
            .expect("the expired approval must be restorable");
    }

    let error = kms
        .export_key(&ExportKeyRequest {
            key_id: key.id,
            target_system: "e2e".to_string(),
            target_public_key: RSA_PUB_PKCS1_B64.to_string(),
            purpose: "migration".to_string(),
            approval_id: Some(approval_id.to_string()),
            protection_scheme: None,
            version: None,
            tenant_id: None,
        })
        .await
        .expect_err("an expired approval must not unlock an export");

    handle.abort();

    match error {
        KmsError::Api {
            status, message, ..
        } => {
            assert_eq!(status, 403, "the refusal must be a 403: {message}");
            assert!(
                !message.contains("wrapped_key"),
                "no key material may leave the KMS: {message}"
            );
        }
        other => panic!("the refusal must be an API error: {other}"),
    }
}

/// A key the SDK does not know about is a 404, and the SDK says so.
#[tokio::test]
async fn an_unknown_key_is_reported_as_not_found() {
    let (base, _state, handle) = spawn_server().await;
    let kms = admin_client(&base);

    let missing = uuid::Uuid::new_v4();
    let error = kms
        .get_key(&missing, None)
        .await
        .expect_err("an unknown key must be refused");

    handle.abort();

    assert!(error.is_not_found(), "the refusal must be a 404: {error}");
    assert_eq!(error.status(), Some(404));
    let message = error.message().unwrap_or_default();
    assert!(
        message.contains("not found"),
        "the message must say what happened: {message}"
    );
}

/// The SDK installs a tenant-scoped policy and takes it back again.
///
/// The withdrawal matters: now that policies are persisted, one that turns
/// out to be wrong would outlive every restart, so the operator needs a way
/// to remove it — and the SDK has to be able to reach that endpoint. The
/// tenant dimension is checked on the way through, because a policy that
/// cannot be scoped to a tenant cannot be governed either.
#[tokio::test]
async fn the_sdk_installs_a_tenant_scoped_policy_and_withdraws_it_again() {
    let (base, _state, handle) = spawn_server().await;
    let kms = officer_client(&base, OFFICER_SECRETS[0]);

    let created = kms
        .create_policy(&CreatePolicyRequest {
            name: "tenant-scoped-allow".to_string(),
            effect: gm_kms_sdk::PolicyEffect::Allow,
            condition: json!({ "operator": "always" }),
            resources: vec!["*".to_string()],
            subjects: vec!["*".to_string()],
            tenant: Some(TENANT.to_string()),
            enabled: true,
        })
        .await
        .expect("create the policy");

    assert_eq!(created.tenant.as_deref(), Some(TENANT));
    assert_eq!(created.name, "tenant-scoped-allow");

    // It is listed and fetchable.
    let listed = kms.list_policies().await.expect("list the policies");
    assert!(
        listed.iter().any(|p| p.id == created.id),
        "the new policy must be listed"
    );
    let fetched = kms.get_policy(&created.id).await.expect("get the policy");
    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.tenant.as_deref(), Some(TENANT));

    // It can be withdrawn — and a second withdrawal is reported, not ignored.
    kms.delete_policy(&created.id)
        .await
        .expect("delete the policy");
    let error = kms
        .get_policy(&created.id)
        .await
        .expect_err("the policy is gone");
    assert!(error.is_not_found(), "the refusal must be a 404: {error}");
    let error = kms
        .delete_policy(&created.id)
        .await
        .expect_err("it is already gone");
    assert!(error.is_not_found(), "the refusal must be a 404: {error}");

    handle.abort();
}
