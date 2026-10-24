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
