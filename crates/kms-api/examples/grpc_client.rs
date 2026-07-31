//! Simple gRPC client example for KMS
//!
//! Run with: cargo run --example grpc_client
//! Requires the KMS server to be running on localhost:9090

use base64::{Engine, engine::general_purpose::STANDARD};
use kms_api::grpc::pb::kms_service_client::KmsServiceClient;
use kms_api::grpc::pb::{CreateKeyRequest, EncryptRequest};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== KMS gRPC Client Test ===\n");

    let mut client = KmsServiceClient::connect("http://127.0.0.1:9090")
        .await
        .expect("Failed to connect to gRPC server. Is the server running on port 9090?");

    // 1. Create a key
    println!("1. Creating key 'test-grpc-key'...");
    let request = tonic::Request::new(CreateKeyRequest {
        name: "test-grpc-key".to_string(),
        spec: "aes-256-gcm".to_string(),
        tenant_id: "test-tenant".to_string(),
    });

    let response = client.create_key(request).await?;
    let key = response.into_inner().key.unwrap();
    println!("   Created key: {} ({})\n", key.name, key.id);

    let key_id = key.id.clone();

    // 2. List keys
    println!("2. Listing keys...");
    let request = tonic::Request::new(kms_api::grpc::pb::ListKeysRequest {
        limit: 10,
        offset: 0,
        tenant_id: "test-tenant".to_string(),
    });
    let response = client.list_keys(request).await?;
    let keys = response.into_inner().keys;
    println!("   Found {} key(s)\n", keys.len());
    for key in &keys {
        println!("   - {} ({})", key.name, key.id);
    }
    println!();

    // 3. Encrypt
    println!("3. Encrypting 'Hello, gRPC!'...");
    let plaintext = "Hello, gRPC!";
    let _plaintext_b64 = STANDARD.encode(plaintext);

    let request = tonic::Request::new(EncryptRequest {
        key_id: key_id.clone(),
        plaintext: plaintext.as_bytes().to_vec(),
        aad: vec![],
        tenant_id: String::new(),
    });

    let response = client.encrypt(request).await?;
    let encrypted = response.into_inner();
    println!("   Ciphertext: {}", encrypted.ciphertext);
    println!("   Nonce: {}", encrypted.nonce);
    println!("   Tag: {}", encrypted.tag);
    println!("   Version: {}\n", encrypted.version);

    // 4. Get key
    println!("4. Getting key details...");
    let request = tonic::Request::new(kms_api::grpc::pb::GetKeyRequest {
        id: key_id.clone(),
        tenant_id: String::new(),
    });
    let response = client.get_key(request).await?;
    let key = response.into_inner().key.unwrap();
    println!(
        "   Key: {} ({}) - {} v{}\n",
        key.name, key.id, key.spec, key.version
    );

    println!("=== gRPC Test Complete ===");
    Ok(())
}
