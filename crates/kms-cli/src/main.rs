//! kms-cli - Command line interface for KMS

mod report;

use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{CommandFactory, Parser, ValueEnum};
use clap_complete::{Generator, Shell};
use report::HtmlReport;
use std::fs;
use std::io::Write;

#[derive(Clone, Debug, ValueEnum)]
enum OutputFormat {
    Json,
    Html,
    Both,
}

#[derive(Parser, Debug)]
#[command(name = "kms")]
#[command(about = "KMS CLI - Key Management System CLI", long_about = None)]
struct Cli {
    /// KMS server URL
    #[arg(short, long, default_value = "http://127.0.0.1:8080")]
    server: String,

    /// Command to run
    #[command(subcommand)]
    command: Command,
}

#[derive(Parser, Debug)]
enum Command {
    /// Create a new key
    Create {
        /// Key name
        #[arg(short, long)]
        name: String,

        /// Key spec (aes-256-gcm, ed25519, sm4, sm2, etc.)
        #[arg(short, long, default_value = "aes-256-gcm")]
        spec: String,

        /// Tenant ID
        #[arg(short, long, default_value = "default")]
        tenant_id: String,
    },
    /// List all keys
    List {
        /// Tenant ID to filter by
        #[arg(short, long)]
        tenant_id: Option<String>,
    },
    /// Get key info
    Get {
        /// Key ID
        key_id: String,
    },
    /// Encrypt data
    Encrypt {
        /// Key ID
        #[arg(short, long)]
        key_id: String,

        /// Plaintext to encrypt
        #[arg(short, long)]
        plaintext: String,
    },
    /// Decrypt data
    Decrypt {
        /// Key ID
        #[arg(short, long)]
        key_id: String,

        /// Ciphertext (base64)
        #[arg(short, long)]
        ciphertext: String,

        /// Nonce (base64)
        #[arg(short, long)]
        nonce: String,

        /// Tag (base64)
        #[arg(short, long)]
        tag: String,
    },
    /// Sign data
    Sign {
        /// Key ID
        #[arg(short, long)]
        key_id: String,

        /// Data to sign (base64)
        #[arg(short, long)]
        data: String,
    },
    /// Verify signature
    Verify {
        /// Key ID
        #[arg(short, long)]
        key_id: String,

        /// Data that was signed (base64)
        #[arg(short, long)]
        data: String,

        /// Signature to verify (base64)
        #[arg(short, long)]
        signature: String,
    },
    /// Rotate key
    Rotate {
        /// Key ID
        #[arg(short, long)]
        key_id: String,
    },
    /// Delete key (soft delete)
    Delete {
        /// Key ID
        #[arg(short, long)]
        key_id: String,
    },
    /// SM9 Sign
    Sm9Sign {
        /// Identity (e.g., user@example.com)
        #[arg(short, long)]
        identity: String,

        /// Data to sign (base64)
        #[arg(short, long)]
        data: String,
    },
    /// SM9 Verify
    Sm9Verify {
        /// Identity
        #[arg(short, long)]
        identity: String,

        /// Data that was signed (base64)
        #[arg(short, long)]
        data: String,

        /// w component (base64)
        #[arg(short, long)]
        w: String,

        /// h component (hex)
        #[arg(short, long)]
        h: String,

        /// s component (base64)
        #[arg(short, long)]
        s: String,
    },
    /// SM9 Encrypt
    Sm9Encrypt {
        /// Identity (recipient)
        #[arg(short, long)]
        identity: String,

        /// Plaintext to encrypt
        #[arg(short, long)]
        plaintext: String,
    },
    /// SM9 Decrypt
    Sm9Decrypt {
        /// Identity (recipient)
        #[arg(short, long)]
        identity: String,

        /// c1 component (base64)
        #[arg(short, long)]
        c1: String,

        /// c2 component (base64)
        #[arg(short, long)]
        c2: String,

        /// c3 component (hex)
        #[arg(short, long)]
        c3: String,
    },
    /// Hash data
    Hash {
        /// Data to hash (base64)
        #[arg(short, long)]
        data: String,

        /// Algorithm (sm3, sha256)
        #[arg(short, long, default_value = "sha256")]
        algorithm: String,
    },
    /// Envelope encrypt
    EnvelopeEncrypt {
        /// KEK ID (AES-256 key)
        #[arg(short, long)]
        kek_id: String,

        /// Plaintext to encrypt (string)
        #[arg(short, long)]
        plaintext: String,

        /// DEK length in bytes (default 32)
        #[arg(short, long)]
        dek_length: Option<usize>,
    },
    /// Envelope decrypt
    EnvelopeDecrypt {
        /// KEK ID (AES-256 key)
        #[arg(short, long)]
        kek_id: String,

        /// KEK version used for encryption
        #[arg(short, long)]
        kek_version: u32,

        /// Wrapped DEK (base64)
        #[arg(short, long)]
        wrapped_dek: String,

        /// DEK nonce (base64)
        #[arg(short, long)]
        dek_nonce: String,

        /// Ciphertext (base64)
        #[arg(short, long)]
        ciphertext: String,

        /// Data nonce (base64)
        #[arg(short, long)]
        data_nonce: String,

        /// Tag (base64)
        #[arg(short, long)]
        tag: String,
    },
    /// Import a key
    ImportKey {
        /// Key name
        #[arg(short, long)]
        name: String,

        /// Key spec
        #[arg(short, long, default_value = "aes-256-gcm")]
        spec: String,

        /// Format (raw, pkcs8, jwk)
        #[arg(short, long, default_value = "raw")]
        format: String,

        /// Wrapped key (base64)
        #[arg(short, long)]
        wrapped_key: String,

        /// Encrypted transport key (base64)
        #[arg(short, long)]
        encrypted_transport_key: String,

        /// Source fingerprint (SHA-256 hex)
        #[arg(short, long)]
        source_fingerprint: String,

        /// Tenant ID
        #[arg(short, long, default_value = "default")]
        tenant_id: String,
    },
    /// Export a key
    ExportKey {
        /// Key ID
        #[arg(short, long)]
        key_id: String,

        /// Target system public key (base64, RSA)
        #[arg(short, long)]
        target_public_key: String,

        /// Export purpose
        #[arg(short, long, default_value = "migration")]
        purpose: String,
    },
    /// Derive shared secret using DH key exchange
    DhDerive {
        /// Key ID of our private key
        #[arg(short, long)]
        key_id: String,

        /// DH algorithm (ECDH-P256, ECDH-P384, X25519, SM2-KEX)
        #[arg(short, long, default_value = "ECDH-P256")]
        algorithm: String,

        /// Peer's public key (base64)
        #[arg(short, long)]
        peer_public_key: String,
    },
    /// Generate compliance and crypto configuration reports
    #[command(subcommand)]
    Report(ReportCommand),
    /// Generate shell completions
    Completion {
        /// Shell to generate completions for
        #[arg(value_enum, default_value = "bash")]
        shell: Shell,
    },
    /// Health check
    Health,
}

#[derive(Parser, Debug)]
enum ReportCommand {
    /// Generate crypto configuration report (key inventory, algorithms, drift detection)
    CryptoConfig {
        /// Output format
        #[arg(short, long, default_value = "json")]
        output: OutputFormat,

        /// Output directory
        #[arg(short = 'd', long, default_value = ".")]
        output_dir: String,

        /// Filter by tenant ID
        #[arg(short, long)]
        tenant_id: Option<String>,
    },
    /// Generate DJCP Level 3 compliance self-assessment report
    Compliance {
        /// Output format
        #[arg(short, long, default_value = "json")]
        output: OutputFormat,

        /// Output directory
        #[arg(short = 'd', long, default_value = ".")]
        output_dir: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let client = reqwest::Client::new();

    match cli.command {
        Command::Create {
            name,
            spec,
            tenant_id,
        } => {
            let resp = client
                .post(format!("{}/v1/keys", cli.server))
                .json(&serde_json::json!({
                    "name": name,
                    "spec": spec,
                    "tenant_id": tenant_id
                }))
                .send()
                .await?;

            if resp.status().is_success() {
                let key: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&key)?);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::List { tenant_id } => {
            let url = if let Some(ref tid) = tenant_id {
                format!("{}/v1/keys?tenant_id={}", cli.server, tid)
            } else {
                format!("{}/v1/keys", cli.server)
            };
            let resp = client.get(url).send().await?;

            if resp.status().is_success() {
                let keys: Vec<serde_json::Value> = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&keys)?);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::Get { key_id } => {
            let resp = client
                .get(format!("{}/v1/keys/{}", cli.server, key_id))
                .send()
                .await?;

            if resp.status().is_success() {
                let key: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&key)?);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::Encrypt { key_id, plaintext } => {
            let encoded = STANDARD.encode(plaintext.as_bytes());
            let resp = client
                .post(format!("{}/v1/keys/{}/encrypt", cli.server, key_id))
                .json(&serde_json::json!({
                    "plaintext": encoded
                }))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::Decrypt {
            key_id,
            ciphertext,
            nonce,
            tag,
        } => {
            let resp = client
                .post(format!("{}/v1/keys/{}/decrypt", cli.server, key_id))
                .json(&serde_json::json!({
                    "ciphertext": ciphertext,
                    "nonce": nonce,
                    "tag": tag
                }))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                if let Some(plaintext) = result.get("plaintext")
                    && let Some(encoded) = plaintext.as_str()
                {
                    let bytes = STANDARD
                        .decode(encoded)
                        .map_err(|e| anyhow::anyhow!("Base64 decode error: {e}"))?;
                    println!("{}", String::from_utf8_lossy(&bytes));
                }
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::Sign { key_id, data } => {
            let resp = client
                .post(format!("{}/v1/keys/{}/sign", cli.server, key_id))
                .json(&serde_json::json!({
                    "data": data
                }))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::Verify {
            key_id,
            data,
            signature,
        } => {
            let resp = client
                .post(format!("{}/v1/keys/{}/verify", cli.server, key_id))
                .json(&serde_json::json!({
                    "data": data,
                    "signature": signature
                }))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::Rotate { key_id } => {
            let resp = client
                .post(format!("{}/v1/keys/{}/rotate", cli.server, key_id))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::Delete { key_id } => {
            let resp = client
                .delete(format!("{}/v1/keys/{}", cli.server, key_id))
                .send()
                .await?;

            if resp.status().is_success() {
                println!("Key {} deleted successfully", key_id);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::Sm9Sign { identity, data } => {
            let resp = client
                .post(format!("{}/v1/sm9/sign", cli.server))
                .json(&serde_json::json!({
                    "identity": identity,
                    "data": data
                }))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::Sm9Verify {
            identity,
            data,
            w,
            h,
            s,
        } => {
            let resp = client
                .post(format!("{}/v1/sm9/verify", cli.server))
                .json(&serde_json::json!({
                    "identity": identity,
                    "data": data,
                    "w": w,
                    "h": h,
                    "s": s
                }))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::Sm9Encrypt {
            identity,
            plaintext,
        } => {
            let encoded = STANDARD.encode(plaintext.as_bytes());
            let resp = client
                .post(format!("{}/v1/sm9/encrypt", cli.server))
                .json(&serde_json::json!({
                    "identity": identity,
                    "plaintext": encoded
                }))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::Sm9Decrypt {
            identity,
            c1,
            c2,
            c3,
        } => {
            let resp = client
                .post(format!("{}/v1/sm9/decrypt", cli.server))
                .json(&serde_json::json!({
                    "identity": identity,
                    "c1": c1,
                    "c2": c2,
                    "c3": c3
                }))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::Hash { data, algorithm } => {
            let resp = client
                .post(format!("{}/v1/hash", cli.server))
                .json(&serde_json::json!({
                    "data": data,
                    "algorithm": algorithm
                }))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::EnvelopeEncrypt {
            kek_id,
            plaintext,
            dek_length,
        } => {
            let encoded = STANDARD.encode(plaintext.as_bytes());
            let mut body = serde_json::json!({
                "kek_id": kek_id,
                "plaintext": encoded
            });
            if let Some(len) = dek_length {
                body["dek_length"] = serde_json::json!(len);
            }
            let resp = client
                .post(format!("{}/v1/envelope/encrypt", cli.server))
                .json(&body)
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::EnvelopeDecrypt {
            kek_id,
            kek_version,
            wrapped_dek,
            dek_nonce,
            ciphertext,
            data_nonce,
            tag,
        } => {
            let resp = client
                .post(format!("{}/v1/envelope/decrypt", cli.server))
                .json(&serde_json::json!({
                    "kek_id": kek_id,
                    "kek_version": kek_version,
                    "wrapped_dek": wrapped_dek,
                    "dek_nonce": dek_nonce,
                    "ciphertext": ciphertext,
                    "data_nonce": data_nonce,
                    "tag": tag
                }))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                if let Some(plaintext) = result.get("plaintext")
                    && let Some(encoded) = plaintext.as_str()
                {
                    let bytes = STANDARD
                        .decode(encoded)
                        .map_err(|e| anyhow::anyhow!("Base64 decode error: {e}"))?;
                    println!("{}", String::from_utf8_lossy(&bytes));
                }
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::ImportKey {
            name,
            spec,
            format,
            wrapped_key,
            encrypted_transport_key,
            source_fingerprint,
            tenant_id,
        } => {
            let resp = client
                .post(format!("{}/v1/keys/import", cli.server))
                .json(&serde_json::json!({
                    "name": name,
                    "spec": spec,
                    "format": format,
                    "wrapped_key": wrapped_key,
                    "encrypted_transport_key": encrypted_transport_key,
                    "source_fingerprint": source_fingerprint,
                    "tenant_id": tenant_id
                }))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::ExportKey {
            key_id,
            target_public_key,
            purpose,
        } => {
            let resp = client
                .post(format!("{}/v1/keys/export/{}", cli.server, key_id))
                .json(&serde_json::json!({
                    "target_public_key": target_public_key,
                    "purpose": purpose
                }))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::DhDerive {
            key_id,
            algorithm,
            peer_public_key,
        } => {
            let resp = client
                .post(format!("{}/v1/dh/derive", cli.server))
                .json(&serde_json::json!({
                    "key_id": key_id,
                    "algorithm": algorithm,
                    "peer_public_key": peer_public_key
                }))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::Health => {
            let resp = client
                .get(format!("{}/v1/health", cli.server))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                eprintln!("Error: {}", resp.status());
            }
        }
        Command::Report(report_cmd) => {
            let keys_url;
            let tenant_filter: Option<String>;

            match &report_cmd {
                ReportCommand::CryptoConfig { tenant_id, .. } => {
                    keys_url = if let Some(tid) = tenant_id {
                        format!("{}/v1/keys?tenant_id={}", cli.server, tid)
                    } else {
                        format!("{}/v1/keys", cli.server)
                    };
                    tenant_filter = tenant_id.clone();
                }
                ReportCommand::Compliance { .. } => {
                    keys_url = format!("{}/v1/keys", cli.server);
                    tenant_filter = None;
                }
            }

            let keys: Vec<report::KeyEntry> = match client.get(keys_url).send().await {
                Ok(resp) if resp.status().is_success() => match resp.json().await {
                    Ok(keys) => keys,
                    Err(e) => {
                        eprintln!("Error parsing keys response: {}", e);
                        return Ok(());
                    }
                },
                Ok(resp) => {
                    eprintln!("Error fetching keys: {}", resp.status());
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("Error connecting to KMS server: {}", e);
                    return Ok(());
                }
            };

            match report_cmd {
                ReportCommand::CryptoConfig {
                    output, output_dir, ..
                } => {
                    let report = report::CryptoConfigReport::generate(
                        &cli.server,
                        tenant_filter.as_deref(),
                        keys,
                        "metrics unavailable for CLI",
                    );
                    write_report_output(&output, &output_dir, "crypto-config", &report)?;
                }
                ReportCommand::Compliance { output, output_dir } => {
                    let report = report::ComplianceReport::generate(
                        &cli.server,
                        &keys,
                        "metrics unavailable for CLI",
                    );
                    write_report_output(&output, &output_dir, "compliance", &report)?;
                }
            }
        }
        Command::Completion { shell } => {
            let cmd = Cli::command();
            shell.generate(&cmd, &mut std::io::stdout());
        }
    }

    Ok(())
}

fn write_report_output<T: serde::Serialize + HtmlReport>(
    output: &OutputFormat,
    output_dir: &str,
    base_name: &str,
    report: &T,
) -> anyhow::Result<()> {
    fs::create_dir_all(output_dir)?;

    let write_json = |report: &T| -> anyhow::Result<()> {
        let json = match serde_json::to_string_pretty(report) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("Error serializing report to JSON: {}", e);
                return Ok(());
            }
        };
        let path = format!("{output_dir}/{base_name}.json");
        fs::File::create(&path)?.write_all(json.as_bytes())?;
        println!("JSON report written to {}", path);
        Ok(())
    };

    let write_html = |report: &T| {
        let html = report.to_html();
        let path = format!("{output_dir}/{base_name}.html");
        let mut f = fs::File::create(&path).expect("create HTML file");
        f.write_all(html.as_bytes()).expect("write HTML file");
        println!("HTML report written to {}", path);
    };

    match output {
        OutputFormat::Json => write_json(report)?,
        OutputFormat::Html => write_html(report),
        OutputFormat::Both => {
            write_json(report)?;
            write_html(report);
        }
    }
    Ok(())
}
