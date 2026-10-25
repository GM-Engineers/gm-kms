//! Interface-level guard for the fail-closed startup semantics (audit B0 / P1-4).
//!
//! `src/cmd/server.rs::in_memory_fallback_permitted` has unit-level coverage,
//! but the property that matters in production is what the **process** does:
//! with an unreachable PostgreSQL and no explicit opt-in, the KMS must refuse
//! to start instead of silently booting with an in-memory keystore — every key
//! would be gone after the next restart, while the operator believes the KMS
//! is durable.
//!
//! These cases drive the real binary (`CARGO_BIN_EXE_kms`), so they cover the
//! whole startup path: configuration → PostgreSQL → keystore selection →
//! listeners, rather than one helper function.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tempfile::TempDir;

/// A PostgreSQL URL nothing listens on: the TCP connect is refused at once.
const UNREACHABLE_PG_URL: &str = "postgres://kms:kms@127.0.0.1:1/kms";

/// The startup deadline for the PostgreSQL connection attempt (seconds).
///
/// sqlx retries the connection until its own 30 s pool acquire timeout
/// expires, so without an explicit deadline the refusal below would only be
/// reached after a full timeout per attempt — the test would spend a minute
/// proving that the gate works.
const CONNECT_TIMEOUT_SECS: u64 = 2;

/// How long the server process may take to exit before the case fails.
///
/// The refusal itself is reached in a few seconds (two connection attempts
/// of `CONNECT_TIMEOUT_SECS` each), but the process still has to shut its
/// runtime down, and a shared CI runner can be slow enough to stretch that
/// well past the work itself. The deadline therefore has to be generous: it
/// exists to catch a startup that never gives up, not to police a few
/// seconds of work.
const EXIT_DEADLINE_SECS: u64 = 180;

/// The marker the fail-closed keystore gate prints (audit P1-4).
const REFUSAL_MARKER: &str = "refusing to start without a persistent keystore";

/// The marker of the *next* gate on the startup path: the plaintext gRPC
/// listener is refused unless the operator opted in (audit PR-4.1).
const TLS_GATE_MARKER: &str = "KMS gRPC requires TLS in production";

/// Write a minimal configuration that points at an unreachable PostgreSQL.
fn write_config(dir: &Path, allow_in_memory: bool) -> PathBuf {
    let path = dir.join("kms.toml");
    let toml = format!(
        r#"
[backend]
backend_type = "software"
allow_in_memory = {allow_in_memory}

[database]
url = "{UNREACHABLE_PG_URL}"
connect_timeout_secs = {CONNECT_TIMEOUT_SECS}

[redis]
enabled = false

[backup]
enabled = false

[rate_limit]
enabled = false

[quota]
enabled = false
"#
    );
    std::fs::write(&path, toml).expect("the configuration file must be writable");
    path
}

/// A TCP port that is free right now.
///
/// 8080 / 9090 are skipped: the server treats them as "not overridden" and
/// falls back to the ports from the configuration file.
fn free_port() -> u16 {
    loop {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        if port != 8080 && port != 9090 {
            return port;
        }
    }
}

/// The environment the startup must see: no insecure opt-in, and no database
/// override that could mask the unreachable PostgreSQL.
///
/// The database TLS mode is pinned to `verify_ca` with a CA path, because the
/// production default (`verify_ca`) is mandatory and the server refuses to
/// start when it is not configured (audit PR-4.4). The opt-in modes
/// (`no_verify` / `disabled`) would require `KMS_DEV_MODE` / `KMS_ALLOW_INSECURE`,
/// and those flags also lift the in-memory keystore gate — which is exactly
/// what this file must not do.
fn clean_env<'a>(
    cmd: &'a mut tokio::process::Command,
    ca_cert: &Path,
) -> &'a mut tokio::process::Command {
    cmd.env("KMS_API_KEY", "b8d-startup-test-key")
        .env("KMS_DB_TLS_MODE", "verify_ca")
        .env("KMS_DB_TLS_CA_CERT", ca_cert)
        .env_remove("KMS_DEV_MODE")
        .env_remove("KMS_ALLOW_INSECURE")
        .env_remove("KMS_API_KEY_ROLE")
        .env_remove("KMS_KEK")
        .env_remove("KMS_KEK_FILE")
        .env_remove("DATABASE_URL")
        .env_remove("POSTGRES_HOST")
        .env_remove("POSTGRES_PORT")
        .env_remove("POSTGRES_DB")
        .env_remove("POSTGRES_USER")
        .env_remove("POSTGRES_PASSWORD")
        .env_remove("REDIS_URL")
        .env_remove("BACKUP_ENABLED")
        .env_remove("BACKUP_MASTER_KEY_PASSPHRASE")
        .env_remove("RATE_LIMIT_ENABLED")
        .env_remove("QUOTA_ENABLED")
}

/// Start the real binary with the given configuration and wait for it to exit.
async fn run_server(config: &Path, work_dir: &Path) -> std::process::Output {
    // A placeholder CA file: the PostgreSQL connection is refused long before
    // any TLS handshake could happen, but the startup insists on a CA path.
    let ca_cert = work_dir.join("db-ca.pem");
    std::fs::write(&ca_cert, b"-----BEGIN CERTIFICATE-----\n").expect("write the CA placeholder");

    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_kms"));
    cmd.arg("--server")
        .arg("--config")
        .arg(config)
        .arg("--rest-port")
        .arg(free_port().to_string())
        .arg("--grpc-port")
        .arg(free_port().to_string())
        .current_dir(work_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    clean_env(&mut cmd, &ca_cert);

    tokio::time::timeout(Duration::from_secs(EXIT_DEADLINE_SECS), cmd.output())
        .await
        .expect("the server must exit instead of running forever")
        .expect("the server process must be runnable")
}

/// Audit B8-d: an unreachable PostgreSQL without an explicit opt-in must stop
/// the process, and the refusal must be visible on stderr.
#[tokio::test]
async fn b8d_server_refuses_to_start_without_a_persistent_keystore() {
    let dir = TempDir::new().expect("temp dir");
    let config = write_config(dir.path(), false);

    let output = run_server(&config, dir.path()).await;
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "the server must refuse to start without a persistent keystore; stderr={stderr}"
    );
    assert!(
        stderr.contains(REFUSAL_MARKER),
        "the refusal must be explained on stderr, got: {stderr}"
    );
}

/// Audit B8-d: the control for the case above.
///
/// With the explicit opt-in the keystore gate must let the startup through.
/// The process still stops at the *next* gate (the plaintext gRPC listener),
/// which proves the keystore gate was passed rather than skipped for an
/// unrelated reason.
#[tokio::test]
async fn b8d_server_passes_the_keystore_gate_when_the_fallback_is_opted_in() {
    let dir = TempDir::new().expect("temp dir");
    let config = write_config(dir.path(), true);

    let output = run_server(&config, dir.path()).await;
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stderr.contains(REFUSAL_MARKER),
        "the explicit opt-in must lift the in-memory keystore refusal, stderr={stderr}"
    );
    assert!(
        stderr.contains(TLS_GATE_MARKER),
        "the startup must have progressed past the keystore gate and stopped at the \
         plaintext-TLS gate instead, stderr={stderr}"
    );
}
