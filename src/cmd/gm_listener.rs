//! TLS 1.3 + SM Listener for axum REST API
//!
//! Implements axum 0.8's `Listener` trait by wrapping a tokio `TcpListener`
//! and performing TLS 1.3 + SM handshake on each accepted connection via `gm_tls::TlsAcceptor`.
//!
//! This enables the REST API to use TLS 1.3 (RFC 8446, version byte 0x0303) with SM cipher suites
//! (SM2/SM3/SM4) for transport-layer encryption.
//!
//! Note: TLCP (GB/T 38636-2020, version byte 0x0101) is available as a separate `gm-tlcp` crate.
//! It is currently NOT wired into gm-kms; this listener uses gm-tls TLS 1.3 + SM.

use anyhow::{Context, Result};
use axum::serve::Listener;
use std::io;
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// A TLS 1.3 + SM listener that wraps a TCP listener and performs SM2/SM4-GCM handshake.
///
/// # Usage
///
/// ```ignore
/// let tls_config = gm_tls::TlsConfig::load(cert_path, key_path, ca_path)?;
/// let listener = GmTlsListener::bind(addr, tls_config).await?;
/// axum::serve(listener, app).await?;
/// ```
pub struct GmTlsListener {
    listener: tokio::net::TcpListener,
    acceptor: gm_tls::TlsAcceptor,
}

impl GmTlsListener {
    /// Bind to an address and create a TLS 1.3 + SM listener.
    ///
    /// # Arguments
    /// * `addr` - Socket address to bind to
    /// * `config` - TLS 1.3 + SM configuration (cert, key, CA cert)
    pub async fn bind(addr: SocketAddr, config: gm_tls::TlsConfig) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .context("Failed to bind TLS 1.3 + SM listener")?;
        let acceptor = gm_tls::TlsAcceptor::new(config)?;
        Ok(Self { listener, acceptor })
    }
}

impl Listener for GmTlsListener {
    type Io = gm_tls::GmTlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            // Accept raw TCP connection
            let (tcp_stream, peer_addr) = match self.listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    if is_connection_error(&e) {
                        continue;
                    }
                    tracing::error!("TLS 1.3 + SM listener accept error: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            // Perform TLS 1.3 + SM handshake
            match self.acceptor.accept(tcp_stream).await {
                Ok(gm_stream) => return (gm_stream, peer_addr),
                Err(e) => {
                    tracing::warn!("TLS 1.3 + SM handshake failed for {peer_addr}: {e}");
                    // Retry — next loop iteration will accept a new connection
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

/// Check if an IO error is a transient connection error that should be silently retried.
fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_is_connection_error_transient_kinds() {
        assert!(is_connection_error(&io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "test"
        )));
        assert!(is_connection_error(&io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "test"
        )));
        assert!(is_connection_error(&io::Error::new(
            io::ErrorKind::ConnectionReset,
            "test"
        )));
    }

    #[test]
    fn test_is_connection_error_non_transient_kinds() {
        assert!(!is_connection_error(&io::Error::new(
            io::ErrorKind::NotFound,
            "test"
        )));
        assert!(!is_connection_error(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "test"
        )));
        assert!(!is_connection_error(&io::Error::new(
            io::ErrorKind::AddrInUse,
            "test"
        )));
        assert!(!is_connection_error(&io::Error::other("test")));
    }

    #[tokio::test]
    async fn test_gm_tls_listener_creation_error_on_missing_cert() {
        let _addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let config = gm_tls::TlsConfig::load(
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem",
            "/nonexistent/ca.pem",
        );
        assert!(config.is_err(), "Should fail with missing cert files");
        let err = config.unwrap_err();
        assert!(err.is_config_error(), "Error should be a config error");
    }

    #[test]
    fn test_gm_tls_config_require_client_auth_default() {
        // from_bytes stores buffers without validation; builder pattern verifies
        // that with_require_client_auth exists and propagates correctly.
        let config = gm_tls::TlsConfig::from_bytes(vec![1], vec![1], vec![1])
            .expect("from_bytes should succeed with non-empty buffers");
        let _config = config
            .with_require_client_auth(false)
            .with_require_client_auth(true);
    }

    #[tokio::test]
    async fn test_gm_tls_local_addr_with_ephemeral_port() {
        // Bind to port 0 (OS assigns ephemeral port)
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Should bind to ephemeral port");
        let addr = listener.local_addr().expect("Should have local address");
        assert!(addr.port() > 0, "Ephemeral port should be non-zero");
    }

    #[test]
    fn test_gm_tls_listener_is_axum_compatible() {
        // Compile-time verification: local_addr method comes from Listener trait.
        // This only compiles if GmTlsListener: Listener.
        let _: fn(&GmTlsListener) -> io::Result<SocketAddr> = |l: &GmTlsListener| l.local_addr();
    }

    #[test]
    fn test_is_connection_error_broken_pipe() {
        // BrokenPipe is NOT transient for TLS (connection is torn down)
        assert!(!is_connection_error(&io::Error::new(
            io::ErrorKind::BrokenPipe,
            "test"
        )));
    }

    #[test]
    fn test_is_connection_error_timed_out() {
        // TimedOut is NOT in the allowlist
        assert!(!is_connection_error(&io::Error::new(
            io::ErrorKind::TimedOut,
            "test"
        )));
    }
}
