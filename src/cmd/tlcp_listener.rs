//! TLCP (GB/T 38636-2020) Listener for axum REST API.
//!
//! Implements axum 0.8's `Listener` trait by wrapping a tokio `TcpListener`
//! and performing a TLCP handshake on each accepted connection via
//! `gm_tlcp::TlcpAcceptor::accept_with_certs`.
//!
//! TLCP differs from TLS 1.3 + SM (see `gm_listener.rs`) in three operational
//! aspects relevant to this listener:
//!
//! 1. **Dual certificates**: TLCP requires both a signing certificate and an
//!    encryption certificate (plus their corresponding SM2 private keys), all
//!    of which must be supplied at construction time via
//!    [`TlcpAcceptor::with_dual_certs`].
//! 2. **No ALPN**: TLCP has no application-layer protocol negotiation, which is
//!    why gm-kms' gRPC listener still uses TLS 1.3 + SM (`gm-tls`).
//! 3. **Different stream type**: the handshake returns `TlcpStream<TcpStream>`
//!    rather than `GmTlsStream<TcpStream>`; axum only requires that the stream
//!    impl `AsyncRead + AsyncWrite + Unpin + Send`, which both provide.
//!
//! For TLCP protocol-level details see
//! [`gm-tlcp/src/lib.rs`](https://github.com/GM-Engineers/gm/blob/main/gm/gm-tlcp/src/lib.rs).

use anyhow::{Context, Result};
use axum::serve::Listener;
use gm_crypto::sm2::Sm2KeyPair;
use gm_tlcp::TlcpAcceptor;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use tokio::net::TcpStream;

/// A TLCP listener that wraps a TCP listener and performs SM2 dual-cert ECDHE
/// handshake on each accepted connection.
///
/// # Usage
///
/// ```ignore
/// let acceptor = TlcpListener::load_acceptor(
///     Path::new("server-sign.crt"),  // DER-encoded signing cert
///     Path::new("server-enc.crt"),   // DER-encoded encryption cert
///     Path::new("server-sign.key.pem"),  // SM2 signing private key (PEM)
///     Path::new("server-enc.key.pem"),   // SM2 encryption private key (PEM)
/// )?;
/// let listener = TlcpListener::bind(addr, acceptor).await?;
/// axum::serve(listener, app).await?;
/// ```
pub struct TlcpListener {
    listener: tokio::net::TcpListener,
    acceptor: TlcpAcceptor,
}

impl TlcpListener {
    /// Bind to an address and create a TLCP listener using a pre-built
    /// `TlcpAcceptor` (typically produced by [`TlcpListener::load_acceptor`]).
    pub async fn bind(addr: SocketAddr, acceptor: TlcpAcceptor) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .context("Failed to bind TLCP listener")?;
        Ok(Self { listener, acceptor })
    }

    /// Load dual SM2 certificates + private keys from disk and construct a
    /// `TlcpAcceptor` configured for production dual-cert ECDHE handshake.
    ///
    /// * `sign_cert_path` — DER-encoded X.509 signing certificate
    /// * `enc_cert_path`  — DER-encoded X.509 encryption certificate
    /// * `sign_key_path`  — PEM-encoded SM2 signing private key
    /// * `enc_key_path`   — PEM-encoded SM2 encryption private key
    pub fn load_acceptor(
        sign_cert_path: &Path,
        enc_cert_path: &Path,
        sign_key_path: &Path,
        enc_key_path: &Path,
    ) -> Result<TlcpAcceptor> {
        let sign_cert = std::fs::read(sign_cert_path).with_context(|| {
            format!(
                "Failed to read TLCP signing cert (DER): {}",
                sign_cert_path.display()
            )
        })?;
        let enc_cert = std::fs::read(enc_cert_path).with_context(|| {
            format!(
                "Failed to read TLCP encryption cert (DER): {}",
                enc_cert_path.display()
            )
        })?;
        let sign_pem = std::fs::read_to_string(sign_key_path).with_context(|| {
            format!(
                "Failed to read TLCP signing key (PEM): {}",
                sign_key_path.display()
            )
        })?;
        let enc_pem = std::fs::read_to_string(enc_key_path).with_context(|| {
            format!(
                "Failed to read TLCP encryption key (PEM): {}",
                enc_key_path.display()
            )
        })?;

        let sign_key = Sm2KeyPair::from_private_key_pem(&sign_pem).with_context(|| {
            format!(
                "Failed to parse TLCP signing key (PEM SM2): {}",
                sign_key_path.display()
            )
        })?;
        let enc_key = Sm2KeyPair::from_private_key_pem(&enc_pem).with_context(|| {
            format!(
                "Failed to parse TLCP encryption key (PEM SM2): {}",
                enc_key_path.display()
            )
        })?;

        Ok(TlcpAcceptor::new().with_dual_certs(sign_cert, enc_cert, sign_key, enc_key))
    }
}

impl Listener for TlcpListener {
    type Io = gm_tlcp::TlcpStream<TcpStream>;
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
                    tracing::error!("TLCP listener accept error: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            // Perform TLCP dual-cert ECDHE handshake.
            // We pass `accept_with_certs` rather than `accept` so the configured
            // dual-cert path is always taken; `accept` would fall back to a
            // simplified simulated handshake if dual-certs were absent.
            match self.acceptor.clone().accept_with_certs(tcp_stream).await {
                Ok(tlcp_stream) => return (tlcp_stream, peer_addr),
                Err(e) => {
                    tracing::warn!("TLCP handshake failed for {peer_addr}: {e}");
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
    async fn test_load_acceptor_missing_sign_cert() {
        // All paths non-existent → load_acceptor should bail at the first read
        // with a context message mentioning the signing cert path.
        let res = TlcpListener::load_acceptor(
            Path::new("/nonexistent/sign.crt"),
            Path::new("/nonexistent/enc.crt"),
            Path::new("/nonexistent/sign.pem"),
            Path::new("/nonexistent/enc.pem"),
        );
        // `gm_tlcp::TlcpAcceptor` does not impl Debug, so we can't use
        // `unwrap_err()`. Match manually instead.
        let err_str = match res {
            Ok(_) => panic!("Should fail when sign cert is missing"),
            Err(e) => e.to_string(),
        };
        assert!(
            err_str.contains("signing cert") || err_str.contains("sign"),
            "Error message should reference the signing cert, got: {err_str}"
        );
    }

    #[tokio::test]
    async fn test_load_acceptor_missing_enc_cert() {
        // sign cert exists but enc cert does not → fails at enc_cert read.
        // We can't easily create a real DER cert here; just use a non-empty
        // placeholder for sign and a missing path for enc.
        let tmp = tempfile::NamedTempFile::new().expect("create tmp file");
        std::fs::write(tmp.path(), b"\x30\x82\x00\x00").expect("write tmp");

        let res = TlcpListener::load_acceptor(
            tmp.path(),
            Path::new("/nonexistent/enc.crt"),
            Path::new("/nonexistent/sign.pem"),
            Path::new("/nonexistent/enc.pem"),
        );
        let err_str = match res {
            Ok(_) => panic!("Should fail when enc cert is missing"),
            Err(e) => e.to_string(),
        };
        assert!(
            err_str.contains("encryption cert") || err_str.contains("enc"),
            "Error message should reference the encryption cert, got: {err_str}"
        );
    }

    #[test]
    fn test_tlcp_listener_is_axum_compatible() {
        // Compile-time verification: `local_addr` method comes from the
        // `Listener` trait. This only compiles if `TlcpListener: Listener`.
        let _: fn(&TlcpListener) -> io::Result<SocketAddr> = |l: &TlcpListener| l.local_addr();
    }

    #[tokio::test]
    async fn test_bind_with_unconfigured_acceptor() {
        // An acceptor with NO dual certs can still be bound — but it will fail
        // handshakes. This test just verifies bind() itself does not depend
        // on cert configuration.
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let acceptor = TlcpAcceptor::new();
        let listener = TlcpListener::bind(addr, acceptor)
            .await
            .expect("bind should succeed regardless of acceptor config");
        let bound = listener.local_addr().expect("local_addr");
        assert!(bound.port() > 0, "Ephemeral port should be non-zero");
    }
}
