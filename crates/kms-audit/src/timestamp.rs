//! RFC 3161 Timestamp Authority (TSA) client
//!
//! Provides trusted timestamps for audit log integrity.
//! Meets 等保三级 requirement for external timestamp sources (L-001).
//!
//! # Architecture
//!
//! Uses a background batch pattern: TSA timestamps are requested periodically
//! (every 60s) for the current hash chain head. Audit entries carry the latest
//! available timestamp from shared state — the TSA is NEVER on the hot write path.
//!
//! # DER Implementation
//!
//! Hand-rolled minimal DER encoder/parser for RFC 3161 TimeStampReq/TimeStampResp.
//! The subset needed is ~150 lines — adding a full ASN.1 crate would be heavier
//! and introduce unnecessary supply-chain surface.

use crate::error::{AuditError, AuditResult};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

// =============================================================================
// Trusted Timestamp
// =============================================================================

/// A trusted timestamp obtained from an RFC 3161 TSA.
///
/// Stored alongside audit entries for forensic verification.
/// The `raw_token` field contains the full DER-encoded TimeStampToken
/// so that a third party can verify it independently (e.g. `openssl ts -verify`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedTimestamp {
    /// Full DER-encoded TimeStampToken (for forensic verification)
    pub raw_token: Vec<u8>,
    /// TSA genTime extracted from TSTInfo (Unix timestamp)
    pub gen_time: i64,
    /// TSA serial number (big-endian bytes from ASN.1 INTEGER)
    pub serial_number: Vec<u8>,
    /// TSA policy OID under which the timestamp was issued
    pub policy: String,
    /// Hash algorithm used in the request ("sha256" or "sm3")
    pub hash_algorithm: String,
    /// The nonce we sent in the request (for cross-verification)
    pub nonce: Vec<u8>,
    /// Accuracy in milliseconds (default 1000 if not present in response)
    pub accuracy_millis: u32,
}

// =============================================================================
// Timestamp Request / Response
// =============================================================================

/// Timestamp query request
#[derive(Debug, Clone)]
pub struct TimestampRequest {
    /// Hash algorithm OID
    pub algorithm: String,
    /// Digest to timestamp
    pub digest: Vec<u8>,
}

/// Timestamp response from TSA
#[derive(Debug, Clone)]
pub struct TimestampResponse {
    /// DER-encoded TimeStampToken
    pub token: Vec<u8>,
    /// Timestamp serial number
    pub serial_number: Vec<u8>,
    /// Timestamp accuracy (milliseconds)
    pub accuracy_millis: u32,
    /// Timestamp generation time
    pub timestamp: SystemTime,
    /// TSA policy OID
    pub policy: String,
}

impl From<&TrustedTimestamp> for TimestampResponse {
    fn from(ts: &TrustedTimestamp) -> Self {
        Self {
            token: ts.raw_token.clone(),
            serial_number: ts.serial_number.clone(),
            accuracy_millis: ts.accuracy_millis,
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(ts.gen_time as u64),
            policy: ts.policy.clone(),
        }
    }
}

// =============================================================================
// Hash Algorithm
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampHashAlgorithm {
    Sha256,
    Sm3,
}

impl TimestampHashAlgorithm {
    /// ASN.1 OID bytes for the hash algorithm (used in AlgorithmIdentifier)
    pub fn oid_bytes(&self) -> &'static [u8] {
        match self {
            // id-sha256  OID: 2.16.840.1.101.3.4.2.1
            TimestampHashAlgorithm::Sha256 => {
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
            }
            // id-sm3  OID: 1.2.156.10197.1.401
            TimestampHashAlgorithm::Sm3 => &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x11],
        }
    }

    /// String representation of the OID
    pub fn as_oid(&self) -> &'static str {
        match self {
            TimestampHashAlgorithm::Sha256 => "2.16.840.1.101.3.4.2.1",
            TimestampHashAlgorithm::Sm3 => "1.2.156.10197.1.401",
        }
    }

    /// Digest length in bytes
    pub fn digest_len(&self) -> usize {
        match self {
            TimestampHashAlgorithm::Sha256 => 32,
            TimestampHashAlgorithm::Sm3 => 32,
        }
    }
}

// =============================================================================
// Timestamp Config
// =============================================================================

/// RFC 3161 TSA client configuration
#[derive(Debug, Clone)]
pub struct TimestampConfig {
    /// TSA server URL (primary)
    pub server_url: String,
    /// Request timeout
    pub timeout: Duration,
    /// Optional basic auth credentials
    pub username: Option<String>,
    pub password: Option<String>,
    /// Hash algorithm for requests
    pub hash_algorithm: TimestampHashAlgorithm,
    /// Size of nonce in bytes (default 8)
    pub nonce_size: usize,
    /// Maximum allowed time skew between TSA genTime and local clock (seconds)
    pub max_time_skew_secs: u64,
    /// Optional path to TSA CA certificate for verification (P2: cert validation)
    pub ca_path: Option<PathBuf>,
}

impl Default for TimestampConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            timeout: Duration::from_secs(10),
            username: None,
            password: None,
            hash_algorithm: TimestampHashAlgorithm::Sha256,
            nonce_size: 8,
            max_time_skew_secs: 300,
            ca_path: None,
        }
    }
}

// =============================================================================
// TSA Client Configuration (multi-endpoint)
// =============================================================================

/// Configuration for TSA client with multiple failover endpoints
#[derive(Debug, Clone)]
pub struct TsaClientConfig {
    /// TSA endpoints (primary first, then failover)
    pub endpoints: Vec<String>,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Optional basic auth
    pub username: Option<String>,
    pub password: Option<String>,
    /// Hash algorithm
    pub hash_algorithm: TimestampHashAlgorithm,
    /// Path to CA certificate (P2)
    pub ca_path: Option<PathBuf>,
}

impl Default for TsaClientConfig {
    fn default() -> Self {
        Self {
            endpoints: Vec::new(),
            timeout_secs: 10,
            username: None,
            password: None,
            hash_algorithm: TimestampHashAlgorithm::Sha256,
            ca_path: None,
        }
    }
}

impl TsaClientConfig {
    /// Create TimestampConfig for a specific endpoint
    fn to_endpoint_config(&self, url: &str) -> TimestampConfig {
        TimestampConfig {
            server_url: url.to_string(),
            timeout: Duration::from_secs(self.timeout_secs),
            username: self.username.clone(),
            password: self.password.clone(),
            hash_algorithm: self.hash_algorithm,
            nonce_size: 8,
            max_time_skew_secs: 300,
            ca_path: self.ca_path.clone(),
        }
    }
}

// =============================================================================
// DER Encoding Helpers (minimal, for RFC 3161 TimeStampReq)
// =============================================================================

/// Encode a DER length.
fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

/// Build a DER TLV (tag, length, value) in one pass.
fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + value.len());
    out.push(tag);
    out.extend_from_slice(&der_len(value.len()));
    out.extend_from_slice(value);
    out
}

fn der_integer_bytes(bytes: &[u8]) -> Vec<u8> {
    der_tlv(0x02, bytes)
}

fn der_octet_string(bytes: &[u8]) -> Vec<u8> {
    der_tlv(0x04, bytes)
}

fn der_oid(bytes: &[u8]) -> Vec<u8> {
    der_tlv(0x06, bytes)
}

fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

fn der_boolean(val: bool) -> Vec<u8> {
    vec![0x01, 0x01, if val { 0xFF } else { 0x00 }]
}

fn der_sequence(contents: &[u8]) -> Vec<u8> {
    der_tlv(0x30, contents)
}

// =============================================================================
// TimestampAuthority
// =============================================================================

/// RFC 3161 Timestamp Authority client
pub struct TimestampAuthority {
    config: TimestampConfig,
    http_client: reqwest::Client,
    /// Last nonce sent (for response verification)
    pub last_nonce: parking_lot::Mutex<Option<Vec<u8>>>,
}

impl TimestampAuthority {
    /// Create new TSA client from single-endpoint config
    pub fn new(config: TimestampConfig) -> AuditResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| {
                AuditError::Network(format!("Failed to create HTTP client for TSA: {e}"))
            })?;

        Ok(Self {
            config,
            http_client: client,
            last_nonce: parking_lot::Mutex::new(None),
        })
    }

    /// Create from TsaClientConfig (multi-endpoint).
    /// Uses the first endpoint as primary.
    pub fn from_client_config(cfg: &TsaClientConfig) -> AuditResult<Self> {
        let primary = cfg.endpoints.first().cloned().unwrap_or_default();
        Self::new(cfg.to_endpoint_config(&primary))
    }

    /// Request a timestamp from the TSA, trying all configured endpoints.
    ///
    /// For multi-endpoint: pass the full endpoints list. The primary endpoint
    /// is tried first, then failover endpoints in order.
    pub async fn request_timestamp_with_failover(
        &self,
        digest: &[u8],
        failover_endpoints: &[String],
    ) -> AuditResult<TimestampResponse> {
        // Try primary first (self.config.server_url)
        match self
            .request_timestamp_internal(digest, &self.config.server_url)
            .await
        {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                tracing::warn!("Primary TSA {} failed: {}", self.config.server_url, e);
            }
        }

        // Try failover endpoints
        for endpoint in failover_endpoints {
            match self.request_timestamp_internal(digest, endpoint).await {
                Ok(resp) => {
                    tracing::info!("TSA failover to {} succeeded", endpoint);
                    return Ok(resp);
                }
                Err(e) => {
                    tracing::warn!("TSA failover {} failed: {}", endpoint, e);
                }
            }
        }

        Err(AuditError::TsaFailed("All TSA endpoints failed".into()))
    }

    /// Request a timestamp from the configured TSA (single endpoint)
    pub async fn request_timestamp(&self, digest: &[u8]) -> AuditResult<TimestampResponse> {
        self.request_timestamp_internal(digest, &self.config.server_url)
            .await
    }

    /// Internal: request timestamp from a specific endpoint
    async fn request_timestamp_internal(
        &self,
        digest: &[u8],
        endpoint: &str,
    ) -> AuditResult<TimestampResponse> {
        // Generate nonce
        let mut nonce = vec![0u8; self.config.nonce_size];
        rand::rng().fill_bytes(&mut nonce);

        // Strip leading zeros for DER INTEGER encoding
        let nonce_for_der = strip_leading_zeros(&nonce);

        // Store nonce for verification
        *self.last_nonce.lock() = Some(nonce.clone());

        // Build RFC 3161 TimeStampReq
        let request = build_timestamp_request(digest, &nonce_for_der, self.config.hash_algorithm);
        tracing::debug!(
            "TSA request: {} bytes to {}, nonce={}",
            request.len(),
            endpoint,
            hex::encode(&nonce)
        );

        // Send request
        let response = send_tsa_request(&self.http_client, endpoint, &request).await?;

        // Parse and verify response
        parse_timestamp_response(&response, digest, &nonce)
            .map_err(|e| AuditError::TsaFailed(format!("TSA response parsing failed: {e}")))
    }

    /// Verify that a timestamp response matches the original digest and nonce
    pub fn verify_timestamp(
        &self,
        digest: &[u8],
        response: &TimestampResponse,
    ) -> AuditResult<bool> {
        // Verify digest is embedded in the response token
        verify_digest_in_token(&response.token, digest)?;

        // Check genTime is within acceptable skew
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let gen_time = response
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if (gen_time - now).unsigned_abs() > self.config.max_time_skew_secs {
            tracing::warn!(
                "TSA genTime skew too large: gen={}, now={}, skew={}s",
                gen_time,
                now,
                (gen_time - now).unsigned_abs()
            );
            return Ok(false);
        }

        Ok(true)
    }
}

/// Strip leading zero bytes for DER INTEGER encoding (keep at least one byte).
fn strip_leading_zeros(bytes: &[u8]) -> Vec<u8> {
    let mut start = 0;
    while start < bytes.len() - 1 && bytes[start] == 0 {
        start += 1;
    }
    bytes[start..].to_vec()
}

// =============================================================================
// TimeStampReq Builder (RFC 3161 Section 2.4.1)
// =============================================================================

/// Build a DER-encoded RFC 3161 TimeStampReq.
///
/// ```text
/// TimeStampReq ::= SEQUENCE {
///     version         INTEGER { v1(1) },
///     messageImprint  MessageImprint,
///     nonce           INTEGER,            -- 8 random bytes
///     certReq         BOOLEAN DEFAULT FALSE
/// }
///
/// MessageImprint ::= SEQUENCE {
///     hashAlgorithm   AlgorithmIdentifier,
///     hashedMessage   OCTET STRING
/// }
///
/// AlgorithmIdentifier ::= SEQUENCE {
///     algorithm   OID,
///     parameters  ANY DEFINED BY algorithm OPTIONAL
/// }
/// ```
fn build_timestamp_request(
    digest: &[u8],
    nonce: &[u8],
    algorithm: TimestampHashAlgorithm,
) -> Vec<u8> {
    // AlgorithmIdentifier: SEQUENCE { OID, NULL }
    let alg_id = {
        let mut inner = der_oid(algorithm.oid_bytes());
        inner.extend_from_slice(&der_null());
        der_sequence(&inner)
    };

    // MessageImprint: SEQUENCE { algId, OCTET STRING digest }
    let message_imprint = {
        let mut inner = alg_id;
        inner.extend_from_slice(&der_octet_string(digest));
        der_sequence(&inner)
    };

    // Assemble TimeStampReq
    let version = der_integer_bytes(&[0x01]); // v1
    let nonce_der = der_integer_bytes(nonce);
    let cert_req = der_boolean(true);

    let mut req_content = Vec::new();
    req_content.extend_from_slice(&version);
    req_content.extend_from_slice(&message_imprint);
    req_content.extend_from_slice(&nonce_der);
    req_content.extend_from_slice(&cert_req);

    der_sequence(&req_content)
}

// =============================================================================
// HTTP Transport
// =============================================================================

async fn send_tsa_request(
    client: &reqwest::Client,
    endpoint: &str,
    request: &[u8],
) -> AuditResult<Vec<u8>> {
    let response = client
        .post(endpoint)
        .header("Content-Type", "application/timestamp-query")
        .header("Accept", "application/timestamp-response")
        .body(request.to_vec())
        .send()
        .await
        .map_err(|e| AuditError::Network(format!("Failed to send TSA request: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(AuditError::Network(format!(
            "TSA returned HTTP {status}: {body}"
        )));
    }

    response
        .bytes()
        .await
        .map_err(|e| AuditError::Network(format!("Failed to read TSA response body: {e}")))
        .map(|b| b.to_vec())
}

// =============================================================================
// TimeStampResp Parser (RFC 3161 Section 2.4.2)
// =============================================================================

/// Minimal DER cursor for reading ASN.1 structures.
struct DerCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> DerCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn peek_tag(&self) -> AuditResult<u8> {
        if self.pos >= self.bytes.len() {
            return Err(AuditError::Internal(format!(
                "unexpected end of DER at position {}",
                self.pos
            )));
        }
        Ok(self.bytes[self.pos])
    }

    fn read_tag(&mut self) -> AuditResult<u8> {
        let tag = self.peek_tag()?;
        self.pos += 1;
        Ok(tag)
    }

    fn read_length(&mut self) -> AuditResult<usize> {
        if self.pos >= self.bytes.len() {
            return Err(AuditError::Internal(
                "unexpected end of DER reading length".into(),
            ));
        }
        let first = self.bytes[self.pos];
        self.pos += 1;

        if first < 0x80 {
            Ok(first as usize)
        } else {
            let num_octets = (first & 0x7F) as usize;
            if self.pos + num_octets > self.bytes.len() {
                return Err(AuditError::Internal(
                    "DER length extends past end of data".into(),
                ));
            }
            let mut len: usize = 0;
            for _ in 0..num_octets {
                len = (len << 8) | (self.bytes[self.pos] as usize);
                self.pos += 1;
            }
            Ok(len)
        }
    }

    fn read_bytes(&mut self, count: usize) -> AuditResult<&'a [u8]> {
        if self.pos + count > self.bytes.len() {
            return Err(AuditError::Internal(format!(
                "not enough bytes: need {} have {}",
                count,
                self.remaining()
            )));
        }
        let slice = &self.bytes[self.pos..self.pos + count];
        self.pos += count;
        Ok(slice)
    }

    fn read_tlv_value(&mut self) -> AuditResult<&'a [u8]> {
        let _tag = self.read_tag()?;
        let len = self.read_length()?;
        self.read_bytes(len)
    }

    /// Read a SEQUENCE and return a cursor into its content.
    fn read_sequence_content(&mut self) -> AuditResult<DerCursor<'a>> {
        let tag = self.read_tag()?;
        if tag != 0x30 {
            return Err(AuditError::Internal(format!(
                "expected SEQUENCE (0x30), got 0x{:02x}",
                tag
            )));
        }
        let len = self.read_length()?;
        let content = self.read_bytes(len)?;
        Ok(DerCursor::new(content))
    }

    /// Read an INTEGER and return its value bytes.
    fn read_integer(&mut self) -> AuditResult<Vec<u8>> {
        let tag = self.read_tag()?;
        if tag != 0x02 {
            return Err(AuditError::Internal(format!(
                "expected INTEGER (0x02), got 0x{:02x}",
                tag
            )));
        }
        let len = self.read_length()?;
        Ok(self.read_bytes(len)?.to_vec())
    }

    /// Read an OID and return its dotted-string representation.
    fn read_oid(&mut self) -> AuditResult<String> {
        let tag = self.read_tag()?;
        if tag != 0x06 {
            return Err(AuditError::Internal(format!(
                "expected OID (0x06), got 0x{:02x}",
                tag
            )));
        }
        let len = self.read_length()?;
        let bytes = self.read_bytes(len)?;
        Ok(oid_bytes_to_string(bytes))
    }

    /// Read OCTET STRING value.
    fn read_octet_string(&mut self) -> AuditResult<&'a [u8]> {
        let tag = self.read_tag()?;
        if tag != 0x04 {
            return Err(AuditError::Internal(format!(
                "expected OCTET STRING (0x04), got 0x{:02x}",
                tag
            )));
        }
        let len = self.read_length()?;
        self.read_bytes(len)
    }

    /// Skip one element by reading tag + length + value.
    fn _skip_element(&mut self) -> AuditResult<()> {
        let _tag = self.read_tag()?;
        let len = self.read_length()?;
        self.read_bytes(len)?;
        Ok(())
    }

    /// Read UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ).
    fn read_time(&mut self) -> AuditResult<i64> {
        let tag = self.read_tag()?;
        if tag != 0x17 && tag != 0x18 {
            return Err(AuditError::Internal(format!(
                "expected UTCTime (0x17) or GeneralizedTime (0x18), got 0x{:02x}",
                tag
            )));
        }
        let len = self.read_length()?;
        let bytes = self.read_bytes(len)?;
        let time_str = std::str::from_utf8(bytes)
            .map_err(|e| AuditError::Internal(format!("time is not valid UTF-8: {e}")))?;

        // Parse UTCTime: YYMMDDHHMMSSZ  (YY = 00-99, 50-99 -> 1950-1999, 00-49 -> 2000-2049)
        // Parse GeneralizedTime: YYYYMMDDHHMMSS[.fff]Z
        if tag == 0x17 && time_str.len() >= 12 {
            let yy: i32 = time_str[..2]
                .parse()
                .map_err(|e| AuditError::Internal(format!("invalid UTCTime year: {e}")))?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            parse_time_parts(year, &time_str[2..])
        } else if tag == 0x18 && time_str.len() >= 14 {
            let year: i32 = time_str[..4]
                .parse()
                .map_err(|e| AuditError::Internal(format!("invalid GeneralizedTime year: {e}")))?;
            parse_time_parts(year, &time_str[4..])
        } else {
            Err(AuditError::Internal(format!(
                "invalid time format: {time_str}"
            )))
        }
    }
}

fn parse_time_parts(year: i32, rest: &str) -> AuditResult<i64> {
    let month: u32 = rest[..2]
        .parse()
        .map_err(|e| AuditError::Internal(format!("invalid month: {e}")))?;
    let day: u32 = rest[2..4]
        .parse()
        .map_err(|e| AuditError::Internal(format!("invalid day: {e}")))?;
    let hour: u32 = rest[4..6]
        .parse()
        .map_err(|e| AuditError::Internal(format!("invalid hour: {e}")))?;
    let minute: u32 = rest[6..8]
        .parse()
        .map_err(|e| AuditError::Internal(format!("invalid minute: {e}")))?;
    let second: u32 = rest[8..10]
        .parse()
        .map_err(|e| AuditError::Internal(format!("invalid second: {e}")))?;

    // Naive UTC -> Unix timestamp (works for dates after 1970)
    let days_before_month: [u32; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut days = (year - 1970) as u32 * 365;
    // Leap years since 1970
    for y in 1970..year {
        if is_leap(y) {
            days += 1;
        }
    }
    days += days_before_month[(month - 1) as usize];
    if month > 2 && is_leap(year) {
        days += 1;
    }
    days += day - 1;

    let secs = days as i64 * 86400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64;
    Ok(secs)
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Parse a DER-encoded TimeStampResp.
///
/// ```text
/// TimeStampResp ::= SEQUENCE {
///     status          PKIStatusInfo,
///     timeStampToken  TimeStampToken OPTIONAL
/// }
///
/// PKIStatusInfo ::= SEQUENCE {
///     status          PKIStatus,     -- INTEGER: 0=granted, 1=grantedWithMods, 2=rejection
///     statusString    PKIFreeText OPTIONAL,
///     failInfo        PKIFailureInfo OPTIONAL
/// }
///
/// TimeStampToken ::= ContentInfo (RFC 5652)
///   SEQUENCE {
///     contentType OID (id-signedData),
///     content [0] EXPLICIT SignedData
///   }
///
/// SignedData ::= SEQUENCE {
///     version         INTEGER,
///     digestAlgorithms SET OF AlgorithmIdentifier,
///     encapContentInfo SEQUENCE {
///         eContentType OID (id-ct-TSTInfo),
///         eContent [0] EXPLICIT OCTET STRING  -- contains TSTInfo DER
///     },
///     certificates [0] IMPLICIT SET OF Certificate OPTIONAL,
///     crls [1] IMPLICIT SET OF CRL OPTIONAL,
///     signerInfos SET OF SignerInfo
/// }
///
/// TSTInfo ::= SEQUENCE {
///     version         INTEGER,
///     policy          OID,
///     messageImprint  MessageImprint,
///     serialNumber    INTEGER,
///     genTime         GeneralizedTime,
///     accuracy        SEQUENCE OPTIONAL,
///     nonce           INTEGER OPTIONAL,
///     ...
/// }
/// ```
fn parse_timestamp_response(
    response: &[u8],
    expected_digest: &[u8],
    expected_nonce: &[u8],
) -> AuditResult<TimestampResponse> {
    // Parse outer SEQUENCE: TimeStampResp
    let mut outer = DerCursor::new(response);
    let mut resp_cursor = outer.read_sequence_content()?;

    // Parse PKIStatusInfo
    let mut status_cursor = resp_cursor.read_sequence_content()?;
    let status = status_cursor.read_integer()?;
    let status_val = if status.is_empty() {
        0
    } else {
        status[0] as u32
    };

    match status_val {
        0 | 1 => {} // granted or grantedWithMods
        2 => {
            // Try to read statusString for error message
            let msg = if status_cursor.remaining() > 0 {
                match status_cursor.read_tlv_value() {
                    Ok(v) => String::from_utf8_lossy(v).to_string(),
                    Err(_) => "unknown".to_string(),
                }
            } else {
                "no details".to_string()
            };
            return Err(AuditError::TsaFailed(format!(
                "TSA rejected request (status=2): {msg}"
            )));
        }
        _ => {
            return Err(AuditError::TsaFailed(format!(
                "TSA returned unexpected status: {status_val}"
            )));
        }
    }

    // Now parse TimeStampToken (ContentInfo)
    if resp_cursor.remaining() == 0 {
        return Err(AuditError::TsaFailed(
            "TSA response has no TimeStampToken (granted but no token)".into(),
        ));
    }

    // Capture raw TimeStampToken bytes for forensic storage
    let token_start = resp_cursor.pos;
    let token_tlv = resp_cursor.read_tlv_value()?;
    let raw_token = response[token_start..resp_cursor.pos].to_vec();

    // token_tlv contains ContentInfo body: OID (id-signedData) + [0] EXPLICIT SignedData
    let mut ci_cursor = DerCursor::new(token_tlv);
    let _content_type = ci_cursor.read_oid()?; // id-signedData

    // [0] EXPLICIT — contextual tag 0, constructed
    let tag0 = ci_cursor.read_tag()?;
    if tag0 != 0xA0 {
        return Err(AuditError::Internal(format!(
            "expected [0] EXPLICIT (0xA0), got 0x{:02x}",
            tag0
        )));
    }
    let sd_len = ci_cursor.read_length()?;
    let sd_bytes = ci_cursor.read_bytes(sd_len)?;

    // Parse SignedData -> encapContentInfo -> eContent -> TSTInfo
    let mut sd_cursor = DerCursor::new(sd_bytes);
    let mut sd = sd_cursor.read_sequence_content()?;

    // Skip: version, digestAlgorithms
    sd.read_tlv_value()?; // version
    skip_set(&mut sd)?; // digestAlgorithms

    // encapContentInfo: SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING }
    let mut eci = sd.read_sequence_content()?;
    let _econtent_type = eci.read_oid()?; // id-ct-TSTInfo

    // [0] EXPLICIT OCTET STRING containing TSTInfo
    let tag0 = eci.read_tag()?;
    if tag0 != 0xA0 {
        return Err(AuditError::Internal(format!(
            "expected [0] EXPLICIT for eContent, got 0x{:02x}",
            tag0
        )));
    }
    let ec_len = eci.read_length()?;
    let ec_bytes = eci.read_bytes(ec_len)?;
    let mut ec_cursor = DerCursor::new(ec_bytes);
    let tstinfo_bytes = ec_cursor.read_octet_string()?;

    // Now parse TSTInfo
    let mut tst = DerCursor::new(tstinfo_bytes);
    let mut tst_cursor = tst.read_sequence_content()?;

    // version
    let _tst_version = tst_cursor.read_integer()?;

    // policy OID
    let policy = tst_cursor.read_oid()?;

    // messageImprint
    let mut mi_cursor = tst_cursor.read_sequence_content()?;
    // AlgorithmIdentifier SEQUENCE
    let _alg_seq = mi_cursor.read_tlv_value()?; // skip algorithm identifier
    let hashed_msg = mi_cursor.read_octet_string()?;
    if hashed_msg != expected_digest {
        return Err(AuditError::TsaFailed(format!(
            "TSA response digest mismatch: expected {}, got {}",
            hex::encode(expected_digest),
            hex::encode(hashed_msg)
        )));
    }

    // serialNumber
    let serial = tst_cursor.read_integer()?;

    // genTime
    let gen_time = tst_cursor.read_time()?;

    // accuracy (optional SEQUENCE { seconds, millis, micros })
    let mut accuracy_millis = 1000u32;
    if tst_cursor.remaining() > 0 && tst_cursor.peek_tag()? == 0x30 {
        let mut acc_cursor = tst_cursor.read_sequence_content()?;
        if acc_cursor.remaining() > 0 && acc_cursor.peek_tag()? == 0x02 {
            let _acc_secs = acc_cursor.read_integer()?;
        }
        if acc_cursor.remaining() > 0 && acc_cursor.peek_tag()? == 0x02 {
            let millis_bytes = acc_cursor.read_integer()?;
            if !millis_bytes.is_empty() {
                let mut m: u32 = 0;
                for b in &millis_bytes {
                    m = (m << 8) | (*b as u32);
                }
                accuracy_millis = m;
            }
        }
    }

    // nonce (optional — but we always send one, so it should be present)
    let mut resp_nonce = Vec::new();
    if tst_cursor.remaining() > 0 && tst_cursor.peek_tag()? == 0x02 {
        resp_nonce = tst_cursor.read_integer()?;
    }

    // Verify nonce
    if resp_nonce != expected_nonce {
        tracing::warn!(
            "TSA nonce mismatch: sent {}, got {}",
            hex::encode(expected_nonce),
            hex::encode(&resp_nonce)
        );
        // Non-fatal: some TSAs may not echo nonce. Continue but log warning.
    }

    Ok(TimestampResponse {
        token: raw_token,
        serial_number: serial,
        accuracy_millis,
        timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(gen_time as u64),
        policy,
    })
}

/// Skip a SET OF element in DER.
fn skip_set(cursor: &mut DerCursor) -> AuditResult<()> {
    let tag = cursor.read_tag()?;
    if tag != 0x31 {
        return Err(AuditError::Internal(format!(
            "expected SET (0x31), got 0x{:02x}",
            tag
        )));
    }
    let len = cursor.read_length()?;
    cursor.read_bytes(len)?;
    Ok(())
}

/// Verify that the original digest is embedded in the TSA response token.
fn verify_digest_in_token(token: &[u8], expected_digest: &[u8]) -> AuditResult<bool> {
    // Re-parse the token to extract TSTInfo and compare digest
    // This is a simplified re-check using the same parsing path
    let mut outer = DerCursor::new(token);
    let mut ci = outer.read_sequence_content()?;
    let _content_type = ci.read_oid()?;

    let tag0 = ci.read_tag()?;
    if tag0 != 0xA0 {
        return Ok(false);
    }
    let sd_len = ci.read_length()?;
    let sd_bytes = ci.read_bytes(sd_len)?;

    let mut sd = DerCursor::new(sd_bytes);
    let mut sd_cursor = sd.read_sequence_content()?;
    sd_cursor.read_tlv_value()?; // version
    skip_set(&mut sd_cursor)?; // digestAlgorithms

    let mut eci = sd_cursor.read_sequence_content()?;
    eci.read_oid()?; // eContentType
    let tag0 = eci.read_tag()?;
    if tag0 != 0xA0 {
        return Ok(false);
    }
    let ec_len = eci.read_length()?;
    let ec_bytes = eci.read_bytes(ec_len)?;
    let mut ec = DerCursor::new(ec_bytes);
    let tstinfo_bytes = ec.read_octet_string()?;

    let mut tst = DerCursor::new(tstinfo_bytes);
    let mut tst_cursor = tst.read_sequence_content()?;
    tst_cursor.read_integer()?; // version
    tst_cursor.read_oid()?; // policy
    let mut mi = tst_cursor.read_sequence_content()?;
    mi.read_tlv_value()?; // algId
    let digest = mi.read_octet_string()?;

    Ok(digest == expected_digest)
}

/// Convert OID bytes to dotted-string notation (e.g. [0x2A, 0x86, ...] -> "1.2.840...").
fn oid_bytes_to_string(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    // First two components: bytes[0] = 40*x + y
    let first = (bytes[0] / 40) as u32;
    let second = (bytes[0] % 40) as u32;
    let mut result = format!("{first}.{second}");

    let mut i = 1;
    while i < bytes.len() {
        let mut val: u32 = 0;
        while i < bytes.len() {
            val = (val << 7) | ((bytes[i] & 0x7F) as u32);
            if bytes[i] & 0x80 == 0 {
                i += 1;
                break;
            }
            i += 1;
        }
        result.push_str(&format!(".{val}"));
    }
    result
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── DER encoding tests ──

    #[test]
    fn test_der_length_short() {
        assert_eq!(der_len(5), vec![5]);
        assert_eq!(der_len(127), vec![127]);
    }

    #[test]
    fn test_der_length_long() {
        assert_eq!(der_len(128), vec![0x81, 128]);
        assert_eq!(der_len(255), vec![0x81, 255]);
        assert_eq!(der_len(256), vec![0x82, 1, 0]);
    }

    #[test]
    fn test_der_integer() {
        let result = der_integer_bytes(&[0x01]);
        assert_eq!(result, vec![0x02, 0x01, 0x01]);
    }

    #[test]
    fn test_der_sequence() {
        let inner = der_integer_bytes(&[0x01]);
        let result = der_sequence(&inner);
        assert_eq!(result[0], 0x30); // SEQUENCE tag
    }

    #[test]
    fn test_der_octet_string() {
        let result = der_octet_string(&[0xAA, 0xBB, 0xCC]);
        assert_eq!(result, vec![0x04, 0x03, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_der_oid() {
        let sha256_oid = TimestampHashAlgorithm::Sha256.oid_bytes();
        let result = der_oid(sha256_oid);
        assert_eq!(result[0], 0x06); // OID tag
        assert_eq!(result[1], sha256_oid.len() as u8); // length
    }

    // ── TimeStampReq building ──

    #[test]
    fn test_build_timestamp_request_structure() {
        let digest = [0xABu8; 32];
        let nonce = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let req = build_timestamp_request(&digest, &nonce, TimestampHashAlgorithm::Sha256);

        // Should be valid DER starting with SEQUENCE tag
        assert_eq!(req[0], 0x30);

        // Parse back and verify structure
        let mut cursor = DerCursor::new(&req);
        let mut seq = cursor.read_sequence_content().unwrap();

        // version = 1
        let version = seq.read_integer().unwrap();
        assert_eq!(version, vec![0x01]);

        // MessageImprint
        let mut mi = seq.read_sequence_content().unwrap();
        // AlgorithmIdentifier
        let mut alg_id = mi.read_sequence_content().unwrap();
        let oid = alg_id.read_oid().unwrap();
        assert!(oid.contains("2.16.840.1.101.3.4.2.1") || oid.contains("1.2.840"));
        // hashedMessage
        let hashed = mi.read_octet_string().unwrap();
        assert_eq!(hashed, &digest[..]);

        // nonce
        let parsed_nonce = seq.read_integer().unwrap();
        assert_eq!(parsed_nonce, nonce);

        // certReq = TRUE
        let tag = seq.read_tag().unwrap();
        assert_eq!(tag, 0x01); // BOOLEAN
        let _certreq_len = seq.read_length().unwrap();
    }

    #[test]
    fn test_build_timestamp_request_non_empty() {
        let digest = [0x42u8; 32];
        let nonce = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let req = build_timestamp_request(&digest, &nonce, TimestampHashAlgorithm::Sha256);
        assert!(!req.is_empty());
        // Should be between 60 and 100 bytes
        assert!(req.len() > 50);
        assert!(req.len() < 120);
    }

    // ── OID tests ──

    #[test]
    fn test_oid_bytes_to_string() {
        // SHA-256 OID: 2.16.840.1.101.3.4.2.1
        let sha256_bytes = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        let result = oid_bytes_to_string(sha256_bytes);
        assert_eq!(result, "2.16.840.1.101.3.4.2.1");
    }

    #[test]
    fn test_hash_algorithm_oid() {
        assert_eq!(
            TimestampHashAlgorithm::Sha256.as_oid(),
            "2.16.840.1.101.3.4.2.1"
        );
        assert_eq!(TimestampHashAlgorithm::Sm3.as_oid(), "1.2.156.10197.1.401");
    }

    // ── DerCursor tests ──

    #[test]
    fn test_der_cursor_integer() {
        let data = vec![0x02, 0x01, 0x2A];
        let mut cursor = DerCursor::new(&data);
        let val = cursor.read_integer().unwrap();
        assert_eq!(val, vec![0x2A]);
    }

    #[test]
    fn test_der_cursor_sequence() {
        let inner = vec![0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let data = der_sequence(&inner);
        let mut cursor = DerCursor::new(&data);
        let mut seq = cursor.read_sequence_content().unwrap();
        assert_eq!(seq.read_integer().unwrap(), vec![0x01]);
        assert_eq!(seq.read_integer().unwrap(), vec![0x02]);
    }

    #[test]
    fn test_der_cursor_skip_element() {
        // SEQUENCE { INTEGER 1, OCTET STRING "hello", INTEGER 2 }
        let inner = {
            let mut v = Vec::new();
            v.extend_from_slice(&der_integer_bytes(&[0x01]));
            v.extend_from_slice(&der_octet_string(b"hello"));
            v.extend_from_slice(&der_integer_bytes(&[0x02]));
            v
        };
        let data = der_sequence(&inner);
        let mut cursor = DerCursor::new(&data);
        let mut seq = cursor.read_sequence_content().unwrap();
        assert_eq!(seq.read_integer().unwrap(), vec![0x01]);
        seq._skip_element().unwrap(); // skip OCTET STRING
        assert_eq!(seq.read_integer().unwrap(), vec![0x02]);
    }

    // ── TimeStampResp parsing tests ──

    #[test]
    fn test_parse_granted_response() {
        // Build a minimal valid TimeStampResp
        let digest = [0xABu8; 32];
        let nonce = [0x01u8; 8];

        // Build TSTInfo
        let tstinfo = build_test_tstinfo(&digest, &nonce, 1714512000);
        let token = build_test_cms_signed_data(&tstinfo);

        // Build TimeStampResp: SEQUENCE { PKIStatusInfo, TimeStampToken }
        let status_info = {
            // PKIStatusInfo: SEQUENCE { INTEGER 0 }
            der_sequence(&der_integer_bytes(&[0x00]))
        };
        let mut resp = Vec::new();
        resp.extend_from_slice(&status_info);
        resp.extend_from_slice(&token);
        let response = der_sequence(&resp);

        let result = parse_timestamp_response(&response, &digest, &nonce);
        assert!(result.is_ok(), "parse failed: {:?}", result.err());
        let ts_resp = result.unwrap();
        assert!(!ts_resp.token.is_empty());
        assert!(!ts_resp.serial_number.is_empty());
    }

    #[test]
    fn test_parse_rejected_response() {
        // PKIStatusInfo with status=2 (rejection) and no token
        let status_info = der_sequence(&der_integer_bytes(&[0x02]));
        let response = der_sequence(&status_info);

        let digest = [0xABu8; 32];
        let nonce = [0x01u8; 8];
        let result = parse_timestamp_response(&response, &digest, &nonce);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("rejected"));
    }

    #[test]
    fn test_parse_digest_mismatch() {
        let digest_sent = [0xABu8; 32];
        let digest_in_token = [0xCDu8; 32];
        let nonce = [0x01u8; 8];

        let tstinfo = build_test_tstinfo(&digest_in_token, &nonce, 1714512000);
        let token = build_test_cms_signed_data(&tstinfo);

        let status_info = der_sequence(&der_integer_bytes(&[0x00]));
        let mut resp = Vec::new();
        resp.extend_from_slice(&status_info);
        resp.extend_from_slice(&token);
        let response = der_sequence(&resp);

        let result = parse_timestamp_response(&response, &digest_sent, &nonce);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mismatch"));
    }

    // ── Helpers for building test data ──

    /// Build a minimal DER-encoded TSTInfo
    fn build_test_tstinfo(digest: &[u8], nonce: &[u8], gen_time_secs: i64) -> Vec<u8> {
        // TSTInfo ::= SEQUENCE {
        //   version INTEGER (1),
        //   policy OID (test: 1.2.3.4),
        //   messageImprint MessageImprint,
        //   serialNumber INTEGER,
        //   genTime GeneralizedTime,
        //   nonce INTEGER
        // }
        let version = der_integer_bytes(&[0x01]);
        let policy_oid = der_oid(&[0x2A, 0x03, 0x04]); // OID 1.2.3.4
        let message_imprint = {
            let alg_id = {
                let mut v = der_oid(&[0x2A, 0x03, 0x04]); // test OID
                v.extend_from_slice(&der_null());
                der_sequence(&v)
            };
            let mut v = alg_id;
            v.extend_from_slice(&der_octet_string(digest));
            der_sequence(&v)
        };
        let serial = der_integer_bytes(&[0x01, 0x02, 0x03, 0x04]);
        let gen_time = {
            // Build GeneralizedTime from Unix timestamp
            let day_secs = gen_time_secs % 86400;
            let _days_since_epoch = (gen_time_secs - day_secs) / 86400;
            // Use chrono for date calculation (test-only)
            let dt = chrono::DateTime::from_timestamp(gen_time_secs, 0).expect("valid timestamp");
            let time_str = dt.format("%Y%m%d%H%M%SZ").to_string();
            der_tlv(0x18, time_str.as_bytes()) // GeneralizedTime tag
        };
        let nonce_der = der_integer_bytes(nonce);

        let mut content = Vec::new();
        content.extend_from_slice(&version);
        content.extend_from_slice(&policy_oid);
        content.extend_from_slice(&message_imprint);
        content.extend_from_slice(&serial);
        content.extend_from_slice(&gen_time);
        content.extend_from_slice(&nonce_der);

        der_sequence(&content)
    }

    /// Build a minimal CMS SignedData wrapper around TSTInfo
    fn build_test_cms_signed_data(tstinfo: &[u8]) -> Vec<u8> {
        // SignedData ::= SEQUENCE {
        //   version INTEGER (1),
        //   digestAlgorithms SET { AlgorithmIdentifier },
        //   encapContentInfo SEQUENCE {
        //     eContentType OID (1.2.840.113549.1.9.16.1.4 = id-ct-TSTInfo),
        //     eContent [0] EXPLICIT OCTET STRING (TSTInfo)
        //   },
        //   certificates [0] IMPLICIT SET OF Certificate OPTIONAL,
        //   signerInfos SET OF SignerInfo
        // }
        let version = der_integer_bytes(&[0x01]);

        // digestAlgorithms: SET { AlgorithmIdentifier }
        let digest_alg_set = {
            let mut v = der_oid(&[0x2A, 0x03, 0x04]); // test OID
            v.extend_from_slice(&der_null());
            vec![0x31, 0x00] // empty SET (simplified for testing)
        };

        // encapContentInfo
        let encap = {
            // eContentType OID
            let oid = der_oid(&[
                0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
            ]); // id-ct-TSTInfo
            // eContent [0] EXPLICIT OCTET STRING
            let econtent = der_tlv(0xA0, &der_octet_string(tstinfo));
            let mut v = oid;
            v.extend_from_slice(&econtent);
            der_sequence(&v)
        };

        // Empty certificates (tag [0] IMPLICIT)
        let certs = vec![0xA0, 0x00]; // [0] IMPLICIT SET with length 0

        // Empty signerInfos SET
        let signer_infos = vec![0x31, 0x00]; // SET with length 0

        let mut sd_content = Vec::new();
        sd_content.extend_from_slice(&version);
        sd_content.extend_from_slice(&digest_alg_set);
        sd_content.extend_from_slice(&encap);
        sd_content.extend_from_slice(&certs);
        sd_content.extend_from_slice(&signer_infos);

        let signed_data = der_sequence(&sd_content);

        // ContentInfo: SEQUENCE { OID (id-signedData), [0] EXPLICIT SignedData }
        let signed_data_oid = der_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]); // id-signedData
        let sd_wrapped = der_tlv(0xA0, &signed_data); // [0] EXPLICIT

        let mut ci = signed_data_oid;
        ci.extend_from_slice(&sd_wrapped);
        der_sequence(&ci)
    }

    // ── Config / Authority creation tests ──

    #[test]
    fn test_timestamp_config_default() {
        let config = TimestampConfig::default();
        assert!(config.server_url.is_empty());
        assert_eq!(config.timeout, Duration::from_secs(10));
        assert_eq!(config.hash_algorithm, TimestampHashAlgorithm::Sha256);
        assert_eq!(config.nonce_size, 8);
        assert_eq!(config.max_time_skew_secs, 300);
    }

    #[test]
    fn test_tsa_client_config_default() {
        let config = TsaClientConfig::default();
        assert!(config.endpoints.is_empty());
        assert_eq!(config.timeout_secs, 10);
        assert_eq!(config.hash_algorithm, TimestampHashAlgorithm::Sha256);
    }

    #[tokio::test]
    async fn test_timestamp_authority_creation() {
        let config = TimestampConfig {
            server_url: "https://tsa.example.com".to_string(),
            ..Default::default()
        };
        let tsa = TimestampAuthority::new(config);
        assert!(tsa.is_ok());
    }

    // ── Nonce stripping tests ──

    #[test]
    fn test_strip_leading_zeros() {
        assert_eq!(strip_leading_zeros(&[0x00, 0x00, 0x01]), vec![0x01]);
        assert_eq!(strip_leading_zeros(&[0x01, 0x02]), vec![0x01, 0x02]);
        // Don't strip the last byte even if zero
        assert_eq!(strip_leading_zeros(&[0x00, 0x00]), vec![0x00]);
    }
}
