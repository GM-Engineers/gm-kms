//! The KMS client.

use std::time::Duration;

use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use url::Url;
use uuid::Uuid;

use crate::error::{KmsError, Result};
use crate::models::*;

/// A client of the KMS REST API.
///
/// The client is cheap to clone: cloning shares the underlying connection
/// pool. Build one with [`Client::builder`].
///
/// ```no_run
/// # async fn run() -> gm_kms_sdk::Result<()> {
/// use gm_kms_sdk::{Client, CreateKeyRequest, KeySpec};
///
/// let kms = Client::builder("https://kms.example.com")
///     .api_key("secret")
///     .tenant("acme")
///     .build()?;
///
/// let key = kms
///     .create_key(&CreateKeyRequest {
///         name: "orders".to_string(),
///         spec: KeySpec::Sm4,
///         tenant_id: None,
///     })
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Client {
    base_url: Url,
    http: reqwest::Client,
    api_key: Option<String>,
    tenant: String,
}

impl Client {
    /// Start building a client for the KMS at `base_url`.
    pub fn builder(base_url: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(base_url)
    }

    /// Build a client for the KMS at `base_url`, without credentials.
    ///
    /// The tenant defaults to `"default"`, the same default the server uses.
    pub fn new(base_url: impl Into<String>) -> Result<Client> {
        ClientBuilder::new(base_url).build()
    }

    /// A copy of this client that acts in another tenant.
    ///
    /// The copy shares the connection pool; only the default tenant differs.
    pub fn for_tenant(&self, tenant: impl Into<String>) -> Client {
        let mut scoped = self.clone();
        scoped.tenant = tenant.into();
        scoped
    }

    /// The tenant used when a call does not name one.
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The URL of the KMS.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    // ── Internals ────────────────────────────────────────────────────────

    /// Resolve the tenant of a call: the explicit one, else the client's.
    fn resolve_tenant(&self, explicit: Option<&str>) -> String {
        explicit
            .filter(|tenant| !tenant.is_empty())
            .unwrap_or(&self.tenant)
            .to_string()
    }

    /// Build the URL of an endpoint, keeping any path prefix of the base URL.
    fn endpoint(&self, path: &str) -> Result<Url> {
        let mut url = self.base_url.clone();
        // A base URL that ends with a slash leaves an empty segment behind;
        // it must go, or the endpoint is built as "/api//v1/keys".
        let trailing_slash = url.path().ends_with('/');
        {
            let mut segments = url.path_segments_mut().map_err(|()| {
                KmsError::InvalidUrl("the server URL cannot be used as a base".to_string())
            })?;
            if trailing_slash {
                segments.pop();
            }
            for segment in path.split('/').filter(|segment| !segment.is_empty()) {
                segments.push(segment);
            }
        }
        Ok(url)
    }

    /// Append query parameters to a URL.
    fn query(mut url: Url, pairs: &[(&str, &str)]) -> Url {
        {
            let mut query = url.query_pairs_mut();
            for (name, value) in pairs {
                query.append_pair(name, value);
            }
        }
        url
    }

    /// Serialize a request body and stamp the resolved tenant into it.
    ///
    /// The tenant travels in the body for some endpoints and as a query
    /// parameter for others; this helper covers the ones that carry it in the
    /// body.
    fn body_with_tenant<T: Serialize>(request: &T, tenant: &str) -> Result<serde_json::Value> {
        let mut body = serde_json::to_value(request)?;
        if let Some(object) = body.as_object_mut() {
            object.insert(
                "tenant_id".to_string(),
                serde_json::Value::String(tenant.to_string()),
            );
        }
        Ok(body)
    }

    /// Send a request and return the raw response.
    async fn send(
        &self,
        method: Method,
        url: Url,
        body: Option<serde_json::Value>,
    ) -> Result<reqwest::Response> {
        let mut request = self.http.request(method, url);
        if let Some(api_key) = &self.api_key {
            request = request.header("x-api-key", api_key);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        Ok(request.send().await?)
    }

    /// Send a request and decode the JSON answer.
    async fn send_json<T: DeserializeOwned>(
        &self,
        method: Method,
        url: Url,
        body: Option<serde_json::Value>,
    ) -> Result<T> {
        let response = self.send(method, url, body).await?;
        let status = response.status();
        if !status.is_success() {
            return Err(self.api_error(status, response).await);
        }
        Ok(response.json::<T>().await?)
    }

    /// Send a request whose answer has no body.
    async fn send_empty(
        &self,
        method: Method,
        url: Url,
        body: Option<serde_json::Value>,
    ) -> Result<()> {
        let response = self.send(method, url, body).await?;
        let status = response.status();
        if !status.is_success() {
            return Err(self.api_error(status, response).await);
        }
        Ok(())
    }

    /// Turn a non-2xx answer into a [`KmsError::Api`].
    async fn api_error(&self, status: StatusCode, response: reqwest::Response) -> KmsError {
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());

        let body = response.text().await.unwrap_or_default();
        let message = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(|error| error.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| {
                if body.trim().is_empty() {
                    status
                        .canonical_reason()
                        .unwrap_or("the request failed")
                        .to_string()
                } else {
                    body
                }
            });

        KmsError::Api {
            status: status.as_u16(),
            message,
            retry_after,
        }
    }

    // ── Keys ──────────────────────────────────────────────────────────────

    /// Create a key.
    ///
    /// The tenant of [`CreateKeyRequest::tenant_id`] wins; `None` uses the
    /// client's tenant.
    pub async fn create_key(&self, request: &CreateKeyRequest) -> Result<Key> {
        let tenant = self.resolve_tenant(request.tenant_id.as_deref());
        let body = Client::body_with_tenant(request, &tenant)?;
        self.send_json(Method::POST, self.endpoint("/v1/keys")?, Some(body))
            .await
    }

    /// Fetch the metadata of a key.
    pub async fn get_key(&self, key_id: &Uuid, tenant: Option<&str>) -> Result<Key> {
        let tenant = self.resolve_tenant(tenant);
        let url = self.endpoint(&format!("/v1/keys/{key_id}"))?;
        let url = Client::query(url, &[("tenant_id", &tenant)]);
        self.send_json(Method::GET, url, None).await
    }

    /// List the keys of a tenant.
    pub async fn list_keys(&self, tenant: Option<&str>) -> Result<Vec<Key>> {
        let tenant = self.resolve_tenant(tenant);
        let url = self.endpoint("/v1/keys")?;
        let url = Client::query(url, &[("tenant_id", &tenant)]);
        self.send_json(Method::GET, url, None).await
    }

    /// Rotate a key, producing a new version.
    ///
    /// A rotation that requires an approval needs its `approval_id`.
    pub async fn rotate_key(
        &self,
        key_id: &Uuid,
        approval_id: Option<&str>,
        tenant: Option<&str>,
    ) -> Result<Key> {
        let tenant = self.resolve_tenant(tenant);
        let url = self.endpoint(&format!("/v1/keys/{key_id}/rotate"))?;
        let mut pairs = vec![("tenant_id", tenant.as_str())];
        if let Some(approval_id) = approval_id {
            pairs.push(("approval_id", approval_id));
        }
        let url = Client::query(url, &pairs);
        self.send_json(Method::POST, url, None).await
    }

    /// Delete a key.
    ///
    /// A deletion that requires an approval needs its `approval_id`.
    pub async fn delete_key(
        &self,
        key_id: &Uuid,
        approval_id: Option<&str>,
        tenant: Option<&str>,
    ) -> Result<()> {
        let tenant = self.resolve_tenant(tenant);
        let url = self.endpoint(&format!("/v1/keys/{key_id}"))?;
        let mut pairs = vec![("tenant_id", tenant.as_str())];
        if let Some(approval_id) = approval_id {
            pairs.push(("approval_id", approval_id));
        }
        let url = Client::query(url, &pairs);
        self.send_empty(Method::DELETE, url, None).await
    }

    // ── Cryptographic operations ──────────────────────────────────────────

    /// Encrypt data with a key.
    ///
    /// The returned [`EncryptedData`] carries the nonce, the tag and the
    /// format version; pass it back to [`Client::decrypt`] unchanged.
    pub async fn encrypt(
        &self,
        key_id: &Uuid,
        request: &EncryptRequest,
        tenant: Option<&str>,
    ) -> Result<EncryptedData> {
        let tenant = self.resolve_tenant(tenant);
        let body = serde_json::to_value(request)?;
        let url = self.endpoint(&format!("/v1/keys/{key_id}/encrypt"))?;
        let url = Client::query(url, &[("tenant_id", &tenant)]);
        self.send_json(Method::POST, url, Some(body)).await
    }

    /// Decrypt data with a key.
    pub async fn decrypt(
        &self,
        key_id: &Uuid,
        request: &DecryptRequest,
        tenant: Option<&str>,
    ) -> Result<Vec<u8>> {
        let tenant = self.resolve_tenant(tenant);
        let body = serde_json::to_value(request)?;
        let url = self.endpoint(&format!("/v1/keys/{key_id}/decrypt"))?;
        let url = Client::query(url, &[("tenant_id", &tenant)]);
        let result: DecryptResult = self.send_json(Method::POST, url, Some(body)).await?;
        Ok(result.plaintext)
    }

    /// Sign data with an asymmetric key.
    pub async fn sign(
        &self,
        key_id: &Uuid,
        request: &SignRequest,
        tenant: Option<&str>,
    ) -> Result<Signature> {
        let tenant = self.resolve_tenant(tenant);
        let body = serde_json::to_value(request)?;
        let url = self.endpoint(&format!("/v1/keys/{key_id}/sign"))?;
        let url = Client::query(url, &[("tenant_id", &tenant)]);
        self.send_json(Method::POST, url, Some(body)).await
    }

    /// Verify a signature.
    pub async fn verify(
        &self,
        key_id: &Uuid,
        request: &VerifyRequest,
        tenant: Option<&str>,
    ) -> Result<bool> {
        let tenant = self.resolve_tenant(tenant);
        let body = serde_json::to_value(request)?;
        let url = self.endpoint(&format!("/v1/keys/{key_id}/verify"))?;
        let url = Client::query(url, &[("tenant_id", &tenant)]);
        let result: VerifyResult = self.send_json(Method::POST, url, Some(body)).await?;
        Ok(result.valid)
    }

    /// Compute a managed HMAC-SM3 tag.
    ///
    /// The AAD is domain-separated into the MAC input; the same AAD must be
    /// supplied to [`Client::hmac_verify`].
    pub async fn hmac(
        &self,
        key_id: &Uuid,
        request: &HmacRequest,
        tenant: Option<&str>,
    ) -> Result<MacTag> {
        let tenant = self.resolve_tenant(tenant);
        let body = serde_json::to_value(request)?;
        let url = self.endpoint(&format!("/v1/keys/{key_id}/hmac"))?;
        let url = Client::query(url, &[("tenant_id", &tenant)]);
        self.send_json(Method::POST, url, Some(body)).await
    }

    /// Verify a managed HMAC-SM3 tag.
    pub async fn hmac_verify(
        &self,
        key_id: &Uuid,
        request: &HmacVerifyRequest,
        tenant: Option<&str>,
    ) -> Result<bool> {
        let tenant = self.resolve_tenant(tenant);
        let body = serde_json::to_value(request)?;
        let url = self.endpoint(&format!("/v1/keys/{key_id}/hmac/verify"))?;
        let url = Client::query(url, &[("tenant_id", &tenant)]);
        let result: VerifyResult = self.send_json(Method::POST, url, Some(body)).await?;
        Ok(result.valid)
    }

    /// Compute a hash.
    pub async fn hash(&self, request: &HashRequest) -> Result<HashResult> {
        let body = serde_json::to_value(request)?;
        self.send_json(Method::POST, self.endpoint("/v1/hash")?, Some(body))
            .await
    }

    // ── Envelope encryption ───────────────────────────────────────────────

    /// Encrypt data with a data-encrypting key wrapped by a key-encrypting key.
    pub async fn envelope_encrypt(
        &self,
        request: &EnvelopeEncryptRequest,
    ) -> Result<EnvelopeEncrypted> {
        let tenant = self.resolve_tenant(request.tenant_id.as_deref());
        let body = Client::body_with_tenant(request, &tenant)?;
        self.send_json(
            Method::POST,
            self.endpoint("/v1/envelope/encrypt")?,
            Some(body),
        )
        .await
    }

    /// Decrypt an envelope-encrypted payload.
    pub async fn envelope_decrypt(&self, request: &EnvelopeDecryptRequest) -> Result<Vec<u8>> {
        let tenant = self.resolve_tenant(request.tenant_id.as_deref());
        let body = Client::body_with_tenant(request, &tenant)?;
        let result: DecryptResult = self
            .send_json(
                Method::POST,
                self.endpoint("/v1/envelope/decrypt")?,
                Some(body),
            )
            .await?;
        Ok(result.plaintext)
    }

    /// Re-wrap a data-encrypting key under a newer version of the
    /// key-encrypting key.
    pub async fn envelope_rewrap(
        &self,
        request: &EnvelopeRewrapRequest,
    ) -> Result<EnvelopeRewrapped> {
        let tenant = self.resolve_tenant(request.tenant_id.as_deref());
        let body = Client::body_with_tenant(request, &tenant)?;
        self.send_json(
            Method::POST,
            self.endpoint("/v1/envelope/rewrap")?,
            Some(body),
        )
        .await
    }

    // ── Import and export ─────────────────────────────────────────────────

    /// Import an externally generated key.
    pub async fn import_key(&self, request: &ImportKeyRequest) -> Result<ImportKeyResult> {
        let tenant = self.resolve_tenant(request.tenant_id.as_deref());
        let body = Client::body_with_tenant(request, &tenant)?;
        self.send_json(Method::POST, self.endpoint("/v1/keys/import")?, Some(body))
            .await
    }

    /// Export a key.
    ///
    /// The export is refused with **403** when the approval does not exist,
    /// has expired, or is bound to another key.
    pub async fn export_key(&self, request: &ExportKeyRequest) -> Result<ExportKeyResult> {
        let tenant = self.resolve_tenant(request.tenant_id.as_deref());
        let body = serde_json::to_value(request)?;
        let url = self.endpoint(&format!("/v1/keys/export/{}", request.key_id))?;
        let url = Client::query(url, &[("tenant_id", &tenant)]);
        self.send_json(Method::POST, url, Some(body)).await
    }

    // ── Approvals ─────────────────────────────────────────────────────────

    /// Raise an approval request.
    ///
    /// The requestor is derived from the API key by the server; a
    /// body-supplied requestor is ignored.
    pub async fn create_approval(&self, request: &CreateApprovalRequest) -> Result<Approval> {
        let tenant = self.resolve_tenant(request.tenant_id.as_deref());
        let body = Client::body_with_tenant(request, &tenant)?;
        self.send_json(Method::POST, self.endpoint("/v1/approvals")?, Some(body))
            .await
    }

    /// Fetch an approval request.
    pub async fn get_approval(&self, request_id: &str) -> Result<Approval> {
        self.send_json(
            Method::GET,
            self.endpoint(&format!("/v1/approvals/{request_id}"))?,
            None,
        )
        .await
    }

    /// Approve an approval request.
    ///
    /// The approver's identity and authority come from the API key; one key
    /// is one vote, so a multi-party quorum needs several distinct keys.
    pub async fn approve(&self, request_id: &str, comment: Option<&str>) -> Result<Approval> {
        let body = serde_json::to_value(&ApproveRequest {
            comment: comment.map(str::to_string),
        })?;
        self.send_json(
            Method::POST,
            self.endpoint(&format!("/v1/approvals/{request_id}/approve"))?,
            Some(body),
        )
        .await
    }

    /// Reject an approval request.
    pub async fn reject(&self, request_id: &str, reason: &str) -> Result<Approval> {
        let body = serde_json::to_value(&RejectRequest {
            reason: reason.to_string(),
        })?;
        self.send_json(
            Method::POST,
            self.endpoint(&format!("/v1/approvals/{request_id}/reject"))?,
            Some(body),
        )
        .await
    }

    /// Cancel an approval request.
    ///
    /// Only the key that raised the request may cancel it.
    pub async fn cancel(&self, request_id: &str) -> Result<Approval> {
        self.send_json(
            Method::POST,
            self.endpoint(&format!("/v1/approvals/{request_id}/cancel"))?,
            Some(json!({})),
        )
        .await
    }

    /// List the pending approval requests of a tenant.
    pub async fn list_pending_approvals(&self, tenant: Option<&str>) -> Result<Vec<Approval>> {
        let tenant = self.resolve_tenant(tenant);
        let url = self.endpoint(&format!("/v1/approvals/pending/{tenant}"))?;
        self.send_json(Method::GET, url, None).await
    }

    // ── Policies ──────────────────────────────────────────────────────────

    /// Create a PBAC policy.
    pub async fn create_policy(&self, request: &CreatePolicyRequest) -> Result<Policy> {
        let body = serde_json::to_value(request)?;
        self.send_json(Method::POST, self.endpoint("/v1/policies")?, Some(body))
            .await
    }

    /// List the PBAC policies.
    pub async fn list_policies(&self) -> Result<Vec<Policy>> {
        self.send_json(Method::GET, self.endpoint("/v1/policies")?, None)
            .await
    }

    /// Fetch a PBAC policy.
    pub async fn get_policy(&self, policy_id: &str) -> Result<Policy> {
        self.send_json(
            Method::GET,
            self.endpoint(&format!("/v1/policies/{policy_id}"))?,
            None,
        )
        .await
    }

    /// Remove a PBAC policy.
    ///
    /// The server answers `204 No Content` on success and `404` when no such
    /// policy exists, so a typo is reported instead of looking like a
    /// successful removal.
    pub async fn delete_policy(&self, policy_id: &str) -> Result<()> {
        self.send_empty(
            Method::DELETE,
            self.endpoint(&format!("/v1/policies/{policy_id}"))?,
            None,
        )
        .await
    }

    // ── Health ────────────────────────────────────────────────────────────

    /// Fetch the health of the KMS.
    pub async fn health(&self) -> Result<Health> {
        self.send_json(Method::GET, self.endpoint("/v1/health")?, None)
            .await
    }

    /// Probe the liveness of the KMS.
    pub async fn healthz(&self) -> Result<()> {
        self.send_empty(Method::GET, self.endpoint("/healthz")?, None)
            .await
    }

    /// Probe the readiness of the KMS.
    pub async fn readyz(&self) -> Result<()> {
        self.send_empty(Method::GET, self.endpoint("/readyz")?, None)
            .await
    }

    // ── SM9 (国密标识密码) ────────────────────────────────────────────────

    /// Sign data with the SM9 identity-based scheme.
    pub async fn sm9_sign(&self, request: &Sm9SignRequest) -> Result<Sm9Signature> {
        let body = serde_json::to_value(request)?;
        self.send_json(Method::POST, self.endpoint("/v1/sm9/sign")?, Some(body))
            .await
    }

    /// Verify an SM9 signature.
    pub async fn sm9_verify(&self, request: &Sm9VerifyRequest) -> Result<bool> {
        let body = serde_json::to_value(request)?;
        let result: VerifyResult = self
            .send_json(Method::POST, self.endpoint("/v1/sm9/verify")?, Some(body))
            .await?;
        Ok(result.valid)
    }

    /// Encrypt data for an SM9 identity.
    pub async fn sm9_encrypt(&self, request: &Sm9EncryptRequest) -> Result<Sm9Ciphertext> {
        let body = serde_json::to_value(request)?;
        self.send_json(Method::POST, self.endpoint("/v1/sm9/encrypt")?, Some(body))
            .await
    }

    /// Decrypt an SM9 ciphertext.
    pub async fn sm9_decrypt(&self, request: &Sm9DecryptRequest) -> Result<Vec<u8>> {
        let body = serde_json::to_value(request)?;
        let result: DecryptResult = self
            .send_json(Method::POST, self.endpoint("/v1/sm9/decrypt")?, Some(body))
            .await?;
        Ok(result.plaintext)
    }

    // ── Key derivation ────────────────────────────────────────────────────

    /// Derive a shared secret with a Diffie-Hellman key exchange.
    pub async fn dh_derive(&self, request: &DhDeriveRequest) -> Result<DerivedSecret> {
        let tenant = self.resolve_tenant(request.tenant_id.as_deref());
        let body = Client::body_with_tenant(request, &tenant)?;
        self.send_json(Method::POST, self.endpoint("/v1/dh/derive")?, Some(body))
            .await
    }
}

/// The builder of a [`Client`].
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    base_url: String,
    api_key: Option<String>,
    tenant: Option<String>,
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
}

impl ClientBuilder {
    /// Start building a client for the KMS at `base_url`.
    pub fn new(base_url: impl Into<String>) -> ClientBuilder {
        ClientBuilder {
            base_url: base_url.into(),
            api_key: None,
            tenant: None,
            timeout: None,
            connect_timeout: None,
        }
    }

    /// Set the API key sent as the `x-api-key` header.
    pub fn api_key(mut self, api_key: impl Into<String>) -> ClientBuilder {
        self.api_key = Some(api_key.into());
        self
    }

    /// Set the tenant used by calls that do not name one.
    ///
    /// Defaults to `"default"`, the same default the server uses.
    pub fn tenant(mut self, tenant: impl Into<String>) -> ClientBuilder {
        self.tenant = Some(tenant.into());
        self
    }

    /// Set the timeout of a whole request.
    pub fn timeout(mut self, timeout: Duration) -> ClientBuilder {
        self.timeout = Some(timeout);
        self
    }

    /// Set the timeout of establishing the connection.
    pub fn connect_timeout(mut self, connect_timeout: Duration) -> ClientBuilder {
        self.connect_timeout = Some(connect_timeout);
        self
    }

    /// Build the client.
    pub fn build(self) -> Result<Client> {
        let base_url = Url::parse(&self.base_url)
            .map_err(|error| KmsError::InvalidUrl(format!("{}: {error}", self.base_url)))?;
        if base_url.cannot_be_a_base() {
            return Err(KmsError::InvalidUrl(self.base_url));
        }

        let mut http = reqwest::Client::builder();
        if let Some(timeout) = self.timeout {
            http = http.timeout(timeout);
        }
        if let Some(connect_timeout) = self.connect_timeout {
            http = http.connect_timeout(connect_timeout);
        }

        Ok(Client {
            base_url,
            http: http.build()?,
            api_key: self.api_key,
            tenant: self.tenant.unwrap_or_else(|| "default".to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The endpoint URLs are the one thing the SDK builds by hand, and a
    /// mistake there sends the request to the wrong place — or to a path that
    /// means something else entirely. The rules are pinned here.
    #[test]
    fn the_endpoint_is_built_on_top_of_the_base_url() {
        let client = Client::new("https://kms.example.com").expect("client");
        assert_eq!(
            client.endpoint("/v1/keys").unwrap().as_str(),
            "https://kms.example.com/v1/keys"
        );
        assert_eq!(
            client
                .endpoint("/v1/keys/6f1c2f6e-9a3d-4a1e-9d2b-0f5a7c9e1d33/rotate")
                .unwrap()
                .as_str(),
            "https://kms.example.com/v1/keys/6f1c2f6e-9a3d-4a1e-9d2b-0f5a7c9e1d33/rotate"
        );
    }

    /// A deployment behind a reverse proxy mounts the KMS under a path
    /// prefix; the prefix must survive.
    #[test]
    fn a_path_prefix_of_the_base_url_is_kept() {
        for base in [
            "https://kms.example.com/api",
            "https://kms.example.com/api/",
        ] {
            let client = Client::new(base).expect("client");
            assert_eq!(
                client.endpoint("/v1/keys").unwrap().as_str(),
                "https://kms.example.com/api/v1/keys",
                "the prefix of {base} must be kept"
            );
        }
    }

    /// The tenant travels as a query parameter on some endpoints; it must be
    /// escaped, not pasted in.
    #[test]
    fn the_query_parameters_are_escaped() {
        let client = Client::new("https://kms.example.com").expect("client");
        let url = Client::query(
            client.endpoint("/v1/keys").unwrap(),
            &[("tenant_id", "a b&c=d")],
        );
        assert_eq!(
            url.as_str(),
            "https://kms.example.com/v1/keys?tenant_id=a+b%26c%3Dd"
        );
        assert_eq!(
            url.query_pairs()
                .find(|(name, _)| name == "tenant_id")
                .unwrap()
                .1,
            "a b&c=d"
        );
    }

    /// The tenant of a call is the explicit one, else the client's, else the
    /// server's own default.
    #[test]
    fn the_tenant_is_resolved_in_the_documented_order() {
        let client = Client::builder("https://kms.example.com")
            .tenant("acme")
            .build()
            .expect("client");
        assert_eq!(client.tenant(), "acme");
        assert_eq!(client.resolve_tenant(Some("other")), "other");
        assert_eq!(client.resolve_tenant(None), "acme");
        // An empty tenant is not a tenant.
        assert_eq!(client.resolve_tenant(Some("")), "acme");

        let default = Client::new("https://kms.example.com").expect("client");
        assert_eq!(default.tenant(), "default");
        assert_eq!(default.resolve_tenant(None), "default");
    }

    /// A URL that cannot be a base is refused when the client is built, not
    /// on the first request.
    #[test]
    fn an_unusable_url_is_refused_when_the_client_is_built() {
        assert!(Client::new("not a url").is_err());
        assert!(Client::new("mailto:kms@example.com").is_err());
    }
}
