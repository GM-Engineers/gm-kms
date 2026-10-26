"""
GM-KMS Python SDK - Core Client Module
"""

import base64
import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict, Any, List
import urllib.request
import urllib.error
import urllib.parse


class KeySpec(str, Enum):
    """Supported key specifications"""
    AES_256_GCM = "aes-256-gcm"
    SM4 = "sm4"
    ED25519 = "ed25519"
    SM2 = "sm2"
    ECDSA_P256 = "ecdsa-p256"
    ECDSA_P384 = "ecdsa-p384"
    HMAC_SHA256 = "hmac-sha256"


class PolicyEffect(str, Enum):
    """PBAC policy effects

    The server accepts ``"allow"`` and ``"deny"`` on the way in and answers
    ``"Allow"`` and ``"Deny"`` on the way out, so the lookup is
    case-insensitive.
    """

    ALLOW = "allow"
    DENY = "deny"

    @classmethod
    def _missing_(cls, value: object) -> Optional["PolicyEffect"]:
        if isinstance(value, str):
            lowered = value.lower()
            for member in cls:
                if member.value == lowered:
                    return member
        return None


class Error(Exception):
    """GM-KMS Error

    ``status`` carries the HTTP status the server answered with, when the
    failure came from the server rather than from the transport. A 404 and a
    403 are different answers, and a caller has to be able to tell them
    apart.
    """

    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.status = status


@dataclass
class KeyMeta:
    """Key metadata"""
    id: str
    name: str
    spec: KeySpec
    status: str
    version: int
    tenant_id: str
    created_at: str
    rotated_at: Optional[str] = None
    description: Optional[str] = None


@dataclass
class EncryptResult:
    """Encryption result"""
    key_id: str
    version: int
    ciphertext: str
    nonce: str
    tag: str


@dataclass
class SignResult:
    """Signing result"""
    key_id: str
    version: int
    signature: str


@dataclass
class VerifyResult:
    """Verification result"""
    valid: bool


@dataclass
class Policy:
    """PBAC policy"""

    id: str
    name: str
    effect: PolicyEffect
    condition: Dict[str, Any]
    resources: List[str]
    subjects: List[str]
    # The tenant the policy is restricted to, None when it applies to every
    # tenant.
    tenant: Optional[str] = None
    enabled: bool = True


class Client:
    """
    GM-KMS Python SDK Client

    Args:
        server_url: KMS server URL (e.g., "http://localhost:8080")
        api_key: API key for authentication (optional)
        tenant_id: Default tenant ID (optional, can be overridden per-request)

    Example:
        client = Client(
            server_url="http://localhost:8080",
            api_key="your-api-key",
            tenant_id="tenant-1"
        )

        key = client.create_key(name="my-key", spec=KeySpec.AES_256_GCM)
        result = client.encrypt(key_id=key.id, plaintext=b"secret")
    """

    def __init__(
        self,
        server_url: str,
        api_key: Optional[str] = None,
        tenant_id: str = "default",
        timeout: float = 30.0,
    ):
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.tenant_id = tenant_id
        self.timeout = timeout

    def _make_request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        tenant_id: Optional[str] = None,
    ) -> Any:
        """Make an HTTP request to the KMS server"""
        url = f"{self.server_url}{path}"
        data = json.dumps(body).encode("utf-8") if body else None

        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            # The server reads the API key from the `x-api-key` header. It does
            # not look at `Authorization`, so a Bearer token there is simply
            # not seen and every call is refused as unauthenticated.
            headers["x-api-key"] = self.api_key

        req = urllib.request.Request(
            url,
            data=data,
            headers=headers,
            method=method,
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                raw = response.read()
                # A 204 No Content carries no body: there is nothing to
                # parse, and asking for JSON would fail on the empty payload.
                if not raw:
                    return None
                return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8")
            try:
                error_data = json.loads(error_body)
                raise Error(
                    error_data.get("error", f"HTTP {e.code}: {error_body}"),
                    status=e.code,
                )
            except json.JSONDecodeError:
                raise Error(f"HTTP {e.code}: {error_body}", status=e.code)
        except urllib.error.URLError as e:
            raise Error(f"Connection error: {e.reason}")

    def create_key(
        self,
        name: str,
        spec: KeySpec,
        tenant_id: Optional[str] = None,
        description: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> KeyMeta:
        """
        Create a new key

        Args:
            name: Key name
            spec: Key specification (e.g., KeySpec.AES_256_GCM)
            tenant_id: Tenant ID (uses default if not specified)
            description: Optional key description
            metadata: Optional metadata (tags, labels)

        Returns:
            KeyMeta: Created key metadata
        """
        tid = tenant_id or self.tenant_id
        body = {
            "name": name,
            "spec": spec.value if isinstance(spec, KeySpec) else spec,
            "tenant_id": tid,
        }
        if description:
            body["description"] = description
        if metadata:
            body["metadata"] = metadata

        result = self._make_request("POST", "/v1/keys", body)
        return self._parse_key_meta(result)

    def get_key(self, key_id: str) -> KeyMeta:
        """
        Get key metadata

        Args:
            key_id: Key ID

        Returns:
            KeyMeta: Key metadata
        """
        result = self._make_request("GET", f"/v1/keys/{key_id}")
        return self._parse_key_meta(result)

    def list_keys(self, tenant_id: Optional[str] = None) -> List[KeyMeta]:
        """
        List keys for a tenant

        Args:
            tenant_id: Tenant ID (uses default if not specified)

        Returns:
            List[KeyMeta]: List of key metadata
        """
        tid = tenant_id or self.tenant_id
        result = self._make_request("GET", f"/v1/keys?tenant_id={tid}")
        return [self._parse_key_meta(k) for k in result] if isinstance(result, list) else [self._parse_key_meta(result)]

    def encrypt(
        self,
        key_id: str,
        plaintext: bytes,
        aad: Optional[bytes] = None,
    ) -> EncryptResult:
        """
        Encrypt data

        Args:
            key_id: Key ID to use for encryption
            plaintext: Data to encrypt
            aad: Additional authenticated data (optional)

        Returns:
            EncryptResult: Encryption result with ciphertext, nonce, tag
        """
        plaintext_b64 = base64.b64encode(plaintext).decode("ascii")
        body = {"plaintext": plaintext_b64}
        if aad:
            body["aad"] = base64.b64encode(aad).decode("ascii")

        result = self._make_request("POST", f"/v1/keys/{key_id}/encrypt", body)
        return EncryptResult(
            key_id=result["key_id"],
            version=result["version"],
            ciphertext=result["ciphertext"],
            nonce=result["nonce"],
            tag=result["tag"],
        )

    def decrypt(
        self,
        key_id: str,
        ciphertext: str,
        nonce: str,
        tag: str,
    ) -> bytes:
        """
        Decrypt data

        Args:
            key_id: Key ID to use for decryption
            ciphertext: Encrypted ciphertext (base64)
            nonce: Nonce/IV (base64)
            tag: Authentication tag (base64)

        Returns:
            bytes: Decrypted plaintext
        """
        body = {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": tag,
        }
        result = self._make_request("POST", f"/v1/keys/{key_id}/decrypt", body)
        return base64.b64decode(result["plaintext"])

    def sign(
        self,
        key_id: str,
        data: bytes,
    ) -> SignResult:
        """
        Sign data

        Args:
            key_id: Key ID to use for signing
            data: Data to sign

        Returns:
            SignResult: Signing result with signature
        """
        data_b64 = base64.b64encode(data).decode("ascii")
        body = {"data": data_b64}
        result = self._make_request("POST", f"/v1/keys/{key_id}/sign", body)
        return SignResult(
            key_id=result["key_id"],
            version=result["version"],
            signature=result["signature"],
        )

    def verify(
        self,
        key_id: str,
        data: bytes,
        signature: str,
    ) -> VerifyResult:
        """
        Verify a signature

        Args:
            key_id: Key ID to use for verification
            data: Original data that was signed
            signature: Signature to verify (base64)

        Returns:
            VerifyResult: Verification result
        """
        data_b64 = base64.b64encode(data).decode("ascii")
        body = {"data": data_b64, "signature": signature}
        result = self._make_request("POST", f"/v1/keys/{key_id}/verify", body)
        return VerifyResult(valid=result["valid"])

    def rotate_key(self, key_id: str) -> KeyMeta:
        """
        Rotate a key

        Args:
            key_id: Key ID to rotate

        Returns:
            KeyMeta: Rotated key metadata
        """
        result = self._make_request("POST", f"/v1/keys/{key_id}/rotate")
        return self._parse_key_meta(result)

    def delete_key(self, key_id: str) -> None:
        """
        Delete a key (soft delete)

        Args:
            key_id: Key ID to delete
        """
        self._make_request("DELETE", f"/v1/keys/{key_id}")

    def health(self) -> str:
        """
        Check KMS health

        Returns:
            str: Health status
        """
        result = self._make_request("GET", "/v1/health")
        return result.get("status", "unknown")

    def create_policy(
        self,
        name: str,
        effect: PolicyEffect,
        condition: Dict[str, Any],
        resources: List[str],
        subjects: List[str],
        tenant: Optional[str] = None,
        enabled: bool = True,
    ) -> Policy:
        """
        Create a PBAC policy

        Args:
            name: Policy name
            effect: PolicyEffect.ALLOW or PolicyEffect.DENY
            condition: Condition expression, as a JSON document
            resources: Resource patterns the policy applies to
            subjects: Subject patterns the policy applies to
            tenant: Restrict the policy to this tenant. None leaves the policy
                unscoped, so it applies to every tenant; a glob pattern such
                as "tenant-*" covers a family of tenants.
            enabled: Whether the policy is active

        Returns:
            Policy: The created policy
        """
        body: Dict[str, Any] = {
            "name": name,
            "effect": effect.value if isinstance(effect, PolicyEffect) else effect,
            "condition": condition,
            "resources": resources,
            "subjects": subjects,
            "enabled": enabled,
        }
        if tenant:
            body["tenant"] = tenant

        result = self._make_request("POST", "/v1/policies", body)
        return self._parse_policy(result)

    def list_policies(self) -> List[Policy]:
        """
        List the PBAC policies

        Returns:
            List[Policy]: The installed policies
        """
        result = self._make_request("GET", "/v1/policies")
        if isinstance(result, list):
            return [self._parse_policy(p) for p in result]
        return [self._parse_policy(result)]

    def get_policy(self, policy_id: str) -> Policy:
        """
        Get a PBAC policy

        Args:
            policy_id: Policy ID

        Returns:
            Policy: The policy
        """
        result = self._make_request("GET", f"/v1/policies/{policy_id}")
        return self._parse_policy(result)

    def delete_policy(self, policy_id: str) -> None:
        """
        Remove a PBAC policy

        Without this a policy that turns out to be wrong could never be
        withdrawn, and now that policies are persisted it would outlive every
        restart.

        Args:
            policy_id: Policy ID
        """
        self._make_request("DELETE", f"/v1/policies/{policy_id}")

    def _parse_policy(self, data: Dict[str, Any]) -> Policy:
        """Parse a policy from an API response"""
        return Policy(
            id=data["id"],
            name=data["name"],
            effect=PolicyEffect(data.get("effect", "allow")),
            condition=data.get("condition", {}),
            resources=data.get("resources", []),
            subjects=data.get("subjects", []),
            tenant=data.get("tenant"),
            enabled=data.get("enabled", True),
        )

    def _parse_key_meta(self, data: Dict[str, Any]) -> KeyMeta:
        """Parse key metadata from API response"""
        return KeyMeta(
            id=data["id"],
            name=data["name"],
            spec=KeySpec(data.get("spec", data.get("key_spec", "aes-256-gcm"))),
            status=data["status"],
            version=data["version"],
            tenant_id=data["tenant_id"],
            created_at=data["created_at"],
            rotated_at=data.get("rotated_at"),
            description=data.get("description"),
        )


# Convenience functions for quick usage
def create_client(
    server_url: str,
    api_key: Optional[str] = None,
    tenant_id: str = "default",
) -> Client:
    """Create a KMS client"""
    return Client(server_url=server_url, api_key=api_key, tenant_id=tenant_id)
