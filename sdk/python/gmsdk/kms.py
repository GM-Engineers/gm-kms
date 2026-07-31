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


class Error(Exception):
    """GM-KMS Error"""
    pass


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
    ) -> Dict[str, Any]:
        """Make an HTTP request to the KMS server"""
        url = f"{self.server_url}{path}"
        data = json.dumps(body).encode("utf-8") if body else None

        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        req = urllib.request.Request(
            url,
            data=data,
            headers=headers,
            method=method,
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8")
            try:
                error_data = json.loads(error_body)
                raise Error(error_data.get("error", f"HTTP {e.code}: {error_body}"))
            except json.JSONDecodeError:
                raise Error(f"HTTP {e.code}: {error_body}")
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
