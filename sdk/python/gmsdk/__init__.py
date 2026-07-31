"""
GM-KMS Python SDK

A Python SDK for GM-KMS (Key Management Service)

Usage:
    from gmsdk import Client

    client = Client(
        server_url="http://localhost:8080",
        api_key="your-api-key",
        tenant_id="tenant-1"
    )

    # Create a key
    key = client.create_key(name="my-key", spec="aes-256-gcm")

    # Encrypt
    result = client.encrypt(key_id=key["id"], plaintext=b"secret data")

    # Decrypt
    plaintext = client.decrypt(key_id=key["id"], **result)
"""

__version__ = "0.1.0"

from .kms import Client, KeySpec, Error

__all__ = ["Client", "KeySpec", "Error", "__version__"]
