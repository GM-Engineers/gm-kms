# GM-KMS Python SDK

Python SDK for GM-KMS (Key Management Service)

## Installation

从本地源码安装：

```bash
cd sdk/python
pip install -e .
```

## Quick Start

```python
from gmsdk import Client, KeySpec

# Create client
client = Client(
    server_url="http://localhost:8080",
    api_key="your-api-key",
    tenant_id="tenant-1"
)

# Create a key
key = client.create_key(
    name="my-aes-key",
    spec=KeySpec.AES_256_GCM,
)
print(f"Created key: {key.id}")

# Encrypt data
result = client.encrypt(key_id=key.id, plaintext=b"my-secret-data")
print(f"Encrypted: {result.ciphertext}")

# Decrypt data
plaintext = client.decrypt(
    key_id=key.id,
    ciphertext=result.ciphertext,
    nonce=result.nonce,
    tag=result.tag,
)
print(f"Decrypted: {plaintext}")

# Sign and verify
sig = client.sign(key_id=key.id, data=b"data to sign")
valid = client.verify(key_id=key.id, data=b"data to sign", signature=sig.signature)
print(f"Signature valid: {valid.valid}")
```

## Supported Key Specs

| Spec | Type | Usage |
|------|------|-------|
| `aes-256-gcm` | Symmetric | Encryption/Decryption |
| `sm4` | Symmetric | Encryption/Decryption (Chinese standard) |
| `ed25519` | Asymmetric | Signing/Verification |
| `sm2` | Asymmetric | Signing/Verification (Chinese standard) |
| `ecdsa-p256` | Asymmetric | Signing/Verification |
| `ecdsa-p384` | Asymmetric | Signing/Verification |
| `hmac-sha256` | Symmetric | HMAC computation |

## API Reference

### Client Configuration

```python
from gmsdk import Client

# Basic usage
client = Client("http://localhost:8080")

# With authentication
client = Client(
    server_url="http://localhost:8080",
    api_key="your-api-key",
    tenant_id="tenant-1",
    timeout=60.0,
)
```

### Key Management

```python
# Create key
key = client.create_key(
    name="key-name",
    spec=KeySpec.AES_256_GCM,
    tenant_id="tenant-1",  # optional, uses client's default
    description="Optional description",
)

# Get key metadata
key = client.get_key(key_id="key-id")

# List keys
keys = client.list_keys(tenant_id="tenant-1")

# Rotate key
key = client.rotate_key(key_id="key-id")

# Delete key
client.delete_key(key_id="key-id")
```

### Encryption

```python
from gmsdk import Client, KeySpec

client = Client("http://localhost:8080")

# Encrypt
result = client.encrypt(
    key_id="key-id",
    plaintext=b"secret data",
    aad=b"additional authenticated data",  # optional
)

# Decrypt
plaintext = client.decrypt(
    key_id="key-id",
    ciphertext=result.ciphertext,
    nonce=result.nonce,
    tag=result.tag,
)
```

### Signing

```python
# Sign
sig = client.sign(key_id="key-id", data=b"data to sign")

# Verify
valid = client.verify(
    key_id="key-id",
    data=b"data to sign",
    signature=sig.signature,
)
print(f"Valid: {valid.valid}")
```

### Health Check

```python
status = client.health()
print(status)  # "healthy"
```

## Error Handling

```python
from gmsdk import Client, Error

client = Client("http://localhost:8080")

try:
    key = client.get_key(key_id="nonexistent-key")
except Error as e:
    print(f"KMS Error: {e}")
```

## License

MIT
