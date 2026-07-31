# GM-KMS JavaScript/TypeScript SDK

JavaScript and TypeScript SDK for GM-KMS (Key Management Service)

## Installation

从本地源码安装：

```bash
cd sdk/javascript
npm install
```

## Quick Start

### TypeScript

```typescript
import { Client, KeySpec } from './src/index';  // 本地导入

const client = new Client({
  serverUrl: 'http://localhost:8080',
  apiKey: 'your-api-key',
  tenantId: 'tenant-1',
});

async function main() {
  // Create a key
  const key = await client.createKey({
    name: 'my-aes-key',
    spec: KeySpec.AES_256_GCM,
  });
  console.log(`Created key: ${key.id}`);

  // Encrypt data
  const result = await client.encrypt({
    keyId: key.id,
    plaintext: Buffer.from('my-secret-data'),
  });
  console.log(`Encrypted: ${result.ciphertext}`);

  // Decrypt data
  const plaintext = await client.decrypt({
    keyId: key.id,
    ciphertext: result.ciphertext,
    nonce: result.nonce,
    tag: result.tag,
  });
  console.log(`Decrypted: ${plaintext.toString()}`);

  // Sign and verify
  const sig = await client.sign({
    keyId: key.id,
    data: Buffer.from('data to sign'),
  });
  const valid = await client.verify({
    keyId: key.id,
    data: Buffer.from('data to sign'),
    signature: sig.signature,
  });
  console.log(`Signature valid: ${valid.valid}`);
}

main().catch(console.error);
```

### JavaScript

```javascript
const { Client, KeySpec } = require('./src/index');  // 本地导入

const client = new Client({
  serverUrl: 'http://localhost:8080',
  apiKey: 'your-api-key',
  tenantId: 'tenant-1',
});

async function main() {
  const key = await client.createKey({
    name: 'my-key',
    spec: KeySpec.AES_256_GCM,
  });

  const result = await client.encrypt({
    keyId: key.id,
    plaintext: Buffer.from('secret data'),
  });

  const plaintext = await client.decrypt({
    keyId: key.id,
    ciphertext: result.ciphertext,
    nonce: result.nonce,
    tag: result.tag,
  });

  console.log(plaintext.toString());
}

main().catch(console.error);
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

```typescript
const client = new Client({
  serverUrl: 'http://localhost:8080',
  apiKey: 'your-api-key',      // optional
  tenantId: 'tenant-1',         // optional, defaults to 'default'
  timeout: 30000,               // optional, timeout in ms
});
```

### Key Management

```typescript
// Create key
const key = await client.createKey({
  name: 'key-name',
  spec: KeySpec.AES_256_GCM,
  tenantId: 'tenant-1',  // optional
  description: 'Optional description',
});

// Get key metadata
const key = await client.getKey(keyId);

// List keys
const keys = await client.listKeys(tenantId);

// Rotate key
const key = await client.rotateKey(keyId);

// Delete key
await client.deleteKey(keyId);
```

### Encryption

```typescript
// Encrypt
const result = await client.encrypt({
  keyId: 'key-id',
  plaintext: Buffer.from('secret data'),
  aad: Buffer.from('additional data'),  // optional
});

// Decrypt
const plaintext = await client.decrypt({
  keyId: 'key-id',
  ciphertext: result.ciphertext,
  nonce: result.nonce,
  tag: result.tag,
});
```

### Signing

```typescript
// Sign
const sig = await client.sign({
  keyId: 'key-id',
  data: Buffer.from('data to sign'),
});

// Verify
const valid = await client.verify({
  keyId: 'key-id',
  data: Buffer.from('data to sign'),
  signature: sig.signature,
});
```

### Health Check

```typescript
const status = await client.health();
console.log(status);  // "healthy"
```

## Error Handling

```typescript
import { Client, Error } from './src/index';  // 本地导入

const client = new Client({ serverUrl: 'http://localhost:8080' });

try {
  const key = await client.getKey('nonexistent-key');
} catch (e) {
  if (e instanceof Error) {
    console.error(`KMS Error: ${e.message}`);
  } else {
    throw e;
  }
}
```

## License

MIT
