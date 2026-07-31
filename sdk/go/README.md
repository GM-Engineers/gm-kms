# GM-KMS Go SDK

Go SDK for GM-KMS (Key Management Service)

## Installation

从本地源码安装：

```bash
cd sdk/go
go mod init github.com/GM-Engineers/gm-kms-sdk-go
go get ./...
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    kms "your/module/path/kms"  // 根据实际模块路径配置
)

func main() {
    // Create client
    client, err := kms.New("http://localhost:8080",
        kms.WithAPIKey("your-api-key"),
        kms.WithTenantID("tenant-1"),
    )
    if err != nil {
        panic(err)
    }

    ctx := context.Background()

    // Create a key
    key, err := client.CreateKey(ctx, &kms.CreateKeyRequest{
        Name:     "my-aes-key",
        Spec:     kms.SpecAes256Gcm,
        TenantID: "tenant-1",
    })
    if err != nil {
        panic(err)
    }
    fmt.Printf("Created key: %s\n", key.ID)

    // Encrypt data
    secret := []byte("my-secret-data")
    enc, err := client.Encrypt(ctx, key.ID, secret)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Encrypted: ciphertext=%s\n", enc.Ciphertext)

    // Decrypt data
    decrypted, err := client.Decrypt(ctx, key.ID, enc.Ciphertext, enc.Nonce, enc.Tag)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Decrypted: %s\n", string(decrypted))

    // Sign and verify
    sig, err := client.Sign(ctx, key.ID, []byte("data-to-sign"))
    if err != nil {
        panic(err)
    }

    valid, err := client.Verify(ctx, key.ID, []byte("data-to-sign"), sig.Signature)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Signature valid: %v\n", valid.Valid)
}
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

```go
// Create with defaults
client, _ := kms.New("http://localhost:8080")

// With API key authentication
client, _ := kms.New("http://localhost:8080",
    kms.WithAPIKey("your-api-key"),
)

// With default tenant ID
client, _ := kms.New("http://localhost:8080",
    kms.WithTenantID("tenant-1"),
)

// With custom HTTP client
httpClient := &http.Client{Timeout: 60 * time.Second}
client, _ := kms.New("http://localhost:8080",
    kms.WithHTTPClient(httpClient),
)
```

### Key Management

```go
// Create key
key, err := client.CreateKey(ctx, &kms.CreateKeyRequest{
    Name:     "key-name",
    Spec:     kms.SpecAes256Gcm,
    TenantID: "tenant-1",
})

// Get key metadata
key, err := client.GetKey(ctx, "key-id")

// List keys
keys, err := client.ListKeys(ctx, "tenant-1")

// Rotate key
key, err := client.RotateKey(ctx, "key-id")

// Delete key
err := client.DeleteKey(ctx, "key-id")
```

### Encryption

```go
// Encrypt
result, err := client.Encrypt(ctx, keyID, []byte("plaintext"))

// Decrypt
plaintext, err := client.Decrypt(ctx, keyID, result.Ciphertext, result.Nonce, result.Tag)
```

### Signing

```go
// Sign
sig, err := client.Sign(ctx, keyID, []byte("data"))

// Verify
valid, err := client.Verify(ctx, keyID, []byte("data"), sig.Signature)
```

### Health Check

```go
status, err := client.Health(ctx)
fmt.Println(status) // "healthy"
```

## License

MIT
