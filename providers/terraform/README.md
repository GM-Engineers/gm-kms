# KMS Terraform Provider

Terraform configurations for integrating gm-kms with your Terraform infrastructure-as-code.

## Approach

This implementation uses **Terraform's built-in HTTP data source** to communicate with the KMS REST API. No external provider installation required.

## Quick Start

### 1. Create a Key

```hcl
data "http" "create_key" {
  url = "http://127.0.0.1:8080/v1/keys"

  method = "POST"
  request_body = jsonencode({
    name      = "my-app-key"
    spec      = "aes-256-gcm"
    tenant_id = "production"
  })

  request_headers = {
    Content-Type = "application/json"
  }
}

locals {
  key_response = jsondecode(data.http.create_key.response_body)
  key_id       = local.key_response.id
}

output "key_id" {
  value = local.key_id
}
```

### 2. Encrypt Data

```hcl
data "http" "encrypt" {
  url = "http://127.0.0.1:8080/v1/keys/${local.key_id}/encrypt?tenant_id=production"

  method = "POST"
  request_body = jsonencode({
    plaintext = base64encode("sensitive-database-password")
  })

  request_headers = {
    Content-Type = "application/json"
  }
}

locals {
  encrypted = jsondecode(data.http.encrypt.response_body)
}

output "ciphertext" {
  value     = local.encrypted.ciphertext
  sensitive = true
}
```

### 3. Decrypt Data

```hcl
data "http" "decrypt" {
  url = "http://127.0.0.1:8080/v1/keys/${local.key_id}/decrypt?tenant_id=production"

  method = "POST"
  request_body = jsonencode({
    ciphertext = local.encrypted.ciphertext
    nonce      = local.encrypted.nonce
    tag        = local.encrypted.tag
  })

  request_headers = {
    Content-Type = "application/json"
  }
}

locals {
  decrypted = jsondecode(data.http.decrypt.response_body)
  plaintext = base64decode(local.decrypted.plaintext)
}
```

### 4. Sign and Verify

```hcl
# Sign
data "http" "sign" {
  url = "http://127.0.0.1:8080/v1/keys/${local.key_id}/sign?tenant_id=production"

  method = "POST"
  request_body = jsonencode({
    data = base64encode("document-content")
  })

  request_headers = {
    Content-Type = "application/json"
  }
}

# Verify
data "http" "verify" {
  url = "http://127.0.0.1:8080/v1/keys/${local.key_id}/verify?tenant_id=production"

  method = "POST"
  request_body = jsonencode({
    data      = base64encode("document-content")
    signature = jsondecode(data.http.sign.response_body).signature
  })

  request_headers = {
    Content-Type = "application/json"
  }
}

output "signature_valid" {
  value = jsondecode(data.http.verify.response_body).valid
}
```

### 5. Key Rotation

```hcl
data "http" "rotate_key" {
  url = "http://127.0.0.1:8080/v1/keys/${local.key_id}/rotate"

  method = "POST"

  request_headers = {
    Content-Type = "application/json"
  }
}
```

### 6. Delete Key

```hcl
data "http" "delete_key" {
  url = "http://127.0.0.1:8080/v1/keys/${local.key_id}"

  method = "DELETE"

  request_headers = {
    Content-Type = "application/json"
  }
}
```

## Complete Example

```hcl
terraform {
  required_version = ">= 1.0"
}

variable "kms_server_url" {
  default = "http://127.0.0.1:8080"
}

variable "tenant_id" {
  default = "production"
}

locals {
  api_url = var.kms_server_url
  tenant  = var.tenant_id
}

# Create encryption key
data "http" "create_key" {
  url = "${local.api_url}/v1/keys"

  method = "POST"
  request_body = jsonencode({
    name      = "app-database-key"
    spec      = "aes-256-gcm"
    tenant_id = local.tenant
  })

  request_headers = {
    Content-Type = "application/json"
  }
}

locals {
  key = jsondecode(data.http.create_key.response_body)
}

# Encrypt a secret
data "http" "encrypt_secret" {
  url = "${local.api_url}/v1/keys/${local.key.id}/encrypt?tenant_id=${local.tenant}"

  method = "POST"
  request_body = jsonencode({
    plaintext = base64encode("super-secret-password-123!")
  })

  request_headers = {
    Content-Type = "application/json"
  }
}

locals {
  encrypted = jsondecode(data.http.encrypt_secret.response_body)
}

# Store encrypted secret
resource "local_file" "encrypted_secret" {
  filename = "encrypted.txt"
  content  = local.encrypted.ciphertext
}

# Outputs
output "key_id" {
  description = "The ID of the created key"
  value       = local.key.id
}

output "key_version" {
  description = "The version of the created key"
  value       = local.key.version
}

output "encrypted_at" {
  description = "Timestamp of encryption"
  value       = timestamp()
}
```

## API Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create Key | POST | `/v1/keys` |
| Get Key | GET | `/v1/keys/{id}` |
| List Keys | GET | `/v1/keys` |
| Delete Key | DELETE | `/v1/keys/{id}` |
| Rotate Key | POST | `/v1/keys/{id}/rotate` |
| Encrypt | POST | `/v1/keys/{id}/encrypt` |
| Decrypt | POST | `/v1/keys/{id}/decrypt` |
| Sign | POST | `/v1/keys/{id}/sign` |
| Verify | POST | `/v1/keys/{id}/verify` |
| Health | GET | `/v1/health` |

## Authentication

For production deployments, add authentication headers:

```hcl
data "http" "create_key" {
  # ...

  request_headers = {
    Content-Type  = "application/json"
    Authorization = "Bearer ${var.api_token}"
  }
}
```

## Health Check

```hcl
data "http" "kms_health" {
  url = "http://127.0.0.1:8080/v1/health"
}

output "kms_status" {
  value = jsondecode(data.http.kms_health.response_body).status  # "ok", "degraded", or "error"
}
```

## Supported Key Specs

- `aes-256-gcm` - AES-256-GCM symmetric encryption
- `sm4` - SM4 symmetric encryption (Chinese standard)
- `ed25519` - Ed25519 digital signatures
- `sm2` - SM2 digital signatures (Chinese standard)
- `ecdsa-p256` - ECDSA P-256
- `ecdsa-p384` - ECDSA P-384

## File Structure

```
providers/terraform/
├── README.md           # This file
├── variables.tf       # Input variables
├── main.tf            # Main examples
└── .gitignore         # Git ignore rules
```
