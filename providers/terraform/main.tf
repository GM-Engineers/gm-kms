# KMS Terraform Provider - Main Configuration
#
# This file provides practical examples for using KMS with Terraform's
# built-in HTTP data source. No external provider required.

terraform {
  required_version = ">= 1.0"
}

# -----------------------------------------------------------------------------
# Provider Configuration
# -----------------------------------------------------------------------------

locals {
  api_url = var.kms_server_url
  tenant  = var.tenant_id
}

# -----------------------------------------------------------------------------
# KMS Key Creation
# -----------------------------------------------------------------------------

resource "null_resource" "kms_key" {
  count = var.key_name != "" ? 1 : 0

  triggers = {
    name      = var.key_name
    spec      = var.key_spec
    tenant_id = local.tenant
    key_id    = "" # Store created key ID
  }

  provisioner "local-exec" {
    command = <<EOT
      RESPONSE=$(curl -s -X POST "${local.api_url}/v1/keys" \
        -H "Content-Type: application/json" \
        ${var.api_token != "" ? "-H \"Authorization: Bearer ${var.api_token}\"" : ""} \
        -d '{"name":"${var.key_name}","spec":"${var.key_spec}","tenant_id":"${local.tenant}"}')

      KEY_ID=$(echo "$RESPONSE" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)

      if [ -n "$KEY_ID" ]; then
        echo "Created key: $KEY_ID"
        echo "$RESPONSE" > .terraform/kms_key_${var.key_name}.json
      else
        echo "Failed to create key: $RESPONSE"
        exit 1
      fi
    EOT
    interpreter = ["/bin/bash", "-c"]
  }
}

# -----------------------------------------------------------------------------
# Encryption
# -----------------------------------------------------------------------------

locals {
  encryption_result = var.plaintext != "" ? jsondecode(
    data.http.kms_encrypt.response_body
  ) : null
}

data "http" "kms_encrypt" {
  count = var.plaintext != "" && var.key_name != "" ? 1 : 0

  url = "${local.api_url}/v1/keys/${var.key_name}/encrypt?tenant_id=${local.tenant}"

  method = "POST"
  request_body = jsonencode({
    plaintext = base64encode(var.plaintext)
  })

  request_headers = merge(
    { Content-Type = "application/json" },
    var.api_token != "" ? { Authorization = "Bearer ${var.api_token}" } : {}
  )
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "kms_server_url" {
  description = "KMS server URL"
  value       = local.api_url
}

output "tenant_id" {
  description = "Tenant ID"
  value       = local.tenant
}

output "key_name" {
  description = "Configured key name"
  value       = var.key_name
}

output "key_spec" {
  description = "Configured key specification"
  value       = var.key_spec
}

output "key_created" {
  description = "Whether a key was created"
  value       = var.key_name != "" ? (length(null_resource.kms_key) > 0) : false
}

output "encryption_configured" {
  description = "Whether encryption is configured"
  value       = var.plaintext != "" && var.key_name != ""
}
