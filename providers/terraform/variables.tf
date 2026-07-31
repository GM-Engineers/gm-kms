# KMS Terraform Provider - Variables
#
# Input variables for KMS Terraform integration

variable "kms_server_url" {
  description = "KMS server URL"
  type        = string
  default     = "http://127.0.0.1:8080"
}

variable "tenant_id" {
  description = "Tenant ID for multi-tenant operations"
  type        = string
  default     = "default"
}

variable "key_name" {
  description = "Name of the key to create"
  type        = string
  default     = ""
}

variable "key_spec" {
  description = "Key specification"
  type        = string
  default     = "aes-256-gcm"

  validation {
    condition     = contains(["aes-256-gcm", "sm4", "ed25519", "sm2", "ecdsa-p256", "ecdsa-p384", "hmac-sha256"], var.key_spec)
    error_message = "Key spec must be one of: aes-256-gcm, sm4, ed25519, sm2, ecdsa-p256, ecdsa-p384, hmac-sha256"
  }
}

variable "api_token" {
  description = "API token for authentication (if required)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "plaintext" {
  description = "Plaintext to encrypt (optional)"
  type        = string
  default     = ""
  sensitive   = true
}
