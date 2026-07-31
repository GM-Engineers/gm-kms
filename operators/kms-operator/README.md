# GM-KMS Kubernetes Operator

A Kubernetes operator for managing GM-KMS keys as native Kubernetes secrets.

## Overview

The GM-KMS Operator bridges Kubernetes secrets management with GM-KMS (Key Management Service). It allows you to:

- Create and manage encryption keys in GM-KMS using Kubernetes Custom Resources
- Automatically sync keys as Kubernetes secrets
- Handle key rotation seamlessly
- Support for both symmetric (AES-256-GCM, SM4) and asymmetric (Ed25519, SM2, ECDSA) keys

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                         │
│                                                              │
│  ┌─────────────┐     ┌──────────────────┐     ┌──────────┐ │
│  │   KmsKey    │────▶│  KMS Operator    │────▶│  Secret  │ │
│  │  Resource   │     │  (Controller)     │     │  (TLS/   │ │
│  └─────────────┘     └──────────────────┘     │  Opaque) │ │
│                              │                └──────────┘ │
│                              │                               │
└──────────────────────────────┼───────────────────────────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │      GM-KMS          │
                    │   (Key Management)    │
                    └──────────────────────┘
```

## Installation

### Prerequisites

- Kubernetes 1.19+
- GM-KMS running and accessible
- kubectl configured

### Install the Operator

```bash
# Install CRD
kubectl apply -f config/crd/bases/kms.example.com_kmskeys.yaml

# Install RBAC
kubectl apply -f config/rbac/role.yaml

# Deploy the operator
kubectl apply -f config/manager/manager.yaml
```

## Usage

### Create a KMSKey resource

```yaml
apiVersion: kms.example.com/v1alpha1
kind: KmsKey
metadata:
  name: my-app-key
  namespace: default
spec:
  tenantId: "tenant-1"
  spec: "aes-256-gcm"
  secretName: "my-app-encryption-key"
  secretType: "Opaque"  # or "kubernetes.io/tls"
```

### Apply the resource

```bash
kubectl apply -f my-key.yaml
```

### Check status

```bash
kubectl get kmskey my-app-key
kubectl describe kmskey my-app-key
```

### Use the secret

```bash
# The operator creates a Kubernetes secret
kubectl get secret my-app-encryption-key

# Use in your application
apiVersion: v1
kind: Pod
metadata:
  name: my-app
spec:
  containers:
  - name: app
    env:
    - name: ENCRYPTION_KEY
      valueFrom:
        secretKeyRef:
          name: my-app-encryption-key
          key: key
```

## Key Specifications

| Spec | Type | Secret Content |
|------|------|----------------|
| `aes-256-gcm` | Symmetric | 32-byte key |
| `sm4` | Symmetric | 16-byte key |
| `ed25519` | Asymmetric | Private key (PEM) |
| `sm2` | Asymmetric | Private key (PEM) |
| `ecdsa-p256` | Asymmetric | Private key (PEM) |
| `ecdsa-p384` | Asymmetric | Private key (PEM) |
| `hmac-sha256` | Symmetric | 32-byte key |

## Key Rotation

The operator supports manual key rotation via `kubectl` or by updating the key metadata. Automatic rotation is handled by the KMS server when you call the rotate API.

## Development

### Prerequisites

- Go 1.21+
- kubebuilder 3.x (for code generation)
- operator-sdk 1.x
- Docker (for building images)

### Build

```bash
make build
```

### Run Locally

```bash
# Set environment variables
export KMS_SERVER_URL=http://localhost:8080
export KMS_API_KEY=your-api-key

# Run the operator
make run
```

### Test

```bash
make test
```

### Deploy to Cluster

```bash
# Build and push image
make docker-build docker-push

# Install CRD and deploy
make install deploy
```

## Project Structure

```
operators/kms-operator/
├── api/v1alpha1/
│   └── kmskey_types.go      # CRD type definitions
├── internal/
│   ├── controller/
│   │   └── kmskey_controller.go  # Reconciliation logic
│   └── kmsclient/
│       └── client.go         # KMS API client
├── main.go                  # Entry point
├── go.mod                   # Go module
└── Makefile                 # Build targets
```

## RBAC Permissions

The operator requires the following RBAC permissions:

```yaml
# Cluster-scoped
- apiGroups: ["kms.example.com"]
  resources: ["kmskeys"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

# For secret management
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
```

## License

MIT
