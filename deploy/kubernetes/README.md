# KMS Kubernetes Deployment

This directory contains Kubernetes manifests for deploying gm-kms in a production environment.

## Prerequisites

- Kubernetes 1.24+
- Prometheus Operator (for monitoring)
- Ingress controller (nginx-ingress recommended)
- PostgreSQL 14+ (external or via operator)
- Redis 7+ (external or via operator)

## Quick Start

```bash
# Create namespace
kubectl apply -f kms-deployment.yaml -f kms-hpa-pdb.yaml -f kms-monitoring.yaml

# Verify deployment
kubectl -n kms-system get pods -l app=kms

# Check logs
kubectl -n kms-system logs -l app=kms
```

## Components

| File | Description |
|------|-------------|
| `kms-deployment.yaml` | Deployment, Service, ConfigMap, TLS secrets |
| `kms-hpa-pdb.yaml` | HPA, PDB, NetworkPolicy, RBAC |
| `kms-monitoring.yaml` | ServiceMonitor, PodMonitor for Prometheus |

## Configuration

Update the `kms.toml` in the ConfigMap section with your environment-specific settings:

```toml
[database]
host = "postgres.database.svc.cluster.local"
port = 5432
name = "kms"
username = "kms_user"  # Use secret in production
password = "kms_pass"  # Use Kubernetes Secret in production
```

## Security Considerations

1. **TLS**: Configure proper TLS certificates in the `kms-tls` secret
2. **Secrets**: Use Kubernetes Secrets for sensitive configuration
3. **Network Policies**: Restrict traffic between namespaces
4. **ServiceAccount**: Use least-privilege RBAC policies

## Scaling

The HPA is configured to scale between 3 and 10 replicas based on CPU/memory utilization:

- CPU target: 70% utilization
- Memory target: 80% utilization

## Monitoring

Metrics are exposed on port 8080 at `/metrics` endpoint. The ServiceMonitor/PodMonitor resources integrate with Prometheus Operator.

Key metrics:
- `key_operations_total` - Total key operations by type
- `key_errors_total` - Error count
- `rate_limit_hits_total` - Rate limit hits
- `quota_exceeded_total` - Quota exceeded events
