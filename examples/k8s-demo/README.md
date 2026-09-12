# gm-kms Kubernetes Demo Deployment

> **DEMO ONLY — NOT PRODUCTION**
>
> This is a minimal Kubernetes manifest to help you try out gm-kms in a cluster.
> It is **not** a production-ready deployment. See the README at the repo root
> for what gm-kms is and is not, and the known limitations.

## What this gives you

- A single-pod `Deployment` running the `kms` binary (REST + gRPC)
- A `ClusterIP` `Service` exposing REST on 8080 and gRPC on 9090
- Sensible resource requests, liveness/readiness probes, read-only root filesystem
- A `ConfigMap` example for `kms.toml`

## What this does NOT give you

- HA / multi-replica setup — replicas: 1, no `podAntiAffinity`, no topology spread
- Horizontal Pod Autoscaler (HPA)
- Pod Disruption Budget (PDB)
- Network Policies
- Prometheus / Grafana monitoring stack
- Ingress / TLS termination (gm-kms handles its own TLS via `[rest_tls]` config)
- ServiceAccount / RBAC for production-grade isolation
- Persistent storage (the `software` keystore is in-memory; PostgreSQL is external)
- Backup / disaster recovery

If you need any of the above, **do not start from this manifest** — design your own based on your environment's requirements.

## Usage

```bash
# 1. Build the Docker image first
docker build -t gm-kms:demo .

# 2. (Optional) Build a kind/minikube cluster if you don't have one
kind create cluster

# 3. Apply the demo
kubectl apply -f deployment.yaml

# 4. Check the pod is running
kubectl -n kms-demo get pods -l app=kms

# 5. Port-forward to test
kubectl -n kms-demo port-forward svc/kms-service 8080:8080
curl http://localhost:8080/v1/health
```

## Cleaning up

```bash
kubectl delete -f deployment.yaml
kubectl delete namespace kms-demo
```

## See also

- [../../README.md](../../README.md) — project positioning
- [../../docs/guides/deployment-guide.md](../../docs/guides/deployment-guide.md) — generic deployment guide (binary, not k8s)
