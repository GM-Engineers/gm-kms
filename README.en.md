# gm-kms

[![GitHub Release](https://img.shields.io/github/v/release/GM-Engineers/gm-kms?include_prereleases)](https://github.com/GM-Engineers/gm-kms/releases)

**[中文版](./README.md)**

> **Positioning**: gm-kms is a **Rust reference implementation of a national-cryptography (国密) KMS**, aimed at learning, internal demos, ecosystem integration, and small-scale auxiliary scenarios.
> It is **NOT** a production-ready KMS, **does NOT replace** commercial cloud KMS (Aliyun / Huawei Cloud / Tencent Cloud / AWS KMS), and has **NOT passed** third-party cryptographic evaluation (密评) or MLPS certification (等保).
> See "What this project is / is not" below.

## What this project is

- **A Rust national-crypto KMS reference implementation**: complete coverage of SM2 / SM3 / SM4 / SM9 algorithms, envelope encryption, key rotation, PBAC, MFA, WORM audit, approval workflow — the core patterns of any KMS
- **A learning resource**: reading the code teaches you how to implement a KMS in Rust. Start at [LEARN.md](./LEARN.md)
- **A wire-up demo for the gm workspace ecosystem**: `gm-crypto` + `gm-tls` + `gm-sm9-rs` + `gm-tlcp` + `gm-ca` integrated end-to-end
- **A runnable binary for small internal / demo scenarios**: REST + gRPC dual API

## What this project is NOT

| Not claimed capability | Why |
|---|---|
| A production-ready KMS | No SLA, no commercial support, still v0.x; production features (key lifecycle guarantees, HA, DR) not covered |
| A commercial KMS replacement | Aliyun KMS / Huawei Cloud KMS / Tencent Cloud KMS / AWS KMS provide managed HA, compliance certifications, key lineage, managed HSM integration |
| A certified compliance deliverable | Self-assessment ≠ third-party certification; TLCP cert chain verification not integrated; SM9 master key in memory by default |
| Direct use in finance / government production systems | Same as above; mandatory cryptographic evaluation needs separate assessment |
| A multi-tenant SaaS backend | No commercial support capacity |

## Suitable / Not-suitable scenarios

| Scenario | Suitable? | Notes |
|---|---|---|
| Learning Rust KMS implementation | Yes | Start from [LEARN.md](./LEARN.md) |
| National-crypto PoC / internal demo | Yes | Note TLCP cert chain verification is missing |
| gm workspace ecosystem integration demo | Yes | Full wire-up available |
| Small-scale internal tooling KMS backend | Yes | Evaluate your own security boundary |
| Kubernetes internal deployment | Partial | See [examples/k8s-demo/](./examples/k8s-demo/README.md) (demo, not production) |
| Aliyun / Huawei / Tencent Cloud KMS replacement | No | See table above |
| Cryptographic evaluation deliverable | No | See table above |
| Finance / government production KMS | No | See table above |

## Features

| Category | Details |
|----------|---------|
| **GM algorithms** | SM2 sign / encrypt / key exchange, SM3 hash, SM4 symmetric encryption, SM9 IBE sign / encrypt |
| **International algorithms** | AES-256-GCM, Ed25519, ECDSA-P256/P384, RSA-4096 |
| **Key management** | Generate, rotate, destroy, import / export |
| **Access control** | PBAC policy engine, MFA (TOTP), approval workflow |
| **Audit log** | WORM storage, hash-chain tamper-evidence, 3-year retention |
| **Backends** | PostgreSQL, Redis, in-memory software keystore |
| **REST API** | TLS 1.3 + SM (gm-tls) or **TLCP (gm-tlcp)** selectable backend |
| **gRPC API** | TLS 1.3 + SM (TLCP not yet supported, see known limitations) |

## Tech stack

- **Language**: Rust 1.85+ (Edition 2024)
- **Async runtime**: tokio
- **Web**: axum 0.8, tonic 0.14
- **Database**: PostgreSQL 16+, Redis 7+
- **Cryptography**: ring, gm-crypto (SM2/SM3/SM4/SM9)
- **External deps**: gm-tls (TLS 1.3 + SM), gm-sm9-rs (SM9 dual-backend), gm-ca (CA certs), gm-tlcp (TLCP, GB/T 38636-2020)

## Quick start (learning / demo)

```bash
# 1. Start dependency services
docker compose up -d
# Starts PostgreSQL and Redis (does NOT start kms itself)

# 2. Set environment variables
cp -n .env.example .env || true
export DATABASE_URL="postgres://kms:kms123@localhost:5432/kms"
export KMS_KEK="<your-kek-hex-64>"

# 3. Build and test
cargo build --release
cargo test --workspace           # 998+ tests

# 4. Start the service (default TLS 1.3 + SM)
cargo run --release -p kms -- --server

# 4b. Start REST over TLCP (requires dual certificates prepared first)
REST_TLS_BACKEND=tlcp \
REST_TLS_TLCP_SIGN_CERT_PATH=./certs/server-sign.crt \
REST_TLS_TLCP_ENC_CERT_PATH=./certs/server-enc.crt \
REST_TLS_TLCP_SIGN_KEY_PATH=./certs/server-sign.key.pem \
REST_TLS_TLCP_ENC_KEY_PATH=./certs/server-enc.key.pem \
cargo run --release -p kms -- --server
```

Tutorials:
- [docs/guides/deployment-guide.md](./docs/guides/deployment-guide.md) — general deployment
- [docs/guides/tlcp-deployment.md](./docs/guides/tlcp-deployment.md) — TLCP mode deployment
- [LEARN.md](./LEARN.md) — code walk-through (recommended starting point)
- [examples/](./examples/) — runnable examples

## Project layout

```
gm-kms/
├── crates/                    # core crates
│   ├── kms-core/              # core types and algorithm abstractions
│   ├── kms-keystore/          # key-storage backends
│   ├── kms-api/               # REST/gRPC API
│   ├── kms-policy/            # PBAC policy engine
│   ├── kms-audit/             # audit log
│   ├── kms-cli/               # command-line tool
│   ├── kms-hsm/               # TPM 2.0 HSM emulation (stub)
│   ├── kms-mfa/               # MFA / TOTP
│   ├── kms-approval/          # approval workflow
├── src/                       # binary entry points
│   ├── main.rs
│   └── cmd/
│       ├── server.rs          # REST + gRPC server
│       ├── config.rs          # configuration loader
│       ├── gm_listener.rs     # TLS 1.3 + SM axum listener
│       └── tlcp_listener.rs   # TLCP axum listener (added in this project)
├── examples/                  # runnable examples (incl. k8s-demo)
├── docs/                      # documentation
│   ├── guides/                # deployment guides
│   ├── requirements/          # functional-requirements docs
│   └── wiki/                  # terminology and technical entries
├── operators/                 # K8s Operator (Go, experimental)
├── providers/terraform/       # Terraform provider (experimental)
└── fuzz/                      # fuzz targets
```

## Compliance self-assessment

| Standard | Self-assessment |
|---|---|
| GM/T 0002-2012 (SM4) | Implemented (kms-core) |
| GM/T 0004-2012 (SM3) | Implemented (gm-crypto) |
| GM/T 0003-2012 (SM2) | Implemented (gm-crypto) |
| GM/T 0044-2016 (SM9) | Implemented (dual-backend cross-validated) |
| GB/T 38636-2020 (TLCP) | REST implemented; gRPC uses TLS 1.3+SM; cert chain verification NOT integrated (known limitation) |
| MLPS 2.0 Level 3 (等保 2.0 三级) | Partial capabilities; **NOT certified by third-party cryptographic evaluation** |

> **Note**: The table above is the maintainer team's self-assessment based on the code. **It does NOT equal** passing national cryptographic authority evaluation (密评) or MLPS certification. Any compliance delivery requires third-party assessment.

## Known limitations (inherent to this project)

| Limitation | Impact | Mitigation |
|---|---|---|
| gRPC over TLCP not implemented | gRPC uses TLS 1.3 + SM, not TLCP protocol | TLCP REST available; gRPC planned for future version |
| TLCP cert chain verification not integrated | TLCP handshake does not verify peer CA chain | Only trust peer bytes; waiting for upstream gm-tlcp `TlcpCertPair` to wire `cert_verify` |
| SM9 master key in memory by default | Process crash or memory dump could leak | Production should use HSM/TPM (kms-hsm currently a stub) |
| No bug bounty | No incentive for vulnerability disclosure | GitHub Security Advisory reporting still available |
| No commercial support / SLA | No upstream response-time commitment | See "Suitable / Not-suitable scenarios" above |

## Test counts (verified, as of v0.3.0)

| Crate | Test count | Status |
|-------|-----------|--------|
| kms-core | 282 | passed |
| kms-api | 267 (+ 5 ignored) | passed |
| kms-policy | 28 | passed |
| kms-audit | 95 | passed |
| kms-hsm | 52 | passed |
| kms-mfa | 46 | passed |
| kms-approval | 16 | passed |
| kms-keystore | 86 (+ 13 ignored) | passed |
| kms-cli | 8 | passed |
| kms binary (incl. tlcp_listener + config TLCP tests) | 37 | passed |
| integration_tests / kat_vectors | 81 | passed |
| **Total** | **998 passed** (plus 25 ignored) | |

## Third-party components

This project depends on the following external / community implementations (full attribution and licensing in [NOTICE](./NOTICE)):

- **SM2 / SM3 / SM4** (`gm-crypto`): built on top of community Rust crates `sm2` / `sm3` / `sm4`, with additional business-layer implementations for SM2 ZA, SM3 HMAC, SM4 GCM-CBC and similar
- **SM9** (`gm-sm9-rs`): Rust port of [GmSSL](https://github.com/guanzhi/GmSSL) (Apache-2.0); provides pure-Rust and GmSSL FFI dual backends
- **TLCP** (`gm-tlcp`): pure-Rust implementation of GB/T 38636-2020
- **gm-tls / gm-ca / gm-crypto / gm-sm9-rs / gm-tlcp**: all from the [gm workspace](https://github.com/GM-Engineers/gm), pinned to a single git revision via crates.io dependencies plus the `[patch.crates-io]` block in the root `Cargo.toml`

## License

MIT OR Apache-2.0
