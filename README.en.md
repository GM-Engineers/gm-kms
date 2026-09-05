# gm-kms

[![GitHub Release](https://img.shields.io/github/v/release/GM-Engineers/gm-kms?include_prereleases)](https://github.com/GM-Engineers/gm-kms/releases)

**[中文版](./README.md)**

National-cryptography (国密 / GM/T) Key Management Service supporting the SM2 / SM3 / SM4 / SM9 algorithm family.

## Features

| Category | Details |
|----------|---------|
| **GM algorithms** | SM2 sign / encrypt / key exchange, SM3 hash, SM4 symmetric encryption, SM9 IBE sign / encrypt |
| **International algorithms** | AES-256-GCM, Ed25519, ECDSA-P256/P384, RSA-4096 |
| **Key management** | Generate, rotate, destroy, import / export |
| **Access control** | PBAC policy engine, MFA (TOTP), approval workflow |
| **Audit log** | WORM storage, hash-chain tamper-evidence, 3-year retention |
| **Backends** | PostgreSQL, Redis, in-memory software keystore |
| **Transport** | REST API (axum, TLS 1.3 + SM ciphers), gRPC (tonic) |

## Tech stack

- **Language**: Rust 1.85+ (Edition 2024)
- **Async runtime**: tokio
- **Web**: axum 0.8, tonic 0.14
- **Database**: PostgreSQL 16+, Redis 7+
- **Crypto**: ring, gm-crypto (SM2/SM3/SM4/SM9)
- **External deps**: gm-tls (TLS 1.3 + SM transport), gm-sm9-rs (SM9 dual-backend), gm-ca (CA certs)

## Prerequisites

- **Rust 1.85+** (Edition 2024)
- **GmSSL 3.1.1** system library (needed for the SM9 dual-backend)
  ```bash
  git clone --depth 1 --branch v3.1.1 https://github.com/guanzhi/GmSSL.git
  cd GmSSL && mkdir build && cd build
  cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON
  make -j$(nproc) && sudo make install && sudo ldconfig
  ```
- **PostgreSQL 16+** and **Redis 7+** (for production deployment)
- If GmSSL is not available, you can use the pure-Rust backend: `--features pure-rust`

## Installation

The `kms` binary of this project is **not published to crates.io** and cannot be installed via `cargo install`. Use one of the following three ways to obtain the executable:

### Option 1: Download prebuilt binaries (recommended, no Rust toolchain needed)

Download the platform binary from [GitHub Releases](https://github.com/GM-Engineers/gm-kms/releases), ready to run:

| Platform | File |
|----------|------|
| Linux x86_64 | `kms-linux-x86_64` |
| Linux ARM64 (aarch64) | `kms-linux-aarch64` |
| macOS Intel (x86_64) | `kms-macos-x86_64` |
| macOS Apple Silicon (aarch64) | `kms-macos-aarch64` |
| Windows x86_64 | `kms-windows-x86_64.exe` |

On Linux / macOS, make it executable after download:

```bash
chmod +x kms-linux-x86_64
./kms-linux-x86_64 --help
```

Each release ships with `SHA256SUMS.txt` for integrity verification:

```bash
sha256sum -c SHA256SUMS.txt
```

> Latest version: `v0.2.1` (recommended upgrade)

### Option 2: Docker image

```bash
docker build -t gm-kms .
docker run -d --name kms --network host gm-kms --server
```

### Option 3: Build from source

Requires Rust 1.85+ and GmSSL (or `--features pure-rust`). See [Prerequisites](#prerequisites) and [Quick start](#quick-start):

```bash
cargo build --release
# Artifact is at target/release/kms
```

## Quick start

### 1. Start the dependency services

```bash
docker compose up -d
# Starts PostgreSQL and Redis (does NOT start kms itself)
```

### 2. Set environment variables

```bash
# Copy the env-var template
cp -n .env.example .env || true
# Test keys are baked in; replace for production deployment
export DATABASE_URL="postgres://kms:kms123@localhost:5432/kms"
export KMS_KEK="<your-kek-hex-64>"
```

### 3. Build and test

```bash
# Build
cargo build --release

# Run all tests
cargo test --workspace

# Run a specific crate's tests
cargo test -p kms-core
cargo test -p kms-api

# Full CI check (format → clippy → build → test)
make check
```

### 4. Start the service

```bash
# Option A: run directly
cargo run --release -p kms -- --server

# Option B: Docker container (with GmSSL)
docker build -t gm-kms .
docker run -d --name kms --network host \
  -e DATABASE_URL="postgres://kms:kms123@localhost:5432/kms" \
  -e KMS_KEK="<your-kek-hex-64>" \
  gm-kms --server
```

### 5. Developer helper commands

```bash
# One-shot CI check (fmt + clippy + build + test)
make check

# Generate SBOM (CycloneDX JSON + XML)
make sbom

# Security scanning (requires local Docker)
make zap-baseline       # OWASP ZAP passive scan
make zap-api-scan       # ZAP active scan

# Compliance reports
make report-crypto      # Cryptography configuration report
make report-compliance  # DJCP Level-3 self-assessment report
```

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
│   ├── kms-hsm/               # TPM 2.0 HSM emulation
│   ├── kms-mfa/               # MFA / TOTP
│   ├── kms-approval/          # approval workflow
├── operators/                 # Kubernetes Operator
├── docs/                      # documentation
│   ├── guides/                # deployment guides
│   ├── requirements/          # functional-requirements docs
│   └── wiki/                  # terminology and technical entries
├── examples/                  # example code
└── providers/terraform/       # Terraform provider
├── Makefile                   # developer helper commands
├── docker-compose.yml         # PostgreSQL + Redis dependency services
├── Dockerfile                 # production container image (with GmSSL)
```

## Documentation

- [Deployment guide](docs/guides/deployment-guide.md)
- [Requirements index](docs/requirements/README.md)
- [Terminology wiki](docs/wiki/gmt-index.md)
- [GM/T standard index](docs/wiki/gmt-standards.md)

## Standards compliance

| Standard | Status |
|----------|--------|
| GM/T 0002-2012 (SM4) | ✅ |
| GM/T 0004-2012 (SM3) | ✅ |
| GM/T 0003-2012 (SM2) | ✅ |
| GM/T 0044-2016 (SM9) | ✅ (GmSSL + pure-Rust dual-backend) |
| GB/T 38636-2020 (TLCP) | ⚠️ Reference impl: `gm-tlcp` crate (maintained separately). The gm-kms REST/gRPC entry currently runs TLS 1.3 + SM ciphers (via gm-tls). |
| Multi-Level Protection Scheme 2.0 Level 3 (等保 2.0 三级) | ✅ (partial) |

> **SM9 backend**: defaults to GmSSL 3.1.1 for the GM/T 0044-2016 standard curve parameters and SM3 hash. A pure-Rust backend is also provided (`pure-rust` feature); the dual backend is cross-validated for correctness.

> **SM9**: the `gm-sm9-rs` crate lives in the [gm workspace](https://github.com/GM-Engineers/gm) (alongside `gm-crypto`, `gm-tls`, `gm-ca`)

## Test counts

| Crate | Test count | Status |
|-------|-----------|--------|
| kms-core | 278 | ✅ |
| kms-policy | 28 | ✅ |
| kms-audit | 95 | ✅ |
| kms-hsm | 52 | ✅ |
| kms-mfa | 45 | ✅ |
| kms-approval | 16 | ✅ |
| kms-keystore | 87 + 6 benchmark | ✅ |
| kms-cli | 8 | ✅ |
| kms-api | 261 | ✅ |
| integration / KAT | 81 | ✅ |
| **Total** | **959 + 6 benchmark** | **all passing** |

> Note: the 6 benchmark tests are ignored by default; run them with `cargo test -- --ignored`

## Third-party components

This project depends on the following external / community implementations (full attribution and licensing in [NOTICE](./NOTICE)):

- **SM2 / SM3 / SM4** (`gm-crypto`): built on top of the community Rust crates `sm2` / `sm3` / `sm4`, with additional business-layer implementations for SM2 ZA, SM3 HMAC, SM4 GCM-CBC and similar. See the [gm workspace repo](https://github.com/GM-Engineers/gm) for the exact scope.
- **SM9** (`gm-sm9-rs`): Rust port of [GmSSL](https://github.com/guanzhi/GmSSL) (Apache-2.0); provides pure-Rust and GmSSL FFI dual backends.
- **gm-tls / gm-ca / gm-crypto / gm-sm9-rs**: all from the [gm workspace](https://github.com/GM-Engineers/gm); pinned to a single git revision via crates.io dependencies plus the `[patch.crates-io]` block in the root `Cargo.toml`.

## License

MIT OR Apache-2.0
