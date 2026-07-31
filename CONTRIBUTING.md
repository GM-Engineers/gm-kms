# Contributing to gm-kms

Thank you for your interest in contributing to **gm-kms** — a key management
service (KMS) built on the [`gm`](https://github.com/GM-Engineers/gm) workspace
(SM2 / SM3 / SM4 / SM9 cryptography, TLS 1.3 with TLCP).

This document is the bilingual (中文 / English) contribution guide.

## Code of Conduct / 行为准则

This project adheres to the [Contributor Covenant](CODE_OF_CONDUCT.md).
By participating, you agree to uphold it.

## Getting started / 环境准备

- **Rust toolchain 1.85+** (Edition 2024). Install via [rustup](https://rustup.rs).
- `gm-kms` depends on `gm` via **versioned crates.io dependencies** — no local
  `../gm` path is required. Build:

  ```bash
  cargo build --workspace
  cargo test  --workspace
  ```

- KMS self-tests (KAT-style) live under `crates/kms-core/src/self_test.rs`.

## Workspace layout / 工作区结构

| Crate | Purpose |
|-------|---------|
| `kms-core` | Core key store, sealing, self-tests |
| `kms-api` | REST API surface |
| `kms-keystore` | Backend key storage |
| `kms-approval` | Approval workflow |
| `kms-audit` | Audit logging |
| `kms-hsm` | HSM / TPM backends (feature-gated) |
| `kms-mfa` | Multi-factor authentication |
| `kms-policy` | Access policy engine |
| `kms-cli` | Command-line client |

## Development workflow / 开发规范

- Format: `cargo fmt --all`
- Lint: `cargo clippy --workspace --all-targets`
- Supply chain: `cargo deny check` (see `deny.toml`)
- HSM/TPM backends are feature-gated; build with e.g.
  `cargo build --features kms-hsm/tpm2-tss` when hardware is available.

## Commit & PR guidelines / 提交规范

- Keep PRs focused; explain the motivation and include test evidence.
- Sign your commits (DCO): `git commit -s`.
- CI must be green (`cargo test`, `clippy`, `cargo deny check`, `cargo fmt`).

## License / 许可证

By contributing, you agree your contributions are licensed under **MIT OR Apache-2.0**,
consistent with the project. Do not introduce code under GPL / LGPL / AGPL.

## Security / 安全

Do **not** open public issues for vulnerabilities. Follow
[SECURITY.md](SECURITY.md) and report privately.

## Questions / 疑问

Open an issue or discussion on `GM-Engineers/gm-kms`.
