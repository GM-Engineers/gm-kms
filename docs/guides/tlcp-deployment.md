# TLCP Mode Deployment Guide / TLCP 模式部署指南

> Document version: 1.0.0 | 文档版本: 1.0.0
> Last updated: 2026-09-12

---

## Language Switch / 语言切换

**[English](#overview) | [中文](#概述)**

---

<!-- English Section -->

## Overview

This guide covers running the gm-kms REST API over **TLCP** (Transport Layer Cryptographic Protocol, GB/T 38636-2020) instead of the default TLS 1.3 + SM mode.

**TLCP differs from TLS 1.3 + SM in three operationally important ways:**

| Aspect | TLS 1.3 + SM (gm-tls) | TLCP (gm-tlcp) |
|---|---|---|
| Protocol version byte | `0x03, 0x03` | `0x01, 0x01` |
| Certificate system | Single cert | **Dual certs** (sign + enc) |
| ALPN | Supported | Not supported |
| gRPC compatible | Yes | **No** (gRPC stays on TLS 1.3 + SM) |

## Prerequisites

In addition to the [generic deployment prerequisites](./deployment-guide.md#software-requirements):

- **Two SM2 certificates** (one for signing, one for encryption), DER-encoded
- **Two SM2 private keys**, PEM-encoded (one per cert)
- The signing cert must be valid for SM2 ECDSA (OID `1.2.156.10197.1.501`)
- The encryption cert must be valid for SM2 encryption (for ECC suites)

## Generating test dual certificates

For learning / demo purposes, you can generate self-signed dual certs with [`gm-ca`](https://github.com/GM-Engineers/gm) or the example provided with gm-tlcp. For real deployments use a CA-issued pair.

```bash
# 1. Generate two SM2 keypairs
openssl ecparam -name SM2 -genkey -noout -out server-sign.key.pem
openssl ecparam -name SM2 -genkey -noout -out server-enc.key.pem

# 2. Generate self-signed certs
openssl req -new -x509 -key server-sign.key.pem -out server-sign.crt \
    -days 365 -subj "/CN=tls-server-sign"
openssl req -new -x509 -key server-enc.key.pem -out server-enc.crt \
    -days 365 -subj "/CN=tls-server-enc"

# Note: openssl SM2 CSR/cert generation may require a recent openssl (>= 3.2).
# For a more reliable path use `gm-ca` or Tongsuo.
```

> **Note**: Production deployments should use a CA to sign these certs, not
> self-signed. The TLCP protocol allows the handshake to complete either way;
> gm-kms does NOT verify the CA chain (see [Known Limitations](#known-limitations)).

## Configuration

### Via `kms.toml`

```toml
[rest_tls]
enabled = true
backend = "tlcp"                       # select TLCP mode

# cert_path / key_path are unused for backend = "tlcp" (gm-tls single-cert)
cert_path = "/path/to/unused.crt"
key_path  = "/path/to/unused.key"

# TLCP dual-cert paths
tlcp_sign_cert_path = "/etc/kms/tlcerts/server-sign.crt"        # DER
tlcp_enc_cert_path  = "/etc/kms/tlcerts/server-enc.crt"         # DER
tlcp_sign_key_path  = "/etc/kms/tlcerts/server-sign.key.pem"    # PEM
tlcp_enc_key_path   = "/etc/kms/tlcerts/server-enc.key.pem"     # PEM

require_client_auth = false
```

### Via environment variables

```bash
export REST_TLS_BACKEND=tlcp
export REST_TLS_TLCP_SIGN_CERT_PATH=/etc/kms/tlcerts/server-sign.crt
export REST_TLS_TLCP_ENC_CERT_PATH=/etc/kms/tlcerts/server-enc.crt
export REST_TLS_TLCP_SIGN_KEY_PATH=/etc/kms/tlcerts/server-sign.key.pem
export REST_TLS_TLCP_ENC_KEY_PATH=/etc/kms/tlcerts/server-enc.key.pem
```

Environment variables override file values.

## Starting the server

```bash
cargo run --release -p kms -- --server
# Look for this log line:
#   INFO REST API listening on tlcp://0.0.0.0:8080
```

## Verifying the handshake

Use the gm-tlcp example client (in the gm workspace) to verify the handshake:

```bash
cd ../gm/gm-tlcp
# 1. Build gm-tlcp simple_server with the same dual certs
cargo run --example simple_server
#   (configure to load /etc/kms/tlcerts/server-{sign,enc}.{crt,key.pem})

# 2. Run against gm-kms (override bind address):
cargo run --example simple_client -- 127.0.0.1 8080
```

Or write a custom TLCP client:

```rust
use gm_tlcp::TlcpConnector;

let tcp = tokio::net::TcpStream::connect("127.0.0.1:8080").await?;
let mut tls = TlcpConnector::new().connect_with_certs(tcp).await?;
tls.write_application_data(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n").await?;
let response = tls.read_application_data().await?;
println!("{}", String::from_utf8_lossy(&response));
```

## Known limitations

These are inherent to gm-kms 0.3.0 and will not change without upstream coordination:

- **gRPC remains on TLS 1.3 + SM**, not TLCP. TLCP has no ALPN, so gRPC's HTTP/2
  negotiation cannot complete over TLCP without protocol extensions (out of scope).
  Workaround: expose TLCP for REST clients and keep gRPC on TLS 1.3 + SM, OR
  put gRPC on a separate port and force-h2 server-side (not yet implemented).
- **Certificate chain verification not integrated** (see
  [`gm-tlcp/issues/4.3`](../../discuss/00-tlcp-implementation-status.md#43-cert-chain-verification-not-integrated)).
  The handshake completes even with untrusted CAs. Wait for upstream
  `TlcpCertPair` to wire `cert_verify`.
- **No mutual auth (mTLS) on TLCP yet**. The `require_client_auth` setting
  applies to TLS 1.3 + SM only. TLCP server-side client cert processing
  requires upstream support.

---

<!-- Chinese Section -->

## 概述

本指南介绍如何让 gm-kms REST API 运行在 **TLCP**（传输层密码协议，GB/T 38636-2020）模式，而不是默认的 TLS 1.3 + SM 模式。

**TLCP 与 TLS 1.3 + SM 在三个运营层面有重要差异：**

| 维度 | TLS 1.3 + SM（gm-tls） | TLCP（gm-tlcp） |
|---|---|---|
| 协议版本字节 | `0x03, 0x03` | `0x01, 0x01` |
| 证书系统 | 单证书 | **双证书**（sign + enc） |
| ALPN | 支持 | 不支持 |
| gRPC 兼容 | 是 | **否**（gRPC 保持 TLS 1.3 + SM） |

## 前置条件

除[通用部署前置条件](./deployment-guide.md#software-requirements)外，还需：

- 两份 SM2 证书（一签一加），DER 编码
- 两份 SM2 私钥，PEM 编码（一证一密）
- 签名证书必须支持 SM2 ECDSA（OID `1.2.156.10197.1.501`）
- 加密证书必须支持 SM2 加密（用于 ECC 套件）

## 生成测试双证书

学习 / 演示用途，可用 [`gm-ca`](https://github.com/GM-Engineers/gm) 或 gm-tlcp 自带示例生成自签双证书。生产环境请使用 CA 签发的证书对。

```bash
# 1. 生成两个 SM2 密钥对
openssl ecparam -name SM2 -genkey -noout -out server-sign.key.pem
openssl ecparam -name SM2 -genkey -noout -out server-enc.key.pem

# 2. 生成自签证书
openssl req -new -x509 -key server-sign.key.pem -out server-sign.crt \
    -days 365 -subj "/CN=tls-server-sign"
openssl req -new -x509 -key server-enc.key.pem -out server-enc.crt \
    -days 365 -subj "/CN=tls-server-enc"

# 注意：openssl SM2 CSR/证书生成可能需要较新版本（>= 3.2）。
# 更稳妥的路径是使用 `gm-ca` 或 Tongsuo。
```

> **注意**：生产部署应使用 CA 签发，而非自签。TLCP 协议允许任意方式完成握手；
> gm-kms 当前**不验证 CA 链**（见[已知限制](#已知限制)）。

## 配置

### 通过 `kms.toml`

```toml
[rest_tls]
enabled = true
backend = "tlcp"                       # 选择 TLCP 模式

# backend = "tlcp" 时 cert_path / key_path 字段不使用（gm-tls 单证书路径）
cert_path = "/path/to/unused.crt"
key_path  = "/path/to/unused.key"

# TLCP 双证书路径
tlcp_sign_cert_path = "/etc/kms/tlcerts/server-sign.crt"        # DER
tlcp_enc_cert_path  = "/etc/kms/tlcerts/server-enc.crt"         # DER
tlcp_sign_key_path  = "/etc/kms/tlcerts/server-sign.key.pem"    # PEM
tlcp_enc_key_path   = "/etc/kms/tlcerts/server-enc.key.pem"     # PEM

require_client_auth = false
```

### 通过环境变量

```bash
export REST_TLS_BACKEND=tlcp
export REST_TLS_TLCP_SIGN_CERT_PATH=/etc/kms/tlcerts/server-sign.crt
export REST_TLS_TLCP_ENC_CERT_PATH=/etc/kms/tlcerts/server-enc.crt
export REST_TLS_TLCP_SIGN_KEY_PATH=/etc/kms/tlcerts/server-sign.key.pem
export REST_TLS_TLCP_ENC_KEY_PATH=/etc/kms/tlcerts/server-enc.key.pem
```

环境变量会覆盖文件中的值。

## 启动服务

```bash
cargo run --release -p kms -- --server
# 应当看到以下日志行：
#   INFO REST API listening on tlcp://0.0.0.0:8080
```

## 验证握手

使用 gm-tlcp 自带 example client 验证握手：

```bash
cd ../gm/gm-tlcp
# 1. 用相同双证书启动 gm-tlcp simple_server
cargo run --example simple_server
#   （配置加载 /etc/kms/tlcerts/server-{sign,enc}.{crt,key.pem}）

# 2. 客户端测试 gm-kms（修改绑定地址）：
cargo run --example simple_client -- 127.0.0.1 8080
```

或写自定义 TLCP 客户端：

```rust
use gm_tlcp::TlcpConnector;

let tcp = tokio::net::TcpStream::connect("127.0.0.1:8080").await?;
let mut tls = TlcpConnector::new().connect_with_certs(tcp).await?;
tls.write_application_data(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n").await?;
let response = tls.read_application_data().await?;
println!("{}", String::from_utf8_lossy(&response));
```

## 已知限制

以下限制为 gm-kms 0.3.0 固有，需上游协作才能解除：

- **gRPC 保持 TLS 1.3 + SM**，未走 TLCP。TLCP 协议无 ALPN，gRPC 的 HTTP/2
  协商无法在 TLCP 上完成（除非扩展协议，超出本版本范围）。临时方案：REST 走 TLCP，
  gRPC 走 TLS 1.3 + SM；或将 gRPC 放独立端口强制 h2（未实现）。
- **证书链验证未集成**（参见 [`gm-tlcp/issues/4.3`](../../discuss/00-tlcp-implementation-status.md#43-cert链验证未集成)）。
  即使对端 CA 不可信，握手也会完成。等待上游 `TlcpCertPair` 接入 `cert_verify`。
- **TLCP 暂不支持 mTLS**。`require_client_auth` 当前只对 TLS 1.3 + SM 生效。
  TLCP 服务端客户端证书处理需要上游支持。
