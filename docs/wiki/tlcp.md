# TLCP — Transport Layer Cryptographic Protocol / 传输层密码协议

> **中文**：[TLCP（GB/T 38636-2020）](#tlcp-是什么)
>
> Reference: GM/T 0028 / GB/T 38636-2020 / GB/T 39786-2021

---

## English

### What is TLCP?

TLCP (Transport Layer Cryptographic Protocol) is a Chinese national standard
specified in GB/T 38636-2020. It defines a TLS-like transport-layer protocol
that uses the **GM/T** algorithm family (SM2 / SM3 / SM4) instead of the
international algorithms (RSA / ECDSA / AES / SHA-2 / SHA-3).

The protocol was first published in 2018 as a "TLCP technical specification"
and formalized as the national standard GB/T 38636-2020 in 2020. It is required
by several Chinese cybersecurity and compliance frameworks, including:

- **GM/T 0028-2014** — Requirements for cryptographic application interfaces
  in cryptographic modules and devices
- **GB/T 39786-2021** — Technical requirements for cryptographic application of
  information systems in finance (and adjacent domains)

### TLCP vs. TLS 1.3

| Dimension | TLS 1.3 (RFC 8446) | TLCP (GB/T 38636-2020) |
|---|---|---|
| Version byte | `0x03, 0x03` | `0x01, 0x01` |
| Certificate system | Single cert | **Dual certs** (sign + enc) |
| Key exchange | `key_share` extension (TLS 1.3 style) | `ServerKeyExchange` / `ClientKeyExchange` (TLS 1.2 style) |
| Cipher suite IDs | `0x13xx` | `0xE0xx` |
| PRF | HKDF | SM3-iterated (TLS 1.2 style) |
| Session resumption | Session ticket (RFC 5077) | Session ID (TLS 1.2 style) |
| 0-RTT / Early Data | Supported | **Not supported** |
| PSK | Supported | **Not supported** |
| KeyUpdate | Supported | **Not supported** |
| ALPN | Supported | **Not supported** (operationally significant — see below) |
| Regulatory framing | IETF RFC | **GB national standard** |

### Why dual certificates?

TLCP requires **two server-side certificates**:

- A **signing certificate** whose private key is used to sign the
  `ServerKeyExchange` message (analogous to TLS 1.3's `key_share` signature)
- An **encryption certificate** whose holder decrypts the (optional)
  `ClientKeyExchange` PMS in ECC suites

This split lets the two operations be governed by separate CAs / key
infrastructures — useful when an organization wants to keep long-lived signing
keys offline (HSM-only) while using shorter-lived encryption keys more freely.

The 4 TLCP cipher suites are:

| ID | Name |
|----|------|
| `0xE0, 0x01` | `TLS_ECC_SM4_GCM_SM3` |
| `0xE0, 0x03` | `TLS_ECC_SM4_CBC_SM3` |
| `0xE0, 0x11` | `TLS_ECDHE_SM4_GCM_SM3` |
| `0xE0, 0x13` | `TLS_ECDHE_SM4_CBC_SM3` |

### The ALPN gap

TLCP does not include an Application-Layer Protocol Negotiation (ALPN)
mechanism — there is no equivalent of TLS 1.3's `application_layer_protocol`
extension. This has a direct operational consequence:

- **gRPC requires HTTP/2 + ALPN** to negotiate `h2`. gRPC over TLCP is therefore
  **not straightforward**: a TLCP handshake completes, but the underlying
  transport cannot negotiate h2 with the client.
- **HTTP/1.1** (used by most REST APIs) does not require ALPN. REST over TLCP
  works as a plain encrypted stream.

gm-kms 0.3.0 reflects this asymmetry: REST can run over TLCP, gRPC stays on
TLS 1.3 + SM. Extending gRPC to TLCP requires either (a) a TLCP custom
extension carrying ALPN-like metadata (requires upstream `gm-tlcp` change),
or (b) a separate gRPC port that forces `h2` server-side.

### Rust implementation

TLCP is implemented in the [`gm-tlcp`](https://github.com/GM-Engineers/gm) crate
(workspace member). It is a pure-Rust implementation that does not require the
C-based GmSSL library for any operation.

---

## 中文

### TLCP 是什么？

TLCP（Transport Layer Cryptographic Protocol，传输层密码协议）是中国国家标准
GB/T 38636-2020 定义的传输层密码协议。它形似 TLS，但使用**国密 GM/T 算法族**
（SM2 / SM3 / SM4），而不是国际算法（RSA / ECDSA / AES / SHA-2 / SHA-3）。

该协议最早于 2018 年以"TLCP 技术规范"形式发布，2020 年正式成为国家标准
GB/T 38636-2020。在多个中国网络安全和合规框架中被强制要求：

- **GM/T 0028-2014** — 密码模块/设备中密码应用接口要求
- **GB/T 39786-2021** — 信息系统密码应用基本要求（金融及相邻领域）

### TLCP vs. TLS 1.3

| 维度 | TLS 1.3 (RFC 8446) | TLCP (GB/T 38636-2020) |
|---|---|---|
| 版本字节 | `0x03, 0x03` | `0x01, 0x01` |
| 证书系统 | 单证书 | **双证书**（sign + enc） |
| 密钥交换 | `key_share` 扩展（TLS 1.3 风） | `ServerKeyExchange` / `ClientKeyExchange`（TLS 1.2 风） |
| 密码套件 ID | `0x13xx` | `0xE0xx` |
| PRF | HKDF | SM3 迭代式（TLS 1.2 PRF 风） |
| 会话恢复 | Session ticket（RFC 5077） | Session ID（TLS 1.2 风） |
| 0-RTT / Early Data | 支持 | **不支持** |
| PSK | 支持 | **不支持** |
| KeyUpdate | 支持 | **不支持** |
| ALPN | 支持 | **不支持**（运营层面影响重大 — 见下） |
| 监管口径 | IETF RFC | **中国国家标准** |

### 为什么需要双证书？

TLCP 要求**服务端双证书**：

- **签名证书**：私钥用于对 `ServerKeyExchange` 消息签名（类比 TLS 1.3 的
  `key_share` 签名）
- **加密证书**：在 ECC 套件下，持有者解密（可选的）`ClientKeyExchange` 中的 PMS

这种切分让两类操作可由不同 CA / 密钥基础设施分别管理——当组织希望把长期
签名密钥离线（仅 HSM）使用、同时让短期加密密钥更灵活时尤其有用。

4 套 TLCP 密码套件：

| ID | 名称 |
|----|------|
| `0xE0, 0x01` | `TLS_ECC_SM4_GCM_SM3` |
| `0xE0, 0x03` | `TLS_ECC_SM4_CBC_SM3` |
| `0xE0, 0x11` | `TLS_ECDHE_SM4_GCM_SM3` |
| `0xE0, 0x13` | `TLS_ECDHE_SM4_CBC_SM3` |

### ALPN 缺口

TLCP **没有**应用层协议协商（ALPN）机制——没有 TLS 1.3 `application_layer_protocol`
扩展的对应物。这带来一个直接的运营后果：

- **gRPC 需要 HTTP/2 + ALPN** 来协商 `h2`。因此 **gRPC over TLCP 并不简单**：
  TLCP 握手可以完成，但底层传输无法与客户端协商 h2。
- **HTTP/1.1**（多数 REST API 使用）不需要 ALPN。REST over TLCP 作为普通加密流工作。

gm-kms 0.3.0 反映了这种不对称：REST 可走 TLCP，gRPC 保持 TLS 1.3 + SM。
要让 gRPC 也走 TLCP，需要：(a) 在 TLCP 握手中加入类似 ALPN 的自定义扩展
（需要上游 `gm-tlcp` 改动），或 (b) gRPC 走独立端口服务端强制 `h2`。

### Rust 实现

TLCP 在 [`gm-tlcp`](https://github.com/GM-Engineers/gm) crate 中实现（gm workspace
成员）。纯 Rust 实现，不依赖 C 版的 GmSSL 库。

---

## See also

- [`tlcp-deployment.md`](../guides/tlcp-deployment.md) — How to deploy gm-kms with TLCP
- [`../../LEARN.md`](../../LEARN.md) — Code walkthrough including `src/cmd/tlcp_listener.rs`
- [`gm-tlcp/src/lib.rs`](https://github.com/GM-Engineers/gm/blob/main/gm/gm-tlcp/src/lib.rs) — Full TLCP API documentation
