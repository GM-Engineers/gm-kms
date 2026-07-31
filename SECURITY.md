# Security Policy — gm-kms

## Reporting Security Issues

We take security vulnerabilities in **gm-kms** seriously and appreciate
responsible disclosure of your findings.

### Disclosure Process

1. **Do not open a public issue.** Security vulnerabilities must not be
   discussed in public GitHub issues.

2. **Report via GitHub Security Advisory.** Use the
   [Private vulnerability reporting](https://github.com/GM-Engineers/gm-kms/security/advisories/new)
   feature. This ensures encrypted communication with maintainers.

3. **Provide details.** Include:
   - Description of the vulnerability and its impact
   - Steps to reproduce (proof-of-concept code if available)
   - Affected versions / components
   - Any suggested fixes

### What to Expect

| Phase | Timeline |
|-------|----------|
| Acknowledgment | Within 3 business days |
| Initial assessment | Within 5 business days |
| Patch release for critical issues | Within 14 days |
| Patch release for high-severity issues | Within 30 days |
| Public disclosure (CVE) | Coordinated with reporter, typically after patch release |

### Scope

The following are in scope for our security program:

- **kms-core**: Key management core, envelope encryption, key import/export,
  SM9 key rotation, secret zeroization
- **kms-api**: REST and gRPC API surface, authentication, tenant isolation,
  audit logging
- **kms-keystore**: Backend key storage (in-memory, PostgreSQL, Redis, TPM, HSM)
- **kms-approval**: Approval workflow for sensitive operations (key export, etc.)
- **kms-audit**: Audit logging and query
- **kms-hsm**: HSM / TPM integration
- **kms-mfa**: Multi-factor authentication (TOTP)
- **kms-policy**: Policy engine (rate limiting, access control)
- **kms-cli**: Command-line client (`kmsclient`)

### Out of Scope

- Issues requiring physical access to the running process
- Denial of service caused by unbounded resource allocation in non-default
  configurations
- Issues in dependencies that are not exploitable through our API
- Theoretical attacks that are not practically exploitable

### Recognition

We will acknowledge reporters in the advisory and release notes (unless you
prefer to remain anonymous). We do not currently offer a bug bounty program.

### Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

Only the latest release receives security patches.
