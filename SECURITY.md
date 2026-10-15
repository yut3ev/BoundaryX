# Security Policy

BoundaryX is an authorization analysis and security testing tool designed to help security engineers, penetration testers, and application developers systematically evaluate authorization boundaries, detect Broken Object Level Authorization (BOLA/IDOR), verify tenant isolation, and ensure Broken Function Level Authorization (BFLA) defenses are robust.

Because BoundaryX interacts directly with target HTTP APIs and handles sensitive test credentials, the security and integrity of the tool itself are of paramount importance.

---

## Supported Versions

Only the latest release branch of BoundaryX receives active security patches.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Reporting a Vulnerability

We take all security vulnerability reports seriously. If you discover a vulnerability within BoundaryX (including potential bypasses of the Scope boundary engine, insecure secret handling, credential exposure in logs, or path traversal during report exports), please disclose it responsibly.

### How to Report
- **Email**: Send vulnerability reports directly to `security@boundaryx.local` (or file a confidential security advisory through GitHub Security Advisories).
- **Subject Line**: `[SECURITY VULNERABILITY] BoundaryX - <Brief Description>`
- **PGP Encryption**: If sending sensitive proof-of-concept material, request our public PGP key before sending plaintext exploit steps.

### Information to Include
To help us triage and resolve the issue quickly, please provide:
1. **Description**: Clear description of the vulnerability and its potential security impact.
2. **Component Affected**: Specific module (e.g., `boundaryx.security.scope`, `boundaryx.infrastructure.http`, `boundaryx.security.redaction`).
3. **Environment**: Operating System (Windows/Linux), Python version, BoundaryX version.
4. **Reproduction Steps**: Step-by-step instructions or minimal reproduction script.
5. **Mitigation Suggestion**: Any recommended patch or workaround, if available.

### Response Timelines
- **Initial Acknowledgement**: Within 24-48 business hours.
- **Triage and Assessment**: Within 5 business days.
- **Remediation Release**: Aimed within 14-30 business days depending on severity.
- **Public Disclosure**: Coordinated after a fixed release is published.

---

## Safe Testing & Boundary Protection Principles

BoundaryX operates under strict **security-first guardrails** to prevent accidental disruption or testing against unintended targets. Users are required to adhere to the following operational standards:

### 1. Authorized Scope Enforcement
- **Strict Hostname Verification**: BoundaryX evaluates target URLs against user-configured scope rules using canonical hostname comparison and punycode normalization. Substring matching is strictly prohibited to prevent subdomain takeover or homograph confusion.
- **No Automatic Blind Redirects**: BoundaryX explicitly disables unverified HTTP redirect following. Every HTTP redirection (`301`, `302`, `307`, `308`) causes the client to halt and evaluate the target `Location` header against authorized scope rules before dispatching the subsequent hop.
- **Explicit Exclusions**: Critical administrative endpoints, debug consoles, or infrastructure services (such as cloud metadata endpoints `169.254.169.254`) should be configured as explicit exclusion rules.

### 2. Least-Privilege & Staging Environment Guidance
- **Non-Destructive Testing**: By default, BoundaryX encourages the use of **Offline** or **Preview** modes to inspect request structures and policy models before issuing live network requests in **Active** mode.
- **Dedicated Test Tenants**: When evaluating cross-tenant authorization (BOLA/IDOR), always provision dedicated, isolated test tenant partitions with synthetic data. Never run automated destructive mutations (`DELETE`, state modifications) against production or shared customer tenants.
- **Disposable Test Credentials**: Utilize dedicated test API keys or tokens with limited lifespans. Never use production root administrator credentials.

### 3. Credential Scrubbing & Vault Storage
- **Decoupled Secrets**: Authentication secrets (passwords, bearer tokens, API keys) are managed exclusively by the `SecretManager` via authenticated symmetric encryption (Fernet) and are never persisted in plaintext project export files unless explicitly requested.
- **Automated Redaction Engine**: Outbound and inbound HTTP snapshots captured in the Evidence Vault are automatically sanitized through `RedactionEngine` to scrub sensitive authorization headers (`Authorization`, `Cookie`, `X-API-Key`) and sensitive payload fields before being exported or rendered.
- **Sanitized Logging**: All application logs pass through a `SecretFilter` handler that strips Bearer tokens, Basic auth hashes, JWT strings, and session IDs before writing to log files or standard output.

### 4. Cryptographic Integrity of Evidence
- **Immutable SHA-256 Hashes**: Every evidence item recorded in the Evidence Vault is hashed using deterministic canonical JSON serialization and SHA-256. This prevents post-test evidence tampering and provides chain-of-custody verification for compliance audits.
