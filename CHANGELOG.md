# Changelog

All notable changes to the BoundaryX project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0-RC1] - 2026-10-16

### Hardening & Pre-Release Verification Pass
- **Engine-Level Scope Enforcement**: Added `HardenedHttpClient` with pre-flight scope verification and hop-by-hop redirect chain validation. URLs with userinfo/credentials (`@`) are strictly rejected.
- **Deep Scope Security Verification**: Added `test_scope_security_deep.py` testing IDNA punycode homographs, suffix/prefix spoofing, and CIDR/IP boundaries (all 43 engine tests passing).
- **Gemini Analyst Security Guardrails**: Upgraded to official `google-genai` SDK with mandatory human consent, context redaction preview, prompt injection delimiter fences, and citation validation against hallucinated evidence IDs.
- **Desktop Shell & Build Hardening**: Fixed strict TypeScript issues across all 10 workbench views; committed deterministic `package-lock.json`; verified production Vite bundling.
- **Clean Container Verification**: Tested and passed in an isolated `ubuntu:24.04` container with fresh Git clone.
- **Supply Chain & Release Automation**: Pinned GitHub Actions workflows, generated CycloneDX SBOM (`docs/SBOM.json`), and created automated packaging scripts.

---

## [0.1.0] - 2026-10-15

### Initial Production Release

BoundaryX 0.1.0 marks the initial release of the Desktop Application Security Testing & Authorization Analysis Tool. This release establishes an evidence-first, security-hardened desktop platform designed to discover, test, analyze, and document authorization boundaries, Broken Object Level Authorization (BOLA/IDOR), multi-tenant isolation breaches, and Broken Function Level Authorization (BFLA) vulnerabilities in modern distributed applications and APIs.

---

### Detailed Feature Breakdown Across All 14 Core Modules

#### 1. Scope & Boundary Enforcement (`boundaryx.security.scope`)
- **Strict Hostname & Scheme Normalization**: Implemented `normalize_hostname` with trailing dot removal, IPv6 bracket stripping, canonical IP normalization, and IDN/punycode encoding (ACE) to prevent DNS homograph confusion.
- **No Substring Matching**: Scope matching enforces strict equality or explicit subdomain wildcard matching (`*.example.com`).
- **Path Prefix and Exclusion Rules**: Hierarchical URL path validation with normalized dot segments (`..`, `.`) and trailing slash preservation.
- **Redirection Boundary Guard**: Implemented `validate_redirect` to independently evaluate each `Location` header target against active scope rules before permitting subsequent hops.
- **Embedded Credential Rejection**: Prohibits URLs containing `user:pass@host` format to prevent credential leakage and spoofing.
- **Batch Evaluation & Scope Preview**: Added `validate_all_urls` and `preview_scope` for real-time validation feedback.

#### 2. Identity & Role Modeling (`boundaryx.domain.identities`)
- **Comprehensive Subject Representation**: Modeled users, API service accounts, and external entities with `Identity` domain model.
- **Standardized Role Classifications**: Built-in `RoleType` enum including `ANONYMOUS`, `AUTHENTICATED`, `READ_ONLY`, `EDITOR`, `ADMIN`, `TENANT_MEMBER`, `TENANT_OWNER`, and `CUSTOM`.
- **Authentication Profile Decoupling**: Credentials and tokens are cleanly decoupled from identity entities and resolved through the encrypted security layer.
- **Authentication Methods**: Support for `COOKIE`, `BEARER_TOKEN`, `CUSTOM_HEADER`, `BASIC_AUTH`, and `IMPORTED` authentication mechanisms.
- **Operational Status Tracking**: Added `IdentityStatus` (`ACTIVE`, `INACTIVE`, `ARCHIVED`) and customizable analyst tags.

#### 3. Tenant Partitioning & Boundary Isolation (`boundaryx.domain.resources.tenant`)
- **Multi-Tenant Boundary Entity**: Modeled `Tenant` with unique tenant keys, regional tags, tier configurations, and owning identity associations.
- **Tenant Memberships**: `TenantMembership` association entity supporting scoped identity roles per tenant partition.
- **Cross-Tenant Invariants**: Architectural abstractions to verify that subject requests never cross tenant boundary partitions unless explicitly permitted by multi-tenant sharing rules.

#### 4. Resource Catalog & Endpoint Association (`boundaryx.domain.resources`)
- **Granular Resource Modeling**: Modeled `Resource` entities representing sensitive API objects (documents, user profiles, invoices, purchase orders, administrative configurations).
- **Resource Categorization**: Built-in `ResourceType` classifications (`DOCUMENT`, `ORDER`, `INVOICE`, `API_RESOURCE`, `USER_PROFILE`, `ORGANIZATION`, `CUSTOM`).
- **Endpoint Pattern Mapping**: Associate resources with API route patterns (e.g. `/api/v1/orders/{id}`) and HTTP method restrictions.
- **Sensitivity Tiers**: Configurable `SensitivityLevel` (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`) to prioritize testing targets.
- **Hierarchical Resources**: Support for parent-child resource relationships to model folder hierarchies and compound objects.

#### 5. Deterministic Policy Engine & Conflict Detection (`boundaryx.domain.policies`)
- **Deterministic Policy Evaluation**: `PolicyEngine` matching subject selectors, resource selectors, action verbs (`READ`, `WRITE`, `DELETE`, `EXECUTE`, `ADMIN`), and route patterns.
- **Selector Specificity Scoring**: Automatic precedence resolution based on specificity score (identity ID > tenant ID > role type; resource ID > tenant ID > resource type > route pattern).
- **Conflict & Contradiction Detection**: Analyzes policy matrices to detect overlapping rules that produce opposing decisions (`ALLOW` vs `DENY`).
- **Policy Invariant Coverage Analysis**: Calculates test coverage percentages across defined identities, resources, and actions.
- **Confidence Provenance**: Trace policy definitions back to documentation, passive observation, analyst assumptions, or explicit user rules.

#### 6. Traffic Ingestion & Normalization (`boundaryx.infrastructure.imports`)
- **HAR 1.2 Importer (`HarImporter`)**: Full parsing of HTTP Archive (HAR 1.2) files from Burp Suite, OWASP ZAP, Chrome DevTools, and mitmproxy. Safe streaming and size bounds (100MB file limit, 5MB body limit).
- **Raw HTTP Importer (`RawHttpImporter`)**: Ingestion of raw RFC 7230 request and response text blocks.
- **Native BoundaryX Exchange Format (`BoundaryXImporter`)**: JSON schema-validated traffic exchange format for reproducible test fixtures.
- **Traffic Record Normalization**: Structured normalization into `TrafficRecordModel` extracting method, URL components, request/response headers, status codes, elapsed timing, and content types.

#### 7. Authorization Test Lab (`boundaryx.application.testing`)
- **Tri-Mode Test Execution (`ExecutionMode`)**:
  - `OFFLINE`: Replay and evaluate authorization invariants purely against imported traffic and cached evidence without sending network packets.
  - `PREVIEW`: Dry-run simulation detailing parameter resolution, injected headers, and expected decisions without dispatching live traffic.
  - `ACTIVE`: Controlled active network execution against live endpoints within authorized scope boundaries.
- **Template Parameter Substitution**: Dynamic path, header, and query parameter substitution (e.g. `{resource_id}`, `{tenant_id}`).
- **Analytical Verdict Classification**: Granular `TestOutcome` categorizing results into `EXPECTED_ALLOW`, `EXPECTED_DENIAL`, `UNEXPECTED_ALLOW` (vulnerability defect), `UNEXPECTED_DENIAL`, and `INSUFFICIENT_EVIDENCE`.
- **Cancellation & Safety Hooks**: Real-time test abort support via worker thread flags.

#### 8. Interactive Authorization & Trust Graph (`boundaryx.domain.relationships`)
- **Graph Relationship Modeling**: Directional edges (`OWNS`, `MEMBER_OF`, `HAS_ACCESS`, `DENIED_ACCESS`, `MANAGES`, `PARENT_OF`, `VIOLATES`) linking identities, tenants, resources, and policies.
- **NetworkX Graph Engine**: Construction of multi-directed graphs for cycle detection, unreachable resource analysis, and shortest-path privilege escalation analysis.
- **Relationship Confidence**: Edge verification tiers (`CONFIRMED`, `USER_DEFINED`, `INFERRED`, `SUSPECTED_VIOLATION`).

#### 9. Finding Lifecycle & Confidence Explanation System (`boundaryx.domain.findings`)
- **Granular Defect Classification**: `FindingCategory` covering `CROSS_TENANT_ACCESS`, `CROSS_USER_ACCESS`, `IDOR`, `PRIVILEGE_ESCALATION`, `MISSING_AUTHORIZATION`, and `BROKEN_BOUNDARY`.
- **Confidence Explanation Model**: `ConfidenceExplanation` justifying findings with observed factors (e.g., HTTP 200 with sensitive payload), reproducibility checks, and explicit policy contradiction flags.
- **Severity Ratings**: Standardized severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`).
- **Operational Triage States**: Full lifecycle tracking (`NEW`, `NEEDS_REVIEW`, `CONFIRMED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`, `FIXED`, `REOPENED`).
- **Reproduction Steps & Remediation**: Detailed step-by-step reproduction instructions and code remediation advice for developers.

#### 10. Cryptographic Evidence Vault (`boundaryx.domain.evidence`)
- **Immutable Evidence Records**: Cryptographic proof capturing complete outbound HTTP requests, inbound HTTP responses, policy evaluation snapshots, and identity/tenant contexts.
- **Deterministic SHA-256 Digest**: Canonical JSON serialization and SHA-256 hashing (`compute_content_hash`) to ensure tamper evidence.
- **Chain of Custody**: Cryptographic verification ensures assessment findings can be audited by third-party compliance teams.
- **Export Packaging**: Standalone JSON evidence files and bundled ZIP packages with integrity manifests.

#### 11. Multi-Format Assessment Reporting (`boundaryx.infrastructure.exports`)
- **14-Section Assessment Report**: Full-length security audit report conforming to international penetration testing standards.
  1. Executive Summary & Risk Posture
  2. Scope & Target Boundaries
  3. Identity & Role Architecture
  4. Resource & Tenant Inventory
  5. Access Control Policy Mapping
  6. Findings Summary & Severity Metrics
  7. Detailed Vulnerability Findings
  8. Broken Object Level Authorization (BOLA/IDOR) Analysis
  9. Broken Function Level Authorization (BFLA) Analysis
  10. Tenant & Boundary Isolation Evaluation
  11. Automated Test Execution Details
  12. Compliance & Standards Alignment (OWASP API Security Top 10)
  13. Remediation Roadmap & Priority Actions
  14. Evidence Verification & Technical Appendix
- **Export Formats**:
  - `HTML`: Self-contained, responsive offline HTML document with embedded CSS themes.
  - `Markdown`: Clean GitHub-flavored Markdown for technical repositories and wiki documentation.
  - `JSON`: Machine-readable structured report for CI/CD ingestion and vulnerability management tools.
  - `CSV`: Tabular findings export for spreadsheet tracking.
- **Path Traversal Protection**: Hardened path sanitization (`_sanitize_path`) preventing directory traversal attacks.

#### 12. Secret Management & Authenticated Symmetric Encryption (`boundaryx.security.secrets`)
- **Fernet Authenticated Encryption**: AES-128 in CBC mode with HMAC-SHA256 authenticated encryption for all stored credentials and API tokens.
- **Secure File Storage**: Enforces strict POSIX directory (`0o700`) and file (`0o600`) permissions where supported.
- **Key Rotation**: In-place key rotation re-encrypting all secrets under a newly generated cryptographic key.
- **Zero Logging Guarantee**: Secret manager guarantees that plaintext secret values are never logged or exposed in stack traces.

#### 13. Automated Secret Redaction & Token Masking Engine (`boundaryx.security.redaction`)
- **Multi-Vector Redaction**: Sanitizes sensitive data across HTTP headers, query parameters, URL path strings, JSON payloads, and form data.
- **Predefined Security Rules**: Automatic masking for `Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `api_key`, `token`, `password`, `secret`, and session identifiers.
- **Custom Rule Engine**: Support for user-defined regex rules and field-name replacement patterns.
- **Best-Effort Safety**: Applied automatically during evidence creation, audit logging, and report exporting.

#### 14. Tamper-Evident Audit Logging & Diagnostic Bundling (`boundaryx.security.audit` & `boundaryx.infrastructure.logging`)
- **Structured Audit Trail**: Records security-relevant events (`PROJECT_CREATED`, `SCOPE_CHANGED`, `IDENTITY_MODIFIED`, `TEST_STARTED`, `FINDING_STATUS_CHANGED`, `REPORT_EXPORTED`) in SQLite.
- **Audit Detail Scrubbing**: Automatically sanitizes audit event details through `RedactionEngine`.
- **SecretFilter Log Sanitizer**: Custom logging filter stripping Bearer tokens, Basic credentials, JWT patterns, and session cookies from all log records.
- **Diagnostic Bundle Exporter**: One-click generation of sanitized ZIP diagnostic bundles containing system specs, recent logs, database schema status, and anonymized configurations.

---

### Packaging & Runtime Enhancements
- **Portable Mode**: Zero-install standalone operation with local database and log resolution next to the executable.
- **PyInstaller Bundles**: Complete Windows executable (`BoundaryX.exe`) and Linux binary distributions.
- **High-DPI Support**: High-DPI screen scaling for PySide6 desktop UI.
- **SQLite Optimization**: Enabled WAL journal mode, strict foreign key enforcement, and synchronous normal settings for concurrent reliability.
