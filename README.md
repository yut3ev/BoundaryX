# BoundaryX

**Desktop Application Security Testing & Authorization Analysis Tool**

BoundaryX is an advanced desktop security testing platform engineered to analyze, test, and prove authorization boundaries in modern web applications, distributed APIs, and multi-tenant architectures. Built specifically for security engineers, penetration testers, and application security teams, BoundaryX eliminates guesswork by providing deterministic policy evaluation, cryptographic evidence verification, and multi-tenant isolation analysis.

---

## Core Philosophy

Traditional dynamic application security testing (DAST) tools focus on injection flaws and generic payloads, frequently failing to identify Broken Object Level Authorization (BOLA/IDOR), Broken Function Level Authorization (BFLA), and cross-tenant data leaks. BoundaryX approaches authorization testing through four foundational principles:

1. **Evidence-First**: Every finding is backed by immutable, cryptographically verifiable HTTP snapshots and evaluation traces. No unsubstantiated alerts.
2. **Map Trust**: Authorization cannot be analyzed in isolation. BoundaryX maps identities, roles, tenant partitions, and protected resources into an interactive multi-directional trust graph.
3. **Verify Access**: Policies and permissions are evaluated deterministically against structured models and observed traffic.
4. **Prove Boundaries**: Systematically test horizontal (cross-tenant), vertical (privilege escalation), and contextual boundary limits across offline replay, dry-run simulation, and controlled active testing.

---

## System Architecture

BoundaryX is engineered in Python 3.12+ following **Clean Layered Architecture** with strict layer separation:

- **Presentation Layer (`boundaryx.ui`)**: Native PySide6 (Qt) desktop user interface with hardware-accelerated rendering, Dark and Light themes, high-DPI scaling, and responsive asynchronous workers.
- **Application Layer (`boundaryx.application`)**: Orchestration services managing project state, scope persistence, test case lifecycles, and report generation.
- **Domain Layer (`boundaryx.domain`)**: Pure business logic containing entity models (Identities, Tenants, Resources), deterministic `PolicyEngine`, trust graph relationship algorithms (NetworkX), and finding triage models.
- **Security Layer (`boundaryx.security`)**: Cross-cutting defensive primitives including strict `ScopeManager`, authenticated secret encryption (`SecretManager` via Fernet), multi-vector `RedactionEngine`, and tamper-evident `AuditLogger`.
- **Infrastructure Layer (`boundaryx.infrastructure`)**: High-performance SQLite database engine with Write-Ahead Logging (WAL) and strict foreign keys via SQLAlchemy 2.x, security-hardened HTTPX network client, multi-format traffic importers (HAR 1.2, Raw HTTP, JSON), and audit report exporters.

---

## Key Capabilities

### 1. Project & Scope Management
- Manage isolated assessment workspaces with automated backups and configuration persistence.
- Enforce strict target boundaries with canonical hostname comparison, IDN punycode normalization, scheme/port matching, path prefix rules, and explicit exclusion lists.
- Prohibits substring matching to eliminate unintended testing against external or third-party domains.

### 2. Identity & Tenant Modeling
- Define granular subjects: Users, administrators, service accounts, and unauthenticated visitors across standardized role classifications (`ADMIN`, `EDITOR`, `TENANT_MEMBER`, `ANONYMOUS`, etc.).
- Model multi-tenant partitions and organization boundaries with scoped role memberships.
- Decouple credentials from identities through encrypted authentication profiles (Bearer JWT, Session Cookies, API Keys, Custom Headers).

### 3. Deterministic Authorization Policy Engine
- Define expected access control invariants linking subject selectors, resource selectors, and action verbs (`READ`, `WRITE`, `DELETE`, `EXECUTE`, `ADMIN`).
- Automated specificity scoring and conflict detection to identify contradictory or overlapping authorization rules.
- Test matrix coverage analysis measuring verified versus unverified authorization paths.

### 4. Traffic Explorer (HAR / Raw / JSON)
- Ingest HTTP Archive (HAR 1.2) files from Burp Suite, OWASP ZAP, mitmproxy, and browser network tools.
- Ingest raw RFC 7230 HTTP request/response text blocks and native BoundaryX JSON fixtures.
- Automated URL normalization, header indexing, body size bounding (100MB file limit, 5MB body limit), and syntax validation.

### 5. Tri-Mode Authorization Test Lab
- **Offline Mode**: Replay and verify authorization invariants purely against imported traffic and cached evidence without sending network packets.
- **Preview Mode**: Dry-run simulation detailing parameter substitutions (`{resource_id}`, `{tenant_id}`), injected auth headers, and expected policy outcomes without touching the network.
- **Controlled Active Mode**: Dispatch live requests with token-bucket rate limiting, concurrency semaphores, cancellation controls, and real-time scope enforcement.

### 6. Interactive Trust & Relationship Graph
- Visualize directional authorization edges (`OWNS`, `MEMBER_OF`, `HAS_ACCESS`, `DENIED_ACCESS`, `VIOLATES`) using NetworkX.
- Identify shortest privilege escalation paths, circular permissions, and isolated resources.

### 7. Findings & Confidence Analysis
- Triage vulnerabilities across recognized categories: `CROSS_TENANT_ACCESS`, `BOLA/IDOR`, `BFLA`, `PRIVILEGE_ESCALATION`, and `MISSING_AUTHORIZATION`.
- Structured confidence explanations highlighting supporting indicators (e.g. HTTP 200 with sensitive payload, cross-tenant leak, deterministic reproducibility).
- Automated step-by-step reproduction instructions and code remediation guidance.

### 8. Evidence Vault with SHA-256 Cryptographic Integrity
- Immutable evidence records capturing outbound requests, inbound responses, policy rule states, and execution timing.
- Deterministic canonical JSON serialization and SHA-256 digest calculation (`compute_content_hash`) to guarantee evidence authenticity and chain-of-custody.
- Export evidence as individual sanitized JSON files or bundled ZIP packages with integrity manifests.

### 9. Multi-Format Assessment Reporting
- Export auditor-ready reports conforming to penetration testing standards in **Markdown (`.md`)**, **Standalone Offline HTML (`.html`)**, **Structured JSON (`.json`)**, and **CSV (`.csv`)**.
- Reports feature all 14 standard sections including Executive Summary, Scope Boundaries, BOLA/BFLA Analysis, Tenant Isolation Matrices, OWASP API Security Top 10 Alignment, and Remediation Roadmaps.

### 10. Security Audit Logging & Secret Scrubbing
- Structured audit trail recording all critical actions (`PROJECT_CREATED`, `SCOPE_CHANGED`, `IDENTITY_MODIFIED`, `TEST_STARTED`, `FINDING_STATUS_CHANGED`).
- Multi-vector redaction engine scrubbing passwords, tokens, API keys, and session cookies from evidence, reports, and logs before persistence.

### 11. Portable Runtime Mode
- Run BoundaryX portably with zero installation (`--portable`).
- Database, logs, exports, and encrypted keys are stored locally next to the executable, enabling clean deployment on forensic jump-boxes and USB media.

---

## Security & Safety Model

BoundaryX is built with a defensive security architecture:

- **SSRF Protection**: Target URLs containing embedded credentials (`user:pass@host`) are rejected immediately. Unverified loopback or internal infrastructure IPs are blocked unless explicitly configured in scope.
- **Strict Hostname Matching**: Hostnames are canonicalized, trailing DNS root dots are removed, IPv6 brackets are normalized, and Unicode hostnames are encoded using Punycode (IDNA) to prevent homograph attacks.
- **Manual Redirect Verification**: BoundaryX explicitly disables automatic HTTP redirect following (`follow_redirects=False`). Every `3xx` redirect response halts execution, resolves the `Location` header, and independently verifies the target against scope rules before dispatching subsequent requests.
- **Token-Bucket Rate Limiter**: Configurable requests-per-second (RPS) limiter and semaphore concurrency bounding prevent denial-of-service conditions or triggering target rate limits.
- **Zero-Plaintext Credential Storage**: All secret materials are protected with Fernet authenticated encryption (AES-128-CBC + HMAC-SHA256) with strict file permissions (`0o600`).

---

## Installation Guide

### Prerequisites
- Python 3.12 or 3.13 (64-bit)
- Windows 10/11 or modern Linux distribution (Ubuntu 22.04+, Debian 12+, Fedora 38+)

### Development Installation from Source

1. **Clone the repository**:
   ```bash
   git clone https://github.com/boundaryx/boundaryx.git
   cd boundaryx
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv .venv

   # On Windows (PowerShell):
   .venv\Scripts\Activate.ps1

   # On Linux:
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   python -m pip install --upgrade pip setuptools wheel
   pip install -e ".[dev]"
   ```

4. **Verify installation**:
   ```bash
   python -m boundaryx.app --version
   ```

### Windows Portable Executable
1. Download `BoundaryX-0.1.0-windows-x64-portable.zip` from the GitHub Releases page.
2. Verify the SHA-256 checksum:
   ```powershell
   Get-FileHash -Algorithm SHA256 BoundaryX-0.1.0-windows-x64-portable.zip
   ```
3. Extract the archive to any folder or USB drive.
4. Run `BoundaryX.exe --portable`.

### Linux Standalone Executable
1. Download `BoundaryX-0.1.0-linux-x64-portable.tar.gz` from the Releases page.
2. Verify the SHA-256 checksum:
   ```bash
   sha256sum BoundaryX-0.1.0-linux-x64-portable.tar.gz
   ```
3. Extract and execute:
   ```bash
   tar -xzf BoundaryX-0.1.0-linux-x64-portable.tar.gz
   cd BoundaryX
   ./BoundaryX --portable
   ```

---

## Quick Start Walkthrough

### 1. Seed Demonstration Data
To quickly explore BoundaryX with realistic multi-tenant SaaS authorization data:
```bash
python scripts/seed_demo_data.py --db demo.db --clean
```

### 2. Launch BoundaryX with the Demo Database
```bash
boundaryx --db demo.db
```

### 3. Conduct an Assessment Workflow
1. **Verify Scope**: Inspect `api.apex-saas.internal` on the **Scope** page.
2. **Review Identities & Tenants**: Examine `Alpha Corp` (Alice [Admin], Bob [Editor]) and `Beta Ltd` (Charlie [Member]) on the **Identities** and **Tenants** pages.
3. **Inspect Traffic**: Navigate to **Traffic Explorer** to view the imported HTTP request/response entries.
4. **Run Test Lab**: Open **Test Lab**, select the test case `Cross-Tenant Order Retrieval (BOLA)`, and run in **Preview** mode, then **Active** mode.
5. **Analyze the Violation**: Inspect the newly generated `CRITICAL` finding on the **Findings** page.
6. **Export Report**: Navigate to **Reports** and generate an offline HTML or Markdown assessment report.

---

## Development & Testing Commands

BoundaryX maintains high code quality and test discipline.

```bash
# Run complete test suite
pytest

# Run tests with short tracebacks
pytest -v --tb=short

# Run specific test modules
pytest tests/security/test_scope.py
pytest tests/unit/test_policy_engine.py

# Run tests with code coverage
pytest --cov=boundaryx --cov-report=term --cov-report=xml

# Run Ruff linting and style checks
ruff check src tests scripts

# Auto-fix fixable lint issues
ruff check --fix src tests scripts
```

---

## Packaging Standalone Binaries

BoundaryX includes automated packaging scripts for PyInstaller:

```bash
# On Windows:
python scripts/build_windows.py

# On Linux:
bash scripts/build_linux.sh
```

Both scripts compile the application using `packaging/boundaryx.spec`, package portable distribution archives, and generate SHA-256 checksum files under `dist/`. For in-depth packaging guidance, see [docs/packaging.md](docs/packaging.md).

---

## Documentation Index

- [Architecture Overview](docs/architecture.md): Layered architecture, data flow, and evaluation lifecycle.
- [User Guide](docs/user_guide.md): Step-by-step assessment execution walkthrough.
- [Scope & Safety Model](docs/scope_and_safety.md): Technical breakdown of scope matching, SSRF prevention, and credential redaction.
- [Packaging Guide](docs/packaging.md): Instructions for building standalone executables on Windows and Linux.
- [Security Policy](SECURITY.md): Vulnerability disclosure guidelines and safe testing standards.
- [Contributing Guidelines](CONTRIBUTING.md): Code style, layer constraints, and PR workflows.
- [Changelog](CHANGELOG.md): Detailed release notes for version 0.1.0 across all 14 modules.

---

## License

BoundaryX is released under the [MIT License](LICENSE).
