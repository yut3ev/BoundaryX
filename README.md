# BoundaryX

[![CI](https://github.com/boundaryx/boundaryx/actions/workflows/ci.yml/badge.svg)](https://github.com/boundaryx/boundaryx/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.12+](https://img.shields.io/badge/Python-3.12%2B-brightgreen.svg)](https://www.python.org/)
[![Tauri: v2](https://img.shields.io/badge/Tauri-v2-orange.svg)](https://v2.tauri.app/)

> **BoundaryX** is an enterprise-grade open-source desktop security research workbench for authorized web penetration testing and bug bounty reconnaissance.

BoundaryX establishes an unbroken, cryptographically verified chain of evidence:
$$\text{Scope Rules} \longrightarrow \text{Asset Inventory} \longrightarrow \text{Supervised Recon} \longrightarrow \text{HTTP Evidence} \longrightarrow \text{Test Hypotheses} \longrightarrow \text{Human Verification} \longrightarrow \text{Findings} \longrightarrow \text{Auditor Reports}$$

---

## 1. Core Architecture & Highlights

- **Desktop Shell**: Tauri v2 desktop host with hardware-accelerated rendering and secure, allowlisted IPC.
- **Frontend Workbench (`apps/desktop`)**: React 18 + TypeScript dark-first security UI across 10 specialized views: Overview, Programs & Scope, Assets, Recon Jobs, Traffic & API, Test Planner, Findings, Reports, Toolchain, and Settings.
- **Security Engine (`engine`)**: Python 3.12+ engine managed by `uv` with clean layered domain boundaries.
- **Strict Scope Guard**: Boundary-aware canonicalization, IDNA/Punycode normalization, deceptive suffix collision defenses (`evil-example.com` blocked), IPv4/IPv6 support, and hop-by-hop redirect validation.
- **Tool Adapter Architecture**: Modular adapters for Subfinder, dnsx, httpx, Katana, Nuclei, and ffuf. Subprocess execution uses argv arrays (never `shell=True`), timeouts, output size bounds, and process-tree termination.
- **Optional Gemini Analyst (BYOK)**: Native integration via Google's official `google-genai` SDK. Fully operational offline in **No-AI mode**. Credentials stored in local encrypted OS vaults (never SQLite or logs). Enforces strict prompt injection defenses, minimum context previews, explicit user consent, and citation validation against hallucinated evidence IDs.
- **Evidence Vault & Reporting**: SHA-256 evidence integrity hashes and multi-format exports in Markdown, standalone HTML (with XSS defense), sanitized JSON, and CSV (with formula injection defense).

---

## 2. Repository Layout

```text
BoundaryX/
├── apps/
│   └── desktop/                  # Tauri v2 + React 18 + TypeScript frontend
│       ├── src/                  # 10 core workbench views & layout components
│       ├── src-tauri/            # Rust native shell, sidecar supervisor, and capabilities
│       └── package.json
├── engine/                       # Python 3.12+ security engine (managed with uv)
│   ├── boundaryx/
│   │   ├── domain/               # Relational entities, enums, and asset diff
│   │   ├── scope/                # Canonicalizer, boundary matcher, ScopeGuard
│   │   ├── storage/              # SQLite WAL engine, repositories, migrations
│   │   ├── jobs/                 # Queue, rate limiting, process supervisor
│   │   ├── adapters/             # Subfinder, dnsx, httpx, katana, nuclei, ffuf
│   │   ├── http/                 # HAR 1.2, OpenAPI 3.0/2.0 YAML/JSON, raw HTTP
│   │   ├── ai/                   # google-genai adapter, prompt injection defense, citations
│   │   ├── findings/             # State machine, confidence scoring, deduplication
│   │   ├── reporting/            # Markdown, standalone HTML, JSON, formula-safe CSV
│   │   ├── security/             # RedactionEngine, SecretStore, AuditLogger
│   │   └── ipc/                  # Stdin/stdout NDJSON protocol & dispatcher
│   ├── migrations/               # Versioned SQL migrations (001_initial_schema.sql)
│   ├── tests/                    # 37 passing unit & security tests
│   └── pyproject.toml
├── config/
│   ├── tool-manifest.yaml        # Manifest for external toolchain integrations
│   └── defaults.example.yaml     # Application configuration defaults
├── docs/                         # Specifications, Threat Model, Architecture, Test Results
│   ├── ARCHITECTURE.md
│   ├── DATA_MODEL.md
│   ├── GEMINI_ANALYST.md
│   ├── INTEGRATIONS.md
│   ├── PRODUCT_SPEC.md
│   ├── TEST_PLAN.md
│   ├── TEST_RESULTS.md           # 206 verified passing tests
│   └── THREAT_MODEL.md
├── scripts/
│   ├── build_engine.py           # PyInstaller sidecar bundling script
│   ├── package_linux.sh          # Linux build and packaging script (.deb, AppImage)
│   └── generate_sbom.py          # CycloneDX SBOM generator
├── .github/workflows/
│   ├── ci.yml                    # Automated CI test suite
│   └── release.yml               # Tag-based release pipeline
├── TASKS.md                      # Implementation tracker with stage evidence
└── LICENSE                       # MIT License
```

---

## 3. Quickstart & Installation

### Developer Prerequisites
- Node.js 20+ and `npm`
- Python 3.12+ and `uv`
- Rust stable toolchain (for Tauri desktop shell)

### Build & Run Engine
```bash
# 1. Install engine dependencies
cd engine
uv pip install -e ".[dev]"

# 2. Run engine tests
python -m pytest tests/

# 3. Start engine in IPC sidecar mode
python -m boundaryx.cli --ipc
```

### Build & Run Desktop Frontend
```bash
# 1. Install frontend dependencies
cd apps/desktop
npm install

# 2. Start frontend in development mode
npm run dev

# 3. Build standalone production desktop application
npm run tauri build
```

---

## 4. Linux Packaging (x86_64)

BoundaryX supports automated Linux building for Debian/Ubuntu (`.deb`) and standalone `AppImage`:

```bash
# Install Tauri Linux dependencies (Debian/Ubuntu)
sudo apt-get update && sudo apt-get install -y \
    libwebkit2gtk-4.1-dev build-essential curl wget file libssl-dev libayatana-appindicator3-dev librsvg2-dev

# Run automated Linux packaging script
./scripts/package_linux.sh
```

---

## 5. Security & Authorized Use Notice

> [!IMPORTANT]
> BoundaryX is engineered exclusively for **authorized web application penetration testing, security audits, and bug bounty programs**.
> Entering an unauthorized target or attempting to bypass scope boundaries is strictly prohibited. The engine enforces scope restrictions before dispatching requests, rejecting unapproved hosts and out-of-scope HTTP redirects.

---

## 6. License & SBOM

BoundaryX is licensed under the [MIT License](LICENSE).
Third-party component notices and CycloneDX SBOM are documented in [`docs/SBOM.json`](docs/SBOM.json).
