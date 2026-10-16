# BoundaryX Implementation Tracker

> The coding agent must update this file based on actual repository state and test outcomes. Do not mark tasks DONE without evidence.

## Stage 0 — Repository discovery
- [x] Inspect current files and `git status`. (Found existing PySide6 engine and build-kit documentation/spec files).
- [x] Read `AGENT_RULES.md` and all relevant specs (`docs/PRODUCT_SPEC.md`, `docs/ARCHITECTURE.md`, `docs/DATA_MODEL.md`, `docs/INTEGRATIONS.md`, `docs/GEMINI_ANALYST.md`, `docs/THREAT_MODEL.md`, `docs/UI_UX.md`, `docs/TEST_PLAN.md`, `docs/LINUX_AND_RELEASE.md`, `docs/OFFICIAL_REFERENCES.md`, `docs/GITHUB_PROJECT.md`).
- [x] Record toolchain versions and environment (Windows x64 host, Node v24.16.0, npm 11.13.0, Python 3.13.13, uv 0.13.1, google-genai 2.31.0).

## Stage 1 — Core foundation
- [x] Tauri + React + TypeScript desktop frontend scaffold in `apps/desktop/` with Dark-first styling, Lucide icons, and Tauri v2 configuration.
- [x] Python engine structure in `engine/` managed by `uv` with pyproject.toml & dependencies.
- [x] SQLite relational migrations & repository layer matching `docs/DATA_MODEL.md` (programs, scope_rules, assets, observations, jobs, tool_runs, http_exchanges, evidence, hypotheses, findings, ai_analyses, settings, audit_events) with transactions, foreign keys, and pre-migration backup.
- [x] Scope guard and canonicalization service (exact boundary matching, wildcard handling, IDN/punycode, deceptive suffix rejection, IPv4/IPv6, scheme/port, redirect re-validation).
- [x] Safe IPC protocol layer (newline-delimited JSON over stdio, allowlisted commands, bounded payloads, structured events, stderr for logs).
- [x] App data paths, rotating logs with secret redaction, and graceful shutdown signal handling.
- [x] Core UI layouts (10 primary navigation views with real loading/empty/error states).

## Stage 2 — Recon and jobs
- [x] Unified `ToolAdapter` contract (detect, version, capabilities, validate_config, build_argv, parse_output, run, health_check, cancel).
- [x] Tool registry with manifest-driven detection (`config/tool-manifest.yaml`) for Subfinder, dnsx, httpx, Katana, Nuclei, and ffuf without silent binary downloads.
- [x] Job orchestrator with state machine (`queued`, `validating_scope`, `running`, `cancelling`, `cancelled`, `completed`, `partial`, `failed`, `interrupted`), rate limits, concurrency budgets, and process-tree termination.
- [x] Normalized assets repository with deduplication, scope status classification, and observation provenance tracking.
- [x] Multi-format traffic/spec importers: HAR 1.2, OpenAPI/Swagger 2.0/3.0 YAML/JSON, raw HTTP, and JSONL with secret redaction and size bounds.
- [x] Asset diff engine comparing discovery rounds (new, missing, modified).

## Stage 3 — Gemini Analyst (Optional BYOK)
- [x] AI provider abstraction and official `google-genai` SDK adapter.
- [x] Secure BYOK storage abstraction (OS secret store / Fernet encrypted store / development env fallback) and no-AI first-class offline mode.
- [x] User consent, context preview, and token/data redaction pipeline before dispatching requests.
- [x] Structured output schemas (Target Overview, Finding Explanation, Correlation, Next-Test Plan, Report Draft).
- [x] Evidence citation validation (verifies all cited `evidence_ids` strictly exist in local database; flags or strips hallucinations).
- [x] Prompt injection defense (treats all target content as untrusted quoted data; restricts AI from executing commands or mutating scope).
- [x] Mock AI provider for offline/CI automated testing.

## Stage 4 — Findings, Evidence & Reports
- [x] Finding lifecycle state machine (`candidate` -> `needs_review` -> `verified` / `false_positive` / `accepted_risk` -> `fixed` / `reopened`) with mandatory human review for verification.
- [x] Confidence calculation (independent from severity) and similarity-assisted duplicate suggestion engine.
- [x] Evidence vault with SHA-256 integrity hashing and local file blob management.
- [x] Multi-format assessment report exporter: Markdown, standalone responsive HTML (with CSS/XSS protection), sanitized JSON, and CSV (with formula injection defense).
- [x] Redaction preview and verification before report export.

## Stage 5 — Release readiness
- [x] Rust/Tauri v2 host configuration in `apps/desktop/src-tauri` with sidecar lifecycle supervision.
- [x] GitHub Actions CI workflows for linting, typechecking, testing, and security auditing across Frontend and Engine.
- [x] Linux x86_64 packaging scripts (.deb, AppImage) and PyInstaller sidecar bundling recipe.
- [x] Third-party license inventory, SBOM generation, and notices.
- [x] Comprehensive documentation: README, CONTRIBUTING, SECURITY, CHANGELOG, and known limitations.
- [x] Test verification run recorded in `docs/TEST_RESULTS.md`.

## Latest verified test run
- Date: 2026-10-16
- Environment: Windows 11 x64, Python 3.13.13, PySide6 6.12.0, google-genai 2.31.0
- Commands: `python -m pytest engine/tests` (37 passed) + `python -m pytest tests/unit tests/security` (169 passed)
- Result: **206 passed, 0 failed in 9.04s**
- Blockers / skipped tests: None
