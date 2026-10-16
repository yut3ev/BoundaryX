# BoundaryX Verified Test Results

## 1. Test Execution Metadata
- **Date:** October 16, 2026
- **Operating Systems Tested:**
  - Host: Windows 11 x86_64
  - Isolated Clean Container: Ubuntu 24.04.5 LTS x86_64 (`ubuntu:24.04`)
- **Python Versions:** 3.13.13 (Host) / 3.12.3 (Ubuntu Container)
- **Node.js / npm:** v24.16.0 / npm 11.13.0
- **Framework & Library Versions:**
  - `pydantic`: 2.13.4
  - `httpx`: 0.28.1
  - `cryptography`: 46.0.7
  - `google-genai`: 2.31.0
  - `idna`: 3.11
  - `PyYAML`: 6.0.3
  - `react`: 18.3.1
  - `typescript`: 5.6.3
  - `vite`: 5.4.21

---

## 2. Test Suites Summary

| Test Suite | File Path | Total Tests | Passed | Failed | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Scope Canonicalization** | `engine/tests/test_scope_canonicalization.py` | 7 | 7 | 0 | **PASSED** |
| **Scope Guard & Boundaries** | `engine/tests/test_scope_guard.py` | 4 | 4 | 0 | **PASSED** |
| **Deep Scope & Engine HTTP** | `engine/tests/test_scope_security_deep.py` | 6 | 6 | 0 | **PASSED** |
| **Database & Migrations** | `engine/tests/test_database_and_migrations.py` | 1 | 1 | 0 | **PASSED** |
| **Redaction & Secrets Storage** | `engine/tests/test_redaction_and_secrets.py` | 3 | 3 | 0 | **PASSED** |
| **IPC Protocol & Dispatcher** | `engine/tests/test_ipc_protocol.py` | 2 | 2 | 0 | **PASSED** |
| **Process Supervisor & Cancellation** | `engine/tests/test_process_supervisor.py` | 4 | 4 | 0 | **PASSED** |
| **Tool Adapters & Manifest Registry** | `engine/tests/test_adapters.py` | 3 | 3 | 0 | **PASSED** |
| **Job Orchestrator & Rate Limiting** | `engine/tests/test_job_orchestrator.py` | 2 | 2 | 0 | **PASSED** |
| **Importers (HAR, OpenAPI) & Diff** | `engine/tests/test_importers_and_diff.py` | 3 | 3 | 0 | **PASSED** |
| **Gemini Analyst & Citations** | `engine/tests/test_gemini_analyst.py` | 4 | 4 | 0 | **PASSED** |
| **Findings State Machine & Reports** | `engine/tests/test_findings_and_reports.py` | 4 | 4 | 0 | **PASSED** |
| **Domain & Unit Security Suite** | `tests/unit/` & `tests/security/` | 169 | 169 | 0 | **PASSED** |
| **TOTAL VERIFIED SUITE** | — | **212** | **212** | **0** | **100% PASSED** |

---

## 3. Clean Container Verification (Ubuntu 24.04 LTS x86_64)

Execution in a pristine Ubuntu container with no pre-existing caches or virtual environments:

```bash
docker run --rm -v "${PWD}:/repo" ubuntu:24.04 bash -c "
  apt-get update -qq && apt-get install -y -qq git python3 python3-pip python3-venv > /dev/null
  git clone /repo /tmp/clean-boundaryx
  cd /tmp/clean-boundaryx
  python3 -m venv /tmp/venv
  /tmp/venv/bin/pip install -q --upgrade pip
  /tmp/venv/bin/pip install -q -e ./engine
  /tmp/venv/bin/pip install -q pytest pytest-asyncio
  /tmp/venv/bin/pytest engine/tests/ -v --tb=short
"
```

**Results:**
- Environment: Linux 6.6.114.1-microsoft-standard-WSL2 x86_64 GNU/Linux (`PRETTY_NAME="Ubuntu 24.04.5 LTS"`)
- Python: 3.12.3
- Result: `43 passed in 2.52s` (100% pass)

---

## 4. Frontend Compilation & Production Build

Execution in `apps/desktop`:

```bash
npm run build
# Executes: tsc && vite build
```

**Results:**
- TypeScript Compiler: 0 errors across all 10 pages and layout components.
- Vite: 1,609 modules transformed.
- Production Assets:
  - `dist/index.html`: 0.41 kB (gzip: 0.29 kB)
  - `dist/assets/index-*.css`: 4.29 kB (gzip: 1.42 kB)
  - `dist/assets/index-*.js`: 207.61 kB (gzip: 60.63 kB)
- Build time: 8.96s (100% success)

---

## 5. Security & Verification Checks by Requirement

### A. Scope Enforcement & Deceptive Suffixes
- `test_scope_guard_prevents_suffix_confusion`: PASSED. Rejects `evil-example.com`, `notexample.com`, and `example.com.evil.test`.
- `test_scope_guard_idna_homograph_defense`: PASSED. Normalizes IDNA Unicode homographs (`tаrget.com` -> `xn--trget-1qa.com`) to prevent visual bypasses.
- `test_scope_guard_embedded_credentials_and_userinfo_rejection`: PASSED. Enforces SSRF defense by rejecting URLs containing userinfo (`user:pass@host` or `https://target.com@attacker.com/`).
- `test_scope_guard_redirect_chain_validation`: PASSED. Validates every hop in HTTP 3xx redirect chains; external redirects to third parties (OAuth, open redirects) are denied.
- `test_engine_level_http_client_scope_enforcement`: PASSED. `HardenedHttpClient` raises `ScopeDenialError` before sending any network packets for out-of-scope targets.

### B. SQLite Transactions & Migration Safety
- `test_migrations_and_repositories_workflow`: PASSED. WAL mode enabled, `PRAGMA foreign_keys = ON;`, versioned migrations executed, pre-migration backup snapshots created.

### C. Redaction & Credential Protection
- `test_redaction_engine_headers`: PASSED. Scrubs `Authorization` (Bearer/Basic), `Cookie`, `Set-Cookie`, and `X-Custom-Header`.
- `test_redaction_engine_json_body`: PASSED. Recursively scrubs passwords, API keys, tokens, and secrets from JSON payloads.
- `test_secret_store_encrypted_vault`: PASSED. BYOK API keys stored with Fernet authenticated encryption (0o600 file permissions).

### D. Process Tree Isolation & Safe IPC
- `test_supervisor_cancellation`: PASSED. Terminates child process groups without leaving orphan zombie processes.
- `test_supervisor_sanitizes_environment`: PASSED. Purges sensitive environment variables (`GEMINI_API_KEY`, etc.) before spawning child tools.
- `test_ipc_protocol_parsing_and_oversized_rejection`: PASSED. Enforces 10MB payload cap and rejects un-allowlisted commands.

### E. Gemini Analyst Citations & Prompt Injection
- `test_citation_validator_strips_hallucinated_ids`: PASSED. Strips hallucinated evidence IDs.
- `test_consent_pipeline_requires_explicit_consent`: PASSED. Requires explicit user consent before dispatching context to Google Gemini.
