# BoundaryX Verified Test Results

## 1. Test Execution Metadata
- **Date:** 2026-10-16
- **Operating System:** Windows 11 x86_64 (Development Host) / Ubuntu 22.04 LTS (CI Matrix)
- **Python Version:** 3.13.13 (uv 0.13.1)
- **Node.js Version:** v24.16.0 (npm 11.13.0)
- **Framework Versions:**
  - `pydantic`: 2.13.4
  - `httpx`: 0.28.1
  - `cryptography`: 46.0.7
  - `google-genai`: 2.31.0
  - `idna`: 3.11
  - `PyYAML`: 6.0.3

---

## 2. Test Suites Summary

| Test Suite | File Path | Total Tests | Passed | Failed | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Scope Canonicalization** | `engine/tests/test_scope_canonicalization.py` | 7 | 7 | 0 | **PASSED** |
| **Scope Guard & Boundary Defense** | `engine/tests/test_scope_guard.py` | 4 | 4 | 0 | **PASSED** |
| **Database & Migrations** | `engine/tests/test_database_and_migrations.py` | 1 | 1 | 0 | **PASSED** |
| **Redaction & Secrets Storage** | `engine/tests/test_redaction_and_secrets.py` | 3 | 3 | 0 | **PASSED** |
| **IPC Protocol & Dispatcher** | `engine/tests/test_ipc_protocol.py` | 2 | 2 | 0 | **PASSED** |
| **Process Supervisor & Cancellation** | `engine/tests/test_process_supervisor.py` | 4 | 4 | 0 | **PASSED** |
| **Tool Adapters & Manifest Registry** | `engine/tests/test_adapters.py` | 3 | 3 | 0 | **PASSED** |
| **Job Orchestrator & Rate Limiting** | `engine/tests/test_job_orchestrator.py` | 2 | 2 | 0 | **PASSED** |
| **Importers (HAR, OpenAPI) & Diff** | `engine/tests/test_importers_and_diff.py` | 3 | 3 | 0 | **PASSED** |
| **Gemini Analyst & Citations** | `engine/tests/test_gemini_analyst.py` | 4 | 4 | 0 | **PASSED** |
| **Findings State Machine & Reports** | `engine/tests/test_findings_and_reports.py` | 4 | 4 | 0 | **PASSED** |
| **Legacy Domain & Security Suite** | `tests/unit/` & `tests/security/` | 169 | 169 | 0 | **PASSED** |
| **TOTAL** | — | **206** | **206** | **0** | **100% PASSED** |

---

## 3. Verification Details by Security Requirement

### A. Scope Enforcement & Deceptive Suffixes
- `test_scope_guard_prevents_suffix_confusion`: PASSED. Verifies that `evil-example.com`, `notexample.com`, and `example.com.evil.test` are strictly rejected by the ScopeGuard when `example.com` or `*.example.com` is in scope.
- `test_canonicalize_host_idn_punycode`: PASSED. Confirms Arabic Unicode domains (e.g. `مثال.مصر`) are normalized into valid Punycode (`xn--...`), preventing visual homograph bypasses.
- `test_canonicalize_host_rejects_embedded_credentials`: PASSED. Enforces SSRF defense by rejecting URLs containing userinfo (`user:pass@host`).
- `test_scope_guard_redirect_validation`: PASSED. Proves that every hop in an HTTP 3xx redirect chain is validated; external redirects (e.g. to OAuth providers) are immediately halted and logged.

### B. SQLite Transactions & Migration Safety
- `test_migrations_and_repositories_workflow`: PASSED. Confirms WAL mode is enabled, `PRAGMA foreign_keys = ON;` is strictly enforced, versioned SQL migrations execute deterministically, and automatic pre-migration backup snapshots are taken.

### C. Redaction & Credential Protection
- `test_redaction_engine_headers`: PASSED. Scrubs `Authorization` (Bearer/Basic), `Cookie`, `Set-Cookie`, and `X-Custom-Header` tokens from headers.
- `test_redaction_engine_json_body`: PASSED. Recursively scrubs passwords, API keys, tokens, and secrets from JSON payloads.
- `test_secret_store_encrypted_vault`: PASSED. Verifies BYOK API keys are stored with Fernet authenticated encryption (0o600 file permissions) and are never leaked to plain disk files or logs.

### D. Process Tree Isolation & Safe IPC
- `test_supervisor_cancellation`: PASSED. Terminates entire child process trees using process groups (`taskkill /T` on Windows, `killpg` on Unix) without leaving orphan zombie processes.
- `test_supervisor_sanitizes_environment`: PASSED. Sensitive environment variables (`GEMINI_API_KEY`, etc.) are purged before spawning external child tools.
- `test_ipc_protocol_parsing_and_oversized_rejection`: PASSED. Enforces a 10MB payload cap and rejects un-allowlisted IPC commands.

### E. Gemini Analyst Citations & Prompt Injection
- `test_citation_validator_strips_hallucinated_ids`: PASSED. Confirms that unverified or hallucinated evidence IDs (e.g. `ev-hallucinated-999`) in AI suggestions are stripped and documented in limitations.
- `test_consent_pipeline_requires_explicit_consent`: PASSED. Blocks sending target data to external AI models unless the researcher explicitly reviews redacted context and grants consent.

### F. Assessment Reporting & Injection Defense
- `test_report_generator_html_xss_protection`: PASSED. HTML reports escape malicious payloads (`<script>`, `<img onerror>`) to prevent stored XSS.
- `test_report_generator_csv_formula_injection_defense`: PASSED. CSV exports prepend dangerous formula trigger characters (`=`, `+`, `-`, `@`) with a single quote to defend against spreadsheet command execution.
