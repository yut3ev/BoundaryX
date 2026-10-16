# Architecture — BoundaryX

## 1. Layers

### Desktop UI (`apps/desktop`)
React + TypeScript inside Tauri v2. Responsible for presentation, client-side validation, confirmations, accessible interaction and rendering job events. It is not the security enforcement authority.

### Native host (`apps/desktop/src-tauri`)
Rust commands provide a narrow allowlisted IPC surface. Supervises the Python sidecar lifecycle, forwards structured events, controls shutdown and grants only required Tauri capabilities. Avoid broad shell permissions.

### Engine (`engine`)
Python domain/service layer:
- `domain`: entities and enums
- `scope`: canonicalization and authorization decisions
- `storage`: repositories, migrations, transactions
- `jobs`: queue, state machine, cancellation, concurrency budgets
- `adapters`: external tool interfaces/parsers
- `http`: normalized evidence/import parsers
- `findings`: triage, dedup suggestions and report models
- `ai`: provider interface, Gemini adapter, schema validation/redaction
- `reporting`: Markdown/HTML/JSON/CSV output
- `security`: secret abstraction, log redaction, file validation

### SQLite
Single local DB per OS user, under app-specific OS data directory. Set restrictive file permissions where supported. Use migrations, foreign keys, indices, WAL mode where safe, transaction boundaries, backup before migration. Do not store API keys in this database.

### External toolchain
Optional processes invoked through adapters. Use argv arrays, never shell interpolation. Each adapter declares binary, version strategy, required permissions/impact, supported output and whether active. No installer runs without explicit confirmation.

### Gemini provider
Optional network service. Business logic sends only a sanitized, selected context. Provider returns schema-validated advice; no privilege to make requests or execute commands.

## 2. IPC design

Prefer a local process protocol rather than exposing a network API:
- Rust launches bundled `boundaryx-engine` sidecar using Tauri's supported sidecar mechanism or a tightly supervised child process.
- Requests/responses are newline-delimited JSON with `protocol_version`, `request_id`, `command`, `payload`; progress events contain `event_id`, `job_id`, `type`, `payload`, `timestamp`.
- stdout is reserved for protocol JSON only; logs go to stderr and rotating local logs.
- Maximum message sizes, schema validation and command allowlist are mandatory.
- Reject unknown command names and invalid versions.
- Engine must not accept arbitrary executable paths or arbitrary shell strings from UI.
- If implementation chooses another IPC mechanism, document threat analysis and test it; never bind to `0.0.0.0`.

## 3. Domain boundaries

- Scope service is callable by all target-taking services; adapters cannot bypass it.
- Orchestrator owns processes, rate budgets and concurrency. UI cannot directly spawn tools.
- Evidence service owns redaction, retention and provenance.
- AI provider cannot access the DB broadly; caller passes selected sanitized objects and receives structured output.
- Reporting uses a safe renderer with HTML escaping and output redaction.

## 4. Error model

Normalized error fields: `code`, `message_safe`, `retryable`, `details_redacted`, `correlation_id`. Internal stack traces remain in local logs with secrets redacted. Distinguish user input errors, missing dependency, scope denial, timeout, cancellation, provider quota, invalid model, parser failure, DB failure and bug.

## 5. Process lifecycle

- Start engine with dedicated app data path and protocol handshake.
- Verify protocol compatibility before enabling actions.
- On app exit: ask jobs to cancel, wait bounded grace period, terminate remaining child process groups, record interrupted state, flush DB/logs.
- On next launch: detect interrupted jobs, show them; never silently resume active network actions.

## 6. Packaging

Build Python engine as platform-specific sidecar (for example PyInstaller, after license and reproducibility review), with asset names matching Tauri target triples. Build UI and native shell for each target OS/architecture separately. Verify bundled Python resources, CA certificates/TLS, tool discovery and writable data directories in clean environments. Do not claim one binary works across arbitrary Linux distributions.

## 7. Dependency policy

- Pin direct dependency ranges and commit resolved lockfiles.
- Verify package name/source before adding dependencies; prefer maintained official SDKs.
- Run license and vulnerability audits on release candidates.
- Include notices for bundled/copied dependencies and external templates.
- Separate runtime tool requirements from developer/build requirements.
