# Threat Model & Security Requirements

## Assets to protect

- Gemini API key and future provider secrets.
- Cookies, authorization headers, API tokens, session IDs and passwords imported from traffic.
- Private program notes, private target inventory, requests/responses and vulnerability evidence.
- Integrity of scope rules, findings and generated reports.
- Host system from malicious file input, hostile site content, shell injection or untrusted binaries.

## Trust boundaries

1. UI → Rust IPC → Python engine.
2. Python engine → external OS processes.
3. Imported files/HTTP responses/OpenAPI specs → parsers.
4. Local evidence → Gemini API provider.
5. Application output → GitHub/report exports.
6. Tool binaries and templates → application execution.

## Threats and controls

### Out-of-scope request / redirect
- Threat: a domain or redirect bypasses scope matching.
- Control: exact canonical host rules, label-boundary matching, wildcard logic, exclusion precedence, parse/resolve safety, re-check every redirect hop, DNS/IP policy handling, deny by default.
- Test: `example.com.evil.test`, userinfo URLs, mixed case, trailing dots, punycode, IPv6 literals, encoded paths, redirects to excluded hosts, ports/schemes.

### Shell/argument injection
- Threat: hostile asset names or input becomes a shell command.
- Control: no `shell=True`, argv list, allowlisted executable, safe working directory, environment minimization, path validation, process timeout/kill, no arbitrary command UI.

### Malicious imports
- Threat: oversized file, zip bomb, parser exploit, unsafe YAML tags, HTML/CSV formula injection.
- Control: file size caps, streaming parser, YAML safe loader, archive extraction disabled unless necessary, extension is not trusted, safe HTML escaping, spreadsheet formula escaping when exporting CSV, fuzz tests.

### Prompt injection / hallucinated finding
- Threat: target content tells Gemini to reveal secrets, ignore scope or claim exploit success.
- Control: frame all collected content as untrusted quoted data; no tool/shell/network capability; strict schemas; evidence ID validation; no automatic scope changes or verification status changes; user review and report labels.

### Secret leak
- Threat: API keys/tokens appear in frontend storage, DB, logs, crash bundles, reports or Git.
- Control: OS secret store, environment variable for development only, redaction before persist/log/export/AI, `.gitignore`, secret scan CI, diagnostics preview, leak response instructions.

### Local IPC abuse
- Threat: another local process invokes engine commands.
- Control: IPC only via parent child process; narrow command schema, per-launch secret if socket fallback, bind loopback only, no broad Tauri shell capability, validate protocol and size.

### DoS/resource exhaustion
- Threat: huge responses, infinite crawl, hung scanner, excessive parallel requests, Gemini quota spend.
- Control: per-file/output/body limits, page/depth caps, rate/concurrency budgets, timeout and cancellation, token budget, user-visible estimated external calls, circuit breakers.

### Supply chain / malicious tool binary
- Threat: untrusted executable/template steals data or alters results.
- Control: only official sources, explicit confirmation, version/checksum validation where provided, no silent installers, tool path visibility, optional tool isolation, license inventory.

### Data loss/corruption
- Threat: crashes during migration or jobs.
- Control: transaction migrations, backup before migration, backup/restore tests, atomic exports, interrupted-job states and no surprise resuming.

## Data handling defaults

- Local-first, no telemetry.
- Evidence remains on device unless user explicitly invokes a provider/export.
- Gemini call preview explains provider, selected evidence, potential cost/quota, and redaction.
- Never send cookies/auth headers/passwords by default; redaction occurs before prompt assembly.
- Report exports are sanitized by default and can be previewed.
- Retention/deletion controls documented and tested.

## Security review gates

- Every active job has a scope and rate budget.
- Every external tool execution uses adapter registry and audit event.
- Every user-approved active action records what will run and where.
- No security claim depends only on a frontend-disabled button; validate in engine.
- No open issue labeled “critical” may be silently ignored in a public release.
