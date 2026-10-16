# Test Plan & Public Release Gates

## Test layers

### Unit tests
- Scope canonicalization and rule precedence.
- Domain matching including deceptive suffixes, IDNA/punycode, trailing dots, IPv4/IPv6, explicit ports/schemes, wildcard and exclusions.
- Redirect chain policy and DNS resolution changes according to documented policy.
- Redaction for Authorization, Cookie, Set-Cookie, API key patterns, password/token fields and common query parameters.
- Job state machine transitions and cancellation.
- Adapter argv construction without shell interpretation.
- Tool output parsing, schema validation, evidence link integrity and dedup candidate logic.
- Report HTML escaping / CSV formula injection safeguards.
- Gemini result schema and unknown evidence ID rejection.

### Property/fuzz tests
- URL parsers and scope matcher with malformed/encoded inputs.
- HAR/OpenAPI/CSV/JSON importers for malformed, deeply nested, huge and hostile input.
- IPC payload limits and unknown commands.

### Integration tests
- Temporary SQLite DB and migrations from previous schema.
- Fake executables simulating success, non-zero exit, malformed output, hang, huge output, spawn failure and cancellation.
- Local mock HTTP server only for end-to-end network workflow.
- export→import round-trip and backup→restore.
- Gemini mock provider: success, rate limit, timeout, malformed JSON and invalid key; no real network required.

### UI tests
- Create workspace/program and scope rules.
- Out-of-scope target cannot launch job.
- Missing tool shows install guidance, not success.
- Running job progress and cancellation reflect engine events.
- Candidate finding requires evidence and review for verified state.
- Gemini preview and consent flow.
- Report preview and redaction before export.
- App usable by keyboard for critical workflows.

### Security tests
- Secret scanning in repo and test exports.
- Prompt injection fixture embedded in HTML/response cannot change scope or execute tools.
- Scope enforcement in engine when UI is bypassed.
- Redirect out of scope is blocked at every hop.
- External process cannot receive unsanitized arbitrary command string.
- Output size/time budgets cannot be bypassed by large tool output.
- Diagnostics and logs don't contain seeded secrets.
- No unexpected outbound telemetry.

## Local test targets

Use `make`/scripts or documented commands such as:
- frontend: lint, typecheck, unit tests, production build.
- engine: `uv run pytest`, ruff and mypy/pyright (choose one static type checker and keep config consistent).
- Rust: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.
- full integration: scripted target running the above and packaging smoke tests.

The AI agent must implement actual commands corresponding to the selected stack and document the exact commands. Do not copy these example names if the project's tooling differs.

## Safe target labs

- Primary CI: fixtures and mock server.
- Optional manual E2E: OWASP Juice Shop / crAPI started locally by the researcher. Never place the lab in a public network unintentionally.
- No automated production target tests in CI.

## Release gates

All required:
- [ ] Scope guard test suite passes; no known bypass.
- [ ] No mock or hardcoded values represented as real findings.
- [ ] Critical core workflow UI tests pass.
- [ ] Python, TypeScript and Rust lint/type/build tests pass.
- [ ] Dependency/license review completed; third-party notices generated.
- [ ] Secret scan passes; no API keys or user evidence in Git.
- [ ] Linux artifacts build successfully for declared platform/architecture.
- [ ] Artifact tested in a clean environment and startup/install/uninstall behavior reviewed.
- [ ] Cancellation/shutdown leaves no child processes.
- [ ] Backup/restore/migration tests pass.
- [ ] Report and diagnostics redaction reviewed.
- [ ] README states current limitations and known issues.
- [ ] `CHANGELOG.md` and checksums for release files.

## Test results reporting

Create `docs/TEST_RESULTS.md` per release candidate with exact date, OS/image, toolchain versions, exact commands, pass/fail counts, skipped tests and reasons, build artifact names, known issues. Never invent test outcomes.
