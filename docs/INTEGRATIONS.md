# Tool Integrations & External Dependencies

## Adapter contract

Every tool adapter should implement:
- `detect()`: find configured binary without executing arbitrary user input.
- `version()`: identify exact version; if unavailable, report `unknown` and disable risky operation.
- `capabilities()`: operations, supported output formats, active/passive impact, cancellation support.
- `validate_config(config)`: validate values and limits.
- `build_argv(targets, config)`: return argv array, never shell string.
- `parse_output(stdout/stderr/files)`: bounded, typed normalization with parser warnings.
- `run(context)`: produce typed events and results; honor cancellation/timeouts/limits.
- `health_check()`: verify expected behavior without touching target networks.

## Tool policy

- Passive discovery can still carry provider/terms implications; show data source and scope notes.
- Active scanners are disabled by default and require user opt-in, per-program rate limits, in-scope target selection and preview.
- Tool absence must not break unrelated functions. Manual import remains available.
- Never download tool archives from arbitrary URLs or install through shell-injected commands.
- Make tool path/version visible, but allow custom path only after validating it as an executable file and warning that it is user supplied.
- Do not bundle tool binaries until redistribution rights, dependencies, update process, checksums and license notices have been reviewed.

## Suggested first integrations

See `config/tool-manifest.yaml` for official project references. Check current installation/version docs before implementation because release artifacts and install commands can change.

1. **subfinder** — passive subdomain discovery. Store source metadata when available.
2. **dnsx** — DNS resolution and record checks for imported/discovered hostnames.
3. **httpx** — HTTP probing and metadata collection with conservative defaults.
4. **katana** — web crawling; low default depth/page budget and in-scope redirect enforcement.
5. **nuclei** — optional template-based checks; low rate limit; inspect template source/metadata; never run all templates by default.
6. **ffuf** — active fuzzing only after explicit confirmation, rate/wordlist limits and target review. Disabled by default.

Optional future integration: Nmap or other service discovery only with narrow allowlists, explicit port ranges, and conservative limits. Do not expose a universal “scan all ports/networks” action.

## Install experience

Tool Registry UI fields: `tool`, `state`, `detected_version`, `configured_path`, `operation_class`, `official_docs_url`, `last_health_check`, `notes`.

Buttons: `Check Again`, `Open Official Install Guide`, `Copy Reviewed Command`, `Configure Binary`. Do not run install commands silently. If an in-app installation workflow is later implemented, require explicit user confirmation, verified artifact metadata, hash/signature checking where available, destination control, rollback, and a license notice.

## Parser safety

- Enforce max stdout/stderr bytes, max lines, max JSON depth and parse timeout.
- Preserve unknown fields but do not execute them.
- HTML, XML, YAML and URLs from tools are untrusted.
- Normalize hostnames consistently with the scope module.
- Treat exit code and parsed results separately; partial output may be useful but must say `partial`.
- Do not map every non-zero exit to “no findings”.
