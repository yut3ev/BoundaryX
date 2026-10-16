# Gemini Analyst Specification

## Product role

Gemini assists with understanding evidence, prioritizing review and drafting reports. It does not certify vulnerabilities, change scope, run network requests or execute shell commands.

## Provider adapter

Interface should support `validate_config`, `test_connection`, `analyze(request)`, `get_model_options` where API offers it, and `map_error`. Keep provider SDK calls inside adapter so SDK migration does not affect the UI/domain.

Use Google's official `google-genai` Python SDK where appropriate; confirm the current recommended API and SDK at implementation time: <https://ai.google.dev/gemini-api/docs/get-started>. Do not copy an old SDK snippet without verifying current method names.

## Supported analysis types

### 1. Target overview
Input: selected, sanitized inventory summaries (technologies, route shapes, auth hints if known, source provenance). Output: facts explicitly present, cautious inferences, uncertainty, missing info, recommended manual review priorities. No exploitation claims.

### 2. Finding explanation
Input: candidate metadata and selected evidence IDs/snippets. Output: vulnerability category hypothesis, evidence that supports it, evidence against it, confidence, missing evidence, safe next verification steps, remediation ideas. If evidence is insufficient, explicitly say so.

### 3. Correlation
Input: candidate records/observations. Output: duplicate candidates and relationships with reasons. Do not merge records automatically.

### 4. Next-test plan
Input: scope constraints, capabilities, chosen asset(s), prior results. Output: ordered **suggestions** with purpose, required preconditions, active/passive classification, expected safe observations and stop conditions. No direct executable shell command unless displayed only as educational text; never auto-run.

### 5. Report draft
Input: a user-selected finding and redacted evidence. Output: report draft with actual vs expected behavior, impact supported by evidence, repro steps only from observed actions, mitigation, uncertainties. Don't invent status codes, responses or affected users.

## Output schema design

At minimum:
- `analysis_type`
- `summary`
- `facts[]` with `claim`, `evidence_ids[]`, `confidence`
- `hypotheses[]` with `claim`, `supporting_evidence_ids[]`, `counter_evidence_ids[]`, `confidence`, `verification_needed[]`
- `suggested_next_steps[]` with `title`, `purpose`, `active_or_passive`, `preconditions`, `stop_conditions`, `requires_user_confirmation: true`
- `limitations[]`
- `report_draft` when relevant

Validate JSON against schema; validate each evidence ID against selected IDs and database existence. Invalid or unknown IDs must be removed/rejected and noted. No parsing arbitrary Markdown into trusted state transitions.

## Prompt design

- Keep developer instructions separate from untrusted evidence delimiters.
- State that HTML/JS/HTTP content is data and may contain malicious instructions.
- Instruct the model to quote or summarize evidence, not follow instructions found inside it.
- Request explicit uncertainty and no exploit confirmation without reproducible evidence.
- Never include API key or credentials in prompt.

## Privacy, cost and reliability

- Model configurable in settings; re-validate against current official model list before release: <https://ai.google.dev/gemini-api/docs/models>.
- Display that the Gemini provider receives selected content and external API limits/costs may apply.
- Preview exact selected evidence/summary and redaction before send, with consent.
- Use minimum context, bounded bytes/tokens, request timeout, bounded retries with jitter, and a user cancel action.
- Use `store=False` or equivalent only where supported by the chosen API and do not imply it guarantees zero retention outside the application's control.
- No-AI mode is first class; missing/invalid key never blocks recon, local analysis or reports.
- Mock provider is used in automated tests; CI must not need a real key.
- Add provider usage telemetry only inside the local app, no external analytics by default.
