# Product Requirements — BoundaryX

## 1. Purpose

BoundaryX desktop research workbench لتقليل التكرار في authorized web pentesting وbug bounty. ليس ماسحًا عامًا للإنترنت ولا بديلًا كاملًا عن أدوات proxy/manual testing. القيمة هي ربط scope والأصول والـ traffic والأدلة والخطوات والنتائج في workflow واحدة قابلة للتتبع.

## 2. Personas

- Bug bounty researcher: يدير برامج متعددة، يراجع scope، يستكشف assets، ويكتب تقارير.
- AppSec tester: يستورد OpenAPI/HAR، يوثق الاختبارات والأدلة، ويعيد الفحص.
- Maintainer: يضيف adapter/تحديث tool، ويضمن الاختبارات والتراخيص.

## 3. Main workflows

### Workflow A — Start a program
1. Create program and record official policy URL/notes.
2. Define include/exclude rules and permitted test intensity.
3. Validate rules using test strings before saving.
4. Import assets or start a passive recon job.
5. Inspect provenance and scope status for every asset.

### Workflow B — Recon run
1. Select an in-scope program and subset of assets.
2. Select tool(s) and see exact command/impact/rate limits before an active run.
3. Engine revalidates every target and redirect immediately before the request.
4. Watch live job events; cancel/stop all child processes.
5. Review normalized output, raw-output reference, warnings, duplicates and scope denials.

### Workflow C — Analyze a possible finding
1. Choose asset and evidence.
2. Use local rules or optional Gemini explanation.
3. Review an explicit hypothesis, confidence, supporting evidence IDs and missing evidence.
4. Create candidate; run a safe manual verification plan within scope.
5. Researcher marks verified/false positive only with a reason and evidence.

### Workflow D — Report
1. Select verified finding(s).
2. Preview sanitized output.
3. Export Markdown/HTML/JSON locally.
4. Confirm report does not expose tokens, cookies, account data or secrets.

## 4. Functional requirements

- Programs, scope rules, assets, observations, jobs, tool outputs, HTTP exchanges, test hypotheses, findings, evidence, reports, settings and audit events persist in SQLite.
- Search and filter all normalized records locally.
- External integrations are optional, discoverable and version-aware.
- Offline/no-AI mode remains functional.
- Import/export uses documented schemas and strict limits.
- Every operation has visible status and recoverable error.
- App data location and backup/restore are documented.
- No automatic telemetry.
- User can cancel jobs and shutdown does not leave child processes running.

## 5. Non-functional requirements

- Linux x86_64 first-class tested target.
- Architecture separates UI, domain/services, storage, orchestrator and adapters.
- Type hints and static checks for Python; strict TypeScript; Rust clippy/fmt.
- DB transactions and migrations; app startup validates migration state.
- Logs rotated, redacted and local.
- Accessibility: focus visibility, keyboard support, readable contrast, reduced motion.
- Responsive layout for smaller desktop windows; no critical UI overflow.
- Large outputs streamed/chunked rather than loaded unbounded into memory.
- Graceful behavior if tools/Gemini/Internet are unavailable.

## 6. Out of scope for initial release

- Autonomous exploitation or arbitrary command execution from LLM.
- General internet-wide scanning, credential stuffing, destructive tests, stealth/evasion.
- Automatic account creation, bypassing WAF/CAPTCHA, or accessing unrelated users' data.
- Cloud sync / multi-tenant service / hosted secret relay.
- Guaranteeing discovery of vulnerabilities.
- Bundling every third-party binary by default.

## 7. Success metrics

Collect only locally by default; no telemetry. Evaluate via test fixtures:
- scope guard rejects all known out-of-scope test cases.
- no known secret leaks in export/log fixtures.
- output dedup precision and false-positive rate measured on a seeded labeled dataset.
- crash/cancel tests leave no child process and mark interrupted jobs accurately.
- UI critical workflows pass end-to-end tests.
- reproducible clean build steps documented.

## 8. MVP vs release

“MVP” is an internal staged build, not a public quality claim. Public release requires core workflows, scope guard, data protection, tests, Linux packaging, third-party license inventory, and honest release notes to be complete.
