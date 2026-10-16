# Contributing to BoundaryX

Thanks for helping improve BoundaryX. The project values correctness, reproducibility, maintainability and safe defaults over feature count.

## Before opening a PR

- Search existing issues and discuss substantial architectural changes first.
- Follow `AGENT_RULES.md`, the relevant architecture docs and current code conventions.
- Add or update tests for behavior changes; do not disable a failing test to obtain a green CI run.
- Run the documented lint, typecheck and test commands.
- Do not include real API keys, private targets, HAR files, cookies, reports or raw evidence.
- Include updated documentation, migration notes and screenshots only from synthetic/local data.
- Check licenses for new dependencies and any bundled tool/template.

## PR expectations

- Explain the problem and intended change.
- Describe security/privacy implications and scope impact.
- List tests run and their actual results.
- Mark incomplete behavior as incomplete; no mock result should be presented as production functionality.

## Code principles

- Keep scope enforcement in the engine, not only UI.
- All subprocess invocations go through approved adapters.
- Keep AI output untrusted and schema-validated.
- Keep no-AI and no-external-tool workflows usable.
- Prefer small, testable modules with explicit error types.
