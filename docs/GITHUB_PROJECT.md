# GitHub Repository & Open-Source Readiness

## Before publishing

- Ensure no `.env`, secrets, user database, raw evidence, HAR files, reports, logs, private targets or generated artifacts are staged.
- Scan history as well as the working tree for secrets. If a secret was committed, rotate/revoke it; deleting the visible line is not enough.
- Pick a license intentionally. This kit uses MIT as a default placeholder for the new project's own original code; confirm this matches the owner's intended reuse model before public release. External dependencies and tool templates keep their own licenses.
- Provide README with scope/use disclaimer, installation, supported platform matrix, safety defaults, tool installation notes, screenshots generated from the real app, test instructions, limitations and contribution guidance.
- Add `SECURITY.md`, `CONTRIBUTING.md`, issue templates and pull request template.
- Use protected default branch and require CI checks before merge if available.
- Add topics such as `bug-bounty`, `appsec`, `penetration-testing`, `tauri`, `python` only if accurate.
- Include CHANGELOG and version tags; generate checksums for release assets.

## Suggested README sections

1. What BoundaryX is / is not.
2. Feature status (implemented, experimental, planned) — truthful.
3. Screenshots of the actual running app only.
4. Supported OS/distro/architecture and optional external tools.
5. Build from source and test commands.
6. Gemini BYOK setup, privacy, provider limits and no-AI mode.
7. Scope/safety defaults and authorized-use notice.
8. Known limitations.
9. Development/contribution process.
10. License and third-party notices.

## Repo hygiene

- Commit source and lockfiles, not virtualenvs, `node_modules`, build output, target directories, local DBs or tool binaries.
- `.env.example` must contain only fake/empty placeholders.
- Keep fixtures synthetic or legally redistributable and scrubbed.
- Make CI tests work without API keys or external scanner binaries.
- Never use real customer/target data in screenshots, demos or test fixtures.

## Licensing note

A public GitHub repository without an explicit license does not automatically grant users ordinary open-source reuse rights. Read GitHub's license guidance and choose a license that fits the project: <https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository>.
