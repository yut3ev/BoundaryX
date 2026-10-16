# Linux Development, Packaging & Distribution

## Supported target strategy

Initial declared target: Linux x86_64, tested on a named distro/version (recommend Ubuntu LTS for CI) and an additional clean-environment smoke test. Treat Fedora, Arch, Debian stable and ARM64 as supported only after separate verification. Tauri/WebKit runtime dependencies can vary by distro; package accordingly and document them.

## Developer prerequisites

- Git.
- Node.js LTS and the chosen package manager.
- Rust stable toolchain.
- Python version supported by the current engine, managed via `uv`.
- Tauri v2 Linux system dependencies. Check official current guidance: <https://v2.tauri.app/start/prerequisites/>.
- Project dependencies installed from committed lockfiles.

For Debian/Ubuntu, Tauri's current prerequisites commonly include packages in the WebKitGTK 4.1, build-essential, OpenSSL, appindicator, librsvg and xdo families; the exact package names must be verified against the target distro and current official docs before copying commands into the installer.

## Development commands

The agent must create and document a consistent command set, e.g.:
- install dependencies from lockfiles
- run desktop app in dev mode
- run all lint/type/test checks
- build engine sidecar
- build release app bundle

Do not put unknown commands in docs; every example should be run before release.

## Engine packaging

- Build the Python engine as a platform-specific sidecar.
- Check PyInstaller (or alternative) collection of dynamic libraries, certificates, templates and resource files.
- No dependency may rely on a developer's home directory or globally installed Python packages.
- Verify subprocesses find user-installed tool binaries in a predictable, documented way, while preserving a safe PATH.
- Include architecture triplet handling and sidecar naming required by the selected Tauri version.
- Avoid requiring `sudo` for app startup or scan execution.

## Artifacts

Preferred first release if toolchain supports it:
- `.deb` for tested Debian/Ubuntu target.
- AppImage only after testing FUSE/runtime requirements and external-tool discovery.
- `.rpm` and Flatpak later, after permissions/sandbox and tool access behavior are reviewed.

Do not label one package “Universal Linux” unless verified against the promised set of distros. Explain external runtime libraries and optional tools.

## GitHub Actions

- Separate CI (pull requests/push) from Release (version tag only).
- Install required Tauri/Linux system dependencies in the workflow.
- Cache language package downloads safely but keep lockfile validation.
- Run Python/TS/Rust tests and build. Use least-privilege `permissions`.
- Avoid printing secrets/environment values.
- Release produces checksums and changelog; preserve build logs for diagnosing failures.
- Pin third-party GitHub Actions to reviewed major versions or immutable commit SHAs according to repository policy.

## Clean-install smoke test

1. Start from a clean VM or container supported by the artifact.
2. Install without developer packages where possible.
3. Launch app and check engine handshake, app-data dirs, SQLite migration and settings.
4. Run unit/local mock checks and a scan only against local lab/fixture.
5. Test shutdown/cancel, upgrade migration and uninstall data retention policy.
6. Verify app can run without Gemini key and without optional tool binaries.
7. Collect logs with secrets redacted and document limitations.

## Release process

1. Freeze feature changes.
2. Run complete test suite/security checks.
3. Review dependency and third-party licenses.
4. Update version/changelog and test results.
5. Build on tagged commit in CI.
6. Generate hashes and (if available) SBOM.
7. Test artifacts before marking release final.
8. Publish notes with known issues and required dependencies.
