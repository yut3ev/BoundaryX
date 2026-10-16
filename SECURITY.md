# Security Policy

## Supported versions

Security support is provided for the latest stable release unless the project explicitly documents otherwise.

## Reporting a vulnerability

Please do not publish exploit details or private user evidence in a public issue. Use GitHub's private vulnerability reporting feature if enabled, or contact the repository maintainer using a verified contact method listed in the repository profile. Do not invent or commit a personal email address here.

Include: affected version/commit, environment, minimal reproduction, expected/actual impact, logs with secrets removed. Allow maintainers reasonable time to investigate and coordinate a fix before public disclosure.

## Secret exposure

If a Gemini key or credential has been committed or shared, revoke/rotate it immediately. Removing it in a later commit does not remove it from Git history or cached forks.

## Scope and responsible testing

Security reports should concern BoundaryX or its shipped dependencies in a way that can be reproduced safely. Do not include tests against unrelated real targets. Use local labs and synthetic fixtures whenever possible.
