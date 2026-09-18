# Security policy

## Supported version

Security fixes target the latest tagged release.

## Reporting a vulnerability

Please use GitHub private vulnerability reporting. Do not open a public issue
for a report that contains credentials, private paths, or other sensitive data.

## Product boundary

Codex Context X-Ray performs static, local inspection. It does not launch MCP
servers, hooks, plugins, models, or repository code. It does not claim that a
report proves a repository is safe; a report only describes what the current
deterministic rules could observe.
