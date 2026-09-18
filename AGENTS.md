# Contributor instructions

- Keep scans deterministic, offline, and read-only.
- Never read credentials, session history, browser data, logs, databases, or environment values.
- Treat documentation claims as versioned behavior and link to the official Codex source.
- Prefer explicit `unobserved` or `conditional` states over guesses.
- Tests must use synthetic paths and secrets only.
