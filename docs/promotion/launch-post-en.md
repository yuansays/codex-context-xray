# Launch draft — English

> Draft only. Review the wording and choose a community before publishing.

## Short version

I built Codex Context X-Ray, an offline CLI that explains what Codex will load,
override, ignore, or leave conditional before it starts work.

It reconstructs the documented chain for AGENTS files, project config, Skills,
MCP servers, hooks, command rules, and permissions. The result is a clickable,
self-contained HTML report with source provenance and redacted excerpts.

The scanner is repository-only by default, makes no network requests, launches
nothing, and never reads auth files, sessions, browser data, logs, databases, or
environment values. User-level config is opt-in with `--include-user`.

```bash
pipx install "git+https://github.com/yuansays/codex-context-xray.git@v0.1.0"
codex-xray demo --open
codex-xray scan . --format html --output codex-xray.html --open
```

Repository: https://github.com/yuansays/codex-context-xray

I would especially value small, synthetic compatibility fixtures when the
report differs from current Codex behavior. Please do not attach private
configuration or real credentials to an issue.

## Suggested title

Show: Codex Context X-Ray — see which instructions, tools, and permissions win

## Before publishing

- Replace no text with unverified usage or adoption claims.
- Attach only the fictional demo GIF from `docs/assets/demo.gif`.
- Link to a fixed release tag, not an unpinned branch install.
- Tailor the final sentence to the selected community's rules.
