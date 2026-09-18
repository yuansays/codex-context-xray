<div align="center">

# Codex Context X-Ray

**See what Codex will load, override, ignore, or leave conditional — before it starts work.**

[![CI](https://github.com/yuansays/codex-context-xray/actions/workflows/ci.yml/badge.svg)](https://github.com/yuansays/codex-context-xray/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/yuansays/codex-context-xray)](https://github.com/yuansays/codex-context-xray/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-7c3aed.svg)](LICENSE)

[中文](README.zh-CN.md) · [Try the demo](#ten-second-tour) · [Security boundary](#what-x-ray-never-shows)

![Fictional Codex Context X-Ray demo](docs/assets/demo.gif)

</div>

Codex can inherit instructions, configuration, Skills, MCP servers, hooks, rules,
and permissions from several scopes. When one source wins, another is skipped by
trust, or a byte limit cuts the chain short, the result can be difficult to
explain from the files alone.

`codex-xray` reconstructs that chain locally and turns it into a causal map. It
does not ask a model to guess whether two paragraphs “mean the same thing.” It
reports deterministic loading, precedence, validation, and security conditions.

## Ten-second tour

```console
$ codex-xray demo
Codex Context X-Ray 0.1.0
Result: warning | Sources: 17 (active=9, shadowed=1, conditional=2, ignored=2, unobserved=3)
Findings: 5 (warning=4, info=1)
Coverage: mode=offline-static, target=./apps/orbit, repository_root=.,
          user_config=not requested, trust=trusted, network=not used,
          unobserved=5 areas

Findings
- [WARNING] Hook representations are merged (HOOKS_MIXED_REPRESENTATIONS): ...
- [WARNING] Legacy sandbox disables permission profiles (PERMISSIONS_LEGACY_CONFLICT): ...
- [WARNING] Prefix rules overlap (RULES_OVERLAP): ...
- [WARNING] Duplicate Skill name (SKILL_DUPLICATE_NAME): ...
- [INFO] MCP server is defined in multiple layers (MCP_SERVER_OVERRIDE): ...
```

The output above comes from the built-in, completely fictional example:

```bash
codex-xray demo --open
```

## Install

Python 3.10 or newer is required. v0.1 is distributed through signed Git tags
and GitHub Release artifacts; it is not published to PyPI yet.

```bash
# 1. Install the fixed release tag
pipx install "git+https://github.com/yuansays/codex-context-xray.git@v0.1.0"

# 2. Enter the repository you want to understand
cd your-project

# 3. Generate and open one self-contained report
codex-xray scan . --format html --output codex-xray.html --open
```

With `uv`:

```bash
uv tool install "git+https://github.com/yuansays/codex-context-xray.git@v0.1.0"
```

Every Release also includes a wheel, source archive, and `SHA256SUMS`.

## Commands

```text
codex-xray scan [TARGET]
  [--include-user]
  [--profile NAME]
  [--trust auto|trusted|untrusted]
  [-c KEY=VALUE ...]
  [--format human|json|html]
  [--output PATH]
  [--open]
  [--fail-on never|warning|error]

codex-xray demo [--open]
codex-xray explain <RULE_ID>
```

`TARGET` may be a file or directory. It controls the root-to-target instruction
and configuration chain. Human output goes to the terminal. JSON goes to stdout
unless `--output` is provided. HTML requires `--output`, or `--open` writes a
temporary report and opens it.

Use `--include-user` when you deliberately want to add user instructions,
configuration, Skills, hooks, and rules. Without it, X-Ray does not inspect the
home directory.

CI example:

```bash
codex-xray scan . --trust trusted --format json \
  --output codex-xray.json --fail-on error
```

Exit codes are stable:

| Code | Meaning |
|---:|---|
| `0` | The selected failure threshold was not reached |
| `1` | A finding reached `--fail-on` |
| `2` | The request, parser, or scan failed |

## What v0.1 understands

| Area | Codex behavior reproduced | Result |
|---|---|---|
| Instructions | `AGENTS.override.md`, `AGENTS.md`, fallback names, root-to-target order, byte budget | Active chain, shadowing, truncation |
| Configuration | user/profile/project/CLI precedence, nested project layers, trust, project-restricted keys | Effective values with provenance |
| Skills | repository and opted-in user discovery, frontmatter, duplicate names, enable/disable declarations | Available vs conditional Skills |
| MCP | same-name override, enabled/required, tool allow/deny, approvals | Effective server declarations |
| Hooks | `hooks.json`, inline hooks, feature gate, trust, same-layer merge | Merged lifecycle declarations |
| Rules | static Starlark `prefix_rule` parsing, overlaps, strictest decision | `forbidden > prompt > allow` |
| Permissions | legacy sandbox vs permission profiles, inheritance, filesystem/network declarations | Effective mode and conflicts |

The adapter is pinned to an explicit [official behavior contract](docs/ADAPTER_CONTRACT.md)
so changes in Codex documentation can be reviewed like code changes.

## The report

The HTML report is a single file with no CDN, analytics, server, or remote font.
Its four lanes are:

1. **Instructions** — which instruction file enters the prompt, and where the
   byte budget stops.
2. **Skills & Tools** — Skills and MCP declarations, including duplicates,
   overrides, and trigger-time conditions.
3. **Hooks & Rules** — merged hooks and deterministic command policy outcomes.
4. **Permissions** — the selected sandbox or permission profile and why.

Select any node to see its source, status, precedence, reason, and a redacted
safe excerpt. JSON uses `schema_version: 1` and stable top-level fields:
`coverage`, `layers`, `sources`, `effective_state`, `findings`, and `redactions`.

## Privacy by construction

- Repository-only by default, offline, read-only, and zero telemetry.
- User scope is inspected only with explicit `--include-user`.
- `auth.json`, sessions, logs, SQLite databases, browser data, and environment
  values are never inputs.
- Hooks, MCP servers, plugins, models, and repository code are never launched.
- Home paths become `$HOME`; credentials, private keys, signed query values,
  sensitive headers, and command arguments are redacted.
- Symlinks and junctions that escape the repository or opted-in user root are
  reported, not followed.

### What X-Ray never shows

X-Ray cannot expose hidden system prompts, live conversation context,
cloud-delivered policy, or runtime-only plugin payloads. It also does not claim
to understand arbitrary natural-language contradictions. Those surfaces appear
as `unobserved` or `conditional`, never as invented certainty.

This project is not affiliated with or endorsed by OpenAI. “Codex” is used only
to describe compatibility with the Codex configuration format.

## Why not a generic context linter?

Tools such as [CtxGov](https://github.com/ctxgov/ctxgov) address broader agent
context governance. X-Ray deliberately stays narrow: it reproduces Codex's
documented loading rules and shows the causal path in a clickable local report.
That makes a concrete answer possible without AI semantic scoring.

## Development

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"  # Windows
# .venv/bin/python -m pip install -e ".[dev]"   # macOS/Linux
pytest
ruff check .
mypy src
python -m build
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for fixture and privacy requirements.
Bug reports and small compatibility fixtures are especially useful.

## License

MIT © 2026 Yuan Says AI.
