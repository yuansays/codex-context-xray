# Codex adapter contract

Codex Context X-Ray v0.1 implements an offline interpretation of documented
Codex behavior. The documentation and open-source loader snapshot were reviewed
on **2026-09-18**.

| Surface | Official source | Deterministic behavior used |
|---|---|---|
| Project instructions | [AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md) and [loader source](https://github.com/openai/codex/blob/main/codex-rs/core/src/agents_md.rs) | Global override-or-default outside the project budget; one project file per directory; root-to-target order; shared 32 KiB default project budget |
| Configuration | [Config basics](https://learn.chatgpt.com/docs/config-file/config-basic) | CLI, trusted project, profile, user, cloud, system, built-in precedence |
| Configuration keys | [Config reference](https://learn.chatgpt.com/docs/config-file/config-reference) | Known tables, project restrictions, feature declarations |
| Skills | [Build skills](https://learn.chatgpt.com/docs/build-skills) | Repository/user/admin/system discovery and duplicate-name behavior |
| MCP | [MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) | Server declarations, enablement, required state, tools, approvals |
| Hooks | [Hooks](https://learn.chatgpt.com/docs/hooks) | JSON plus inline merge, trust, feature gate, plugin condition |
| Exec policy | [Rules](https://learn.chatgpt.com/docs/agent-configuration/rules) | Prefix rules and strictest matching decision |
| Permissions | [Permissions](https://learn.chatgpt.com/docs/permissions) | Permission profiles, inheritance, legacy sandbox precedence |

## Confidence labels

- `active`: the source participates under the selected scan inputs.
- `shadowed`: a documented higher-priority source replaces it.
- `conditional`: activation depends on trust, a trigger, or runtime state that
  was not selected or cannot be observed statically.
- `ignored`: Codex's documented rules exclude the source.
- `invalid`: parsing or structural validation failed.
- `unobserved`: the surface is outside the offline scan boundary.

## Non-goals

The adapter does not infer semantic contradictions in prose. It does not query
Codex, start a session, contact OpenAI, execute hooks or rules, or inspect hidden
platform policy. Managed requirements and cloud defaults are therefore reported
as unobserved unless a future explicit input format makes them inspectable.

When the official behavior changes, update the adapter, tests, fixture, this
contract date, and release notes together.
