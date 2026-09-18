"""A fully fictional repository and report used by ``codex-xray demo``."""

from __future__ import annotations

from pathlib import Path

from .html_report import render_html
from .model import Finding, Layer, Report, Severity, Source, SourceStatus

_DEMO_FILES: dict[str, str] = {
    "AGENTS.md": """# Fictional Acme Observatory instructions

- Keep generated observations deterministic.
- Never contact an external service.
""",
    "apps/orbit/AGENTS.md": """# Legacy orbit instructions

- Use the old dashboard layout.
""",
    "apps/orbit/AGENTS.override.md": """# Current orbit override

- Use the compact dashboard layout.
- Keep all sample coordinates fictional.
""",
    ".agents/skills/demo-review/SKILL.md": """---
name: demo-review
description: Review a fictional observatory change from the repository root.
---

# Demo review

Summarize deterministic changes only.
""",
    "apps/orbit/.agents/skills/demo-review/SKILL.md": """---
name: demo-review
description: Review a fictional orbit app change from its nested directory.
---

# Nested demo review

Report the local app scope.
""",
    ".codex/config.toml": """sandbox_mode = "workspace-write"
default_permissions = "review"

[permissions.review]
extends = ":read-only"

[mcp_servers.catalog]
command = "python"
args = ["tools/fictional_catalog.py"]
enabled = true

[hooks]
SessionStart = [{ command = ["python", "tools/fictional_inline_hook.py"] }]
""",
    "apps/orbit/.codex/config.toml": """[mcp_servers.catalog]
enabled = false
required = false
disabled_tools = ["lookup_sample"]
""",
    ".codex/hooks.json": """{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "startup",
        "hooks": [
          {
            "type": "command",
            "command": "python tools/fictional_json_hook.py"
          }
        ]
      }
    ]
  }
}
""",
    ".codex/rules/repository.rules": """prefix_rule(
    pattern = ["git", "status"],
    decision = "allow",
    justification = "Read the fictional repository status."
)

prefix_rule(
    pattern = ["git"],
    decision = "prompt",
    justification = "Ask before other git operations."
)
""",
    "tools/README.md": """# Fictional tools

The commands referenced by this fixture are declarations only. The demo never executes them.
""",
}


def create_demo_repo(root: Path) -> Path:
    """Create a fictional Codex repository and return its nested scan target.

    ``root`` must be an empty destination supplied by the caller (normally a
    temporary directory). Existing files are never overwritten. Returning the
    nested ``apps/orbit`` directory makes the root-to-target precedence chain
    visible to the normal scanner without a demo-specific code path.
    """

    destination = root.resolve() / "fictional-acme-observatory"
    if destination.exists():
        raise FileExistsError(f"Demo destination already exists: {destination}")
    destination.mkdir(parents=True)
    (destination / ".git").mkdir()
    for relative_path, content in sorted(_DEMO_FILES.items()):
        target = destination / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
    return destination / "apps" / "orbit"


def build_demo_report() -> Report:
    """Return the expected causal story for the bundled fictional fixture."""

    sources = [
        Source(
            id="instructions-root",
            kind="instructions",
            scope="repository",
            path="AGENTS.md",
            status=SourceStatus.ACTIVE,
            reason="Loaded first from the repository root.",
            precedence=10,
            excerpt="Keep generated observations deterministic.",
        ),
        Source(
            id="instructions-nested-default",
            kind="instructions",
            scope="apps/orbit",
            path="apps/orbit/AGENTS.md",
            status=SourceStatus.SHADOWED,
            reason="AGENTS.override.md wins in the same directory.",
            precedence=20,
            excerpt="Use the old dashboard layout.",
        ),
        Source(
            id="instructions-nested-override",
            kind="instructions",
            scope="apps/orbit",
            path="apps/orbit/AGENTS.override.md",
            status=SourceStatus.ACTIVE,
            reason="The nested override is appended after the root instructions.",
            precedence=21,
            excerpt="Use the compact dashboard layout.",
        ),
        Source(
            id="skill-root-demo-review",
            kind="skill",
            scope="repository",
            path=".agents/skills/demo-review/SKILL.md",
            status=SourceStatus.CONDITIONAL,
            reason="The Skill is catalogued; full instructions load only if activated.",
            precedence=30,
            excerpt="name: demo-review",
        ),
        Source(
            id="skill-nested-demo-review",
            kind="skill",
            scope="apps/orbit",
            path="apps/orbit/.agents/skills/demo-review/SKILL.md",
            status=SourceStatus.CONDITIONAL,
            reason="Duplicate Skill names remain separately discoverable until activation.",
            precedence=31,
            excerpt="name: demo-review",
        ),
        Source(
            id="mcp-root-catalog",
            kind="mcp",
            scope="repository",
            path=".codex/config.toml#mcp_servers.catalog",
            status=SourceStatus.SHADOWED,
            reason="A closer project layer redeclares the same MCP server id.",
            precedence=40,
            excerpt="catalog: stdio declaration",
        ),
        Source(
            id="mcp-nested-catalog",
            kind="mcp",
            scope="apps/orbit",
            path="apps/orbit/.codex/config.toml#mcp_servers.catalog",
            status=SourceStatus.ACTIVE,
            reason="The nearest project declaration wins for catalog.",
            precedence=41,
            excerpt="catalog: disabled local HTTP declaration",
        ),
        Source(
            id="hook-json-session-start",
            kind="hook",
            scope="repository",
            path=".codex/hooks.json#SessionStart",
            status=SourceStatus.ACTIVE,
            reason="Matching hooks merge and run together when hooks are enabled.",
            precedence=50,
            excerpt="python tools/fictional_json_hook.py",
            metadata={"condition": "Project is trusted and hooks are enabled."},
        ),
        Source(
            id="hook-inline-session-start",
            kind="hook",
            scope="repository",
            path=".codex/config.toml#hooks.SessionStart",
            status=SourceStatus.ACTIVE,
            reason="Inline hooks merge with hooks.json in the same layer.",
            precedence=51,
            excerpt="python tools/fictional_inline_hook.py",
            metadata={"condition": "Project is trusted and hooks are enabled."},
        ),
        Source(
            id="rule-git-status",
            kind="exec-rule",
            scope="repository",
            path=".codex/rules/repository.rules",
            status=SourceStatus.ACTIVE,
            reason="The most restrictive matching decision is effective.",
            precedence=60,
            excerpt="git status: prompt overrides allow",
            metadata={"condition": "The command starts with git status."},
        ),
        Source(
            id="legacy-sandbox-mode",
            kind="sandbox",
            scope="repository",
            path=".codex/config.toml#sandbox_mode",
            status=SourceStatus.ACTIVE,
            reason="Legacy sandbox settings take precedence when both systems appear.",
            precedence=70,
            excerpt='sandbox_mode = "workspace-write"',
        ),
        Source(
            id="permission-profile-review",
            kind="permission-profile",
            scope="repository",
            path=".codex/config.toml#permissions.review",
            status=SourceStatus.IGNORED,
            reason="The legacy sandbox_mode prevents permission profiles from composing.",
            precedence=71,
            excerpt='extends = ":read-only"',
        ),
    ]
    layers = [
        Layer(
            id="repository-root",
            kind="project",
            scope="repository",
            precedence=10,
            source_ids=[source.id for source in sources if source.scope == "repository"],
            reason="Fictional repository root layer.",
        ),
        Layer(
            id="orbit-target",
            kind="project",
            scope="apps/orbit",
            precedence=20,
            source_ids=[source.id for source in sources if source.scope == "apps/orbit"],
            reason="Closer target layer overrides matching project keys.",
        ),
    ]
    findings = [
        Finding(
            id="demo-instruction-override",
            rule_id="instructions.same-directory-override",
            severity=Severity.INFO,
            title="Nested instruction override selected",
            message="The default AGENTS.md beside AGENTS.override.md is shadowed.",
            source_ids=["instructions-nested-default", "instructions-nested-override"],
        ),
        Finding(
            id="demo-duplicate-skill",
            rule_id="skills.duplicate-name",
            severity=Severity.WARNING,
            title="Duplicate Skill name",
            message="Two discoverable Skills declare the name demo-review.",
            source_ids=["skill-root-demo-review", "skill-nested-demo-review"],
        ),
        Finding(
            id="demo-mcp-override",
            rule_id="mcp.same-id-override",
            severity=Severity.INFO,
            title="MCP declaration overridden",
            message="The target-local catalog declaration shadows the root declaration.",
            source_ids=["mcp-root-catalog", "mcp-nested-catalog"],
        ),
        Finding(
            id="demo-hook-merge",
            rule_id="hooks.mixed-declarations",
            severity=Severity.WARNING,
            title="JSON and inline hooks merge",
            message="Both SessionStart declarations remain active in this layer.",
            source_ids=["hook-json-session-start", "hook-inline-session-start"],
        ),
        Finding(
            id="demo-permissions-conflict",
            rule_id="permissions.legacy-conflict",
            severity=Severity.WARNING,
            title="Legacy sandbox and permission profile conflict",
            message="sandbox_mode is effective; the review permission profile does not compose.",
            source_ids=["legacy-sandbox-mode", "permission-profile-review"],
        ),
    ]
    return Report(
        schema_version=1,
        tool={"name": "Codex Context X-Ray", "version": "0.1.0"},
        coverage={
            "mode": "fictional demo",
            "network": "not used",
            "target": "fictional-acme-observatory/apps/orbit",
            "user_config": "not requested",
        },
        layers=layers,
        sources=sources,
        effective_state={
            "instructions": ["instructions-root", "instructions-nested-override"],
            "mcp_servers": {"catalog": "mcp-nested-catalog"},
            "permissions": "legacy sandbox_mode",
        },
        findings=findings,
        redactions=[],
    )


def render_demo_report(report: Report, output: Path) -> Path:
    """Write a supplied demo scan result as offline HTML and return its path."""

    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_html(report), encoding="utf-8", newline="\n")
    return output


__all__ = ["build_demo_report", "create_demo_repo", "render_demo_report"]
