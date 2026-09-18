from __future__ import annotations

from pathlib import Path

from codex_context_xray.analyzers.config import analyze_config
from codex_context_xray.analyzers.mcp import analyze_mcp
from codex_context_xray.model import ScanContext, SourceStatus


def _ctx(root: Path, target: Path | None = None) -> ScanContext:
    return ScanContext(
        target=target or root,
        repo_root=root,
        include_user=False,
        user_home=None,
        codex_home=None,
        profile=None,
        trust_requested="trusted",
        trust_effective="trusted",
        cli_overrides=[],
    )


def test_mcp_partial_override_and_tool_filter_conflict(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    nested = root / "app"
    (root / ".codex").mkdir(parents=True)
    (nested / ".codex").mkdir(parents=True)
    (root / ".codex" / "config.toml").write_text(
        """
[mcp_servers.docs]
command = "secret-runner --token should-never-be-reported"
enabled = true
enabled_tools = ["search", "open"]
""".strip(),
        encoding="utf-8",
    )
    (nested / ".codex" / "config.toml").write_text(
        """
[mcp_servers.docs]
required = true
disabled_tools = ["search"]
""".strip(),
        encoding="utf-8",
    )
    ctx = _ctx(root, nested)
    _, effective = analyze_config(ctx)

    result = analyze_mcp(ctx, effective)

    docs = result.state["mcp"]["servers"][0]
    assert docs == {
        "name": "docs",
        "status": "enabled",
        "enabled": True,
        "required": True,
        "transport": "stdio",
        "enabled_tools": ["open", "search"],
        "disabled_tools": ["search"],
        "effective_denials": ["search"],
        "approvals_configured": False,
    }
    assert any(finding.rule_id == "MCP_SERVER_OVERRIDE" for finding in result.findings)
    assert any(finding.rule_id == "MCP_TOOL_FILTER_OVERLAP" for finding in result.findings)
    serialized = repr(result.state) + repr([source.metadata for source in result.sources])
    assert "should-never-be-reported" not in serialized


def test_required_disabled_server_is_an_error(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    ctx = _ctx(root)
    result = analyze_mcp(
        ctx,
        {
            "mcp_servers": {
                "broken": {
                    "url": "https://example.invalid",
                    "enabled": False,
                    "required": True,
                }
            }
        },
    )

    source = next(source for source in result.sources if source.metadata.get("server") == "broken")
    assert source.status is SourceStatus.IGNORED
    assert any(finding.rule_id == "MCP_REQUIRED_DISABLED" for finding in result.findings)


def test_invalid_server_table_is_reported(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    result = analyze_mcp(_ctx(root), {"mcp_servers": ["not", "a", "table"]})
    assert any(finding.rule_id == "MCP_INVALID_CONFIGURATION" for finding in result.findings)
    assert any(source.status is SourceStatus.INVALID for source in result.sources)
