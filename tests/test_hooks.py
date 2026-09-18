from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from codex_context_xray.analyzers.hooks import analyze_hooks
from codex_context_xray.model import ScanContext, SourceStatus


def _context(repo: Path, *, trust: str = "trusted", include_user: bool = False) -> ScanContext:
    home = repo.parent / "fictional-home"
    codex_home = home / ".codex"
    return ScanContext(
        target=repo,
        repo_root=repo,
        include_user=include_user,
        user_home=home if include_user else None,
        codex_home=codex_home if include_user else None,
        profile=None,
        trust_requested=trust,
        trust_effective=trust,
        cli_overrides=[],
    )


def test_hooks_json_and_inline_hooks_merge_without_execution(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    codex = repo / ".codex"
    codex.mkdir(parents=True)
    (codex / "hooks.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "runner --token fictional-hook-token",
                                }
                            ]
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    (codex / "config.toml").write_text(
        """
[hooks]
[[hooks.PostToolUse]]
matcher = "Bash"
[[hooks.PostToolUse.hooks]]
type = "command"
command = "review --password fictional-hook-password"
""".strip(),
        encoding="utf-8",
    )

    result = analyze_hooks(_context(repo), {"features": {"hooks": True}})
    serialized = json.dumps(asdict(result), ensure_ascii=False, default=str)

    assert len(result.sources) == 2
    assert all(source.status == SourceStatus.ACTIVE for source in result.sources)
    assert {"SessionStart", "PostToolUse"} <= set(result.state["hooks"]["events"])
    assert any(finding.rule_id == "HOOKS_MIXED_REPRESENTATIONS" for finding in result.findings)
    assert result.state["hooks"]["execution_performed"] is False
    assert result.state["hooks"]["mcp_connections_started"] is False
    assert "fictional-hook-token" not in serialized
    assert "fictional-hook-password" not in serialized


def test_project_hooks_are_ignored_when_project_is_untrusted(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    codex = repo / ".codex"
    codex.mkdir(parents=True)
    (codex / "hooks.json").write_text(json.dumps({"hooks": {"SessionEnd": []}}), encoding="utf-8")

    result = analyze_hooks(_context(repo, trust="untrusted"), {})

    assert result.sources[0].status == SourceStatus.IGNORED
    assert result.state["hooks"]["events"] == []


def test_hooks_feature_flag_disables_observed_sources(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    codex = repo / ".codex"
    codex.mkdir(parents=True)
    (codex / "hooks.json").write_text(json.dumps({"hooks": {"SessionStart": []}}), encoding="utf-8")

    result = analyze_hooks(_context(repo), {"features": {"hooks": False}})

    assert result.state["hooks"]["feature_enabled"] is False
    assert result.sources[0].status == SourceStatus.IGNORED


def test_invalid_hooks_json_is_reported_without_running_it(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    codex = repo / ".codex"
    codex.mkdir(parents=True)
    (codex / "hooks.json").write_text('{"hooks": [}', encoding="utf-8")

    result = analyze_hooks(_context(repo), {})

    assert result.sources[0].status == SourceStatus.INVALID
    assert result.sources[0].metadata["execution_performed"] is False
    assert any(finding.rule_id == "HOOKS_INVALID" for finding in result.findings)


def test_user_hooks_are_not_touched_without_include_user(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    context = _context(repo, include_user=False)
    user_hooks = repo.parent / "fictional-home" / ".codex" / "hooks.json"
    user_hooks.parent.mkdir(parents=True)
    user_hooks.write_text("not-json", encoding="utf-8")

    result = analyze_hooks(context, {})

    assert result.sources == []
    assert result.findings == []


def test_external_hook_layer_is_not_followed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside-codex"
    outside.mkdir()
    (outside / "hooks.json").write_text(
        json.dumps(
            {"hooks": {"SessionStart": [{"command": "runner --token must-never-enter-the-report"}]}}
        ),
        encoding="utf-8",
    )
    try:
        (repo / ".codex").symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory symlinks are unavailable on this runner")

    result = analyze_hooks(_context(repo), {})
    serialized = json.dumps(asdict(result), ensure_ascii=False, default=str)

    assert "must-never-enter-the-report" not in serialized
    assert result.sources[0].status == SourceStatus.IGNORED
    assert any(finding.rule_id == "PATH_ESCAPE" for finding in result.findings)
