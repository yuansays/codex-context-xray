from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_context_xray.analyzers.instructions import analyze_instructions
from codex_context_xray.model import ScanContext, SourceStatus


def _ctx(root: Path, target: Path | None = None) -> ScanContext:
    return ScanContext(
        target=target or root,
        repo_root=root,
        include_user=False,
        user_home=None,
        codex_home=None,
        profile=None,
        trust_requested="auto",
        trust_effective="conditional",
        cli_overrides=[],
    )


def test_root_to_target_override_shadow_and_byte_budget(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    nested = root / "services" / "api"
    nested.mkdir(parents=True)
    (root / "AGENTS.md").write_text("root rules", encoding="utf-8")
    (nested / "AGENTS.override.md").write_text("0123456789", encoding="utf-8")
    (nested / "AGENTS.md").write_text("shadowed", encoding="utf-8")

    result = analyze_instructions(_ctx(root, nested), max_bytes=15)

    state = result.state["instructions"]
    assert state["bytes_loaded"] == 15
    assert state["truncated"] is True
    assert [item["path"] for item in state["chain"]] == [
        "AGENTS.md",
        "services/api/AGENTS.override.md",
    ]
    override = next(
        source for source in result.sources if source.path.endswith("AGENTS.override.md")
    )
    normal = next(
        source for source in result.sources if source.path.endswith("services/api/AGENTS.md")
    )
    assert override.metadata == {"bytes_loaded": 5, "truncated": True, "directory_depth": 2}
    assert normal.status is SourceStatus.SHADOWED
    assert any(finding.rule_id == "INSTRUCTIONS_TRUNCATED" for finding in result.findings)


def test_custom_fallback_and_empty_standard_file(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "AGENTS.override.md").write_text("", encoding="utf-8")
    (root / "TEAM.md").write_text("team", encoding="utf-8")

    result = analyze_instructions(_ctx(root), fallback_filenames=("TEAM.md", "../escape"))

    selected = next(source for source in result.sources if source.path.endswith("TEAM.md"))
    empty = next(source for source in result.sources if source.path.endswith("AGENTS.override.md"))
    assert selected.status is SourceStatus.ACTIVE
    assert empty.status is SourceStatus.IGNORED
    assert result.state["instructions"]["source_ids"] == [selected.id]


def test_default_scan_does_not_observe_user_instructions(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    codex_home = tmp_path / "private" / ".codex"
    root.mkdir()
    codex_home.mkdir(parents=True)
    (codex_home / "AGENTS.md").write_text("private", encoding="utf-8")
    ctx = _ctx(root)
    ctx.codex_home = codex_home

    result = analyze_instructions(ctx)

    user = next(source for source in result.sources if source.scope == "user")
    assert user.status is SourceStatus.UNOBSERVED
    assert not result.state["instructions"]["source_ids"]


def test_instruction_symlink_cannot_escape_repository(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    outside = tmp_path / "private.md"
    root.mkdir()
    outside.write_text("external instructions", encoding="utf-8")
    link = root / "AGENTS.md"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("File symlinks are unavailable on this platform")

    result = analyze_instructions(_ctx(root))

    assert not result.state["instructions"]["source_ids"]
    escaped = next(source for source in result.sources if source.scope == "repo")
    assert escaped.status is SourceStatus.IGNORED
    assert any(finding.rule_id == "INSTRUCTIONS_PATH_ESCAPE" for finding in result.findings)
