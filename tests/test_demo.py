from __future__ import annotations

from pathlib import Path

import pytest

from codex_context_xray.demo import build_demo_report, create_demo_repo, render_demo_report
from codex_context_xray.model import Severity, SourceStatus
from codex_context_xray.scanner import scan


def test_create_demo_repo_contains_every_conflict_story(tmp_path: Path) -> None:
    target = create_demo_repo(tmp_path)
    repo = target.parents[1]

    assert target == tmp_path.resolve() / "fictional-acme-observatory/apps/orbit"
    assert (repo / ".git").is_dir()
    assert (repo / "AGENTS.md").is_file()
    assert (repo / "apps/orbit/AGENTS.md").is_file()
    assert (repo / "apps/orbit/AGENTS.override.md").is_file()
    assert (repo / ".agents/skills/demo-review/SKILL.md").is_file()
    assert (repo / "apps/orbit/.agents/skills/demo-review/SKILL.md").is_file()
    assert (repo / ".codex/hooks.json").is_file()
    assert (repo / ".codex/rules/repository.rules").is_file()

    root_config = (repo / ".codex/config.toml").read_text(encoding="utf-8")
    nested_config = (repo / "apps/orbit/.codex/config.toml").read_text(encoding="utf-8")
    assert 'sandbox_mode = "workspace-write"' in root_config
    assert 'default_permissions = "review"' in root_config
    assert "[permissions.review]" in root_config
    assert "[hooks]" in root_config
    assert "[mcp_servers.catalog]" in root_config
    assert "[mcp_servers.catalog]" in nested_config

    all_text = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(repo.rglob("*")) if path.is_file()
    )
    assert "fictional" in all_text.casefold()
    assert "C:\\Users\\" not in all_text


def test_create_demo_repo_never_overwrites_existing_destination(tmp_path: Path) -> None:
    target = create_demo_repo(tmp_path)
    repo = target.parents[1]
    sentinel = repo / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(FileExistsError):
        create_demo_repo(tmp_path)

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_demo_report_covers_all_requested_causal_examples() -> None:
    report = build_demo_report()
    rule_ids = {finding.rule_id for finding in report.findings}
    statuses = {source.status for source in report.sources}

    assert report.schema_version == 1
    assert report.max_severity is Severity.WARNING
    assert SourceStatus.ACTIVE in statuses
    assert SourceStatus.SHADOWED in statuses
    assert SourceStatus.CONDITIONAL in statuses
    assert SourceStatus.IGNORED in statuses
    assert {
        "instructions.same-directory-override",
        "skills.duplicate-name",
        "mcp.same-id-override",
        "hooks.mixed-declarations",
        "permissions.legacy-conflict",
    } <= rule_ids
    assert all(not source.path.startswith(("/", "C:\\")) for source in report.sources)


def test_real_scanner_observes_every_demo_interaction(tmp_path: Path) -> None:
    target = create_demo_repo(tmp_path)

    report = scan(target, trust="trusted")
    rule_ids = {finding.rule_id for finding in report.findings}
    source_by_path = {source.path: source for source in report.sources}

    assert {
        "SKILL_DUPLICATE_NAME",
        "MCP_SERVER_OVERRIDE",
        "HOOKS_MIXED_REPRESENTATIONS",
        "PERMISSIONS_LEGACY_CONFLICT",
        "RULES_OVERLAP",
    } <= rule_ids
    assert source_by_path["./apps/orbit/AGENTS.md"].status is SourceStatus.SHADOWED
    assert source_by_path["./apps/orbit/AGENTS.override.md"].status is SourceStatus.ACTIVE
    assert report.effective_state["permissions"]["mode"] == "legacy_sandbox"
    assert report.coverage["network_access"] is False
    assert report.coverage["target_mutated"] is False


def test_render_demo_report_writes_one_offline_html_file(tmp_path: Path) -> None:
    output = render_demo_report(build_demo_report(), tmp_path / "nested" / "demo.html")
    rendered = output.read_text(encoding="utf-8")

    assert output == (tmp_path / "nested" / "demo.html").resolve()
    assert rendered.startswith("<!doctype html>")
    assert rendered.count('<section class="lane"') == 4
    assert "permissions.legacy-conflict" in rendered
    assert "<script src=" not in rendered
