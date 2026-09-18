from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from codex_context_xray.analyzers.exec_rules import (
    analyze_exec_rules,
    patterns_overlap,
    strictest_decision,
)
from codex_context_xray.model import ScanContext, SourceStatus


def _context(repo: Path, *, trust: str = "trusted") -> ScanContext:
    return ScanContext(
        target=repo,
        repo_root=repo,
        include_user=False,
        user_home=None,
        codex_home=None,
        profile=None,
        trust_requested=trust,
        trust_effective=trust,
        cli_overrides=[],
    )


def _write_rules(repo: Path, name: str, text: str) -> Path:
    directory = repo / ".codex" / "rules"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path


def test_overlapping_rules_report_strictest_decision(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_rules(
        repo,
        "policy.rules",
        """
prefix_rule(pattern = ["git"], decision = "allow")
prefix_rule(pattern = ["git", ["push", "send"]], decision = "forbidden")
""".strip(),
    )

    result = analyze_exec_rules(_context(repo), {})

    rules = result.state["exec_rules"]["rules"]
    overlaps = result.state["exec_rules"]["overlaps"]
    assert len(rules) == 2
    assert overlaps[0]["strictest_decision"] == "forbidden"
    assert any(finding.rule_id == "RULES_OVERLAP" for finding in result.findings)
    assert result.state["exec_rules"]["evaluation_performed"] is False


def test_invalid_starlark_syntax_is_an_error(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_rules(repo, "broken.rules", 'prefix_rule(pattern = ["git"], decision =')

    result = analyze_exec_rules(_context(repo), {})

    assert result.sources[0].status == SourceStatus.INVALID
    assert any(finding.rule_id == "RULES_PARSE_ERROR" for finding in result.findings)


def test_invalid_prefix_rule_field_is_an_error(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_rules(repo, "broken.rules", 'prefix_rule(pattern = ["git"], decision = "maybe")')

    result = analyze_exec_rules(_context(repo), {})

    assert result.sources[0].status == SourceStatus.INVALID
    assert any(finding.rule_id == "RULES_INVALID" for finding in result.findings)


def test_dynamic_starlark_is_conditional_not_executed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_rules(
        repo,
        "dynamic.rules",
        'rule_pattern = ["git"]\nprefix_rule(pattern = rule_pattern)',
    )

    result = analyze_exec_rules(_context(repo), {})

    assert result.sources[0].status == SourceStatus.CONDITIONAL
    assert any(finding.rule_id == "RULES_STATIC_ANALYSIS_INCOMPLETE" for finding in result.findings)
    assert result.sources[0].metadata["evaluation_performed"] is False


def test_sensitive_rule_argument_is_redacted(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_rules(
        repo,
        "sensitive.rules",
        'prefix_rule(pattern = ["client", "--token", "fictional-rule-token"], decision = "prompt")',
    )

    result = analyze_exec_rules(_context(repo), {})
    serialized = json.dumps(asdict(result), ensure_ascii=False, default=str)

    assert "fictional-rule-token" not in serialized
    assert result.state["exec_rules"]["rules"][0]["pattern"][2] == "<redacted>"


def test_untrusted_project_rules_do_not_affect_effective_overlaps(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_rules(repo, "policy.rules", 'prefix_rule(pattern = ["git"], decision = "forbidden")')

    result = analyze_exec_rules(_context(repo, trust="untrusted"), {})

    assert result.sources[0].status == SourceStatus.IGNORED
    assert result.state["exec_rules"]["rules"][0]["ignored"] is True
    assert result.state["exec_rules"]["overlaps"] == []


def test_pattern_overlap_supports_literal_unions() -> None:
    assert patterns_overlap(["git", ["push", "send"]], ["git", "push", "origin"])
    assert not patterns_overlap(["git", ["push", "send"]], ["git", "status"])
    assert strictest_decision(["allow", "prompt", "forbidden"]) == "forbidden"
