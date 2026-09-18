from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from codex_context_xray import scanner
from codex_context_xray.model import SourceStatus
from codex_context_xray.render import render_json
from codex_context_xray.scanner import ScanError, scan


def _repo(tmp_path: Path, name: str = "repo 中文 space") -> Path:
    repo = tmp_path / name
    (repo / ".git").mkdir(parents=True)
    (repo / "AGENTS.md").write_text("Root instructions.\n", encoding="utf-8")
    return repo


def _tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def test_default_scan_does_not_resolve_or_read_user_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)

    def forbidden() -> tuple[Path, Path]:
        raise AssertionError("default scan attempted user discovery")

    monkeypatch.setattr(scanner, "_user_locations", forbidden)
    report = scan(repo, trust="auto")

    assert report.coverage["include_user"] is False
    assert report.coverage["trust"]["effective"] == "conditional"
    assert any(source.status is SourceStatus.UNOBSERVED for source in report.sources)


def test_scan_is_byte_for_byte_read_only_and_schema_is_stable(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    nested = repo / "服务" / "api"
    nested.mkdir(parents=True)
    (nested / "AGENTS.override.md").write_text("Nested instructions.\n", encoding="utf-8")
    before = _tree_hash(repo)

    report = scan(nested, trust="trusted")
    payload = json.loads(render_json(report))

    assert _tree_hash(repo) == before
    assert report.schema_version == 1
    assert set(payload) == {
        "coverage",
        "effective_state",
        "findings",
        "layers",
        "redactions",
        "schema_version",
        "sources",
        "tool",
    }
    assert payload["coverage"]["target"] == "./服务/api"


def test_auto_trust_can_use_opted_in_user_project_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    home = tmp_path / "fictional home"
    codex_home = home / ".codex"
    codex_home.mkdir(parents=True)
    project_key = repo.resolve().as_posix()
    (codex_home / "config.toml").write_text(
        f'[projects."{project_key}"]\ntrust_level = "trusted"\n', encoding="utf-8"
    )
    (repo / ".codex").mkdir()
    (repo / ".codex" / "config.toml").write_text('model = "fictional"\n', encoding="utf-8")
    monkeypatch.setattr(scanner, "_user_locations", lambda: (home, codex_home))

    report = scan(repo, include_user=True, trust="auto")

    assert report.coverage["trust"]["effective"] == "trusted"
    project_sources = [source for source in report.sources if source.scope == "project"]
    assert project_sources
    assert all(source.status is not SourceStatus.CONDITIONAL for source in project_sources)
    serialized = render_json(report)
    assert str(home) not in serialized
    assert "$HOME" in serialized


def test_profile_requires_explicit_user_scope(tmp_path: Path) -> None:
    repo = _repo(tmp_path)

    with pytest.raises(ScanError, match="--include-user"):
        scan(repo, profile="focus")


def test_missing_target_is_a_runtime_error(tmp_path: Path) -> None:
    with pytest.raises(ScanError, match="does not exist"):
        scan(tmp_path / "missing")


def test_cli_override_is_parsed_as_toml_data_not_a_shell_command(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    marker = tmp_path / "must-not-exist"

    report = scan(
        repo,
        trust="trusted",
        cli_overrides=[f'notice="$(touch {marker.as_posix()}) & whoami"'],
    )

    assert not marker.exists()
    cli_source = next(source for source in report.sources if source.id == "config:cli")
    assert cli_source.status is SourceStatus.ACTIVE
    assert cli_source.metadata["keys"] == ["notice"]


def test_global_instructions_do_not_consume_project_byte_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    home = tmp_path / "home"
    codex_home = home / ".codex"
    codex_home.mkdir(parents=True)
    user_text = "global-" * 20
    (codex_home / "AGENTS.md").write_text(user_text, encoding="utf-8")
    (codex_home / "config.toml").write_text(
        "project_doc_max_bytes = 5\n", encoding="utf-8"
    )
    monkeypatch.setattr(scanner, "_user_locations", lambda: (home, codex_home))

    report = scan(repo, include_user=True, trust="trusted")
    state = report.effective_state["instructions"]

    assert state["user_bytes_loaded"] == len(user_text.encode())
    assert state["project_bytes_loaded"] == 5
    assert state["bytes_loaded"] == len(user_text.encode()) + 5
    user_source = next(
        source for source in report.sources if source.path == "$CODEX_HOME/AGENTS.md"
    )
    assert user_source.status is SourceStatus.ACTIVE
    assert user_source.metadata["truncated"] is False


def test_zero_project_instruction_budget_is_respected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    home = tmp_path / "home"
    codex_home = home / ".codex"
    codex_home.mkdir(parents=True)
    (codex_home / "config.toml").write_text(
        "project_doc_max_bytes = 0\n", encoding="utf-8"
    )
    monkeypatch.setattr(scanner, "_user_locations", lambda: (home, codex_home))

    report = scan(repo, include_user=True, trust="trusted")
    state = report.effective_state["instructions"]

    assert state["max_bytes"] == 0
    assert state["project_bytes_loaded"] == 0
    assert not any(
        item["source_id"].startswith("instructions:repo:") for item in state["chain"]
    )
