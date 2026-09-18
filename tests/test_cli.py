from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_context_xray import cli
from codex_context_xray.cli import main
from codex_context_xray.demo import create_demo_repo


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "AGENTS.md").write_text("Fictional.\n", encoding="utf-8")
    return repo


def test_scan_human_and_json_outputs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = _repo(tmp_path)
    assert main(["scan", str(repo), "--trust", "trusted"]) == 0
    assert "Codex Context X-Ray" in capsys.readouterr().out

    assert main(["scan", str(repo), "--trust", "trusted", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 1


def test_html_requires_a_destination_or_open(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path)

    assert main(["scan", str(repo), "--format", "html"]) == 2
    assert "requires --output PATH or --open" in capsys.readouterr().err


def test_html_open_is_explicit_and_writes_one_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    output = tmp_path / "report.html"
    opened: list[str] = []
    monkeypatch.setattr(cli.webbrowser, "open", lambda uri: opened.append(uri) or True)

    result = main(
        [
            "scan",
            str(repo),
            "--trust",
            "trusted",
            "--format",
            "html",
            "--output",
            str(output),
            "--open",
        ]
    )

    assert result == 0
    assert output.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert opened == [output.resolve().as_uri()]


def test_fail_on_warning_uses_exit_code_one(tmp_path: Path) -> None:
    target = create_demo_repo(tmp_path)

    assert main(["scan", str(target), "--trust", "trusted", "--fail-on", "warning"]) == 1
    assert main(["scan", str(target), "--trust", "trusted", "--fail-on", "error"]) == 0


def test_explain_known_and_unknown_rule(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["explain", "PERMISSIONS_LEGACY_CONFLICT"]) == 0
    assert "Legacy sandbox" in capsys.readouterr().out

    assert main(["explain", "NOT_A_RULE"]) == 2
    assert "Unknown rule" in capsys.readouterr().err


def test_demo_completes_without_network_or_user_input(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli.webbrowser, "open", lambda _uri: pytest.fail("browser opened"))

    assert main(["demo"]) == 0
    assert "Codex Context X-Ray" in capsys.readouterr().out
