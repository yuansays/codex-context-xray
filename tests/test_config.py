from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_context_xray.analyzers.config import analyze_config, config_provenance
from codex_context_xray.model import ScanContext, SourceStatus


def _ctx(
    root: Path,
    target: Path | None = None,
    *,
    include_user: bool = False,
    codex_home: Path | None = None,
    profile: str | None = None,
    trust: str = "trusted",
    overrides: list[str] | None = None,
) -> ScanContext:
    return ScanContext(
        target=target or root,
        repo_root=root,
        include_user=include_user,
        user_home=codex_home.parent if codex_home else None,
        codex_home=codex_home,
        profile=profile,
        trust_requested=trust,
        trust_effective=trust,
        cli_overrides=overrides or [],
    )


def test_user_profile_project_nested_and_cli_precedence(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    nested = root / "app"
    codex_home = tmp_path / "home" / ".codex"
    nested.mkdir(parents=True)
    codex_home.mkdir(parents=True)
    (codex_home / "config.toml").write_text(
        'model = "user"\n[features]\nhooks = false\n', encoding="utf-8"
    )
    (codex_home / "work.config.toml").write_text('model = "profile"\n', encoding="utf-8")
    (root / ".codex").mkdir()
    (root / ".codex" / "config.toml").write_text(
        'model = "root"\nprofile = "forbidden"\n[features]\nhooks = true\n',
        encoding="utf-8",
    )
    (nested / ".codex").mkdir()
    (nested / ".codex" / "config.toml").write_text('model = "nested"\n', encoding="utf-8")

    result, effective = analyze_config(
        _ctx(
            root,
            nested,
            include_user=True,
            codex_home=codex_home,
            profile="work",
            overrides=['model="cli"'],
        )
    )

    assert effective["model"] == "cli"
    assert effective["features"]["hooks"] is True
    assert "profile" not in effective
    assert [record.id for record in config_provenance(effective)] == [
        "config:user",
        "config:profile:work",
        "config:project:.",
        "config:project:app",
        "config:cli",
    ]
    assert any(finding.rule_id == "CONFIG_PROJECT_KEY_IGNORED" for finding in result.findings)
    root_source = next(source for source in result.sources if source.id == "config:project:.")
    assert "profile" in root_source.metadata["restricted_keys"]


def test_project_config_is_conditional_or_ignored_by_trust(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / ".codex").mkdir(parents=True)
    (root / ".codex" / "config.toml").write_text('model = "project"\n', encoding="utf-8")

    conditional_result, conditional = analyze_config(
        _ctx(root, trust="conditional")
    )
    ignored_result, ignored = analyze_config(_ctx(root, trust="untrusted"))

    conditional_source = next(
        source for source in conditional_result.sources if source.scope == "project"
    )
    ignored_source = next(source for source in ignored_result.sources if source.scope == "project")
    assert conditional_source.status is SourceStatus.CONDITIONAL
    assert ignored_source.status is SourceStatus.IGNORED
    assert "model" not in conditional
    assert "model" not in ignored


def test_invalid_toml_and_invalid_cli_override_are_reported(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / ".codex").mkdir(parents=True)
    (root / ".codex" / "config.toml").write_text("broken = [", encoding="utf-8")

    result, effective = analyze_config(_ctx(root, overrides=["missing-equals", "x=["]))

    assert not effective
    rules = {finding.rule_id for finding in result.findings}
    assert "CONFIG_INVALID_TOML" in rules
    assert "CONFIG_INVALID_CLI_OVERRIDE" in rules
    assert any(source.status is SourceStatus.INVALID for source in result.sources)


def test_utf8_bom_config_is_supported(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / ".codex").mkdir(parents=True)
    (root / ".codex" / "config.toml").write_text(
        'model = "bom-model"\r\n', encoding="utf-8-sig"
    )

    result, effective = analyze_config(_ctx(root))

    assert effective["model"] == "bom-model"
    assert not [finding for finding in result.findings if finding.severity.value == "error"]


def test_config_symlink_cannot_escape_repository(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    external = tmp_path / "private.toml"
    (root / ".codex").mkdir(parents=True)
    external.write_text('model = "outside"\n', encoding="utf-8")
    link = root / ".codex" / "config.toml"
    try:
        os.symlink(external, link)
    except (OSError, NotImplementedError):
        pytest.skip("File symlinks are unavailable on this platform")

    result, effective = analyze_config(_ctx(root))

    assert "model" not in effective
    assert any(finding.rule_id == "CONFIG_PATH_ESCAPE" for finding in result.findings)
