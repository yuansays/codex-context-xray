from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_context_xray.analyzers.skills import analyze_skills
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


def _skill(directory: Path, name: str, description: str = "Synthetic test skill.") -> Path:
    directory.mkdir(parents=True)
    path = directory / "SKILL.md"
    path.write_text(
        f"---\nname: {name}\ndescription: {description}\n---\n\nDo a deterministic thing.\n",
        encoding="utf-8",
    )
    return path


def test_nested_duplicates_remain_separate_and_untriggered(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    nested = root / "service"
    nested.mkdir(parents=True)
    _skill(root / ".agents" / "skills" / "one", "same-name")
    _skill(nested / ".agents" / "skills" / "two", "same-name")

    result = analyze_skills(_ctx(root, nested))

    sources = [source for source in result.sources if source.metadata.get("name") == "same-name"]
    assert len(sources) == 2
    assert all(source.status is SourceStatus.CONDITIONAL for source in sources)
    assert all(
        "activation" in source.reason.lower() or "activated" in source.reason.lower()
        for source in sources
    )
    duplicate = next(
        finding for finding in result.findings if finding.rule_id == "SKILL_DUPLICATE_NAME"
    )
    assert duplicate.details == {"name": "same-name", "count": 2}


def test_invalid_frontmatter_and_config_disable(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    valid = _skill(root / ".agents" / "skills" / "valid", "valid-skill")
    invalid_dir = root / ".agents" / "skills" / "invalid"
    invalid_dir.mkdir()
    (invalid_dir / "SKILL.md").write_text("no frontmatter", encoding="utf-8")
    (root / ".codex").mkdir()
    relative = valid.relative_to(root).as_posix()
    (root / ".codex" / "config.toml").write_text(
        f'[[skills.config]]\npath = "{relative}"\nenabled = false\n', encoding="utf-8"
    )

    result = analyze_skills(_ctx(root))

    valid_source = next(
        source for source in result.sources if source.metadata.get("name") == "valid-skill"
    )
    invalid_source = next(
        source for source in result.sources if source.path.endswith("invalid/SKILL.md")
    )
    assert valid_source.status is SourceStatus.IGNORED
    assert valid_source.metadata["enabled"] is False
    assert invalid_source.status is SourceStatus.INVALID
    assert any(finding.rule_id == "SKILL_INVALID_FRONTMATTER" for finding in result.findings)


def test_skill_symlink_cannot_escape_repository(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    outside = tmp_path / "outside" / "secret-skill"
    skill_root = root / ".agents" / "skills"
    skill_root.mkdir(parents=True)
    _skill(outside, "outside-skill")
    link = skill_root / "linked"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Directory symlinks are unavailable on this platform")

    result = analyze_skills(_ctx(root))

    escaped = next(source for source in result.sources if source.id.startswith("skills:repo:"))
    assert escaped.status is SourceStatus.IGNORED
    assert any(finding.rule_id == "SKILL_PATH_ESCAPE" for finding in result.findings)


def test_user_skills_are_unobserved_by_default(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    result = analyze_skills(_ctx(root))
    user = next(source for source in result.sources if source.scope == "user")
    assert user.status is SourceStatus.UNOBSERVED
