from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_context_xray.path_safety import (
    PathSafetyError,
    display_path,
    is_within,
    iter_files_within,
    read_text_within,
    resolve_within,
)


def test_resolve_and_read_only_inside_declared_root(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    nested = root / "nested"
    nested.mkdir(parents=True)
    source = nested / "sample.txt"
    source.write_text("synthetic", encoding="utf-8")

    assert resolve_within("nested/sample.txt", root) == source.resolve()
    assert read_text_within(source, root) == "synthetic"
    assert is_within(source, root, must_exist=True)

    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    assert not is_within(outside, root, must_exist=True)
    with pytest.raises(PathSafetyError):
        resolve_within(root / ".." / "outside.txt", root)


def test_external_symlink_is_rejected_and_not_enumerated(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    safe = root / "safe.rules"
    safe.write_text("safe", encoding="utf-8")
    outside = tmp_path / "outside.rules"
    outside.write_text("private", encoding="utf-8")
    link = root / "escape.rules"
    try:
        link.symlink_to(outside)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this runner")

    with pytest.raises(PathSafetyError):
        resolve_within(link, root)
    assert [path.name for path in iter_files_within(root, suffix=".rules")] == ["safe.rules"]


def test_directory_link_is_not_traversed(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.rules").write_text("private", encoding="utf-8")
    link = root / "linked-rules"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory symlinks are unavailable on this runner")

    assert list(iter_files_within(root, suffix=".rules")) == []


def test_display_path_never_emits_absolute_home(tmp_path: Path) -> None:
    home = tmp_path / "home"
    repo = home / "work" / "repo"
    repo.mkdir(parents=True)

    assert display_path(repo / "src" / "main.py", repo_root=repo, user_home=home) == ("src/main.py")
    assert display_path(home / ".codex" / "config.toml", repo_root=repo, user_home=home) == (
        "$HOME/.codex/config.toml"
    )
    assert display_path(tmp_path.parent / "external.txt", repo_root=repo, user_home=home) == (
        "<external-path>"
    )


def test_different_drive_or_root_is_outside(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    candidate = Path(os.path.abspath(os.sep))
    if candidate == root:
        pytest.skip("temporary directory unexpectedly is the filesystem root")
    assert not is_within(candidate, root)
