"""Containment helpers for read-only repository scans.

Every path is checked both lexically and after resolving filesystem links.  The
helpers never traverse a directory symlink or Windows reparse-point during a
recursive scan, which keeps a repository fixture from smuggling external files
into a report.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from pathlib import Path


class PathSafetyError(ValueError):
    """Raised when a requested path escapes its declared scan root."""


def _absolute(path: str | os.PathLike[str]) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _resolved(path: Path, *, strict: bool) -> Path:
    # ``realpath`` handles Windows junctions as well as ordinary symlinks.  Use
    # pathlib's strict mode first so missing paths have consistent semantics.
    if strict:
        return path.resolve(strict=True)
    return Path(os.path.realpath(path))


def _commonpath_is_root(path: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath((os.fspath(path), os.fspath(root)))
        return os.path.normcase(common) == os.path.normcase(os.fspath(root))
    except ValueError:
        # Different Windows drives have no common path.
        return False


def is_within(
    path: str | os.PathLike[str],
    root: str | os.PathLike[str],
    *,
    must_exist: bool = False,
) -> bool:
    """Return whether ``path`` stays in ``root`` before and after link resolution."""

    root_absolute = _absolute(root)
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root_absolute / candidate
    candidate_absolute = _absolute(candidate)

    if not _commonpath_is_root(candidate_absolute, root_absolute):
        return False
    try:
        root_resolved = _resolved(root_absolute, strict=must_exist)
        candidate_resolved = _resolved(candidate_absolute, strict=must_exist)
    except (FileNotFoundError, OSError, RuntimeError):
        return False
    return _commonpath_is_root(candidate_resolved, root_resolved)


def resolve_within(
    path: str | os.PathLike[str],
    root: str | os.PathLike[str],
    *,
    must_exist: bool = True,
) -> Path:
    """Resolve a path only if its lexical and real targets remain under ``root``."""

    root_absolute = _absolute(root)
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root_absolute / candidate
    candidate_absolute = _absolute(candidate)
    if not _commonpath_is_root(candidate_absolute, root_absolute):
        raise PathSafetyError("path is outside the declared scan root")

    try:
        root_resolved = _resolved(root_absolute, strict=must_exist)
        candidate_resolved = _resolved(candidate_absolute, strict=must_exist)
    except FileNotFoundError as exc:
        raise PathSafetyError("path does not exist inside the declared scan root") from exc
    except (OSError, RuntimeError) as exc:
        raise PathSafetyError("path could not be resolved safely") from exc

    if not _commonpath_is_root(candidate_resolved, root_resolved):
        raise PathSafetyError("path resolves outside the declared scan root")
    return candidate_resolved


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return True
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def read_text_within(
    path: str | os.PathLike[str],
    root: str | os.PathLike[str],
    *,
    encoding: str = "utf-8",
    max_bytes: int | None = None,
) -> str:
    """Read a contained regular file without following an escaping link."""

    safe_path = resolve_within(path, root, must_exist=True)
    if not safe_path.is_file():
        raise PathSafetyError("path is not a regular file")
    data = safe_path.read_bytes()
    if max_bytes is not None:
        data = data[:max_bytes]
    return data.decode(encoding)


def iter_files_within(
    root: str | os.PathLike[str],
    *,
    suffix: str | None = None,
    recursive: bool = True,
) -> Iterator[Path]:
    """Yield contained files in deterministic order without traversing links.

    Returned paths retain their lexical location below ``root``.  Every yielded
    file has additionally passed a realpath containment check.
    """

    root_path = resolve_within(root, root, must_exist=True)
    if not root_path.is_dir():
        return

    if not recursive:
        candidates = sorted(root_path.iterdir(), key=lambda item: item.name.casefold())
        for candidate in candidates:
            if _is_link_or_reparse(candidate):
                continue
            if not candidate.is_file() or (suffix and not candidate.name.endswith(suffix)):
                continue
            if is_within(candidate, root_path, must_exist=True):
                yield candidate
        return

    for current, directories, files in os.walk(root_path, topdown=True, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            (
                name
                for name in directories
                if not _is_link_or_reparse(current_path / name)
                and is_within(current_path / name, root_path, must_exist=True)
            ),
            key=str.casefold,
        )
        for name in sorted(files, key=str.casefold):
            candidate = current_path / name
            if suffix and not name.endswith(suffix):
                continue
            if _is_link_or_reparse(candidate):
                continue
            if candidate.is_file() and is_within(candidate, root_path, must_exist=True):
                yield candidate


def display_path(
    path: str | os.PathLike[str],
    *,
    repo_root: str | os.PathLike[str],
    user_home: str | os.PathLike[str] | None = None,
) -> str:
    """Return a stable report path without exposing an absolute home directory."""

    candidate = _absolute(path)
    repo = _absolute(repo_root)
    if _commonpath_is_root(candidate, repo):
        relative = candidate.relative_to(repo)
        return "." if not relative.parts else relative.as_posix()
    if user_home is not None:
        home = _absolute(user_home)
        if _commonpath_is_root(candidate, home):
            relative = candidate.relative_to(home)
            return "$HOME" if not relative.parts else f"$HOME/{relative.as_posix()}"
    return "<external-path>"


__all__ = [
    "PathSafetyError",
    "display_path",
    "is_within",
    "iter_files_within",
    "read_text_within",
    "resolve_within",
]
