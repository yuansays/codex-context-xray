"""Static analysis of Codex instruction discovery and byte budgeting.

The implementation intentionally mirrors only observable, documented behavior:
one non-empty instruction file per directory, root-to-target ordering, and a
shared byte budget.  It never evaluates the instruction text.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from codex_context_xray.model import (
    AnalysisResult,
    Finding,
    Layer,
    ScanContext,
    Severity,
    Source,
    SourceStatus,
)


def _target_directory(ctx: ScanContext) -> Path:
    return ctx.target if ctx.target.is_dir() else ctx.target.parent


def _directories(root: Path, target: Path) -> list[Path]:
    root_resolved = root.resolve(strict=False)
    target_resolved = target.resolve(strict=False)
    try:
        relative = target_resolved.relative_to(root_resolved)
    except ValueError:
        return []
    directories = [root_resolved]
    current = root_resolved
    for part in relative.parts:
        current /= part
        directories.append(current)
    return directories


def _display_path(path: Path, ctx: ScanContext) -> str:
    resolved = path.resolve(strict=False)
    try:
        rel = resolved.relative_to(ctx.repo_root.resolve(strict=False))
        return "." if not rel.parts else rel.as_posix()
    except ValueError:
        pass
    if ctx.codex_home is not None:
        try:
            rel = resolved.relative_to(ctx.codex_home.resolve(strict=False))
            return "$CODEX_HOME" if not rel.parts else f"$CODEX_HOME/{rel.as_posix()}"
        except ValueError:
            pass
    if ctx.user_home is not None:
        try:
            rel = resolved.relative_to(ctx.user_home.resolve(strict=False))
            return "$HOME" if not rel.parts else f"$HOME/{rel.as_posix()}"
        except ValueError:
            pass
    return path.name


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def _read_instruction(path: Path, remaining: int) -> tuple[int, bool, bool]:
    """Return loaded bytes, whether truncated, and whether the file is empty.

    The content itself is deliberately not retained in the report.  Reading at
    most ``remaining + 1`` bytes makes the scan bounded even for huge files.
    """

    with path.open("rb") as handle:
        payload = handle.read(max(remaining, 0) + 1)
    selected = payload[: max(remaining, 0)]
    empty = not selected.decode("utf-8", errors="replace").strip()
    loaded = 0 if empty else len(selected)
    return loaded, len(payload) > remaining, empty


def _read_global_instruction(path: Path) -> tuple[int, bool]:
    """Return full global instruction bytes and whether the content is blank.

    Codex loads the selected CODEX_HOME instruction outside the project-wide
    ``project_doc_max_bytes`` budget. It is therefore measured independently
    and never reported as project-budget truncation.
    """

    payload = path.read_bytes()
    return len(payload), not payload.decode("utf-8", errors="replace").strip()


def _candidate_names(fallback_filenames: Iterable[str]) -> tuple[str, ...]:
    names: list[str] = ["AGENTS.override.md", "AGENTS.md"]
    for item in fallback_filenames:
        clean = item.strip()
        # Fallback names are filenames, not paths.  Refusing path components
        # prevents a config value from escaping the directory being scanned.
        if clean and Path(clean).name == clean and clean not in names:
            names.append(clean)
    return tuple(names)


def analyze_instructions(
    ctx: ScanContext,
    fallback_filenames: Iterable[str] = (),
    max_bytes: int = 32_768,
) -> AnalysisResult:
    """Explain the global and project instruction chain Codex can observe."""

    result = AnalysisResult()
    if max_bytes < 0:
        result.findings.append(
            Finding(
                id="instructions:invalid-budget",
                rule_id="INSTRUCTIONS_INVALID_BUDGET",
                severity=Severity.ERROR,
                title="Invalid instruction byte budget",
                message="project_doc_max_bytes must be zero or a positive integer.",
            )
        )
        max_bytes = 0

    candidates = _candidate_names(fallback_filenames)
    remaining = max_bytes
    user_bytes_loaded = 0
    loaded_ids: list[str] = []
    chain: list[dict[str, object]] = []
    precedence = 0

    # Global instructions are intentionally unobserved unless the caller opted
    # in.  Crucially, this branch does not probe the user directory at all.
    if not ctx.include_user:
        source_id = "instructions:user:unobserved"
        result.sources.append(
            Source(
                id=source_id,
                kind="instructions",
                scope="user",
                path="$CODEX_HOME/AGENTS.override.md | AGENTS.md",
                status=SourceStatus.UNOBSERVED,
                reason="User instructions were not inspected; pass --include-user to opt in.",
                precedence=precedence,
            )
        )
        result.layers.append(
            Layer(
                id="instructions:user",
                kind="instructions",
                scope="user",
                precedence=precedence,
                source_ids=[source_id],
                status=SourceStatus.UNOBSERVED,
                reason="User scope is outside the default repository-only scan.",
            )
        )
    elif ctx.codex_home is not None:
        precedence += 1
        chosen_user: Source | None = None
        discovered: list[Source] = []
        for name in ("AGENTS.override.md", "AGENTS.md"):
            path = ctx.codex_home / name
            if not path.is_file():
                continue
            source_id = f"instructions:user:{name}"
            if not _within(path, ctx.codex_home):
                display = _display_path(path, ctx)
                discovered.append(
                    Source(
                        id=source_id,
                        kind="instructions",
                        scope="user",
                        path=display,
                        status=SourceStatus.IGNORED,
                        reason="The instruction link resolves outside the allowed scan root.",
                        precedence=precedence,
                    )
                )
                result.findings.append(
                    Finding(
                        id=f"{source_id}:escape",
                        rule_id="INSTRUCTIONS_PATH_ESCAPE",
                        severity=Severity.ERROR,
                        title="Instruction path escapes the allowed root",
                        message=f"{display} was not followed outside the selected scan boundary.",
                        source_ids=[source_id],
                    )
                )
                continue
            if chosen_user is not None:
                discovered.append(
                    Source(
                        id=source_id,
                        kind="instructions",
                        scope="user",
                        path=_display_path(path, ctx),
                        status=SourceStatus.SHADOWED,
                        reason=(
                            "A higher-priority instruction filename was selected "
                            "in this directory."
                        ),
                        precedence=precedence,
                    )
                )
                continue
            try:
                loaded, empty = _read_global_instruction(path)
            except OSError as exc:
                source = Source(
                    id=source_id,
                    kind="instructions",
                    scope="user",
                    path=_display_path(path, ctx),
                    status=SourceStatus.INVALID,
                    reason=f"Could not read instruction file: {type(exc).__name__}.",
                    precedence=precedence,
                )
                discovered.append(source)
                result.findings.append(
                    Finding(
                        id=f"{source_id}:read-error",
                        rule_id="INSTRUCTIONS_READ_ERROR",
                        severity=Severity.ERROR,
                        title="Instruction file could not be read",
                        message=f"{source.path} could not be read safely.",
                        source_ids=[source_id],
                    )
                )
                continue
            if empty:
                discovered.append(
                    Source(
                        id=source_id,
                        kind="instructions",
                        scope="user",
                        path=_display_path(path, ctx),
                        status=SourceStatus.IGNORED,
                        reason="Empty instruction files are skipped.",
                        precedence=precedence,
                        metadata={"bytes_loaded": 0},
                    )
                )
                continue
            if chosen_user is None:
                status = SourceStatus.ACTIVE
                reason = "Selected in full outside the project instruction byte budget."
                chosen_user = Source(
                    id=source_id,
                    kind="instructions",
                    scope="user",
                    path=_display_path(path, ctx),
                    status=status,
                    reason=reason,
                    precedence=precedence,
                    metadata={"bytes_loaded": loaded, "truncated": False},
                )
                discovered.append(chosen_user)
                loaded_ids.append(source_id)
                chain.append(
                    {
                        "source_id": source_id,
                        "path": chosen_user.path,
                        "bytes_loaded": loaded,
                        "truncated": False,
                        "budget": "global-unlimited",
                    }
                )
                user_bytes_loaded = loaded
            else:
                discovered.append(
                    Source(
                        id=source_id,
                        kind="instructions",
                        scope="user",
                        path=_display_path(path, ctx),
                        status=SourceStatus.SHADOWED,
                        reason=(
                            "A higher-priority instruction filename was selected "
                            "in this directory."
                        ),
                        precedence=precedence,
                    )
                )
        result.sources.extend(discovered)
        if discovered:
            result.layers.append(
                Layer(
                    id="instructions:user",
                    kind="instructions",
                    scope="user",
                    precedence=precedence,
                    source_ids=[source.id for source in discovered],
                    status=chosen_user.status if chosen_user else SourceStatus.IGNORED,
                    reason="Global instruction selection from CODEX_HOME.",
                )
            )

    directories = _directories(ctx.repo_root, _target_directory(ctx))
    if not directories:
        result.findings.append(
            Finding(
                id="instructions:target-outside-root",
                rule_id="TARGET_OUTSIDE_REPOSITORY",
                severity=Severity.ERROR,
                title="Target is outside the repository",
                message="Instruction discovery stopped because the target is outside repo_root.",
            )
        )
    for index, directory in enumerate(directories):
        precedence += 1
        rel_dir = directory.relative_to(ctx.repo_root.resolve(strict=False)).as_posix() or "."
        discovered = []
        chosen_project: Source | None = None
        for name in candidates:
            path = directory / name
            if not path.is_file():
                continue
            source_id = f"instructions:repo:{rel_dir}:{name}"
            if not _within(path, ctx.repo_root):
                display = _display_path(path, ctx)
                discovered.append(
                    Source(
                        id=source_id,
                        kind="instructions",
                        scope="repo",
                        path=display,
                        status=SourceStatus.IGNORED,
                        reason="The instruction link resolves outside the allowed scan root.",
                        precedence=precedence,
                    )
                )
                result.findings.append(
                    Finding(
                        id=f"{source_id}:escape",
                        rule_id="INSTRUCTIONS_PATH_ESCAPE",
                        severity=Severity.ERROR,
                        title="Instruction path escapes the allowed root",
                        message=f"{display} was not followed outside the selected scan boundary.",
                        source_ids=[source_id],
                    )
                )
                continue
            if chosen_project is not None:
                discovered.append(
                    Source(
                        id=source_id,
                        kind="instructions",
                        scope="repo",
                        path=_display_path(path, ctx),
                        status=SourceStatus.SHADOWED,
                        reason=(
                            "A higher-priority instruction filename was selected "
                            "in this directory."
                        ),
                        precedence=precedence,
                    )
                )
                continue
            try:
                loaded, truncated, empty = _read_instruction(path, remaining)
            except OSError as exc:
                source = Source(
                    id=source_id,
                    kind="instructions",
                    scope="repo",
                    path=_display_path(path, ctx),
                    status=SourceStatus.INVALID,
                    reason=f"Could not read instruction file: {type(exc).__name__}.",
                    precedence=precedence,
                )
                discovered.append(source)
                result.findings.append(
                    Finding(
                        id=f"{source_id}:read-error",
                        rule_id="INSTRUCTIONS_READ_ERROR",
                        severity=Severity.ERROR,
                        title="Instruction file could not be read",
                        message=f"{source.path} could not be read safely.",
                        source_ids=[source_id],
                    )
                )
                continue
            if empty:
                discovered.append(
                    Source(
                        id=source_id,
                        kind="instructions",
                        scope="repo",
                        path=_display_path(path, ctx),
                        status=SourceStatus.IGNORED,
                        reason="Empty instruction files are skipped.",
                        precedence=precedence,
                        metadata={"bytes_loaded": 0},
                    )
                )
                continue
            if chosen_project is None:
                status = SourceStatus.ACTIVE if remaining > 0 else SourceStatus.IGNORED
                reason = (
                    "Selected for this directory."
                    if remaining > 0
                    else "The instruction byte budget was already exhausted."
                )
                chosen_project = Source(
                    id=source_id,
                    kind="instructions",
                    scope="repo",
                    path=_display_path(path, ctx),
                    status=status,
                    reason=reason,
                    precedence=precedence,
                    metadata={
                        "bytes_loaded": loaded,
                        "truncated": truncated,
                        "directory_depth": index,
                    },
                )
                discovered.append(chosen_project)
                if status is SourceStatus.ACTIVE:
                    loaded_ids.append(source_id)
                    chain.append(
                        {
                            "source_id": source_id,
                            "path": chosen_project.path,
                            "bytes_loaded": loaded,
                            "truncated": truncated,
                        }
                    )
                    remaining -= loaded
                    if truncated:
                        result.findings.append(
                            Finding(
                                id=f"{source_id}:truncated",
                                rule_id="INSTRUCTIONS_TRUNCATED",
                                severity=Severity.WARNING,
                                title="Instruction chain was truncated",
                                message=(
                                    f"{chosen_project.path} exceeded the remaining "
                                    "instruction budget."
                                ),
                                source_ids=[source_id],
                            )
                        )
            else:
                discovered.append(
                    Source(
                        id=source_id,
                        kind="instructions",
                        scope="repo",
                        path=_display_path(path, ctx),
                        status=SourceStatus.SHADOWED,
                        reason=(
                            "A higher-priority instruction filename was selected "
                            "in this directory."
                        ),
                        precedence=precedence,
                    )
                )
        result.sources.extend(discovered)
        if discovered:
            layer_status = (
                chosen_project.status if chosen_project is not None else SourceStatus.IGNORED
            )
            result.layers.append(
                Layer(
                    id=f"instructions:repo:{rel_dir}",
                    kind="instructions",
                    scope="repo",
                    precedence=precedence,
                    source_ids=[source.id for source in discovered],
                    status=layer_status,
                    reason="One instruction file may contribute from each repository directory.",
                )
            )

    result.state["instructions"] = {
        "max_bytes": max_bytes,
        "bytes_loaded": user_bytes_loaded + (max_bytes - remaining),
        "user_bytes_loaded": user_bytes_loaded,
        "project_bytes_loaded": max_bytes - remaining,
        "truncated": any(bool(item.get("truncated")) for item in chain),
        "source_ids": loaded_ids,
        "chain": chain,
        "merge_order": "root-to-target; deeper instructions appear later",
    }
    return result
