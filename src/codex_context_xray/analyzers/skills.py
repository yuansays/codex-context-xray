"""Discover Codex Agent Skills without loading their executable resources."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import yaml

from codex_context_xray.analyzers.config import analyze_config
from codex_context_xray.model import (
    AnalysisResult,
    Finding,
    Layer,
    ScanContext,
    Severity,
    Source,
    SourceStatus,
)

_SKILL_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_MAX_SKILL_FILE_BYTES = 1_048_576


def _target_directory(ctx: ScanContext) -> Path:
    return ctx.target if ctx.target.is_dir() else ctx.target.parent


def _directories(root: Path, target: Path) -> list[Path]:
    root_resolved = root.resolve(strict=False)
    target_resolved = target.resolve(strict=False)
    try:
        relative = target_resolved.relative_to(root_resolved)
    except ValueError:
        return []
    result = [root_resolved]
    current = root_resolved
    for part in relative.parts:
        current /= part
        result.append(current)
    return result


def _display_path(path: Path, ctx: ScanContext) -> str:
    resolved = path.resolve(strict=False)
    for base, marker in (
        (ctx.repo_root, "."),
        (ctx.user_home, "$HOME"),
        (ctx.codex_home, "$CODEX_HOME"),
    ):
        if base is None:
            continue
        try:
            rel = resolved.relative_to(base.resolve(strict=False))
        except ValueError:
            continue
        if not rel.parts:
            return marker
        prefix = "" if marker == "." else f"{marker}/"
        return f"{prefix}{rel.as_posix()}"
    return path.name


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def _frontmatter(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        with path.open("rb") as handle:
            payload = handle.read(_MAX_SKILL_FILE_BYTES + 1)
    except OSError as exc:
        return None, f"Could not read SKILL.md: {type(exc).__name__}."
    if len(payload) > _MAX_SKILL_FILE_BYTES:
        return None, "SKILL.md exceeds the 1 MiB static-analysis limit."
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None, "SKILL.md is not valid UTF-8."
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, "SKILL.md must begin with YAML frontmatter."
    closing: int | None = None
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            closing = index
            break
    if closing is None:
        return None, "SKILL.md YAML frontmatter is not closed."
    yaml_text = "\n".join(lines[1:closing])
    try:
        loaded = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        return None, f"Invalid YAML frontmatter: {type(exc).__name__}."
    if not isinstance(loaded, Mapping):
        return None, "SKILL.md frontmatter must be a YAML mapping."
    return {str(key): value for key, value in loaded.items()}, None


def _openai_metadata(path: Path) -> tuple[dict[str, Any], str | None]:
    metadata_path = path.parent / "agents" / "openai.yaml"
    if not metadata_path.is_file():
        return {}, None
    try:
        with metadata_path.open("r", encoding="utf-8-sig") as handle:
            loaded = yaml.safe_load(handle)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        return {}, f"agents/openai.yaml is invalid: {type(exc).__name__}."
    if loaded is None:
        return {}, None
    if not isinstance(loaded, Mapping):
        return {}, "agents/openai.yaml must contain a YAML mapping."
    policy = loaded.get("policy")
    allow_implicit = True
    if isinstance(policy, Mapping) and isinstance(policy.get("allow_implicit_invocation"), bool):
        allow_implicit = bool(policy["allow_implicit_invocation"])
    dependencies = loaded.get("dependencies")
    tool_count = 0
    if isinstance(dependencies, Mapping) and isinstance(dependencies.get("tools"), list):
        tool_count = len(cast(list[object], dependencies["tools"]))
    return {
        "allow_implicit_invocation": allow_implicit,
        "declared_tool_dependencies": tool_count,
        "has_openai_metadata": True,
    }, None


def _normalise_override_path(raw: str, ctx: ScanContext) -> Path:
    if (raw.startswith("~/") or raw.startswith("~\\")) and ctx.user_home is not None:
        return (ctx.user_home / raw[2:]).resolve(strict=False)
    path = Path(raw)
    if path.is_absolute():
        return path.resolve(strict=False)
    return (ctx.repo_root / path).resolve(strict=False)


def _skill_overrides(ctx: ScanContext) -> dict[Path, bool]:
    # Reuse the deterministic configuration resolver.  Its report is not
    # included here, so configuration findings remain owned by analyze_config.
    _, effective = analyze_config(ctx)
    skills = effective.get("skills")
    if not isinstance(skills, Mapping):
        return {}
    entries = skills.get("config")
    if not isinstance(entries, list):
        return {}
    overrides: dict[Path, bool] = {}
    for item in entries:
        if not isinstance(item, Mapping):
            continue
        raw_path = item.get("path")
        enabled = item.get("enabled")
        if isinstance(raw_path, str) and isinstance(enabled, bool):
            overrides[_normalise_override_path(raw_path, ctx)] = enabled
    return overrides


def _scan_skill_root(
    *,
    result: AnalysisResult,
    ctx: ScanContext,
    skill_root: Path,
    allowed_root: Path,
    scope: str,
    precedence: int,
    overrides: Mapping[Path, bool],
    seen_files: set[Path],
) -> list[str]:
    source_ids: list[str] = []
    if not skill_root.is_dir():
        return source_ids
    try:
        children = sorted(skill_root.iterdir(), key=lambda item: item.name.casefold())
    except OSError as exc:
        source_id = f"skills:{scope}:{_display_path(skill_root, ctx)}:read-error"
        result.sources.append(
            Source(
                id=source_id,
                kind="skill",
                scope=scope,
                path=_display_path(skill_root, ctx),
                status=SourceStatus.INVALID,
                reason=f"Skill directory could not be enumerated: {type(exc).__name__}.",
                precedence=precedence,
            )
        )
        result.findings.append(
            Finding(
                id=f"{source_id}:finding",
                rule_id="SKILL_DIRECTORY_READ_ERROR",
                severity=Severity.ERROR,
                title="Skill directory could not be read",
                message=f"{_display_path(skill_root, ctx)} could not be enumerated safely.",
                source_ids=[source_id],
            )
        )
        return [source_id]

    for child in children:
        skill_file = child / "SKILL.md"
        if not skill_file.is_file():
            continue
        resolved = skill_file.resolve(strict=False)
        display = _display_path(skill_file, ctx)
        source_id = f"skills:{scope}:{display}"
        if not _within(resolved, allowed_root):
            result.sources.append(
                Source(
                    id=source_id,
                    kind="skill",
                    scope=scope,
                    path=display,
                    status=SourceStatus.IGNORED,
                    reason="The skill link resolves outside the allowed scan root.",
                    precedence=precedence,
                )
            )
            result.findings.append(
                Finding(
                    id=f"{source_id}:escape",
                    rule_id="SKILL_PATH_ESCAPE",
                    severity=Severity.ERROR,
                    title="Skill path escapes the allowed root",
                    message=f"{display} was not followed outside the selected scan boundary.",
                    source_ids=[source_id],
                )
            )
            source_ids.append(source_id)
            continue
        if resolved in seen_files:
            continue
        seen_files.add(resolved)
        frontmatter, error = _frontmatter(skill_file)
        if error is not None or frontmatter is None:
            result.sources.append(
                Source(
                    id=source_id,
                    kind="skill",
                    scope=scope,
                    path=display,
                    status=SourceStatus.INVALID,
                    reason=error or "Invalid skill frontmatter.",
                    precedence=precedence,
                )
            )
            result.findings.append(
                Finding(
                    id=f"{source_id}:frontmatter",
                    rule_id="SKILL_INVALID_FRONTMATTER",
                    severity=Severity.ERROR,
                    title="Invalid Skill frontmatter",
                    message=f"{display}: {error}",
                    source_ids=[source_id],
                )
            )
            source_ids.append(source_id)
            continue

        name = frontmatter.get("name")
        description = frontmatter.get("description")
        validation_errors: list[str] = []
        if not isinstance(name, str) or not name:
            validation_errors.append("name must be a non-empty string")
        elif len(name) > 64 or _SKILL_NAME.fullmatch(name) is None:
            validation_errors.append("name must be <=64 lowercase letters, digits, and hyphens")
        if not isinstance(description, str) or not description.strip():
            validation_errors.append("description must be a non-empty string")
        elif len(description) > 1_024:
            validation_errors.append("description exceeds 1024 characters")

        openai_meta, metadata_error = _openai_metadata(skill_file)
        if metadata_error:
            result.findings.append(
                Finding(
                    id=f"{source_id}:openai-metadata",
                    rule_id="SKILL_INVALID_OPENAI_METADATA",
                    severity=Severity.WARNING,
                    title="Invalid Codex Skill metadata",
                    message=f"{display}: {metadata_error}",
                    source_ids=[source_id],
                )
            )

        enabled = overrides.get(resolved, True)
        if validation_errors:
            status = SourceStatus.INVALID
            reason = "; ".join(validation_errors) + "."
        elif not enabled:
            status = SourceStatus.IGNORED
            reason = "Disabled by the effective [[skills.config]] entry."
        else:
            status = SourceStatus.CONDITIONAL
            reason = "Available in the initial catalog; full instructions load only if activated."
        result.sources.append(
            Source(
                id=source_id,
                kind="skill",
                scope=scope,
                path=display,
                status=status,
                reason=reason,
                precedence=precedence,
                metadata={
                    "name": name if isinstance(name, str) else None,
                    "description": description if isinstance(description, str) else None,
                    "enabled": enabled,
                    **openai_meta,
                },
            )
        )
        if validation_errors:
            result.findings.append(
                Finding(
                    id=f"{source_id}:schema",
                    rule_id="SKILL_INVALID_FRONTMATTER",
                    severity=Severity.ERROR,
                    title="Invalid Skill frontmatter",
                    message=f"{display}: {'; '.join(validation_errors)}.",
                    source_ids=[source_id],
                )
            )
        source_ids.append(source_id)
    return source_ids


def analyze_skills(ctx: ScanContext) -> AnalysisResult:
    """Discover skill metadata, duplicate names, and activation conditions."""

    result = AnalysisResult()
    overrides = _skill_overrides(ctx)
    seen_files: set[Path] = set()
    precedence = 0

    if ctx.include_user and ctx.user_home is not None:
        precedence += 1
        root = ctx.user_home / ".agents" / "skills"
        source_ids = _scan_skill_root(
            result=result,
            ctx=ctx,
            skill_root=root,
            allowed_root=ctx.user_home,
            scope="user",
            precedence=precedence,
            overrides=overrides,
            seen_files=seen_files,
        )
        if source_ids:
            result.layers.append(
                Layer(
                    id="skills:user",
                    kind="skills",
                    scope="user",
                    precedence=precedence,
                    source_ids=source_ids,
                    status=SourceStatus.CONDITIONAL,
                    reason="User skills are catalogued before activation.",
                )
            )
    else:
        source_id = "skills:user:unobserved"
        result.sources.append(
            Source(
                id=source_id,
                kind="skill",
                scope="user",
                path="$HOME/.agents/skills",
                status=SourceStatus.UNOBSERVED,
                reason="User skills were not inspected; pass --include-user to opt in.",
                precedence=precedence,
            )
        )
        result.layers.append(
            Layer(
                id="skills:user",
                kind="skills",
                scope="user",
                precedence=precedence,
                source_ids=[source_id],
                status=SourceStatus.UNOBSERVED,
                reason="User scope is outside the default repository-only scan.",
            )
        )

    directories = _directories(ctx.repo_root, _target_directory(ctx))
    if not directories:
        result.findings.append(
            Finding(
                id="skills:target-outside-root",
                rule_id="TARGET_OUTSIDE_REPOSITORY",
                severity=Severity.ERROR,
                title="Target is outside the repository",
                message="Skill discovery stopped outside repo_root.",
            )
        )
    for depth, directory in enumerate(directories):
        precedence += 1
        root = directory / ".agents" / "skills"
        source_ids = _scan_skill_root(
            result=result,
            ctx=ctx,
            skill_root=root,
            allowed_root=ctx.repo_root,
            scope="repo",
            precedence=precedence,
            overrides=overrides,
            seen_files=seen_files,
        )
        if source_ids:
            rel = directory.relative_to(ctx.repo_root.resolve(strict=False)).as_posix() or "."
            result.layers.append(
                Layer(
                    id=f"skills:repo:{rel}",
                    kind="skills",
                    scope="repo",
                    precedence=precedence,
                    source_ids=source_ids,
                    status=SourceStatus.CONDITIONAL,
                    reason=f"Repository skills discovered at directory depth {depth}.",
                )
            )

    by_name: dict[str, list[Source]] = {}
    for source in result.sources:
        name = source.metadata.get("name")
        if isinstance(name, str) and source.status is not SourceStatus.INVALID:
            by_name.setdefault(name, []).append(source)
    for name, sources in sorted(by_name.items()):
        if len(sources) < 2:
            continue
        result.findings.append(
            Finding(
                id=f"skills:duplicate:{name}",
                rule_id="SKILL_DUPLICATE_NAME",
                severity=Severity.WARNING,
                title="Duplicate Skill name",
                message=(
                    f"{len(sources)} skills declare {name!r}; Codex lists them "
                    "separately and does not merge them."
                ),
                source_ids=[source.id for source in sources],
                details={"name": name, "count": len(sources)},
            )
        )

    result.state["skills"] = {
        "catalogued": [
            {
                "source_id": source.id,
                "name": source.metadata.get("name"),
                "status": source.status.value,
                "enabled": source.metadata.get("enabled"),
            }
            for source in result.sources
            if isinstance(source.metadata.get("name"), str)
        ],
        "activation": "metadata is catalogued first; SKILL.md instructions load only on activation",
        "duplicate_names": sorted(name for name, sources in by_name.items() if len(sources) > 1),
    }
    return result
