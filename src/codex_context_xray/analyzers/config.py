"""Codex configuration precedence, trust, profile, and CLI override analysis."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import tomli as tomllib

from codex_context_xray.model import (
    AnalysisResult,
    Finding,
    Layer,
    ScanContext,
    Severity,
    Source,
    SourceStatus,
)

# These top-level settings are documented as user/admin concerns and are not
# honored from repository configuration.  Keeping the list explicit makes the
# adapter deterministic and reviewable when Codex changes its schema.
PROJECT_RESTRICTED_KEYS = frozenset(
    {
        "analytics",
        "auth",
        "feedback",
        "forced_chatgpt_workspace_id",
        "forced_login_method",
        "model_catalog_json",
        "model_provider",
        "model_providers",
        "notify",
        "otel",
        "profile",
        "profiles",
    }
)


@dataclass(slots=True)
class ConfigLayerRecord:
    """Internal provenance retained without placing raw values in reports."""

    id: str
    path: str
    scope: str
    precedence: int
    status: SourceStatus
    data: dict[str, Any]


class EffectiveConfig(dict[str, Any]):
    """A dict with non-serialized layer provenance for downstream analyzers."""

    provenance: list[ConfigLayerRecord]

    def __init__(self) -> None:
        super().__init__()
        self.provenance = []


def config_provenance(config: Mapping[str, Any]) -> list[ConfigLayerRecord]:
    if isinstance(config, EffectiveConfig):
        return list(config.provenance)
    return []


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
    for base, marker in (
        (ctx.repo_root, "."),
        (ctx.codex_home, "$CODEX_HOME"),
        (ctx.user_home, "$HOME"),
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


def _load_toml(path: Path) -> dict[str, Any]:
    # ``utf-8-sig`` accepts both ordinary UTF-8 and the BOM emitted by some
    # Windows editors.  TOML itself remains decoded and parsed by tomli.
    text = path.read_text(encoding="utf-8-sig")
    return tomllib.loads(text)


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def _flatten(data: Mapping[str, Any], prefix: tuple[str, ...] = ()) -> list[str]:
    flattened: list[str] = []
    for key in sorted(data):
        value = data[key]
        path = (*prefix, str(key))
        if isinstance(value, Mapping) and value:
            flattened.extend(_flatten(cast(Mapping[str, Any], value), path))
        else:
            flattened.append(".".join(path))
    return flattened


def _deep_merge(
    destination: dict[str, Any],
    incoming: Mapping[str, Any],
    source_id: str,
    origins: dict[str, str],
    prefix: tuple[str, ...] = (),
) -> None:
    for key in sorted(incoming):
        value = incoming[key]
        current_path = (*prefix, str(key))
        dotted = ".".join(current_path)
        if isinstance(value, Mapping):
            existing = destination.get(key)
            if not isinstance(existing, dict):
                destination[key] = {}
                # Replacing a scalar/table boundary shadows all old leaves.
                old_paths = [
                    item
                    for item in origins
                    if item == dotted or item.startswith(f"{dotted}.")
                ]
                for old in old_paths:
                    origins.pop(old, None)
            _deep_merge(
                cast(dict[str, Any], destination[key]),
                cast(Mapping[str, Any], value),
                source_id,
                origins,
                current_path,
            )
        else:
            destination[key] = copy.deepcopy(value)
            for old in [item for item in origins if item.startswith(f"{dotted}.")]:
                origins.pop(old, None)
            origins[dotted] = source_id


def _parse_cli_override(raw: str) -> tuple[dict[str, Any] | None, str | None]:
    if "=" not in raw:
        return None, "Expected KEY=VALUE."
    key_text, value_text = raw.split("=", 1)
    parts = [part.strip() for part in key_text.strip().split(".")]
    if not parts or any(not part for part in parts):
        return None, "Override key contains an empty path component."
    try:
        parsed = tomllib.loads(f"value = {value_text.strip()}\n")
    except (tomllib.TOMLDecodeError, ValueError) as exc:
        return None, f"Invalid TOML value: {type(exc).__name__}."
    nested: dict[str, Any] = {}
    cursor = nested
    for part in parts[:-1]:
        next_table: dict[str, Any] = {}
        cursor[part] = next_table
        cursor = next_table
    cursor[parts[-1]] = parsed["value"]
    return nested, None


def _project_status(ctx: ScanContext) -> SourceStatus:
    effective = ctx.trust_effective.lower()
    if effective == "trusted":
        return SourceStatus.ACTIVE
    if effective == "untrusted":
        return SourceStatus.IGNORED
    return SourceStatus.CONDITIONAL


def _add_file_record(
    *,
    result: AnalysisResult,
    records: list[ConfigLayerRecord],
    ctx: ScanContext,
    path: Path,
    source_id: str,
    scope: str,
    precedence: int,
    requested_status: SourceStatus,
    allowed_root: Path,
) -> None:
    display = _display_path(path, ctx)
    if not _within(path, allowed_root):
        result.sources.append(
            Source(
                id=source_id,
                kind="config",
                scope=scope,
                path=display,
                status=SourceStatus.IGNORED,
                reason="The configuration link resolves outside the allowed scan root.",
                precedence=precedence,
            )
        )
        result.findings.append(
            Finding(
                id=f"{source_id}:escape",
                rule_id="CONFIG_PATH_ESCAPE",
                severity=Severity.ERROR,
                title="Configuration path escapes the allowed root",
                message=f"{display} was not followed outside the selected scan boundary.",
                source_ids=[source_id],
            )
        )
        return
    try:
        parsed = _load_toml(path)
    except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
        result.sources.append(
            Source(
                id=source_id,
                kind="config",
                scope=scope,
                path=display,
                status=SourceStatus.INVALID,
                reason=f"TOML could not be parsed safely: {type(exc).__name__}.",
                precedence=precedence,
            )
        )
        result.findings.append(
            Finding(
                id=f"{source_id}:invalid",
                rule_id="CONFIG_INVALID_TOML",
                severity=Severity.ERROR,
                title="Invalid Codex configuration",
                message=f"{display} is not valid TOML.",
                source_ids=[source_id],
            )
        )
        return

    filtered = copy.deepcopy(parsed)
    restricted: list[str] = []
    if scope == "project":
        restricted = sorted(key for key in filtered if key in PROJECT_RESTRICTED_KEYS)
        for key in restricted:
            filtered.pop(key, None)
        if restricted:
            result.findings.append(
                Finding(
                    id=f"{source_id}:restricted",
                    rule_id="CONFIG_PROJECT_KEY_IGNORED",
                    severity=Severity.WARNING,
                    title="Project configuration contains user-only keys",
                    message=(
                        f"{display} declares keys Codex does not accept from project scope: "
                        + ", ".join(restricted)
                    ),
                    source_ids=[source_id],
                    details={"keys": restricted},
                )
            )

    key_paths = _flatten(filtered)
    status = requested_status
    if not key_paths and requested_status is SourceStatus.ACTIVE:
        status = SourceStatus.IGNORED
    reason_by_status = {
        SourceStatus.ACTIVE: "Loaded at this configuration precedence.",
        SourceStatus.CONDITIONAL: "Loads only when the project is trusted.",
        SourceStatus.IGNORED: (
            "Ignored because the project is untrusted."
            if scope == "project" and key_paths
            else "No eligible settings remain in this file."
        ),
    }
    source = Source(
        id=source_id,
        kind="config",
        scope=scope,
        path=display,
        status=status,
        reason=reason_by_status.get(status, "Configuration source was not applied."),
        precedence=precedence,
        metadata={"keys": key_paths, "restricted_keys": restricted},
    )
    result.sources.append(source)
    records.append(
        ConfigLayerRecord(
            id=source_id,
            path=display,
            scope=scope,
            precedence=precedence,
            status=status,
            data=filtered,
        )
    )


def analyze_config(ctx: ScanContext) -> tuple[AnalysisResult, dict[str, Any]]:
    """Resolve visible Codex configuration and retain private provenance.

    Raw values are returned only through the in-memory ``EffectiveConfig`` used
    by downstream analyzers.  The serializable ``AnalysisResult`` contains key
    paths, never configuration values.
    """

    result = AnalysisResult()
    records: list[ConfigLayerRecord] = []

    if ctx.include_user and ctx.codex_home is not None:
        user_path = ctx.codex_home / "config.toml"
        if user_path.is_file():
            _add_file_record(
                result=result,
                records=records,
                ctx=ctx,
                path=user_path,
                source_id="config:user",
                scope="user",
                precedence=100,
                requested_status=SourceStatus.ACTIVE,
                allowed_root=ctx.codex_home,
            )
        if ctx.profile:
            profile_path = ctx.codex_home / f"{ctx.profile}.config.toml"
            if profile_path.is_file():
                _add_file_record(
                    result=result,
                    records=records,
                    ctx=ctx,
                    path=profile_path,
                    source_id=f"config:profile:{ctx.profile}",
                    scope="profile",
                    precedence=200,
                    requested_status=SourceStatus.ACTIVE,
                    allowed_root=ctx.codex_home,
                )
            else:
                result.findings.append(
                    Finding(
                        id="config:profile:missing",
                        rule_id="CONFIG_PROFILE_MISSING",
                        severity=Severity.ERROR,
                        title="Selected profile was not found",
                        message=(
                            f"The selected profile {ctx.profile!r} was not found in $CODEX_HOME."
                        ),
                    )
                )
    else:
        source_id = "config:user:unobserved"
        result.sources.append(
            Source(
                id=source_id,
                kind="config",
                scope="user",
                path="$CODEX_HOME/config.toml",
                status=SourceStatus.UNOBSERVED,
                reason="User configuration was not inspected; pass --include-user to opt in.",
                precedence=100,
            )
        )
        result.layers.append(
            Layer(
                id="config:user",
                kind="config",
                scope="user",
                precedence=100,
                source_ids=[source_id],
                status=SourceStatus.UNOBSERVED,
                reason="User scope is outside the default repository-only scan.",
            )
        )
        if ctx.profile:
            result.findings.append(
                Finding(
                    id="config:profile:requires-user",
                    rule_id="CONFIG_PROFILE_REQUIRES_USER_SCOPE",
                    severity=Severity.ERROR,
                    title="Profile requires user configuration access",
                    message="--profile can be resolved only together with --include-user.",
                    source_ids=[source_id],
                )
            )

    project_directories = _directories(ctx.repo_root, _target_directory(ctx))
    if not project_directories:
        result.findings.append(
            Finding(
                id="config:target-outside-root",
                rule_id="TARGET_OUTSIDE_REPOSITORY",
                severity=Severity.ERROR,
                title="Target is outside the repository",
                message="Project configuration discovery stopped outside repo_root.",
            )
        )
    project_status = _project_status(ctx)
    for depth, directory in enumerate(project_directories):
        config_path = directory / ".codex" / "config.toml"
        if not config_path.is_file():
            continue
        rel_dir = directory.relative_to(ctx.repo_root.resolve(strict=False)).as_posix() or "."
        _add_file_record(
            result=result,
            records=records,
            ctx=ctx,
            path=config_path,
            source_id=f"config:project:{rel_dir}",
            scope="project",
            precedence=300 + depth,
            requested_status=project_status,
            allowed_root=ctx.repo_root,
        )

    cli_data: dict[str, Any] = {}
    cli_errors = False
    for index, raw in enumerate(ctx.cli_overrides):
        parsed, error = _parse_cli_override(raw)
        if error is not None or parsed is None:
            cli_errors = True
            result.findings.append(
                Finding(
                    id=f"config:cli:{index}:invalid",
                    rule_id="CONFIG_INVALID_CLI_OVERRIDE",
                    severity=Severity.ERROR,
                    title="Invalid CLI configuration override",
                    message=f"CLI override #{index + 1} is invalid: {error}",
                )
            )
            continue
        _deep_merge(cli_data, parsed, "config:cli", {})
    if cli_data:
        cli_record = ConfigLayerRecord(
            id="config:cli",
            path="<command line>",
            scope="cli",
            precedence=1_000,
            status=SourceStatus.ACTIVE,
            data=cli_data,
        )
        records.append(cli_record)
        result.sources.append(
            Source(
                id=cli_record.id,
                kind="config",
                scope="cli",
                path=cli_record.path,
                status=SourceStatus.ACTIVE,
                reason="CLI -c overrides have the highest observed precedence.",
                precedence=cli_record.precedence,
                metadata={"keys": _flatten(cli_data), "override_count": len(ctx.cli_overrides)},
            )
        )
    elif cli_errors:
        result.sources.append(
            Source(
                id="config:cli",
                kind="config",
                scope="cli",
                path="<command line>",
                status=SourceStatus.INVALID,
                reason="No valid CLI overrides were available.",
                precedence=1_000,
            )
        )

    effective = EffectiveConfig()
    origins: dict[str, str] = {}
    for record in sorted(records, key=lambda item: item.precedence):
        if record.status is SourceStatus.ACTIVE:
            _deep_merge(effective, record.data, record.id, origins)
    effective.provenance = list(records)

    active_by_source: dict[str, set[str]] = {}
    for key_path, source_id in origins.items():
        active_by_source.setdefault(source_id, set()).add(key_path)
    source_index = {source.id: source for source in result.sources}
    for record in records:
        source = source_index.get(record.id)
        if source is None or source.status is not SourceStatus.ACTIVE:
            continue
        all_keys = set(_flatten(record.data))
        remaining_keys = active_by_source.get(record.id, set())
        shadowed_keys = sorted(all_keys - remaining_keys)
        source.metadata["effective_keys"] = sorted(remaining_keys)
        source.metadata["shadowed_keys"] = shadowed_keys
        if all_keys and not remaining_keys:
            source.status = SourceStatus.SHADOWED
            source.reason = (
                "Every setting from this source is replaced by a higher-precedence layer."
            )
            record.status = SourceStatus.SHADOWED

    # One layer per observed source keeps the causal graph clickable without
    # exposing values.  Unobserved user scope was added above.
    for source in result.sources:
        if source.id == "config:user:unobserved":
            continue
        result.layers.append(
            Layer(
                id=f"layer:{source.id}",
                kind="config",
                scope=source.scope,
                precedence=source.precedence,
                source_ids=[source.id],
                status=source.status,
                reason=source.reason,
            )
        )

    conditional_keys = sorted(
        {
            key
            for record in records
            if record.status is SourceStatus.CONDITIONAL
            for key in _flatten(record.data)
        }
    )
    ignored_project_keys = sorted(
        {
            key
            for record in records
            if record.scope == "project" and record.status is SourceStatus.IGNORED
            for key in _flatten(record.data)
        }
    )
    result.state["config"] = {
        "trust_requested": ctx.trust_requested,
        "trust_effective": ctx.trust_effective,
        "active_keys": sorted(origins),
        "conditional_project_keys": conditional_keys,
        "ignored_project_keys": ignored_project_keys,
        "profile": ctx.profile,
        "precedence": [record.id for record in sorted(records, key=lambda item: item.precedence)],
    }
    return result, effective
