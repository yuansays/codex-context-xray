"""Static discovery of Codex lifecycle hooks.

The analyzer parses definitions only.  It never runs commands, connects to MCP
servers, or attempts to infer whether a hook would approve a concrete action.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

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
from codex_context_xray.path_safety import (
    PathSafetyError,
    display_path,
    read_text_within,
    resolve_within,
)
from codex_context_xray.redaction import redact


def _target_directory(ctx: ScanContext) -> Path:
    return ctx.target.parent if ctx.target.is_file() else ctx.target


def _project_directories(ctx: ScanContext) -> list[Path]:
    root = ctx.repo_root.resolve()
    target = _target_directory(ctx).resolve()
    try:
        relative = target.relative_to(root)
    except ValueError:
        return [root]
    directories = [root]
    current = root
    for part in relative.parts:
        current = current / part
        directories.append(current)
    return directories


def _display(ctx: ScanContext, path: Path, scope: str) -> str:
    if scope == "user" and ctx.codex_home is not None:
        try:
            relative = path.resolve().relative_to(ctx.codex_home.resolve())
        except (ValueError, OSError):
            pass
        else:
            return "$CODEX_HOME" if not relative.parts else f"$CODEX_HOME/{relative.as_posix()}"
    return display_path(path, repo_root=ctx.repo_root, user_home=ctx.user_home)


def _status(ctx: ScanContext, scope: str, hooks_enabled: bool) -> tuple[SourceStatus, str]:
    if not hooks_enabled:
        return SourceStatus.IGNORED, "Hooks are disabled by features.hooks=false."
    if scope != "project":
        return SourceStatus.ACTIVE, "The hooks feature is enabled for this active layer."
    if ctx.trust_effective == "trusted":
        return SourceStatus.ACTIVE, "The project configuration layer is trusted."
    if ctx.trust_effective == "untrusted":
        return SourceStatus.IGNORED, "Project-local hooks are skipped for an untrusted project."
    return SourceStatus.CONDITIONAL, "Project trust is unresolved, so these hooks are conditional."


def _feature_enabled(config: Mapping[str, Any]) -> bool:
    features = config.get("features")
    if isinstance(features, Mapping):
        value = features.get("hooks", features.get("codex_hooks"))
        if isinstance(value, bool):
            return value
    dotted = config.get("features.hooks", config.get("features.codex_hooks"))
    return dotted if isinstance(dotted, bool) else True


def _event_counts(hooks: Mapping[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in sorted(hooks):
        value = hooks[event]
        counts[str(event)] = len(value) if isinstance(value, list) else 1
    return counts


def _source_id(scope: str, representation: str, displayed_path: str) -> str:
    normalized = displayed_path.replace("\\", "/").replace("/", ":")
    return f"hooks:{scope}:{representation}:{normalized}"


def _parse_json_hooks(text: str) -> tuple[Mapping[str, Any] | None, str | None]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON at line {exc.lineno}, column {exc.colno}"
    if not isinstance(document, Mapping) or not isinstance(document.get("hooks"), Mapping):
        return None, "the document must contain a top-level hooks object"
    return document["hooks"], None


def _parse_inline_hooks(text: str) -> tuple[Mapping[str, Any] | None, str | None]:
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, UnicodeError) as exc:
        return None, f"config.toml could not be parsed: {exc}"
    hooks = document.get("hooks")
    if hooks is None:
        return None, None
    if not isinstance(hooks, Mapping):
        return None, "the inline hooks value is not a table"
    return hooks, None


def _add_definition(
    result: AnalysisResult,
    ctx: ScanContext,
    *,
    scope: str,
    layer_key: str,
    source_path: str,
    representation: str,
    hooks: Mapping[str, Any],
    status: SourceStatus,
    reason: str,
    precedence: int,
) -> str:
    source_id = _source_id(scope, representation, source_path)
    counts = _event_counts(hooks)
    safe_hooks, redactions = redact(
        dict(hooks),
        ctx.user_home,
        location=f"$.sources.{source_id}.definition",
    )
    result.redactions.extend(redactions)
    result.sources.append(
        Source(
            id=source_id,
            kind="hooks",
            scope=scope,
            path=source_path,
            status=status,
            reason=reason,
            precedence=precedence,
            excerpt="events: " + (", ".join(counts) if counts else "(none)"),
            metadata={
                "representation": representation,
                "event_counts": counts,
                "definition": safe_hooks,
                "execution_performed": False,
                "trust_review": "unobserved",
            },
        )
    )
    result.layers.append(
        Layer(
            id=f"hooks-layer:{layer_key}:{representation}",
            kind="hooks",
            scope=scope,
            precedence=precedence,
            source_ids=[source_id],
            status=status,
            reason=reason,
        )
    )
    return source_id


def _add_invalid(
    result: AnalysisResult,
    *,
    scope: str,
    layer_key: str,
    source_path: str,
    representation: str,
    message: str,
    precedence: int,
) -> None:
    source_id = _source_id(scope, representation, source_path)
    result.sources.append(
        Source(
            id=source_id,
            kind="hooks",
            scope=scope,
            path=source_path,
            status=SourceStatus.INVALID,
            reason=message,
            precedence=precedence,
            metadata={"representation": representation, "execution_performed": False},
        )
    )
    result.layers.append(
        Layer(
            id=f"hooks-layer:{layer_key}:{representation}",
            kind="hooks",
            scope=scope,
            precedence=precedence,
            source_ids=[source_id],
            status=SourceStatus.INVALID,
            reason=message,
        )
    )
    result.findings.append(
        Finding(
            id=f"HOOKS_INVALID_{len(result.findings) + 1:03d}",
            rule_id="HOOKS_INVALID",
            severity=Severity.ERROR,
            title="Invalid hook definition",
            message=message,
            source_ids=[source_id],
        )
    )


def _scan_layer(
    result: AnalysisResult,
    ctx: ScanContext,
    *,
    scope: str,
    layer_directory: Path,
    containment_root: Path,
    layer_key: str,
    precedence: int,
    hooks_enabled: bool,
) -> list[str]:
    status, reason = _status(ctx, scope, hooks_enabled)
    discovered: list[str] = []
    representations: dict[str, str] = {}

    if not os.path.lexists(layer_directory):
        return discovered
    try:
        safe_layer_directory = resolve_within(layer_directory, containment_root, must_exist=True)
    except PathSafetyError:
        shown = _display(ctx, layer_directory, scope)
        source_id = _source_id(scope, "directory", shown)
        result.sources.append(
            Source(
                id=source_id,
                kind="hooks",
                scope=scope,
                path=shown,
                status=SourceStatus.IGNORED,
                reason="The hook layer resolves outside its declared configuration root.",
                precedence=precedence,
                metadata={"representation": "directory", "execution_performed": False},
            )
        )
        result.findings.append(
            Finding(
                id=f"HOOKS_PATH_ESCAPE_{len(result.findings) + 1:03d}",
                rule_id="PATH_ESCAPE",
                severity=Severity.ERROR,
                title="Hook layer escapes the scan root",
                message="An external hook layer was not followed or read.",
                source_ids=[source_id],
            )
        )
        return discovered
    if not safe_layer_directory.is_dir():
        return discovered

    json_path = layer_directory / "hooks.json"
    if os.path.lexists(json_path):
        shown = _display(ctx, json_path, scope)
        try:
            text = read_text_within(json_path, containment_root, encoding="utf-8-sig")
        except (PathSafetyError, UnicodeError) as exc:
            _add_invalid(
                result,
                scope=scope,
                layer_key=layer_key,
                source_path=shown,
                representation="json",
                message=f"hooks.json was not read safely: {exc}",
                precedence=precedence,
            )
        else:
            hooks, error = _parse_json_hooks(text)
            if error is not None or hooks is None:
                _add_invalid(
                    result,
                    scope=scope,
                    layer_key=layer_key,
                    source_path=shown,
                    representation="json",
                    message=error or "hooks.json is invalid",
                    precedence=precedence,
                )
            else:
                source_id = _add_definition(
                    result,
                    ctx,
                    scope=scope,
                    layer_key=layer_key,
                    source_path=shown,
                    representation="json",
                    hooks=hooks,
                    status=status,
                    reason=reason,
                    precedence=precedence,
                )
                discovered.append(source_id)
                representations["json"] = source_id

    config_path = layer_directory / "config.toml"
    if os.path.lexists(config_path):
        shown = _display(ctx, config_path, scope)
        try:
            text = read_text_within(config_path, containment_root, encoding="utf-8-sig")
        except (PathSafetyError, UnicodeError):
            # The config analyzer owns general parse/read errors.  Hooks only add a
            # source when an inline hook table was actually observable.
            text = ""
        if text:
            hooks, error = _parse_inline_hooks(text)
            if error is not None:
                _add_invalid(
                    result,
                    scope=scope,
                    layer_key=layer_key,
                    source_path=shown,
                    representation="inline",
                    message=error,
                    precedence=precedence,
                )
            elif hooks is not None:
                source_id = _add_definition(
                    result,
                    ctx,
                    scope=scope,
                    layer_key=layer_key,
                    source_path=shown,
                    representation="inline",
                    hooks=hooks,
                    status=status,
                    reason=reason,
                    precedence=precedence,
                )
                discovered.append(source_id)
                representations["inline"] = source_id

    if {"json", "inline"}.issubset(representations):
        result.findings.append(
            Finding(
                id=f"HOOKS_MIXED_{len(result.findings) + 1:03d}",
                rule_id="HOOKS_MIXED_REPRESENTATIONS",
                severity=Severity.WARNING,
                title="Hook representations are merged",
                message=(
                    "hooks.json and inline [hooks] are both present in the same "
                    "configuration layer; Codex merges them and emits a warning."
                ),
                source_ids=[representations["json"], representations["inline"]],
                details={"layer": layer_key},
            )
        )
    return discovered


def _plugin_declarations(config: Mapping[str, Any]) -> list[dict[str, Any]]:
    plugins = config.get("plugins")
    if not isinstance(plugins, Mapping):
        return []
    declarations: list[dict[str, Any]] = []
    for name in sorted(plugins):
        value = plugins[name]
        enabled: bool | None
        if isinstance(value, bool):
            enabled = value
        elif isinstance(value, Mapping):
            raw_enabled = value.get("enabled", True)
            enabled = raw_enabled if isinstance(raw_enabled, bool) else None
        else:
            enabled = None
        declarations.append(
            {
                "name": str(name),
                "enabled": enabled,
                "hook_payload": "unobserved",
            }
        )
    return declarations


def analyze_hooks(
    ctx: ScanContext,
    effective_config: Mapping[str, Any],
) -> AnalysisResult:
    """Explain active, conditional, ignored, and invalid hook sources."""

    result = AnalysisResult()
    hooks_enabled = _feature_enabled(effective_config)
    source_ids: list[str] = []

    if ctx.include_user and ctx.codex_home is not None:
        source_ids.extend(
            _scan_layer(
                result,
                ctx,
                scope="user",
                layer_directory=ctx.codex_home,
                containment_root=ctx.user_home or ctx.codex_home,
                layer_key="user",
                precedence=20,
                hooks_enabled=hooks_enabled,
            )
        )

    for depth, directory in enumerate(_project_directories(ctx)):
        layer_directory = directory / ".codex"
        if not layer_directory.exists() and not layer_directory.is_symlink():
            continue
        layer_key = f"project:{directory.relative_to(ctx.repo_root).as_posix() or '.'}"
        source_ids.extend(
            _scan_layer(
                result,
                ctx,
                scope="project",
                layer_directory=layer_directory,
                containment_root=ctx.repo_root,
                layer_key=layer_key,
                precedence=100 + depth,
                hooks_enabled=hooks_enabled,
            )
        )

    # A caller may provide an already-merged configuration without source-layer
    # metadata.  Preserve that useful view only when no concrete inline source was
    # discoverable, avoiding duplicate attribution.
    merged_hooks = effective_config.get("hooks")
    has_inline = any(source.metadata.get("representation") == "inline" for source in result.sources)
    if isinstance(merged_hooks, Mapping) and not has_inline:
        status = SourceStatus.ACTIVE if hooks_enabled else SourceStatus.IGNORED
        reason = (
            "Inline hooks are present in the merged effective configuration."
            if hooks_enabled
            else "Hooks are disabled by features.hooks=false."
        )
        source_ids.append(
            _add_definition(
                result,
                ctx,
                scope="effective",
                layer_key="effective",
                source_path="<effective-config>",
                representation="inline",
                hooks=merged_hooks,
                status=status,
                reason=reason,
                precedence=1_000,
            )
        )

    result.state["hooks"] = {
        "feature_enabled": hooks_enabled,
        "source_ids": source_ids,
        "events": sorted(
            {
                event
                for source in result.sources
                if source.status in {SourceStatus.ACTIVE, SourceStatus.CONDITIONAL}
                for event in source.metadata.get("event_counts", {})
            }
        ),
        "plugin_declarations": _plugin_declarations(effective_config),
        "execution_performed": False,
        "mcp_connections_started": False,
    }
    return result


__all__ = ["analyze_hooks"]
