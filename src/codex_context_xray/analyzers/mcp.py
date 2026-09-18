"""Static MCP server definition and tool-filter analysis."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from typing import Any, cast

from codex_context_xray.analyzers.config import ConfigLayerRecord, config_provenance
from codex_context_xray.model import (
    AnalysisResult,
    Finding,
    Layer,
    ScanContext,
    Severity,
    Source,
    SourceStatus,
)


def _flatten(data: Mapping[str, Any], prefix: tuple[str, ...] = ()) -> set[str]:
    paths: set[str] = set()
    for key in sorted(data):
        value = data[key]
        current = (*prefix, str(key))
        if isinstance(value, Mapping) and value:
            paths.update(_flatten(cast(Mapping[str, Any], value), current))
        else:
            paths.add(".".join(current))
    return paths


def _server_tables(record: ConfigLayerRecord) -> tuple[dict[str, Mapping[str, Any]], str | None]:
    raw = record.data.get("mcp_servers")
    if raw is None:
        return {}, None
    if not isinstance(raw, Mapping):
        return {}, "mcp_servers must be a table"
    tables: dict[str, Mapping[str, Any]] = {}
    for name, definition in raw.items():
        if not isinstance(name, str) or not isinstance(definition, Mapping):
            return {}, "every mcp_servers entry must be a named table"
        tables[name] = cast(Mapping[str, Any], definition)
    return tables, None


def _list_of_strings(value: object) -> list[str] | None:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return sorted(cast(list[str], value))


def _transport(definition: Mapping[str, Any]) -> str:
    if "command" in definition:
        return "stdio"
    if "url" in definition:
        return "streamable_http"
    return "unspecified"


def analyze_mcp(ctx: ScanContext, effective_config: Mapping[str, Any]) -> AnalysisResult:
    """Explain MCP overrides, activation, requirements, and tool filters.

    This analyzer never starts a server and never exposes command arguments,
    headers, environment values, or URLs.
    """

    del ctx  # All filesystem access happened in the configuration analyzer.
    result = AnalysisResult()
    records = config_provenance(effective_config)
    if not records:
        synthetic = ConfigLayerRecord(
            id="config:effective",
            path="<effective configuration>",
            scope="effective",
            precedence=0,
            status=SourceStatus.ACTIVE,
            data=dict(effective_config),
        )
        records = [synthetic]

    definitions: dict[
        str, list[tuple[ConfigLayerRecord, Mapping[str, Any], Source]]
    ] = defaultdict(list)
    # Track field provenance across active layers because Codex config tables
    # merge by key; a later partial server table does not erase untouched fields.
    field_origins: dict[tuple[str, str], str] = {}

    for record in sorted(records, key=lambda item: item.precedence):
        tables, error = _server_tables(record)
        if error is not None:
            source_id = f"mcp:{record.id}:invalid"
            result.sources.append(
                Source(
                    id=source_id,
                    kind="mcp",
                    scope=record.scope,
                    path=record.path,
                    status=SourceStatus.INVALID,
                    reason=error + ".",
                    precedence=record.precedence,
                )
            )
            result.findings.append(
                Finding(
                    id=f"{source_id}:finding",
                    rule_id="MCP_INVALID_CONFIGURATION",
                    severity=Severity.ERROR,
                    title="Invalid MCP configuration",
                    message=f"{record.path}: {error}.",
                    source_ids=[source_id],
                )
            )
            continue
        for name, definition in sorted(tables.items()):
            source_id = f"mcp:{record.id}:{name}"
            status = record.status
            reason = {
                SourceStatus.ACTIVE: "This definition contributes to the effective MCP server.",
                SourceStatus.SHADOWED: (
                    "A higher-precedence configuration replaces this definition."
                ),
                SourceStatus.CONDITIONAL: "This definition loads only when its project is trusted.",
                SourceStatus.IGNORED: (
                    "This definition is ignored by the configuration trust boundary."
                ),
            }.get(status, "This definition is not effective.")
            source = Source(
                id=source_id,
                kind="mcp",
                scope=record.scope,
                path=record.path,
                status=status,
                reason=reason,
                precedence=record.precedence,
                metadata={
                    "server": name,
                    "declared_fields": sorted(str(key) for key in definition),
                    "transport": _transport(definition),
                },
            )
            result.sources.append(source)
            definitions[name].append((record, definition, source))
            if record.status in {SourceStatus.ACTIVE, SourceStatus.SHADOWED}:
                for field in _flatten(definition):
                    field_origins[(name, field)] = source_id

    effective_servers_raw = effective_config.get("mcp_servers")
    effective_servers = (
        cast(Mapping[str, Any], effective_servers_raw)
        if isinstance(effective_servers_raw, Mapping)
        else {}
    )
    state_servers: list[dict[str, Any]] = []
    for name, entries in sorted(definitions.items()):
        if len(entries) > 1:
            result.findings.append(
                Finding(
                    id=f"mcp:override:{name}",
                    rule_id="MCP_SERVER_OVERRIDE",
                    severity=Severity.INFO,
                    title="MCP server is defined in multiple layers",
                    message=(
                        f"{name!r} is defined {len(entries)} times; higher-precedence fields win."
                    ),
                    source_ids=[source.id for _, _, source in entries],
                    details={"server": name, "definition_count": len(entries)},
                )
            )

        effective_definition_raw = effective_servers.get(name)
        effective_definition = (
            cast(Mapping[str, Any], effective_definition_raw)
            if isinstance(effective_definition_raw, Mapping)
            else {}
        )
        enabled_raw = effective_definition.get("enabled", True)
        required_raw = effective_definition.get("required", False)
        enabled = enabled_raw if isinstance(enabled_raw, bool) else True
        required = required_raw if isinstance(required_raw, bool) else False

        for _, definition, source in entries:
            declared = _flatten(definition)
            effective_fields = sorted(
                field for field in declared if field_origins.get((name, field)) == source.id
            )
            shadowed_fields = sorted(declared - set(effective_fields))
            source.metadata["effective_fields"] = effective_fields
            source.metadata["shadowed_fields"] = shadowed_fields
            if source.status in {SourceStatus.ACTIVE, SourceStatus.SHADOWED}:
                if not effective_fields and declared:
                    source.status = SourceStatus.SHADOWED
                    source.reason = "All fields are replaced by higher-precedence MCP definitions."
                elif not enabled:
                    source.status = SourceStatus.IGNORED
                    source.reason = "The effective MCP server is explicitly disabled."

        source_ids = [source.id for _, _, source in entries]
        if not isinstance(enabled_raw, bool):
            result.findings.append(
                Finding(
                    id=f"mcp:{name}:enabled-type",
                    rule_id="MCP_INVALID_CONFIGURATION",
                    severity=Severity.ERROR,
                    title="Invalid MCP enabled flag",
                    message=f"{name!r}.enabled must be true or false.",
                    source_ids=source_ids,
                )
            )
        if not isinstance(required_raw, bool):
            result.findings.append(
                Finding(
                    id=f"mcp:{name}:required-type",
                    rule_id="MCP_INVALID_CONFIGURATION",
                    severity=Severity.ERROR,
                    title="Invalid MCP required flag",
                    message=f"{name!r}.required must be true or false.",
                    source_ids=source_ids,
                )
            )

        enabled_tools = _list_of_strings(effective_definition.get("enabled_tools"))
        disabled_tools = _list_of_strings(effective_definition.get("disabled_tools"))
        if enabled_tools is None or disabled_tools is None:
            result.findings.append(
                Finding(
                    id=f"mcp:{name}:tool-filter-type",
                    rule_id="MCP_INVALID_TOOL_FILTER",
                    severity=Severity.ERROR,
                    title="Invalid MCP tool filter",
                    message=f"{name!r} tool filters must be arrays of tool names.",
                    source_ids=source_ids,
                )
            )
            enabled_tools = enabled_tools or []
            disabled_tools = disabled_tools or []
        overlap = sorted(set(enabled_tools) & set(disabled_tools))
        if overlap:
            result.findings.append(
                Finding(
                    id=f"mcp:{name}:tool-filter-overlap",
                    rule_id="MCP_TOOL_FILTER_OVERLAP",
                    severity=Severity.WARNING,
                    title="MCP tool appears in allow and deny filters",
                    message=(
                        f"{name!r} lists the same tool in enabled_tools and disabled_tools; "
                        "the deny list is the restrictive outcome."
                    ),
                    source_ids=source_ids,
                    details={"tools": overlap},
                )
            )
        if required and not enabled:
            result.findings.append(
                Finding(
                    id=f"mcp:{name}:required-disabled",
                    rule_id="MCP_REQUIRED_DISABLED",
                    severity=Severity.ERROR,
                    title="Required MCP server is disabled",
                    message=f"{name!r} cannot satisfy required=true while enabled=false.",
                    source_ids=source_ids,
                )
            )

        server_status = "disabled" if not enabled else "enabled"
        state_servers.append(
            {
                "name": name,
                "status": server_status,
                "enabled": enabled,
                "required": required,
                "transport": _transport(effective_definition),
                "enabled_tools": enabled_tools,
                "disabled_tools": disabled_tools,
                "effective_denials": overlap,
                "approvals_configured": "approvals" in effective_definition,
            }
        )

    for name, value in sorted(effective_servers.items()):
        if name in definitions or not isinstance(value, Mapping):
            continue
        # This path supports callers that provide a plain dict rather than the
        # provenance-bearing result from analyze_config.
        definition = cast(Mapping[str, Any], value)
        source_id = f"mcp:effective:{name}"
        enabled = definition.get("enabled", True)
        result.sources.append(
            Source(
                id=source_id,
                kind="mcp",
                scope="effective",
                path="<effective configuration>",
                status=SourceStatus.ACTIVE if enabled is not False else SourceStatus.IGNORED,
                reason="Effective MCP definition supplied without layer provenance.",
                metadata={"server": name, "transport": _transport(definition)},
            )
        )

    if result.sources:
        result.layers.append(
            Layer(
                id="mcp:effective",
                kind="mcp",
                scope="resolved",
                precedence=max((source.precedence for source in result.sources), default=0),
                source_ids=[source.id for source in result.sources],
                status=SourceStatus.ACTIVE,
                reason="Static MCP definitions only; no server was started.",
            )
        )
    result.state["mcp"] = {
        "servers": state_servers,
        "execution": "not_started",
        "secrets_observed": False,
    }
    return result
