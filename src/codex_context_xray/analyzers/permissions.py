"""Analyze Codex legacy sandbox settings and permission-profile inheritance."""

from __future__ import annotations

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

_BUILTIN_PARENTS = frozenset({":read-only", ":workspace"})
_BUILTIN_SELECTABLE = frozenset({":read-only", ":workspace", ":danger-full-access"})
_LEGACY_KEYS = frozenset({"sandbox_mode", "sandbox_workspace_write"})
_PROFILE_KEYS = frozenset({"default_permissions", "permissions"})


def _relevant(record: ConfigLayerRecord, keys: frozenset[str]) -> bool:
    return any(key in record.data for key in keys)


def _profile_summary(profile: Mapping[str, Any]) -> dict[str, Any]:
    filesystem = profile.get("filesystem")
    network = profile.get("network")
    fs_rules = len(filesystem) if isinstance(filesystem, Mapping) else 0
    network_rules = len(network) if isinstance(network, Mapping) else 0
    return {
        "extends": profile.get("extends") if isinstance(profile.get("extends"), str) else None,
        "filesystem_rule_count": fs_rules,
        "network_rule_count": network_rules,
        "setting_keys": sorted(str(key) for key in profile if key != "extends"),
    }


def _merge_tables(base: dict[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        if key == "extends":
            continue
        previous = merged.get(key)
        if isinstance(previous, dict) and isinstance(value, Mapping):
            merged[key] = _merge_tables(previous, cast(Mapping[str, Any], value))
        else:
            merged[key] = value
    return merged


def analyze_permissions(ctx: ScanContext, effective_config: Mapping[str, Any]) -> AnalysisResult:
    """Resolve the mutually exclusive legacy and permission-profile models."""

    del ctx
    result = AnalysisResult()
    records = config_provenance(effective_config)
    if not records:
        records = [
            ConfigLayerRecord(
                id="config:effective",
                path="<effective configuration>",
                scope="effective",
                precedence=0,
                status=SourceStatus.ACTIVE,
                data=dict(effective_config),
            )
        ]

    # A legacy sandbox declaration in any loaded layer selects the legacy
    # model.  Shadowed values still count as declarations; conditional and
    # untrusted layers do not deterministically load.
    loaded_statuses = {SourceStatus.ACTIVE, SourceStatus.SHADOWED}
    legacy_records = [
        record
        for record in records
        if record.status in loaded_statuses and _relevant(record, _LEGACY_KEYS)
    ]
    profile_records = [
        record
        for record in records
        if record.status in loaded_statuses and _relevant(record, _PROFILE_KEYS)
    ]
    conditional_records = [
        record
        for record in records
        if record.status is SourceStatus.CONDITIONAL
        and _relevant(record, _LEGACY_KEYS | _PROFILE_KEYS)
    ]

    source_ids: list[str] = []
    for record in [*legacy_records, *profile_records, *conditional_records]:
        has_legacy = _relevant(record, _LEGACY_KEYS)
        has_profiles = _relevant(record, _PROFILE_KEYS)
        source_id = f"permissions:{record.id}"
        source_ids.append(source_id)
        if record.status is SourceStatus.CONDITIONAL:
            status = SourceStatus.CONDITIONAL
            reason = "Permission settings load only when the project is trusted."
        elif legacy_records and has_profiles and not has_legacy:
            status = SourceStatus.IGNORED
            reason = (
                "Permission profiles are inactive because a loaded legacy sandbox setting wins."
            )
        else:
            status = SourceStatus.ACTIVE
            reason = "This source contributes to the selected permission model."
        result.sources.append(
            Source(
                id=source_id,
                kind="permissions",
                scope=record.scope,
                path=record.path,
                status=status,
                reason=reason,
                precedence=record.precedence,
                metadata={
                    "declares_legacy_sandbox": has_legacy,
                    "declares_permission_profiles": has_profiles,
                },
            )
        )

    has_profiles = bool(profile_records) or any(
        key in effective_config for key in _PROFILE_KEYS
    )
    has_legacy = bool(legacy_records)
    if has_legacy and has_profiles:
        result.findings.append(
            Finding(
                id="permissions:legacy-profile-conflict",
                rule_id="PERMISSIONS_LEGACY_CONFLICT",
                severity=Severity.WARNING,
                title="Legacy sandbox disables permission profiles",
                message=(
                    "At least one loaded layer declares sandbox_mode or sandbox_workspace_write; "
                    "Codex uses the legacy sandbox model instead of "
                    "default_permissions/[permissions]."
                ),
                source_ids=source_ids,
            )
        )

    raw_profiles = effective_config.get("permissions", {})
    profiles: dict[str, Mapping[str, Any]] = {}
    if raw_profiles is not None and not isinstance(raw_profiles, Mapping):
        result.findings.append(
            Finding(
                id="permissions:invalid-table",
                rule_id="PERMISSIONS_INVALID_PROFILE",
                severity=Severity.ERROR,
                title="Invalid permissions table",
                message="[permissions] must contain named profile tables.",
                source_ids=source_ids,
            )
        )
    elif isinstance(raw_profiles, Mapping):
        for raw_name, raw_profile in sorted(raw_profiles.items(), key=lambda item: str(item[0])):
            name = str(raw_name)
            if not isinstance(raw_profile, Mapping):
                result.findings.append(
                    Finding(
                        id=f"permissions:profile:{name}:invalid",
                        rule_id="PERMISSIONS_INVALID_PROFILE",
                        severity=Severity.ERROR,
                        title="Invalid permission profile",
                        message=f"Permission profile {name!r} must be a table.",
                        source_ids=source_ids,
                    )
                )
                continue
            profiles[name] = cast(Mapping[str, Any], raw_profile)

    parents: dict[str, str | None] = {}
    for name, profile in profiles.items():
        parent_raw = profile.get("extends")
        if parent_raw is None:
            parents[name] = None
        elif not isinstance(parent_raw, str):
            parents[name] = None
            result.findings.append(
                Finding(
                    id=f"permissions:profile:{name}:extends-type",
                    rule_id="PERMISSIONS_INVALID_PROFILE",
                    severity=Severity.ERROR,
                    title="Invalid permission profile parent",
                    message=f"Permission profile {name!r}.extends must be a string.",
                    source_ids=source_ids,
                )
            )
        else:
            parents[name] = parent_raw
            if parent_raw == ":danger-full-access":
                result.findings.append(
                    Finding(
                        id=f"permissions:profile:{name}:danger-parent",
                        rule_id="PERMISSIONS_FORBIDDEN_PARENT",
                        severity=Severity.ERROR,
                        title="Permission profile extends a forbidden base",
                        message=(
                            f"Permission profile {name!r} cannot extend :danger-full-access."
                        ),
                        source_ids=source_ids,
                    )
                )
            elif parent_raw not in _BUILTIN_PARENTS and parent_raw not in profiles:
                result.findings.append(
                    Finding(
                        id=f"permissions:profile:{name}:unknown-parent",
                        rule_id="PERMISSIONS_UNKNOWN_PARENT",
                        severity=Severity.ERROR,
                        title="Unknown permission profile parent",
                        message=(
                            f"Permission profile {name!r} extends unknown profile "
                            f"{parent_raw!r}."
                        ),
                        source_ids=source_ids,
                    )
                )

    cycles: set[tuple[str, ...]] = set()
    visit_state: dict[str, int] = {}

    def visit(name: str, stack: list[str]) -> None:
        state = visit_state.get(name, 0)
        if state == 2:
            return
        if state == 1:
            if name in stack:
                start = stack.index(name)
                cycle = tuple([*stack[start:], name])
                cycles.add(cycle)
            return
        visit_state[name] = 1
        parent = parents.get(name)
        if parent in profiles:
            visit(parent, [*stack, name])
        visit_state[name] = 2

    for profile_name in sorted(profiles):
        visit(profile_name, [])
    for cycle in sorted(cycles):
        result.findings.append(
            Finding(
                id=f"permissions:cycle:{'-'.join(cycle)}",
                rule_id="PERMISSIONS_INHERITANCE_CYCLE",
                severity=Severity.ERROR,
                title="Permission profile inheritance cycle",
                message="Permission profile cycle: " + " -> ".join(cycle) + ".",
                source_ids=source_ids,
                details={"cycle": list(cycle)},
            )
        )

    def resolve_profile(name: str, visiting: frozenset[str] = frozenset()) -> dict[str, Any]:
        if name in visiting or name not in profiles:
            return {}
        parent = parents.get(name)
        inherited: dict[str, Any] = {}
        if parent in profiles:
            inherited = resolve_profile(parent, visiting | {name})
        return _merge_tables(inherited, profiles[name])

    def inheritance_chain(name: str) -> list[str]:
        chain: list[str] = [name]
        seen = {name}
        parent = parents.get(name)
        while isinstance(parent, str):
            chain.append(parent)
            if parent in seen or parent not in profiles:
                break
            seen.add(parent)
            parent = parents.get(parent)
        chain.reverse()
        return chain

    profile_state: dict[str, dict[str, Any]] = {}
    for name, profile in sorted(profiles.items()):
        resolved = resolve_profile(name)
        filesystem = resolved.get("filesystem")
        network = resolved.get("network")
        summary = _profile_summary(profile)
        summary.update(
            {
                "inheritance_chain": inheritance_chain(name),
                "effective_filesystem_rule_count": (
                    len(filesystem) if isinstance(filesystem, Mapping) else 0
                ),
                "effective_network_rule_count": (
                    len(network) if isinstance(network, Mapping) else 0
                ),
            }
        )
        profile_state[name] = summary

    selected_raw = effective_config.get("default_permissions")
    selected = selected_raw if isinstance(selected_raw, str) else None
    if selected_raw is not None and not isinstance(selected_raw, str):
        result.findings.append(
            Finding(
                id="permissions:default-type",
                rule_id="PERMISSIONS_INVALID_DEFAULT",
                severity=Severity.ERROR,
                title="Invalid default permission profile",
                message="default_permissions must be a profile name string.",
                source_ids=source_ids,
            )
        )
    if selected is not None and selected not in profiles and selected not in _BUILTIN_SELECTABLE:
        result.findings.append(
            Finding(
                id="permissions:default-unknown",
                rule_id="PERMISSIONS_UNKNOWN_DEFAULT",
                severity=Severity.ERROR,
                title="Unknown default permission profile",
                message=f"default_permissions selects unknown profile {selected!r}.",
                source_ids=source_ids,
            )
        )
    if profiles and selected is None:
        result.findings.append(
            Finding(
                id="permissions:default-missing",
                rule_id="PERMISSIONS_DEFAULT_MISSING",
                severity=Severity.WARNING,
                title="Permission profiles have no explicit default",
                message="Named profiles exist, but default_permissions is not set.",
                source_ids=source_ids,
            )
        )

    if has_legacy:
        mode = "legacy_sandbox"
        selected_effective: str | None = None
    elif has_profiles:
        mode = "permission_profiles"
        selected_effective = selected
    else:
        mode = "unconfigured"
        selected_effective = None

    # sandbox_mode and approval_policy are enums, not credentials.  Other
    # permission values are represented only by rule counts and key names.
    sandbox_mode = effective_config.get("sandbox_mode")
    approval_policy = effective_config.get("approval_policy")
    result.state["permissions"] = {
        "mode": mode,
        "selected_profile": selected_effective,
        "legacy": {
            "sandbox_mode": sandbox_mode if isinstance(sandbox_mode, str) else None,
            "approval_policy": approval_policy if isinstance(approval_policy, str) else None,
            "workspace_settings_present": "sandbox_workspace_write" in effective_config,
        },
        "profiles": profile_state,
        "conditional_sources": [record.id for record in conditional_records],
    }

    if source_ids:
        result.layers.append(
            Layer(
                id="permissions:effective",
                kind="permissions",
                scope="resolved",
                precedence=max((source.precedence for source in result.sources), default=0),
                source_ids=source_ids,
                status=SourceStatus.ACTIVE if mode != "unconfigured" else SourceStatus.UNOBSERVED,
                reason=(
                    "Legacy sandbox declarations take precedence."
                    if mode == "legacy_sandbox"
                    else "Permission-profile inheritance was analyzed statically."
                ),
            )
        )
    return result
