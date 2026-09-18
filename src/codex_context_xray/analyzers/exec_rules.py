"""Static analyzer for Codex Starlark ``prefix_rule`` files.

Only literal, top-level ``prefix_rule`` calls are interpreted.  The analyzer
never evaluates Starlark or invokes ``codex execpolicy``; dynamic constructs are
reported as unobserved instead of guessed.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

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

_DECISION_RANK = {"allow": 0, "prompt": 1, "forbidden": 2}
_ALLOWED_FIELDS = {"pattern", "decision", "justification", "match", "not_match"}


class _UnobservedRule(ValueError):
    """A valid-looking rule depends on runtime Starlark evaluation."""


def strictest_decision(decisions: Sequence[str]) -> str | None:
    """Return the most restrictive valid decision.

    Codex orders rule decisions as ``forbidden > prompt > allow``.
    """

    valid = [decision for decision in decisions if decision in _DECISION_RANK]
    return max(valid, key=_DECISION_RANK.__getitem__) if valid else None


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


def _status(ctx: ScanContext, scope: str) -> tuple[SourceStatus, str]:
    if scope != "project":
        return SourceStatus.ACTIVE, "This rules directory belongs to an active user layer."
    if ctx.trust_effective == "trusted":
        return SourceStatus.ACTIVE, "The project configuration layer is trusted."
    if ctx.trust_effective == "untrusted":
        return SourceStatus.IGNORED, "Project-local rules are skipped for an untrusted project."
    return SourceStatus.CONDITIONAL, "Project trust is unresolved, so these rules are conditional."


def _source_id(scope: str, shown: str) -> str:
    normalized = shown.replace("\\", "/").replace("/", ":")
    return f"exec-rules:{scope}:{normalized}"


def _literal(node: ast.AST) -> Any:
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, MemoryError, RecursionError) as exc:
        raise _UnobservedRule("field is dynamic and cannot be evaluated statically") from exc


def _normalize_pattern(value: Any) -> list[str | list[str]]:
    if not isinstance(value, list) or not value:
        raise ValueError("pattern must be a non-empty list")
    normalized: list[str | list[str]] = []
    for item in value:
        if isinstance(item, str) and item:
            normalized.append(item)
        elif (
            isinstance(item, list)
            and item
            and all(isinstance(option, str) and option for option in item)
        ):
            normalized.append(list(dict.fromkeys(item)))
        else:
            raise ValueError("pattern items must be strings or non-empty literal unions")
    return normalized


def _literal_string_list(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a list of strings")
    return value


def _parse_prefix_rule(call: ast.Call) -> dict[str, Any]:
    if len(call.args) > 1:
        raise ValueError("prefix_rule accepts at most one positional pattern")
    values: dict[str, Any] = {}
    if call.args:
        values["pattern"] = _literal(call.args[0])
    for keyword in call.keywords:
        if keyword.arg is None:
            raise ValueError("expanded keyword arguments are not statically observable")
        if keyword.arg not in _ALLOWED_FIELDS:
            raise ValueError(f"unsupported prefix_rule field: {keyword.arg}")
        if keyword.arg in values:
            raise ValueError(f"duplicate prefix_rule field: {keyword.arg}")
        values[keyword.arg] = _literal(keyword.value)

    if "pattern" not in values:
        raise ValueError("prefix_rule is missing required field: pattern")
    pattern = _normalize_pattern(values["pattern"])
    decision = values.get("decision", "allow")
    if not isinstance(decision, str) or decision not in _DECISION_RANK:
        raise ValueError("decision must be allow, prompt, or forbidden")
    justification = values.get("justification")
    if justification is not None and (
        not isinstance(justification, str) or not justification.strip()
    ):
        raise ValueError("justification must be a non-empty string when provided")
    matches = _literal_string_list(values.get("match"), "match")
    not_matches = _literal_string_list(values.get("not_match"), "not_match")
    return {
        "pattern": pattern,
        "decision": decision,
        "justification": justification,
        "match": matches,
        "not_match": not_matches,
        "line": getattr(call, "lineno", None),
    }


def _parse_rules(
    text: str,
) -> tuple[list[dict[str, Any]], list[str], list[str], str | None]:
    try:
        module = ast.parse(text, mode="exec")
    except SyntaxError as exc:
        where = f"line {exc.lineno}, column {exc.offset}" if exc.lineno else "unknown location"
        return [], [], [], f"Starlark-compatible syntax error at {where}: {exc.msg}"

    rules: list[dict[str, Any]] = []
    invalid_rules: list[str] = []
    unsupported: list[str] = []
    for statement in module.body:
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Name)
            and statement.value.func.id == "prefix_rule"
        ):
            try:
                rules.append(_parse_prefix_rule(statement.value))
            except _UnobservedRule as exc:
                unsupported.append(f"line {getattr(statement, 'lineno', '?')}: {exc}")
            except ValueError as exc:
                invalid_rules.append(f"line {getattr(statement, 'lineno', '?')}: {exc}")
            continue
        # A module docstring is inert and fully observable.
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue
        unsupported.append(
            f"line {getattr(statement, 'lineno', '?')}: dynamic or unsupported Starlark statement"
        )
    return rules, invalid_rules, unsupported, None


def _item_options(item: str | list[str]) -> set[str]:
    return {item} if isinstance(item, str) else set(item)


def patterns_overlap(left: Sequence[str | list[str]], right: Sequence[str | list[str]]) -> bool:
    """Return whether any command can match both literal prefix patterns."""

    return all(
        _item_options(left[index]) & _item_options(right[index])
        for index in range(min(len(left), len(right)))
    )


def _add_path_escape(
    result: AnalysisResult,
    ctx: ScanContext,
    *,
    scope: str,
    path: Path,
    precedence: int,
) -> None:
    shown = _display(ctx, path, scope)
    source_id = _source_id(scope, shown)
    result.sources.append(
        Source(
            id=source_id,
            kind="exec_rules",
            scope=scope,
            path=shown,
            status=SourceStatus.IGNORED,
            reason="The rules path resolves outside its declared configuration root.",
            precedence=precedence,
            metadata={"evaluation_performed": False},
        )
    )
    result.findings.append(
        Finding(
            id=f"RULES_PATH_ESCAPE_{len(result.findings) + 1:03d}",
            rule_id="PATH_ESCAPE",
            severity=Severity.ERROR,
            title="Rules path escapes the scan root",
            message="An external rules reference was not followed or read.",
            source_ids=[source_id],
        )
    )


def _scan_rules_directory(
    result: AnalysisResult,
    ctx: ScanContext,
    *,
    scope: str,
    rules_directory: Path,
    containment_root: Path,
    layer_key: str,
    precedence: int,
) -> list[dict[str, Any]]:
    try:
        safe_directory = resolve_within(rules_directory, containment_root, must_exist=True)
    except PathSafetyError:
        if rules_directory.exists() or rules_directory.is_symlink():
            _add_path_escape(
                result,
                ctx,
                scope=scope,
                path=rules_directory,
                precedence=precedence,
            )
        return []
    if not safe_directory.is_dir():
        return []

    status, reason = _status(ctx, scope)
    parsed_rules: list[dict[str, Any]] = []
    source_ids: list[str] = []
    # ``*.rules`` is intentionally non-recursive, matching the documented
    # rules-directory layout and avoiding surprise traversal.
    for path in sorted(rules_directory.glob("*.rules"), key=lambda item: item.name.casefold()):
        shown = _display(ctx, path, scope)
        source_id = _source_id(scope, shown)
        try:
            text = read_text_within(path, containment_root, encoding="utf-8-sig")
        except (PathSafetyError, UnicodeError) as exc:
            source = Source(
                id=source_id,
                kind="exec_rules",
                scope=scope,
                path=shown,
                status=SourceStatus.INVALID,
                reason=f"The rules file was not read safely: {exc}",
                precedence=precedence,
                metadata={"evaluation_performed": False},
            )
            result.sources.append(source)
            source_ids.append(source_id)
            result.findings.append(
                Finding(
                    id=f"RULES_INVALID_{len(result.findings) + 1:03d}",
                    rule_id="RULES_INVALID",
                    severity=Severity.ERROR,
                    title="Invalid rules file",
                    message=source.reason,
                    source_ids=[source_id],
                )
            )
            continue

        rules, invalid_rules, unsupported, syntax_error = _parse_rules(text)
        file_status = status
        file_reason = reason
        if syntax_error is not None:
            file_status = SourceStatus.INVALID
            file_reason = syntax_error
            result.findings.append(
                Finding(
                    id=f"RULES_PARSE_{len(result.findings) + 1:03d}",
                    rule_id="RULES_PARSE_ERROR",
                    severity=Severity.ERROR,
                    title="Rules syntax could not be parsed",
                    message=syntax_error,
                    source_ids=[source_id],
                )
            )
        elif invalid_rules:
            file_status = SourceStatus.INVALID
            file_reason = "One or more prefix_rule calls are structurally invalid."
            result.findings.append(
                Finding(
                    id=f"RULES_INVALID_{len(result.findings) + 1:03d}",
                    rule_id="RULES_INVALID",
                    severity=Severity.ERROR,
                    title="Invalid prefix rule",
                    message="; ".join(invalid_rules),
                    source_ids=[source_id],
                )
            )
        elif unsupported:
            if file_status == SourceStatus.ACTIVE:
                file_status = SourceStatus.CONDITIONAL
            file_reason = "Some Starlark statements are not statically observable."
            result.findings.append(
                Finding(
                    id=f"RULES_STATIC_{len(result.findings) + 1:03d}",
                    rule_id="RULES_STATIC_ANALYSIS_INCOMPLETE",
                    severity=Severity.WARNING,
                    title="Rules file needs runtime validation",
                    message="; ".join(unsupported),
                    source_ids=[source_id],
                )
            )

        safe_rules: list[dict[str, Any]] = []
        for index, rule in enumerate(rules):
            safe_rule, redactions = redact(
                rule,
                ctx.user_home,
                location=f"$.effective_state.exec_rules.rules.{source_id}[{index}]",
            )
            result.redactions.extend(redactions)
            public_rule = {
                "source_id": source_id,
                "index": index,
                "pattern": safe_rule["pattern"],
                "decision": safe_rule["decision"],
                "justification": safe_rule["justification"],
                "example_count": len(rule["match"]),
                "negative_example_count": len(rule["not_match"]),
                "line": rule["line"],
                "conditional": file_status == SourceStatus.CONDITIONAL,
                "ignored": file_status == SourceStatus.IGNORED,
            }
            safe_rules.append(public_rule)
            if file_status != SourceStatus.INVALID:
                parsed_rules.append(public_rule)

        result.sources.append(
            Source(
                id=source_id,
                kind="exec_rules",
                scope=scope,
                path=shown,
                status=file_status,
                reason=file_reason,
                precedence=precedence,
                excerpt=f"{len(rules)} literal prefix rule(s)",
                metadata={
                    "rule_count": len(rules),
                    "invalid_rule_count": len(invalid_rules),
                    "static_problem_count": len(unsupported),
                    "decisions": [rule["decision"] for rule in safe_rules],
                    "evaluation_performed": False,
                },
            )
        )
        source_ids.append(source_id)

    if source_ids:
        layer_status = _status(ctx, scope)[0]
        result.layers.append(
            Layer(
                id=f"exec-rules-layer:{layer_key}",
                kind="exec_rules",
                scope=scope,
                precedence=precedence,
                source_ids=source_ids,
                status=layer_status,
                reason=reason,
            )
        )
    return parsed_rules


def _overlaps(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    overlaps: list[dict[str, Any]] = []
    eligible = [rule for rule in rules if not rule["ignored"]]
    for left_index, left in enumerate(eligible):
        for right in eligible[left_index + 1 :]:
            if not patterns_overlap(left["pattern"], right["pattern"]):
                continue
            overlaps.append(
                {
                    "left": {"source_id": left["source_id"], "index": left["index"]},
                    "right": {"source_id": right["source_id"], "index": right["index"]},
                    "decisions": [left["decision"], right["decision"]],
                    "strictest_decision": strictest_decision([left["decision"], right["decision"]]),
                    "conditional": left["conditional"] or right["conditional"],
                }
            )
    return overlaps


def analyze_exec_rules(
    ctx: ScanContext,
    effective_config: Mapping[str, Any],
) -> AnalysisResult:
    """Parse literal prefix rules and explain deterministic overlap behavior."""

    del effective_config  # Rules are additive sources, not merged config keys.
    result = AnalysisResult()
    rules: list[dict[str, Any]] = []

    if ctx.include_user and ctx.codex_home is not None:
        rules.extend(
            _scan_rules_directory(
                result,
                ctx,
                scope="user",
                rules_directory=ctx.codex_home / "rules",
                containment_root=ctx.user_home or ctx.codex_home,
                layer_key="user",
                precedence=20,
            )
        )

    for depth, directory in enumerate(_project_directories(ctx)):
        relative = directory.relative_to(ctx.repo_root.resolve()).as_posix() or "."
        rules.extend(
            _scan_rules_directory(
                result,
                ctx,
                scope="project",
                rules_directory=directory / ".codex" / "rules",
                containment_root=ctx.repo_root,
                layer_key=f"project:{relative}",
                precedence=100 + depth,
            )
        )

    overlaps = _overlaps(rules)
    for overlap in overlaps:
        left = overlap["left"]
        right = overlap["right"]
        result.findings.append(
            Finding(
                id=f"RULES_OVERLAP_{len(result.findings) + 1:03d}",
                rule_id="RULES_OVERLAP",
                severity=Severity.WARNING,
                title="Prefix rules overlap",
                message=(
                    "A command can match both rules; Codex applies the most restrictive "
                    f"decision ({overlap['strictest_decision']})."
                ),
                source_ids=list(dict.fromkeys([left["source_id"], right["source_id"]])),
                details=overlap,
            )
        )

    result.state["exec_rules"] = {
        "rules": rules,
        "overlaps": overlaps,
        "decision_order": ["forbidden", "prompt", "allow"],
        "static_only": True,
        "evaluation_performed": False,
    }
    return result


__all__ = ["analyze_exec_rules", "patterns_overlap", "strictest_decision"]
