"""Stable human, JSON, and HTML renderers."""

from __future__ import annotations

import json
from collections import Counter
from enum import Enum
from pathlib import Path
from typing import Any

from .html_report import render_html
from .model import Report

_SEVERITY_RANK = {"error": 0, "warning": 1, "info": 2}


def _terminal_safe(value: Any) -> str:
    text = str(value)
    return "".join(
        character if character.isprintable() else f"\\u{ord(character):04x}" for character in text
    )


def _json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return value.as_posix()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def render_json(report: Report) -> str:
    """Return stable, pretty JSON with a final newline."""

    return (
        json.dumps(
            report.to_dict(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            default=_json_default,
        )
        + "\n"
    )


def _coverage_summary(report: Report) -> str | None:
    if not report.coverage:
        return None
    fields: list[str] = []
    for key in ("mode", "target", "repository_root"):
        if key in report.coverage:
            fields.append(f"{key}={_terminal_safe(report.coverage[key])}")
    if "include_user" in report.coverage:
        included = bool(report.coverage["include_user"])
        fields.append(f"user_config={'included' if included else 'not requested'}")
    elif "user_config" in report.coverage:
        fields.append(f"user_config={_terminal_safe(report.coverage['user_config'])}")
    trust = report.coverage.get("trust")
    if isinstance(trust, dict):
        effective = trust.get("effective", "unknown")
        fields.append(f"trust={_terminal_safe(effective)}")
    if "network_access" in report.coverage:
        network = bool(report.coverage["network_access"])
        fields.append(f"network={'used' if network else 'not used'}")
    elif "network" in report.coverage:
        fields.append(f"network={_terminal_safe(report.coverage['network'])}")
    unobserved = report.coverage.get("unobserved")
    if isinstance(unobserved, list):
        fields.append(f"unobserved={len(unobserved)} areas")
    return ", ".join(fields) if fields else "reported"


def render_human(report: Report) -> str:
    """Return a concise plain-text summary suitable for a terminal."""

    statuses = Counter(source.status.value for source in report.sources)
    severities = Counter(finding.severity.value for finding in report.findings)
    state_order = ("active", "shadowed", "conditional", "ignored", "invalid", "unobserved")
    severity_order = ("error", "warning", "info")
    status_text = ", ".join(f"{name}={statuses[name]}" for name in state_order if statuses[name])
    severity_text = ", ".join(
        f"{name}={severities[name]}" for name in severity_order if severities[name]
    )
    maximum = report.max_severity.value if report.max_severity else "clear"
    lines = [
        f"Codex Context X-Ray {_terminal_safe(report.tool.get('version', ''))}".rstrip(),
        f"Result: {maximum} | Sources: {len(report.sources)}"
        + (f" ({status_text})" if status_text else ""),
        f"Findings: {len(report.findings)}" + (f" ({severity_text})" if severity_text else ""),
    ]
    coverage = _coverage_summary(report)
    if coverage is not None:
        lines.append(f"Coverage: {coverage}")
    if report.findings:
        lines.append("")
        lines.append("Findings")
        for finding in sorted(
            report.findings,
            key=lambda item: (_SEVERITY_RANK[item.severity.value], item.rule_id, item.id),
        ):
            lines.append(
                f"- [{finding.severity.value.upper()}] {_terminal_safe(finding.title)} "
                f"({_terminal_safe(finding.rule_id)}): {_terminal_safe(finding.message)}"
            )
    return "\n".join(lines) + "\n"


__all__ = ["render_html", "render_human", "render_json"]
