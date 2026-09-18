"""Stable, JSON-friendly report model used by every analyzer and renderer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class SourceStatus(str, Enum):
    ACTIVE = "active"
    SHADOWED = "shadowed"
    CONDITIONAL = "conditional"
    IGNORED = "ignored"
    INVALID = "invalid"
    UNOBSERVED = "unobserved"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(slots=True)
class Source:
    id: str
    kind: str
    scope: str
    path: str
    status: SourceStatus
    reason: str
    precedence: int = 0
    excerpt: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Layer:
    id: str
    kind: str
    scope: str
    precedence: int
    source_ids: list[str] = field(default_factory=list)
    status: SourceStatus = SourceStatus.ACTIVE
    reason: str = ""


@dataclass(slots=True)
class Finding:
    id: str
    rule_id: str
    severity: Severity
    title: str
    message: str
    source_ids: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AnalysisResult:
    layers: list[Layer] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)
    state: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    redactions: list[dict[str, Any]] = field(default_factory=list)

    def extend(self, other: AnalysisResult) -> None:
        self.layers.extend(other.layers)
        self.sources.extend(other.sources)
        self.findings.extend(other.findings)
        self.redactions.extend(other.redactions)


@dataclass(slots=True)
class ScanContext:
    target: Path
    repo_root: Path
    include_user: bool
    user_home: Path | None
    codex_home: Path | None
    profile: str | None
    trust_requested: str
    trust_effective: str
    cli_overrides: list[str]


@dataclass(slots=True)
class Report:
    schema_version: int
    tool: dict[str, str]
    coverage: dict[str, Any]
    layers: list[Layer]
    sources: list[Source]
    effective_state: dict[str, Any]
    findings: list[Finding]
    redactions: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def max_severity(self) -> Severity | None:
        rank = {Severity.INFO: 0, Severity.WARNING: 1, Severity.ERROR: 2}
        if not self.findings:
            return None
        return max((finding.severity for finding in self.findings), key=rank.__getitem__)
