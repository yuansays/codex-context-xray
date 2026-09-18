"""High-level, read-only Codex context scan orchestration."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import tomli as tomllib

from . import __version__
from .analyzers.config import analyze_config
from .analyzers.exec_rules import analyze_exec_rules
from .analyzers.hooks import analyze_hooks
from .analyzers.instructions import analyze_instructions
from .analyzers.mcp import analyze_mcp
from .analyzers.permissions import analyze_permissions
from .analyzers.skills import analyze_skills
from .model import AnalysisResult, Layer, Report, ScanContext, SourceStatus
from .redaction import redact

DOCS_SNAPSHOT = "2026-09-18"


class ScanError(RuntimeError):
    """Raised for an invalid request or a scan that cannot start."""


def find_repo_root(target: Path) -> Path:
    """Return the nearest Git worktree root, or the target directory itself."""
    directory = target.parent if target.is_file() else target
    directory = directory.resolve()
    for candidate in (directory, *directory.parents):
        marker = candidate / ".git"
        if marker.is_dir() or marker.is_file():
            return candidate
    return directory


def _user_locations() -> tuple[Path, Path]:
    # User path discovery happens only after explicit --include-user opt-in.
    home = Path.home().resolve()
    return home, home / ".codex"


def _detect_trust(repo_root: Path, codex_home: Path | None) -> str:
    if codex_home is None:
        return "conditional"
    config_path = codex_home / "config.toml"
    try:
        raw = config_path.read_bytes()
        parsed = tomllib.loads(raw.decode("utf-8-sig"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return "conditional"
    projects = parsed.get("projects")
    if not isinstance(projects, dict):
        return "conditional"
    canonical = os.path.normcase(str(repo_root.resolve()))
    for configured_path, value in projects.items():
        if os.path.normcase(str(Path(configured_path).expanduser().resolve())) != canonical:
            continue
        if isinstance(value, dict):
            trust = value.get("trust_level")
            if trust in {"trusted", "untrusted"}:
                return str(trust)
    return "conditional"


def _display_path(path_text: str, repo_root: Path, user_home: Path | None) -> str:
    if path_text.startswith("$") or path_text.startswith("<"):
        return path_text
    try:
        path = Path(path_text)
        resolved = (
            path.resolve(strict=False)
            if path.is_absolute()
            else (repo_root / path).resolve(strict=False)
        )
    except (OSError, RuntimeError, ValueError):
        sanitized, _ = redact(path_text, user_home)
        return str(sanitized)
    try:
        relative = resolved.relative_to(repo_root)
        return "." if str(relative) == "." else f"./{relative.as_posix()}"
    except ValueError:
        sanitized, _ = redact(str(resolved), user_home)
        return str(sanitized)


def _sanitize_report(report: Report, repo_root: Path, user_home: Path | None) -> None:
    """Apply a final privacy boundary even when an analyzer missed a field."""
    redaction_records: list[dict[str, Any]] = []
    for source in report.sources:
        source.path = _display_path(source.path, repo_root, user_home)
        if source.excerpt is not None:
            source.excerpt, records = redact(source.excerpt, user_home)
            redaction_records.extend(records)
        source.reason, records = redact(source.reason, user_home)
        redaction_records.extend(records)
        source.metadata, records = redact(source.metadata, user_home)
        redaction_records.extend(records)
    for finding in report.findings:
        finding.message, records = redact(finding.message, user_home)
        redaction_records.extend(records)
        finding.details, records = redact(finding.details, user_home)
        redaction_records.extend(records)
    for key, value in list(report.effective_state.items()):
        report.effective_state[key], records = redact(value, user_home)
        redaction_records.extend(records)
    categories: dict[str, int] = {}
    for record in [*report.redactions, *redaction_records]:
        category = str(record.get("category", "sensitive-value"))
        categories[category] = categories.get(category, 0) + int(record.get("count", 1))
    report.redactions = [
        {"category": key, "count": categories[key]} for key in sorted(categories)
    ]


def scan(
    target: str | Path = ".",
    *,
    include_user: bool = False,
    profile: str | None = None,
    trust: str = "auto",
    cli_overrides: list[str] | None = None,
) -> Report:
    """Statically explain the Codex inputs for *target* without executing them."""
    target_path = Path(target)
    if not target_path.exists():
        raise ScanError(f"Target does not exist: {target}")
    if profile and not include_user:
        raise ScanError("--profile requires --include-user because profiles live in user config.")
    if trust not in {"auto", "trusted", "untrusted"}:
        raise ScanError(f"Unsupported trust mode: {trust}")

    target_path = target_path.resolve()
    repo_root = find_repo_root(target_path)
    user_home: Path | None = None
    codex_home: Path | None = None
    if include_user:
        user_home, codex_home = _user_locations()
    trust_effective = trust if trust != "auto" else _detect_trust(repo_root, codex_home)
    ctx = ScanContext(
        target=target_path,
        repo_root=repo_root,
        include_user=include_user,
        user_home=user_home,
        codex_home=codex_home,
        profile=profile,
        trust_requested=trust,
        trust_effective=trust_effective,
        cli_overrides=list(cli_overrides or []),
    )

    aggregate = AnalysisResult()
    config_result, effective_config = analyze_config(ctx)
    aggregate.extend(config_result)

    fallbacks = effective_config.get("project_doc_fallback_filenames", [])
    if not isinstance(fallbacks, list) or not all(isinstance(item, str) for item in fallbacks):
        fallbacks = []
    byte_limit = effective_config.get("project_doc_max_bytes", 32 * 1024)
    if not isinstance(byte_limit, int) or byte_limit < 0:
        byte_limit = 32 * 1024

    analyses = [
        analyze_instructions(ctx, fallback_filenames=tuple(fallbacks), max_bytes=byte_limit),
        analyze_skills(ctx),
        analyze_mcp(ctx, effective_config),
        analyze_hooks(ctx, effective_config),
        analyze_exec_rules(ctx, effective_config),
        analyze_permissions(ctx, effective_config),
    ]
    state: dict[str, Any] = {"config": effective_config}
    if config_result.state:
        state.update(config_result.state)
    for result in analyses:
        aggregate.extend(result)
        state.update(result.state)

    aggregate.layers.extend(
        [
            Layer(
                id="cloud-managed",
                kind="configuration",
                scope="cloud",
                precedence=5,
                status=SourceStatus.UNOBSERVED,
                reason="Cloud-managed defaults are not visible to an offline repository scan.",
            ),
            Layer(
                id="built-in-runtime",
                kind="configuration",
                scope="runtime",
                precedence=7,
                status=SourceStatus.UNOBSERVED,
                reason="Runtime defaults and hidden platform policy are outside this report.",
            ),
        ]
    )
    report = Report(
        schema_version=1,
        tool={
            "name": "codex-xray",
            "version": __version__,
            "adapter": "codex",
            "docs_snapshot": DOCS_SNAPSHOT,
        },
        coverage={
            "mode": "offline-static",
            "target": _display_path(str(target_path), repo_root, user_home),
            "repository_root": ".",
            "include_user": include_user,
            "trust": {"requested": trust, "effective": trust_effective},
            "observed": [
                "repository instructions",
                "repository .codex configuration",
                "repository skills",
                "declared MCP servers",
                "declared hooks and rules",
                "declared permissions",
            ]
            + (["opted-in user configuration and skills"] if include_user else []),
            "unobserved": [
                "hidden system prompts",
                "live conversation context",
                "cloud-managed defaults and requirements",
                "runtime plugin payloads",
                "MCP and hook runtime behavior",
            ],
            "network_access": False,
            "target_mutated": False,
        },
        layers=aggregate.layers,
        sources=aggregate.sources,
        effective_state=state,
        findings=aggregate.findings,
        redactions=aggregate.redactions,
    )
    _sanitize_report(report, repo_root, user_home)
    return report
