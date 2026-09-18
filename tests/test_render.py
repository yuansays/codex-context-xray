from __future__ import annotations

import json

from codex_context_xray.model import Finding, Layer, Report, Severity, Source, SourceStatus
from codex_context_xray.render import render_html, render_human, render_json


def sample_report(*, malicious: bool = False) -> Report:
    unsafe = '<img src=x onerror="alert(1)"><script>bad()</script>'
    text = unsafe if malicious else "Loaded from the repository root."
    source = Source(
        id="source-root",
        kind="instructions",
        scope="repository",
        path=text if malicious else "AGENTS.md",
        status=SourceStatus.ACTIVE,
        reason=text,
        precedence=10,
        excerpt=text,
        metadata={"condition": text},
    )
    return Report(
        schema_version=1,
        tool={"name": text if malicious else "codex-xray", "version": "0.1.0"},
        coverage={"repository": "observed", "user_config": "not requested"},
        layers=[
            Layer(
                id="project",
                kind="project",
                scope="repository",
                precedence=10,
                source_ids=[source.id],
            )
        ],
        sources=[source],
        effective_state={"instructions": [source.id]},
        findings=[
            Finding(
                id="finding-one",
                rule_id="instructions.demo",
                severity=Severity.WARNING,
                title=text,
                message=text,
                source_ids=[source.id],
            )
        ],
        redactions=[{"kind": "home_path", "count": 1}],
    )


def test_json_is_stable_pretty_and_schema_preserving() -> None:
    report = sample_report()

    first = render_json(report)
    second = render_json(report)

    assert first == second
    assert first.endswith("\n")
    assert first.startswith("{\n")
    payload = json.loads(first)
    assert payload["schema_version"] == 1
    assert payload["sources"][0]["status"] == "active"
    assert payload["findings"][0]["severity"] == "warning"
    assert list(payload) == sorted(payload)


def test_human_summary_is_concise_and_contains_actionable_finding() -> None:
    rendered = render_human(sample_report())

    assert rendered.startswith("Codex Context X-Ray 0.1.0\n")
    assert "Result: warning | Sources: 1 (active=1)" in rendered
    assert "Findings: 1 (warning=1)" in rendered
    assert "[WARNING]" in rendered
    assert "instructions.demo" in rendered
    assert not rendered.startswith("\x1b")


def test_human_summary_neutralizes_terminal_control_characters() -> None:
    report = sample_report()
    report.findings[0].message = "safe\x1b[31mred"

    rendered = render_human(report)

    assert "\x1b" not in rendered
    assert "safe\\u001b[31mred" in rendered


def test_html_has_exactly_four_offline_accessible_lanes() -> None:
    rendered = render_html(sample_report())

    assert rendered.count('<section class="lane"') == 4
    for title in ("Instructions", "Skills &amp; Tools", "Hooks &amp; Rules", "Permissions"):
        assert f">{title}</h2>" in rendered
    assert "Content-Security-Policy" in rendered
    assert "default-src 'none'" in rendered
    assert "<script src=" not in rendered
    assert "<link rel=" not in rendered
    assert "fetch(" not in rendered
    assert 'type="button" class="source-node' in rendered
    assert 'aria-controls="source-detail"' in rendered
    assert "event.key === 'Escape'" in rendered
    assert "previous.focus({preventScroll: true})" in rendered


def test_html_escapes_every_report_controlled_value() -> None:
    rendered = render_html(sample_report(malicious=True))

    assert "<img src=x" not in rendered
    assert "<script>bad()" not in rendered
    assert "&lt;img src=x" in rendered
    assert "&lt;script&gt;bad()&lt;/script&gt;" in rendered
    assert ".innerHTML" not in rendered
    assert ".textContent" in rendered
