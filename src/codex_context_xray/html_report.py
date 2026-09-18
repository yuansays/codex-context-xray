"""Self-contained, offline HTML reports for Codex Context X-Ray."""

from __future__ import annotations

from html import escape
from typing import Any

from .model import Report, Source

LANES: tuple[str, ...] = (
    "Instructions",
    "Skills & Tools",
    "Hooks & Rules",
    "Permissions",
)
_SEVERITY_RANK = {"error": 0, "warning": 1, "info": 2}


def _text(value: Any) -> str:
    """Return a display-safe textual representation before HTML escaping."""

    if value is None:
        return "None"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, set):
        return ", ".join(sorted(_text(item) for item in value)) or "None"
    if isinstance(value, (list, tuple)):
        return ", ".join(_text(item) for item in value) or "None"
    if isinstance(value, dict):
        return ", ".join(f"{key}={_text(value[key])}" for key in sorted(value)) or "None"
    return str(value)


def _escaped(value: Any) -> str:
    return escape(_text(value), quote=True)


def _lane_for(source: Source) -> str:
    explicit = source.metadata.get("lane")
    if explicit in LANES:
        return str(explicit)

    kind = source.kind.casefold().replace("_", "-")
    if any(token in kind for token in ("instruction", "agents", "project-doc")):
        return "Instructions"
    if any(token in kind for token in ("hook", "rule", "execpolicy")):
        return "Hooks & Rules"
    if any(token in kind for token in ("permission", "sandbox", "trust")):
        return "Permissions"
    return "Skills & Tools"


def _condition(source: Source) -> str:
    condition = source.metadata.get("condition")
    if condition is not None:
        return _text(condition)
    if source.status.value == "conditional":
        return source.reason
    return "None"


def _source_node(source: Source) -> str:
    excerpt = source.excerpt if source.excerpt else "Not shown"
    label = source.metadata.get("label", source.path or source.id)
    attributes = {
        "data-source": source.id,
        "data-kind": source.kind,
        "data-scope": source.scope,
        "data-status": source.status.value,
        "data-path": source.path,
        "data-reason": source.reason,
        "data-condition": _condition(source),
        "data-excerpt": excerpt,
    }
    rendered_attributes = " ".join(
        f'{name}="{_escaped(value)}"' for name, value in attributes.items()
    )
    return (
        '<li class="flow-item">'
        f'<button type="button" class="source-node status-{_escaped(source.status.value)}" '
        f'aria-controls="source-detail" aria-expanded="false" {rendered_attributes}>'
        f'<span class="node-label">{_escaped(label)}</span>'
        f'<span class="badge">{_escaped(source.status.value)}</span>'
        f'<span class="node-reason">{_escaped(source.reason)}</span>'
        "</button></li>"
    )


def _lane(name: str, sources: list[Source]) -> str:
    ordered = sorted(sources, key=lambda source: (source.precedence, source.id))
    if ordered:
        body = "".join(_source_node(source) for source in ordered)
    else:
        body = '<li class="empty">No observed sources in this lane.</li>'
    lane_id = name.casefold().replace(" ", "-").replace("&", "and")
    return (
        f'<section class="lane" aria-labelledby="lane-{_escaped(lane_id)}">'
        f'<h2 id="lane-{_escaped(lane_id)}">{_escaped(name)}</h2>'
        f'<ol class="flow" aria-label="{_escaped(name)} precedence chain">{body}</ol>'
        "</section>"
    )


def _coverage_items(report: Report) -> str:
    if not report.coverage:
        return "<li><span>coverage</span><strong>not reported</strong></li>"
    return "".join(
        "<li>"
        f"<span>{_escaped(key.replace('_', ' '))}</span>"
        f"<strong>{_escaped(report.coverage[key])}</strong>"
        "</li>"
        for key in sorted(report.coverage)
    )


def _finding_items(report: Report) -> str:
    if not report.findings:
        return '<li class="finding finding-clear">No deterministic conflicts found.</li>'
    items: list[str] = []
    for finding in sorted(
        report.findings,
        key=lambda item: (_SEVERITY_RANK[item.severity.value], item.rule_id, item.id),
    ):
        items.append(
            f'<li class="finding finding-{_escaped(finding.severity.value)}">'
            f'<span class="badge">{_escaped(finding.severity.value)}</span>'
            f"<strong>{_escaped(finding.title)}</strong>"
            f"<p>{_escaped(finding.message)}</p>"
            f"<code>{_escaped(finding.rule_id)}</code>"
            "</li>"
        )
    return "".join(items)


_STYLES = """
:root {
  color-scheme: dark;
  --bg: #07111f;
  --panel: #0d1a2b;
  --ink: #edf6ff;
  --muted: #9bb0c8;
  --line: #284363;
  --active: #36d399;
  --shadowed: #9aa8ba;
  --conditional: #fbbf24;
  --ignored: #64748b;
  --invalid: #fb7185;
  --unobserved: #a78bfa;
  --focus: #7dd3fc;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font: 15px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  background: radial-gradient(circle at 20% 0, #123058 0, transparent 34%), var(--bg);
  color: var(--ink);
}
header, main, footer { width: min(1440px, calc(100% - 32px)); margin-inline: auto; }
header { padding: 42px 0 24px; }
h1 {
  font-size: clamp(2rem, 5vw, 4.6rem);
  line-height: .95;
  margin: 0 0 14px;
  letter-spacing: -.055em;
}
.eyebrow {
  color: var(--focus);
  font-weight: 800;
  letter-spacing: .16em;
  text-transform: uppercase;
}
.lede { color: var(--muted); max-width: 68ch; font-size: 1.05rem; }
.summary {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(260px, .42fr);
  gap: 16px;
  margin: 8px 0 18px;
}
.panel, .lane {
  background: color-mix(in srgb, var(--panel) 92%, transparent);
  border: 1px solid var(--line);
  border-radius: 18px;
  box-shadow: 0 18px 50px #0005;
}
.panel { padding: 18px; }
.coverage {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 10px;
  list-style: none;
  margin: 0;
  padding: 0;
}
.coverage li { background: #081422; border-radius: 12px; padding: 10px 12px; min-width: 0; }
.coverage span, .coverage strong { display: block; overflow-wrap: anywhere; }
.coverage span {
  color: var(--muted);
  font-size: .76rem;
  text-transform: uppercase;
  letter-spacing: .07em;
}
.coverage strong { margin-top: 3px; }
.legend { display: flex; flex-wrap: wrap; gap: 8px; align-content: flex-start; }
.legend .badge { font-size: .72rem; }
.lanes {
  display: grid;
  grid-template-columns: repeat(4, minmax(230px, 1fr));
  gap: 14px;
  overflow-x: auto;
  padding-bottom: 8px;
}
.lane { padding: 15px; min-height: 350px; }
.lane h2 { font-size: 1rem; margin: 0 0 15px; }
.flow { list-style: none; padding: 0; margin: 0; }
.flow-item { position: relative; padding-bottom: 24px; }
.flow-item:not(:last-child)::after {
  content: "↓";
  position: absolute;
  bottom: 2px;
  left: 50%;
  color: var(--line);
  font-weight: 900;
}
.source-node {
  width: 100%;
  position: relative;
  text-align: left;
  background: #091727;
  border: 1px solid var(--line);
  border-left: 4px solid var(--status, var(--line));
  border-radius: 13px;
  padding: 12px;
  color: var(--ink);
  cursor: pointer;
  transition: transform .15s, border-color .15s;
}
.source-node:hover { transform: translateY(-2px); border-color: var(--focus); }
.source-node:focus-visible { outline: 3px solid var(--focus); outline-offset: 3px; }
.node-label, .node-reason { display: block; overflow-wrap: anywhere; }
.node-label { font-weight: 800; margin-right: 54px; }
.node-reason { color: var(--muted); font-size: .82rem; margin-top: 8px; }
.badge {
  display: inline-flex;
  padding: 2px 7px;
  border-radius: 999px;
  background: color-mix(in srgb, var(--status, var(--line)) 22%, #07111f);
  color: var(--status, var(--ink));
  font-size: .68rem;
  font-weight: 850;
  letter-spacing: .06em;
  text-transform: uppercase;
}
.source-node > .badge { position: absolute; right: 10px; top: 10px; }
.status-active, .finding-info { --status: var(--active); }
.status-shadowed { --status: var(--shadowed); }
.status-conditional, .finding-warning { --status: var(--conditional); }
.status-ignored { --status: var(--ignored); }
.status-invalid, .finding-error { --status: var(--invalid); }
.status-unobserved { --status: var(--unobserved); }
.empty { color: var(--muted); font-style: italic; }
.details {
  position: sticky;
  bottom: 12px;
  z-index: 5;
  margin: 18px 0;
  background: #10233a;
  border: 1px solid var(--focus);
  border-radius: 18px;
  padding: 18px;
  box-shadow: 0 16px 46px #0009;
}
.details[hidden] { display: none; }
.details-head { display: flex; justify-content: space-between; gap: 16px; }
.details h2 { margin: 0; }
.close {
  border: 1px solid var(--line);
  background: #07111f;
  color: var(--ink);
  border-radius: 10px;
  padding: 7px 12px;
  cursor: pointer;
}
.detail-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
  margin-top: 14px;
}
.detail-grid div { min-width: 0; }
.detail-grid dt { color: var(--muted); font-size: .75rem; text-transform: uppercase; }
.detail-grid dd { margin: 3px 0 0; overflow-wrap: anywhere; }
.excerpt {
  white-space: pre-wrap;
  background: #07111f;
  border-radius: 12px;
  padding: 12px;
  max-height: 170px;
  overflow: auto;
}
.findings {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 10px;
}
.finding {
  border-left: 4px solid var(--status, var(--active));
  background: #081422;
  border-radius: 12px;
  padding: 12px;
}
.finding strong { display: block; margin-top: 7px; }
.finding p { color: var(--muted); margin: 4px 0; }
.finding code { font-size: .75rem; }
footer { color: var(--muted); padding: 20px 0 48px; }
@media (max-width: 800px) {
  .summary { grid-template-columns: 1fr; }
  .lanes { grid-template-columns: repeat(4, minmax(270px, 1fr)); }
  .detail-grid { grid-template-columns: 1fr; }
}
@media (prefers-reduced-motion: reduce) {
  * { scroll-behavior: auto !important; transition: none !important; }
}
"""


_SCRIPT = """
(() => {
  'use strict';
  const panel = document.getElementById('source-detail');
  const close = document.getElementById('close-detail');
  const fields = Object.fromEntries(
    ['source','kind','scope','status','path','reason','condition','excerpt']
      .map(name => [name, document.getElementById('detail-' + name)])
  );
  let selected = null;
  function hide() {
    const previous = selected;
    panel.hidden = true;
    if (selected) selected.setAttribute('aria-expanded', 'false');
    selected = null;
    if (previous) previous.focus({preventScroll: true});
  }
  document.querySelectorAll('.source-node').forEach(node => {
    node.addEventListener('click', () => {
      if (selected && selected !== node) selected.setAttribute('aria-expanded', 'false');
      selected = node;
      Object.keys(fields).forEach(name => {
        fields[name].textContent = node.dataset[name] || 'None';
      });
      node.setAttribute('aria-expanded', 'true');
      panel.hidden = false;
      panel.scrollIntoView({block: 'nearest', behavior: 'smooth'});
      close.focus({preventScroll: true});
    });
  });
  close.addEventListener('click', hide);
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !panel.hidden) hide();
  });
})();
"""


def render_html(report: Report) -> str:
    """Render *report* as a deterministic, single-file, offline HTML document."""

    grouped: dict[str, list[Source]] = {lane: [] for lane in LANES}
    for source in report.sources:
        grouped[_lane_for(source)].append(source)
    lanes = "".join(_lane(name, grouped[name]) for name in LANES)
    maximum = report.max_severity.value if report.max_severity else "clear"
    title = report.tool.get("name", "Codex Context X-Ray")
    version = report.tool.get("version", "unknown")
    coverage_items = _coverage_items(report)
    finding_items = _finding_items(report)
    legend = "".join(
        f'<span class="badge status-{_escaped(status)}">{_escaped(status)}</span>'
        for status in (
            "active",
            "shadowed",
            "conditional",
            "ignored",
            "invalid",
            "unobserved",
        )
    )
    detail_fields = "".join(
        f'<div><dt>{_escaped(label)}</dt><dd id="detail-{_escaped(name)}">None</dd></div>'
        for name, label in (
            ("source", "Source ID"),
            ("kind", "Kind"),
            ("scope", "Scope"),
            ("status", "Status"),
            ("path", "Source"),
            ("reason", "Why"),
            ("condition", "Condition"),
        )
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy"
  content="default-src 'none'; style-src 'unsafe-inline';
    script-src 'unsafe-inline'; img-src data:">
<title>{_escaped(title)} report</title>
<style>{_STYLES}</style>
</head>
<body>
<header>
  <div class="eyebrow">Context loading explained before execution</div>
  <h1>{_escaped(title)}</h1>
  <p class="lede">
    Deterministic Codex source precedence and visibility.
    Highest observed finding: <strong>{_escaped(maximum)}</strong>.
    Report schema {_escaped(report.schema_version)} · tool version {_escaped(version)}.
  </p>
</header>
<main>
  <div class="summary">
    <section class="panel" aria-labelledby="coverage-title">
      <h2 id="coverage-title">Coverage</h2>
      <ul class="coverage">{coverage_items}</ul>
    </section>
    <section class="panel" aria-labelledby="legend-title">
      <h2 id="legend-title">Source states</h2>
      <div class="legend">{legend}</div>
    </section>
  </div>
  <div class="lanes" aria-label="Codex context causal lanes">{lanes}</div>
  <section id="source-detail" class="details" role="region" aria-live="polite"
    aria-labelledby="detail-title" hidden>
    <div class="details-head">
      <h2 id="detail-title">Why this source has this state</h2>
      <button id="close-detail" class="close" type="button">Close</button>
    </div>
    <dl class="detail-grid">
      {detail_fields}
      <div><dt>Safe excerpt</dt><dd id="detail-excerpt" class="excerpt">None</dd></div>
    </dl>
  </section>
  <section class="panel" aria-labelledby="findings-title">
    <h2 id="findings-title">Deterministic findings</h2>
    <ul class="findings">{finding_items}</ul>
  </section>
</main>
<footer>
  No remote assets, telemetry, model calls, or executable hooks are used by this report.
</footer>
<script>{_SCRIPT}</script>
</body>
</html>
"""


__all__ = ["LANES", "render_html"]
