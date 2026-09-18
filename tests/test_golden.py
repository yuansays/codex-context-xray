from __future__ import annotations

import hashlib
from pathlib import Path

from codex_context_xray.demo import build_demo_report
from codex_context_xray.html_report import render_html
from codex_context_xray.render import render_json


def test_demo_json_and_html_match_fixed_golden_hashes() -> None:
    golden_path = Path(__file__).with_name("golden") / "demo-report.sha256"
    expected = {
        kind: digest
        for line in golden_path.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
        for kind, digest in [line.split()]
    }
    report = build_demo_report()
    actual = {
        "json": hashlib.sha256(render_json(report).encode()).hexdigest(),
        "html": hashlib.sha256(render_html(report).encode()).hexdigest(),
    }

    assert actual == expected
