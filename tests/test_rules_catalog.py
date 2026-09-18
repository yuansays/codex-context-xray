from __future__ import annotations

import re
from pathlib import Path

from codex_context_xray.rules_catalog import explain


def test_every_emitted_literal_rule_id_is_explainable() -> None:
    source_root = Path(__file__).resolve().parents[1] / "src" / "codex_context_xray"
    pattern = re.compile(r'rule_id="([A-Za-z0-9_.-]+)"')
    emitted: set[str] = set()
    for path in source_root.rglob("*.py"):
        emitted.update(pattern.findall(path.read_text(encoding="utf-8")))

    missing = sorted(rule_id for rule_id in emitted if explain(rule_id) is None)

    assert emitted
    assert missing == []
