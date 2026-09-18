from __future__ import annotations

import tempfile
from pathlib import Path

from codex_context_xray.demo import create_demo_repo
from codex_context_xray.html_report import render_html
from codex_context_xray.scanner import scan


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="xray-offline-") as temporary:
        target = create_demo_repo(Path(temporary))
        html = render_html(scan(target, trust="trusted"))
    lowered = html.lower()
    forbidden = ("<script src=", "<link href=", "http://", "https://", "file://")
    present = [needle for needle in forbidden if needle in lowered]
    if present:
        raise SystemExit(f"HTML is not self-contained: {present}")
    if "fake_test_token_do_not_use" in html:
        raise SystemExit("Synthetic secret leaked into HTML")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
