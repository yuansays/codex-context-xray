from __future__ import annotations

from pathlib import Path

from codex_context_xray.html_report import render_html
from codex_context_xray.render import render_human, render_json
from codex_context_xray.scanner import scan


def test_secret_and_home_path_never_enter_any_report_format(tmp_path: Path) -> None:
    repo = tmp_path / "隐私 repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".codex").mkdir()
    (repo / "AGENTS.md").write_text(
        """Use C:\\Users\\Fictional Person\\private\\notes only.
Authorization: Bearer ultra_secret_value
-----BEGIN PRIVATE KEY-----
fake_private_material_do_not_use
-----END PRIVATE KEY-----
""",
        encoding="utf-8",
    )
    (repo / ".codex" / "config.toml").write_text(
        """[mcp_servers.remote]
url = "https://example.invalid/mcp?X-Amz-Signature=signed_secret_value"
http_headers = { Authorization = "Bearer header_secret_value" }
enabled = true
""",
        encoding="utf-8",
    )
    (repo / ".codex" / "hooks.json").write_text(
        '{"hooks":{"SessionStart":[{"command":["curl","--token","hook_secret_value"]}]}}',
        encoding="utf-8",
    )

    report = scan(repo, trust="trusted")
    rendered = "\n".join((render_json(report), render_html(report), render_human(report)))

    for secret in (
        "ultra_secret_value",
        "fake_private_material_do_not_use",
        "signed_secret_value",
        "header_secret_value",
        "hook_secret_value",
        "Fictional Person",
    ):
        assert secret not in rendered
    assert "$HOME" in rendered
    assert "<redacted" in rendered or "&lt;redacted" in rendered
    assert report.redactions


def test_report_has_no_real_absolute_user_path(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "AGENTS.md").write_text("Safe.\n", encoding="utf-8")

    serialized = render_json(scan(repo, trust="trusted"))

    assert str(Path.home()) not in serialized
    assert tmp_path.as_posix() not in serialized
