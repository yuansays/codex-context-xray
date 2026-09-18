from __future__ import annotations

from pathlib import Path

from codex_context_xray.analyzers.config import analyze_config
from codex_context_xray.analyzers.permissions import analyze_permissions
from codex_context_xray.model import ScanContext, SourceStatus


def _ctx(root: Path, *, trust: str = "trusted") -> ScanContext:
    return ScanContext(
        target=root,
        repo_root=root,
        include_user=False,
        user_home=None,
        codex_home=None,
        profile=None,
        trust_requested=trust,
        trust_effective=trust,
        cli_overrides=[],
    )


def test_legacy_sandbox_wins_over_permission_profiles(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    ctx = _ctx(root)
    result = analyze_permissions(
        ctx,
        {
            "sandbox_mode": "workspace-write",
            "default_permissions": "team",
            "permissions": {"team": {"extends": ":workspace"}},
        },
    )

    assert result.state["permissions"]["mode"] == "legacy_sandbox"
    assert result.state["permissions"]["selected_profile"] is None
    assert any(finding.rule_id == "PERMISSIONS_LEGACY_CONFLICT" for finding in result.findings)
    assert any(source.status is SourceStatus.ACTIVE for source in result.sources)


def test_profile_cycles_forbidden_parent_and_unknown_default(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    result = analyze_permissions(
        _ctx(root),
        {
            "default_permissions": "missing",
            "permissions": {
                "a": {"extends": "b"},
                "b": {"extends": "a"},
                "danger": {"extends": ":danger-full-access"},
            },
        },
    )

    rules = {finding.rule_id for finding in result.findings}
    assert "PERMISSIONS_INHERITANCE_CYCLE" in rules
    assert "PERMISSIONS_FORBIDDEN_PARENT" in rules
    assert "PERMISSIONS_UNKNOWN_DEFAULT" in rules
    assert result.state["permissions"]["mode"] == "permission_profiles"


def test_untrusted_project_permissions_are_not_effective(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / ".codex").mkdir(parents=True)
    (root / ".codex" / "config.toml").write_text(
        'default_permissions = "local"\n[permissions.local]\nextends = ":workspace"\n',
        encoding="utf-8",
    )
    ctx = _ctx(root, trust="untrusted")
    _, effective = analyze_config(ctx)

    result = analyze_permissions(ctx, effective)

    assert result.state["permissions"]["mode"] == "unconfigured"
    assert not result.sources


def test_named_profile_inherits_parent_rules(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    result = analyze_permissions(
        _ctx(root),
        {
            "default_permissions": "child",
            "permissions": {
                "base": {
                    "extends": ":workspace",
                    "filesystem": {"docs/**": "read"},
                    "network": {"example.test": "allow"},
                },
                "child": {
                    "extends": "base",
                    "filesystem": {"build/**": "write"},
                },
            },
        },
    )

    child = result.state["permissions"]["profiles"]["child"]
    assert child["inheritance_chain"] == [":workspace", "base", "child"]
    assert child["effective_filesystem_rule_count"] == 2
    assert child["effective_network_rule_count"] == 1
