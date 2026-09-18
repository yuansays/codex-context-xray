from __future__ import annotations

import json
from pathlib import Path

from codex_context_xray.redaction import PRIVATE_KEY_REDACTED, REDACTED, redact


def test_redact_nested_secrets_home_signed_urls_and_command_arguments() -> None:
    home = Path("C:/Users/Fictional Person")
    private_key = (
        "-----BEGIN PRIVATE KEY-----\ntotally-fictional-key-material\n-----END PRIVATE KEY-----"
    )
    value = {
        "path": "C:/Users/Fictional Person/project/file.txt",
        "apiToken": "synthetic-token-value",
        "headers": {"Authorization": "Bearer synthetic-bearer-value"},
        "url": "https://example.invalid/file?id=7&X-Amz-Signature=signed-value",
        "private": private_key,
        "command": ["tool", "--password", "synthetic-password", "--safe", "yes"],
    }

    sanitized, records = redact(value, home)
    serialized = json.dumps(sanitized, ensure_ascii=False)

    for secret in (
        "synthetic-token-value",
        "synthetic-bearer-value",
        "signed-value",
        "totally-fictional-key-material",
        "synthetic-password",
        "Fictional Person",
    ):
        assert secret not in serialized
    assert "$HOME/project/file.txt" in serialized
    assert sanitized["apiToken"] == REDACTED
    assert sanitized["command"][2] == REDACTED
    assert PRIVATE_KEY_REDACTED in serialized
    assert {record["category"] for record in records} >= {
        "home_path",
        "secret_field",
        "signed_url_parameter",
        "private_key",
        "sensitive_command_argument",
    }
    # Evidence records identify only category/location/replacement, never values.
    record_text = json.dumps(records, ensure_ascii=False)
    assert "synthetic" not in record_text


def test_redact_authorization_and_sensitive_flags_in_free_text() -> None:
    text = (
        'curl -H "Authorization: Bearer fictional-bearer" '
        "--token fictional-cli-token https://example.invalid/"
    )

    sanitized, records = redact(text)

    assert "fictional-bearer" not in sanitized
    assert "fictional-cli-token" not in sanitized
    assert sanitized.count(REDACTED) >= 2
    assert records


def test_redact_preserves_benign_values() -> None:
    value = {
        "title": "Context map",
        "url": "https://example.invalid/docs?page=2",
        "command": ["git", "status", "--short"],
    }

    sanitized, records = redact(value)

    assert sanitized == value
    assert records == []


def test_redact_generic_home_prefixes_without_user_opt_in() -> None:
    value = {
        "windows": r"C:\Users\李 雷\Documents\项目\config.toml",
        "macos": "/Users/Example Person/work/repo/config.toml",
        "linux": "/home/测试 用户/work/repo/config.toml",
        "home_only": r"D:\Users\Exact Name",
    }

    sanitized, records = redact(value)
    serialized = json.dumps(sanitized, ensure_ascii=False)

    assert "李 雷" not in serialized
    assert "Example Person" not in serialized
    assert "测试 用户" not in serialized
    assert "Exact Name" not in serialized
    assert serialized.count("$HOME") == 4
    assert sum(record["category"] == "home_path" for record in records) == 4
