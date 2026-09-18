"""Deterministic redaction for report-safe values.

The scanner never needs secret values to explain configuration precedence.  This
module therefore returns both a sanitized value and a list of *value-free*
redaction records suitable for the public JSON report.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "<redacted>"
PRIVATE_KEY_REDACTED = "<redacted-private-key>"

_SENSITIVE_KEY = re.compile(
    r"(?:^|[_-])(?:"
    r"authorization|cookie|password|passwd|token|access[_-]?token|refresh[_-]?token|"
    r"api[_-]?key|client[_-]?secret|private[_-]?key|secret"
    r")(?:$|[_-])",
    re.IGNORECASE,
)
_SENSITIVE_FLAG = re.compile(
    r"^--?(?:authorization|cookie|password|passwd|token|access-token|refresh-token|"
    r"api-key|api_key|client-secret|private-key|secret)$",
    re.IGNORECASE,
)
_SENSITIVE_URL_KEYS = {
    "access_token",
    "auth",
    "authorization",
    "key",
    "policy",
    "sig",
    "signature",
    "token",
    "x-amz-credential",
    "x-amz-security-token",
    "x-amz-signature",
    "x-goog-credential",
    "x-goog-signature",
}
_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
    r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_ASSIGNMENT = re.compile(
    r"(?i)(?P<prefix>\b(?:authorization|proxy-authorization|cookie|set-cookie|"
    r"password|passwd|token|access[_-]?token|refresh[_-]?token|api[_-]?key|"
    r"client[_-]?secret|private[_-]?key|secret)\b\s*[:=]\s*)"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;\]\}\r\n]+)"
)
_COMMAND_FLAG = re.compile(
    r"(?i)(?P<prefix>(?:^|\s)--?(?:authorization|cookie|password|passwd|token|"
    r"access-token|refresh-token|api-key|api_key|client-secret|private-key|secret)"
    r"(?:=|\s+))(?P<value>\"[^\"]*\"|'[^']*'|\S+)"
)
_HEADER_SECRET = re.compile(
    r"(?i)(?P<prefix>\b(?:authorization|proxy-authorization|cookie|set-cookie)"
    r"\s*:\s*)(?P<value>[^\r\n\"']+)"
)
_GENERIC_HOME = re.compile(
    r"(?i)(?:[A-Z]:[\\/]Users[\\/][^\\/\r\n]+?(?=[\\/]|$)|"
    r"/(?:Users|home)/[^/\r\n]+?(?=/|$))"
)


def _record(kind: str, location: str, replacement: str = REDACTED) -> dict[str, str]:
    """Create a redaction record that intentionally contains no original value."""

    return {"category": kind, "location": location, "replacement": replacement}


def _is_sensitive_key(key: object) -> bool:
    if not isinstance(key, str):
        return False
    if _SENSITIVE_KEY.search(key):
        return True
    normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
    return any(
        normalized.endswith(suffix)
        for suffix in (
            "authorization",
            "cookie",
            "password",
            "passwd",
            "token",
            "accesstoken",
            "refreshtoken",
            "apikey",
            "clientsecret",
            "privatekey",
        )
    )


def _home_variants(user_home: str | Path | None) -> list[str]:
    if user_home is None:
        return []
    raw = str(user_home).rstrip("/\\")
    if not raw:
        return []
    variants = {raw, raw.replace("\\", "/"), raw.replace("/", "\\")}
    return sorted(variants, key=len, reverse=True)


def _sanitize_url(url: str, location: str) -> tuple[str, list[dict[str, str]]]:
    try:
        split = urlsplit(url)
    except ValueError:
        return url, []
    if not split.query:
        return url, []

    changed = False
    query: list[tuple[str, str]] = []
    records: list[dict[str, str]] = []
    for key, value in parse_qsl(split.query, keep_blank_values=True):
        if key.casefold() in _SENSITIVE_URL_KEYS:
            query.append((key, REDACTED))
            records.append(_record("signed_url_parameter", f"{location}.query.{key}"))
            changed = True
        else:
            query.append((key, value))
    if not changed:
        return url, []

    safe_query = urlencode(query, doseq=True).replace("%3Credacted%3E", REDACTED)
    return urlunsplit((split.scheme, split.netloc, split.path, safe_query, split.fragment)), records


def redact_text(
    text: str,
    user_home: str | Path | None = None,
    *,
    location: str = "$",
) -> tuple[str, list[dict[str, str]]]:
    """Redact secrets, signed URL values, and a known home directory from text."""

    sanitized = text
    records: list[dict[str, str]] = []

    for variant in _home_variants(user_home):
        flags = re.IGNORECASE if re.match(r"^[A-Za-z]:[\\/]", variant) else 0
        sanitized, count = re.subn(re.escape(variant), "$HOME", sanitized, flags=flags)
        records.extend(_record("home_path", location, "$HOME") for _ in range(count))

    sanitized, count = _GENERIC_HOME.subn("$HOME", sanitized)
    records.extend(_record("home_path", location, "$HOME") for _ in range(count))

    sanitized, count = _PRIVATE_KEY.subn(PRIVATE_KEY_REDACTED, sanitized)
    records.extend(_record("private_key", location, PRIVATE_KEY_REDACTED) for _ in range(count))

    def replace_url(match: re.Match[str]) -> str:
        safe_url, url_records = _sanitize_url(match.group(0), location)
        records.extend(url_records)
        return safe_url

    sanitized = _URL.sub(replace_url, sanitized)

    def replace_header(match: re.Match[str]) -> str:
        records.append(_record("secret_value", location))
        return f"{match.group('prefix')}{REDACTED}"

    sanitized = _HEADER_SECRET.sub(replace_header, sanitized)

    def replace_assignment(match: re.Match[str]) -> str:
        records.append(_record("secret_value", location))
        return f"{match.group('prefix')}{REDACTED}"

    sanitized = _ASSIGNMENT.sub(replace_assignment, sanitized)

    def replace_flag(match: re.Match[str]) -> str:
        records.append(_record("sensitive_command_argument", location))
        return f"{match.group('prefix')}{REDACTED}"

    sanitized = _COMMAND_FLAG.sub(replace_flag, sanitized)
    return sanitized, records


def redact(
    value: Any,
    user_home: str | Path | None = None,
    *,
    location: str = "$",
) -> tuple[Any, list[dict[str, str]]]:
    """Return ``(sanitized_value, redaction_records)`` for a JSON-like value.

    Mapping keys are retained for explanatory reports, but values under
    credential-like keys are replaced wholesale.  Lists receive special handling
    for argument-array forms such as ``["curl", "--token", "secret"]``.
    """

    if isinstance(value, Path):
        return redact_text(str(value), user_home, location=location)
    if isinstance(value, str):
        return redact_text(value, user_home, location=location)
    if isinstance(value, dict):
        sanitized_map: dict[Any, Any] = {}
        map_records: list[dict[str, str]] = []
        for key in sorted(value, key=lambda item: str(item)):
            child_location = f"{location}.{key}"
            if _is_sensitive_key(key):
                replacement = PRIVATE_KEY_REDACTED if "private" in str(key).casefold() else REDACTED
                sanitized_map[key] = replacement
                map_records.append(_record("secret_field", child_location, replacement))
                continue
            safe_child, child_records = redact(value[key], user_home, location=child_location)
            sanitized_map[key] = safe_child
            map_records.extend(child_records)
        return sanitized_map, map_records
    if isinstance(value, (list, tuple)):
        sanitized_items: list[Any] = []
        item_records: list[dict[str, str]] = []
        hide_next = False
        for index, item in enumerate(value):
            child_location = f"{location}[{index}]"
            if hide_next:
                sanitized_items.append(REDACTED)
                item_records.append(_record("sensitive_command_argument", child_location))
                hide_next = False
                continue
            if isinstance(item, str):
                if _SENSITIVE_FLAG.fullmatch(item):
                    sanitized_items.append(item)
                    hide_next = True
                    continue
                flag, separator, _flag_value = item.partition("=")
                if separator and _SENSITIVE_FLAG.fullmatch(flag):
                    sanitized_items.append(f"{flag}={REDACTED}")
                    item_records.append(_record("sensitive_command_argument", child_location))
                    continue
            safe_child, child_records = redact(item, user_home, location=child_location)
            sanitized_items.append(safe_child)
            item_records.extend(child_records)
        return sanitized_items, item_records
    return value, []


__all__ = ["PRIVATE_KEY_REDACTED", "REDACTED", "redact", "redact_text"]
