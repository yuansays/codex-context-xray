from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".qa",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
}
SKIP_NAMES = {".coverage"}
BLOCKED_NAMES = {"auth.json", "cookies.txt", ".env", "history.jsonl"}
BLOCKED_SUFFIXES = {".sqlite", ".sqlite3", ".db", ".log"}
TEXT_NAMES = {".gitattributes", ".gitignore", "LICENSE", "SHA256SUMS"}
TEXT_SUFFIXES = {
    ".cff",
    ".css",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".py",
    ".rules",
    ".sha256",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"gh[opsu]_[A-Za-z0-9]{30,}"),
    "OpenAI key": re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    "AWS key": re.compile(r"AKIA[A-Z0-9]{16}"),
}


def main() -> int:
    problems: list[str] = []
    for path in ROOT.rglob("*"):
        if (
            not path.is_file()
            or path.name in SKIP_NAMES
            or any(part in SKIP_PARTS or part.endswith(".egg-info") for part in path.parts)
        ):
            continue
        relative = path.relative_to(ROOT).as_posix()
        if path.name.lower() in BLOCKED_NAMES or path.suffix.lower() in BLOCKED_SUFFIXES:
            problems.append(f"blocked release artifact: {relative}")
            continue
        if path.name not in TEXT_NAMES and path.suffix.lower() not in TEXT_SUFFIXES:
            allowed_asset = relative in {
                "docs/assets/demo.gif",
                "docs/assets/social-preview.png",
            }
            if not allowed_asset:
                problems.append(f"unexpected binary or media file: {relative}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            problems.append(f"non-UTF-8 text file: {relative}")
            continue
        for name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                nearby = text[max(0, match.start() - 128) : match.end() + 128].lower()
                if any(
                    marker in nearby
                    for marker in ("fake", "fictional", "do_not_use", "pattern")
                ):
                    continue
                problems.append(f"possible {name}: {relative}")
    if problems:
        raise SystemExit("\n".join(sorted(set(problems))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
