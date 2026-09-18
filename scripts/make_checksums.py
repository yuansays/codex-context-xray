from __future__ import annotations

import hashlib
import sys
from pathlib import Path


def main() -> int:
    source = Path(sys.argv[1])
    output = Path(sys.argv[2])
    lines: list[str] = []
    for path in sorted(item for item in source.iterdir() if item.is_file()):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
