from __future__ import annotations

import subprocess
import sys
import tempfile
import venv
from pathlib import Path


def main() -> int:
    wheels = sorted(Path("dist").glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit(f"Expected one wheel, found {len(wheels)}")
    with tempfile.TemporaryDirectory(prefix="xray-wheel-") as temporary:
        root = Path(temporary)
        venv.EnvBuilder(with_pip=True).create(root)
        scripts = root / ("Scripts" if sys.platform == "win32" else "bin")
        python = scripts / ("python.exe" if sys.platform == "win32" else "python")
        command = scripts / ("codex-xray.exe" if sys.platform == "win32" else "codex-xray")
        # Executables and wheel are created by this script inside one private temp dir.
        subprocess.run(  # noqa: S603
            [str(python), "-m", "pip", "install", str(wheels[0].resolve())],
            check=True,
        )
        subprocess.run(  # noqa: S603
            [str(command), "demo"], check=True, capture_output=True, text=True
        )
        subprocess.run(  # noqa: S603
            [str(command), "explain", "permissions.legacy-wins"],
            check=True,
            capture_output=True,
            text=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
