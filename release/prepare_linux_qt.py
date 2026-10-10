#!/usr/bin/env python3
"""Prepare private Linux Qt link inputs without copying IDA or user data."""
import argparse
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida-dir", type=Path, required=True)
    parser.add_argument("--qt-sdk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    runtime = args.ida_dir.resolve(strict=True)
    sdk = args.qt_sdk.resolve(strict=True)
    subprocess.run([sys.executable, str(ROOT / "ida-agent-plugin/cmake/validate_ida_qt_linux.py"),
                    str(runtime)], check=True, env=dict(os.environ, LD_LIBRARY_PATH=str(runtime)))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(args.output, "w:gz", dereference=True) as archive:
        for module in ("Core", "Gui", "Widgets", "DBus"):
            name = f"libQt6{module}.so.6"
            archive.add(runtime / name, arcname=f"ida-qt/{name}")
        version = tarfile.TarInfo("ida-qt/ida-version.txt")
        version.size = 4
        version.mode = 0o644
        archive.addfile(version, io.BytesIO(b"9.4\n"))
        for directory in ("include", "mkspecs"):
            archive.add(sdk / directory, arcname=f"qt-6.8.2-linux/{directory}")
    print(args.output)


if __name__ == "__main__":
    main()
