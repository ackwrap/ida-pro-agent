#!/usr/bin/env python3
"""Prepare pinned Qt headers and an IDA Qt link bundle for Universal 2 builds."""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
URL = ("https://download.qt.io/online/qtsdkrepository/mac_x64/desktop/qt6_682/qt6_682/"
       "qt.qt6.682.clang_64/6.8.2-0-202501260836qtbase-MacOS-MacOS_14-Clang-MacOS-MacOS_14-X86_64-ARM64.7z")
SHA256 = "7d7634ee7bdc6594961dd745fed9c1f8b6cef862d3442531231d8cf3c183210b"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--x86-ida", type=Path, required=True, help="Intel IDA 9.4 .app")
    parser.add_argument("--arm-ida", type=Path, required=True, help="Extracted arm64 IDA 9.4 .app")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("Run on macOS; neither IDA application needs to run")
    sys.path.insert(0, str(ROOT / "ida-agent-plugin/cmake"))
    from validate_ida_qt_macos import validate
    intel, arm = args.x86_ida.resolve(), args.arm_ida.resolve()
    validate(intel, ["x86_64"])
    validate(arm, ["arm64"])
    build = ROOT / "build/macos-qt"
    build.mkdir(parents=True, exist_ok=True)
    archive = build / "qtbase-6.8.2-macos.7z"
    if not archive.exists():
        temporary = archive.with_suffix(".download")
        with urllib.request.urlopen(URL, timeout=60) as source, temporary.open("wb") as output:
            shutil.copyfileobj(source, output)
        temporary.replace(archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise RuntimeError(f"Qt archive checksum mismatch: {archive}")
    headers = ROOT / "qt-sdk/qt-6.8.2-macos"
    headers.mkdir(parents=True, exist_ok=True)
    # The pinned official archive is authenticated before extraction. Select only
    # headers and mkspecs; Qt binaries are supplied by IDA, not the stock archive.
    with tempfile.TemporaryDirectory(prefix="qt-headers-", dir=build) as directory:
        unpacked = Path(directory)
        subprocess.run(["/usr/bin/tar", "-xf", str(archive), "-C", directory,
                        "--include=mkspecs/*",
                        "--include=lib/Qt*.framework/Versions/A/Headers/*"], check=True)
        shutil.copytree(unpacked / "mkspecs", headers / "mkspecs", dirs_exist_ok=True)
        for module in ("Core", "Gui", "Widgets"):
            target = headers / f"include/Qt{module}"
            if target.is_symlink():
                target.unlink()
            shutil.copytree(unpacked / f"lib/Qt{module}.framework/Versions/A/Headers", target, dirs_exist_ok=True)
    bundle = build / "ida-qt.app"
    (bundle / "Contents").mkdir(parents=True, exist_ok=True)
    shutil.copy2(intel / "Contents/Info.plist", bundle / "Contents/Info.plist")
    for module in ("Core", "Gui", "Widgets"):
        relative = f"Contents/Frameworks/Qt{module}.framework/Versions/A/Qt{module}"
        output = bundle / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["lipo", "-create", str(intel / relative), str(arm / relative),
                        "-output", str(output)], check=True)
        alias = bundle / f"Contents/Frameworks/Qt{module}.framework/Qt{module}"
        if alias.is_symlink():
            alias.unlink()
        alias.symlink_to(f"Versions/A/Qt{module}")
    validate(bundle, ["x86_64", "arm64"])
    print(f"Headers: {headers}\nLink inputs only (do not distribute): {bundle}")


if __name__ == "__main__":
    main()
