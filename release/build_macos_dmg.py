#!/usr/bin/env python3
"""Create a per-user Universal 2 macOS installer DMG from a validated release ZIP."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

from build_macos import ROOT, run, validate_binary


def unpack_release(archive, destination):
    with zipfile.ZipFile(archive) as package:
        names = package.namelist()
        prefix = names[0].split("/", 1)[0] if names else ""
        match = re.fullmatch(r"ida-agent-(\d+\.\d+\.\d+)-macos-universal2", prefix)
        if not match:
            raise ValueError("Unrecognized macOS release name")
        expected = {"ida-mcp", "plugins/ida-agent-plugin.dylib", "README-MACOS.md", "SHA256SUMS.txt"}
        if len(names) != len(expected) or set(names) != {prefix + "/" + name for name in expected}:
            raise ValueError("Release ZIP must contain exactly the expected four files")
        if package.getinfo(prefix + "/SHA256SUMS.txt").file_size > 4096:
            raise ValueError("Release checksum manifest too large")
        sums = dict(line.split("  ", 1)[::-1] for line in package.read(prefix + "/SHA256SUMS.txt").decode("ascii").splitlines())
        if set(sums) != expected - {"SHA256SUMS.txt"}:
            raise ValueError("Release checksums are incomplete")
        for name in expected:
            info = package.getinfo(prefix + "/" + name)
            if info.file_size > 128 * 1024 * 1024:
                raise ValueError("Release member too large")
            data = package.read(info)
            if name in sums and hashlib.sha256(data).hexdigest() != sums[name]:
                raise ValueError(f"Release checksum mismatch: {name}")
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o755 if name in ("ida-mcp", "plugins/ida-agent-plugin.dylib") else 0o644)
    return match.group(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True, help="ZIP produced by build_macos.py")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "release/dist")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("Run on macOS with Xcode command line tools")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="macos-dmg-", dir=output) as temporary:
        work = Path(temporary)
        release = work / "release"
        version = unpack_release(args.archive, release)
        validate_binary(release / "ida-mcp")
        validate_binary(release / "plugins/ida-agent-plugin.dylib", plugin=True)
        stage = work / "image"
        bundle = stage / "IDA Agent Installer.app"
        contents = bundle / "Contents"
        payload = contents / "Resources/payload"
        payload.mkdir(parents=True)
        (contents / "MacOS").mkdir()
        shutil.copy2(release / "ida-mcp", payload / "ida-mcp")
        shutil.copy2(release / "plugins/ida-agent-plugin.dylib", payload / "ida-agent-plugin.dylib")
        (payload / "manifest.json").write_text(json.dumps({"version": version, "sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in payload.iterdir()
        }}, indent=2) + "\n", encoding="utf-8")
        info = {"CFBundleExecutable": "Installer", "CFBundleIdentifier": "com.ida-agent.installer",
                "CFBundleName": "IDA Agent Installer", "CFBundlePackageType": "APPL",
                "CFBundleShortVersionString": version, "CFBundleVersion": version,
                "LSMinimumSystemVersion": "15.0", "NSHighResolutionCapable": True}
        (contents / "Info.plist").write_bytes(plistlib.dumps(info))
        executable = contents / "MacOS/Installer"
        run("xcrun", "clang", "-fobjc-arc", "-O2", "-Wall", "-Wextra", "-Werror",
            "-mmacosx-version-min=15.0", "-arch", "x86_64", "-arch", "arm64",
            ROOT / "release/macos/installer.m", "-framework", "AppKit", "-o", executable)
        run("codesign", "--force", "--sign", "-", bundle)
        run("codesign", "--verify", "--strict", "--deep", bundle)
        run("lipo", executable, "-verify_arch", "x86_64", "arm64")
        run(executable, "--verify-payload")
        shutil.copy2(ROOT / "release/macos/INSTALL.txt", stage / "INSTALL.txt")
        shutil.copy2(release / "README-MACOS.md", stage / "README-MACOS.md")
        name = f"ida-agent-{version}-macos-universal2.dmg"
        image = work / name
        run("hdiutil", "create", "-volname", f"IDA Agent {version}", "-srcfolder", stage,
            "-fs", "HFS+", "-format", "UDZO", image)
        run("hdiutil", "verify", image)
        target = output / name
        os.replace(image, target)
        (output / (name + ".sha256")).write_text(
            f"{hashlib.sha256(target.read_bytes()).hexdigest()}  {name}\n", encoding="ascii")
    print(target)


if __name__ == "__main__":
    main()
