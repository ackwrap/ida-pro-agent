#!/usr/bin/env python3
"""Build, validate and package the macOS Universal 2 gateway and AI plugin."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

from build_parallel import positive_jobs, select_build_jobs

ROOT = Path(__file__).resolve().parents[1]


def run(*command, **kwargs):
    subprocess.run([str(part) for part in command], check=True, **kwargs)


def validate_binary(path, plugin=False):
    run("lipo", path, "-verify_arch", "x86_64", "arm64")
    run("codesign", "--verify", "--strict", path)
    for arch in ("x86_64", "arm64"):
        dependencies = subprocess.check_output(["otool", "-arch", arch, "-L", str(path)], text=True)
        if any(name in dependencies for name in ("libcurl", "libssl", "libcrypto", "libsqlite3", "/usr/local/", "/opt/homebrew/")):
            raise RuntimeError(f"Unexpected external dependency: {dependencies}")
        if plugin:
            for name in ("Foundation.framework", "Security.framework", "QtWidgets.framework", "@rpath/libida.dylib"):
                if name not in dependencies:
                    raise RuntimeError(f"Missing AI plugin dependency: {name}")
            load_commands = subprocess.check_output(["otool", "-arch", arch, "-l", str(path)], text=True)
            lines = load_commands.splitlines()
            rpaths = [lines[i + 2].strip().split(" (offset")[0].removeprefix("path ")
                      for i, line in enumerate(lines) if line.strip() == "cmd LC_RPATH"]
            if set(rpaths) != {"@executable_path", "@executable_path/../Frameworks"}:
                raise RuntimeError(f"Nonportable plugin search paths: {rpaths}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qt-runtime", type=Path, required=True,
                        help="IDA 9.4 .app with both architectures of its Qt frameworks (link inputs only)")
    parser.add_argument("--qt-sdk", type=Path, default=ROOT / "qt-sdk/qt-6.8.2-macos")
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build/release/macos")
    parser.add_argument("--python", type=Path, default=Path(sys.executable), help="Python with websockets installed")
    parser.add_argument("--jobs", type=positive_jobs, help="parallel build jobs (default: all available CPUs)")
    parser.add_argument("--zip-only", action="store_true", help="Build the portable ZIP without the DMG installer")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("Run this script on macOS with Xcode command line tools")
    try:
        jobs = select_build_jobs(args.jobs)
    except argparse.ArgumentTypeError as error:
        parser.error(str(error))
    build = args.build_dir.resolve()
    build.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ, CGO_ENABLED="0", GOOS="darwin")
    for operation in ("vet", "test", "build"):
        run("go", "-C", ROOT / "ida-mcp", operation, "./...", env=environment)
    run("cmake", "-S", ROOT / "ida-agent-plugin", "-B", build, "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_OSX_ARCHITECTURES=x86_64;arm64",
        "-DCMAKE_OSX_DEPLOYMENT_TARGET=15.0", "-DIDA_AGENT_ENABLE_AI=ON",
        "-DIDA_AGENT_ENABLE_QT_AI_CONSOLE=ON", "-DIDA_AGENT_DEPLOY_DEBUG_USER_PLUGIN=OFF",
        "-DIDA_AGENT_ENABLE_INTEGRATION_TESTS=OFF", "-DIDA_AGENT_ENABLE_GUI_TESTS=OFF",
        "-DBUILD_TESTING=ON", f"-DPython3_EXECUTABLE={args.python.absolute()}",
        f"-DIDA_AGENT_IDA_QT_RUNTIME_DIR={args.qt_runtime.resolve()}",
        f"-DIDA_AGENT_QT_SDK_DIR={args.qt_sdk.resolve()}")
    run("cmake", "--build", build, "--parallel", jobs)
    run("ctest", "--test-dir", build, "--output-on-failure", "-LE", "integration")
    slices = []
    for arch in ("amd64", "arm64"):
        output = build / f"ida-mcp-{arch}"
        run("go", "-C", ROOT / "ida-mcp", "build", "-trimpath", "-ldflags=-s -w",
            "-o", output, ".", env=dict(environment, GOARCH=arch))
        slices.append(output)
    gateway = build / "ida-mcp-universal"
    run("lipo", "-create", *slices, "-output", gateway)
    plugin = build / "ida-runtime/plugins/ida-agent-plugin.dylib"
    for path in (gateway, plugin):
        run("codesign", "--force", "--sign", "-", path)
        validate_binary(path, plugin=path == plugin)
    version = (ROOT / "ida-mcp/VERSION").read_text(encoding="ascii").strip()
    name = f"ida-agent-{version}-macos-universal2"
    dist = ROOT / "release/dist"
    dist.mkdir(parents=True, exist_ok=True)
    # Package only this allowlist; Qt, IDA, build trees and private settings never
    # enter the archive, even when packaging from an existing build directory.
    with tempfile.TemporaryDirectory(prefix="macos-package-", dir=dist) as directory:
        stage = Path(directory) / name
        (stage / "plugins").mkdir(parents=True)
        shutil.copy2(gateway, stage / "ida-mcp")
        shutil.copy2(plugin, stage / "plugins/ida-agent-plugin.dylib")
        shutil.copy2(ROOT / "ida-agent-plugin/README-MACOS.md", stage / "README-MACOS.md")
        sums = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(stage).as_posix()}"
                for path in sorted(stage.rglob("*")) if path.is_file()]
        (stage / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="ascii")
        archive = Path(directory) / f"{name}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    package.write(path, path.relative_to(stage.parent))
        target = dist / archive.name
        os.replace(archive, target)
        (dist / f"{target.name}.sha256").write_text(
            f"{hashlib.sha256(target.read_bytes()).hexdigest()}  {target.name}\n", encoding="ascii")
    print(target)
    if not args.zip_only:
        run(args.python.absolute(), ROOT / "release/build_macos_dmg.py", "--archive", target)
        run(args.python.absolute(), ROOT / "release/tests/test_macos_installer.py",
            "--dmg", dist / f"{name}.dmg")


if __name__ == "__main__":
    main()
