#!/usr/bin/env python3
"""Build, validate and package the Linux x64 gateway and full AI plugin."""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

from build_parallel import positive_jobs, select_build_jobs

ROOT = Path(__file__).resolve().parents[1]


def run(*command, **kwargs):
    print("+", " ".join(map(str, command)), flush=True)
    subprocess.run(list(map(str, command)), check=True, **kwargs)


def validate_plugin(plugin):
    environment = dict(os.environ, LC_ALL="C")
    dynamic = subprocess.check_output(["readelf", "-d", str(plugin)], text=True, env=environment)
    if "(RPATH)" in dynamic or "(RUNPATH)" in dynamic:
        raise RuntimeError("The release plugin must not retain build-machine library paths")
    needed = re.findall(r"\(NEEDED\).*\[(.*?)\]", dynamic)
    required = {"libida.so", "libQt6Core.so.6", "libQt6Gui.so.6", "libQt6Widgets.so.6",
                "libssl.so.3", "libcrypto.so.3"}
    if not required.issubset(needed):
        raise RuntimeError(f"Missing full AI plugin dependencies: {required - set(needed)}")
    if any("/" in name or "libcurl" in name or "libsqlite" in name for name in needed):
        raise RuntimeError(f"Unexpected nonportable dependency: {needed}")
    header = subprocess.check_output(["readelf", "-h", str(plugin)], text=True, env=environment)
    if "Advanced Micro Devices X86-64" not in header:
        raise RuntimeError("Expected an x86_64 ELF plugin")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qt-runtime", type=Path, required=True)
    parser.add_argument("--qt-sdk", type=Path, default=ROOT / "qt-sdk/qt-6.8.2-linux")
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build/release/linux")
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--jobs", type=positive_jobs, help="default: all available CPUs")
    args = parser.parse_args()
    if sys.platform != "linux" or platform.machine() != "x86_64":
        parser.error("Run on Linux x86_64")
    try:
        jobs = select_build_jobs(args.jobs)
    except argparse.ArgumentTypeError as error:
        parser.error(str(error))
    build = args.build_dir.resolve()
    build.mkdir(parents=True, exist_ok=True)
    run(args.python.resolve(), ROOT / "release/tests/test_linux_launcher.py")
    environment = dict(os.environ, CGO_ENABLED="0", GOOS="linux", GOARCH="amd64")
    for operation in ("vet", "test", "build"):
        run("go", "-C", ROOT / "ida-mcp", operation, "./...", env=environment)
    run("cmake", "-S", ROOT / "ida-agent-plugin", "-B", build, "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_SKIP_RPATH=ON", "-DBUILD_TESTING=ON",
        "-DIDA_AGENT_ENABLE_AI=ON", "-DIDA_AGENT_ENABLE_QT_AI_CONSOLE=ON",
        "-DIDA_AGENT_DEPLOY_DEBUG_USER_PLUGIN=OFF", "-DIDA_AGENT_ENABLE_INTEGRATION_TESTS=OFF",
        "-DIDA_AGENT_ENABLE_GUI_TESTS=OFF", f"-DPython3_EXECUTABLE={args.python.resolve()}",
        f"-DIDA_AGENT_IDA_QT_RUNTIME_DIR={args.qt_runtime.resolve()}",
        f"-DIDA_AGENT_QT_SDK_DIR={args.qt_sdk.resolve()}")
    run("cmake", "--build", build, "--parallel", jobs)
    run("ctest", "--test-dir", build, "--output-on-failure", "-LE", "integration")
    gateway = build / "ida-mcp"
    run("go", "-C", ROOT / "ida-mcp", "build", "-trimpath", "-buildvcs=false",
        "-ldflags=-s -w", "-o", gateway, ".", env=environment)
    plugin = build / "ida-runtime/plugins/ida-agent-plugin.so"
    validate_plugin(plugin)
    version = (ROOT / "ida-mcp/VERSION").read_text(encoding="ascii").strip()
    name = f"ida-agent-{version}-linux-x64"
    dist = ROOT / "release/dist"
    dist.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="linux-package-", dir=dist) as directory:
        stage = Path(directory) / name
        (stage / "plugins").mkdir(parents=True)
        shutil.copy2(gateway, stage / "ida-mcp")
        shipped_plugin = stage / "plugins/ida-agent-plugin.so"
        shutil.copy2(plugin, shipped_plugin)
        run("strip", "--strip-unneeded", shipped_plugin)
        validate_plugin(shipped_plugin)
        for executable in (stage / "ida-mcp", shipped_plugin):
            executable.chmod(0o755)
        launcher = stage / "idat-with-agent"
        shutil.copy2(ROOT / "release/linux/idat-with-agent", launcher)
        launcher.chmod(0o755)
        shutil.copytree(ROOT / "skills", stage / "skills")
        shutil.copy2(ROOT / "release/linux/INSTALL.md", stage / "README.md")
        licenses = stage / "licenses"
        licenses.mkdir()
        cache = (build / "CMakeCache.txt").read_text(encoding="utf-8")
        curl_source = re.search(r"^CURL_SOURCE_DIR:STATIC=(.+)$", cache, re.MULTILINE)
        if curl_source is None:
            raise RuntimeError("The build cache does not identify the linked curl source")
        shutil.copy2(Path(curl_source[1]) / "COPYING", licenses / "curl-COPYING.txt")
        sums = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(stage).as_posix()}"
                for path in sorted(stage.rglob("*")) if path.is_file()]
        (stage / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="ascii")
        archive_path = Path(directory) / f"{name}.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            archive.add(stage, arcname=name)
        target = dist / archive_path.name
        os.replace(archive_path, target)
        (dist / f"{target.name}.sha256").write_text(
            f"{hashlib.sha256(target.read_bytes()).hexdigest()}  {target.name}\n", encoding="ascii")
    print(target)


if __name__ == "__main__":
    main()
