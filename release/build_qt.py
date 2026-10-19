#!/usr/bin/env python3
"""Build public Qt 6.8.2 link inputs; no IDA installation or GitHub token is needed."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request

from build_parallel import positive_jobs, select_build_jobs

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ida-agent-plugin/cmake"))
from qt_link_inputs import (MACOS_QT_DEPLOYMENT_TARGET, MANIFEST, SOURCE_NAME, SOURCE_SHA256, SOURCE_URL, VERSION,
                            build_manifest, validate_prefix)


def run(*command, **kwargs):
    print("+", " ".join(map(str, command)), flush=True)
    subprocess.run(list(map(str, command)), check=True, **kwargs)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download_source(archive):
    if archive.exists():
        if sha256(archive) != SOURCE_SHA256:
            raise RuntimeError(f"Cached Qt source checksum mismatch: {archive}; remove it before retrying")
        return
    temporary = archive.with_suffix(archive.suffix + ".download")
    try:
        with urllib.request.urlopen(SOURCE_URL, timeout=120) as response, temporary.open("wb") as target:
            if not response.url.startswith("https://"):
                raise RuntimeError("Qt source downloads must stay on HTTPS")
            while block := response.read(1024 * 1024):
                target.write(block)
        if sha256(temporary) != SOURCE_SHA256:
            raise RuntimeError("Qt source checksum mismatch; refusing to extract or compile")
        os.replace(temporary, archive)
    finally:
        temporary.unlink(missing_ok=True)


def extract_source(archive, directory):
    """Extract only the verified, single-root source tree without path traversal."""
    source = directory / f"qtbase-everywhere-src-{VERSION}"
    marker = source / ".ida-agent-extracted"
    if marker.is_file():
        if marker.read_text(encoding="ascii") != SOURCE_SHA256:
            raise RuntimeError("Qt source extraction marker differs; use a fresh work directory")
        return source
    with tarfile.open(archive, "r:xz") as package:
        for member in package.getmembers():
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or path.parts[0] != source.name:
                raise RuntimeError(f"Unsafe Qt source member: {member.name}")
            if not (member.isfile() or member.isdir()):
                raise RuntimeError(f"Unexpected Qt source entry type: {member.name}")
        package.extractall(directory)
    (source / ".ida-agent-extracted").write_text(SOURCE_SHA256, encoding="ascii")
    return source


def configure_command(source, build, prefix, system):
    command = ["cmake", "-S", source, "-B", build, "-G", "Ninja",
               "-DCMAKE_BUILD_TYPE=Release", f"-DCMAKE_INSTALL_PREFIX={prefix}",
               "-DCMAKE_INSTALL_LIBDIR=lib", "-DQT_NAMESPACE=QT", "-DBUILD_SHARED_LIBS=ON",
               "-DQT_BUILD_EXAMPLES=OFF", "-DQT_BUILD_TESTS=OFF"]
    if system == "darwin":
        command += ["-DCMAKE_OSX_ARCHITECTURES=x86_64;arm64",
                    f"-DCMAKE_OSX_DEPLOYMENT_TARGET={MACOS_QT_DEPLOYMENT_TARGET}",
                    "-DFEATURE_framework=ON"]
        # Qt 6.8.2 Cocoa still uses APIs unavailable when the minimum target is
        # 15.0. This link-only Qt build targets 14; our product still targets 15.
        # Homebrew libraries are usually arm64-only on this runner. Build the
        # bundled third-party sources for both slices, using Apple TLS instead.
        bundled = ("zlib", "doubleconversion", "libb2", "pcre2", "freetype", "harfbuzz",
                   "jpeg", "png", "sqlite", "textmarkdownreader")
        command += [f"-DFEATURE_system_{name}=OFF" for name in bundled]
        command += [f"-DFEATURE_{name}=OFF" for name in ("icu", "zstd", "openssl", "dbus", "glib", "brotli")]
    return command


def validate_inputs(prefix, system):
    validate_prefix(prefix, system)
    validator = ROOT / f"ida-agent-plugin/cmake/validate_ida_qt_{'linux' if system == 'linux' else 'macos'}.py"
    command = [sys.executable, validator, "--prefix", prefix]
    if system == "darwin":
        command += ["x86_64", "arm64"]
    environment = dict(os.environ)
    if system == "linux":
        environment["LD_LIBRARY_PATH"] = str(prefix / "lib")
    run(*command, env=environment)


def install_framework_headers(prefix):
    """Expose framework headers through the same include tree used on Linux."""
    for module in ("Core", "Gui", "Widgets"):
        headers = prefix / f"lib/Qt{module}.framework/Headers"
        shutil.copytree(headers, prefix / f"include/Qt{module}", dirs_exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=ROOT / "build/qt-public")
    parser.add_argument("--work-dir", type=Path, default=ROOT / "build/qt-source")
    parser.add_argument("--jobs", type=positive_jobs, help="Qt build jobs (default: at most 8)")
    args = parser.parse_args()
    if sys.platform not in ("linux", "darwin") or (sys.platform == "linux" and platform.machine() != "x86_64"):
        parser.error("Run on Linux x86_64 or macOS with Xcode command line tools")
    prefix = args.prefix.resolve()
    if (prefix / MANIFEST).exists():
        validate_inputs(prefix, sys.platform)
        print(f"Reusing validated public Qt inputs: {prefix}")
        return
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    archive = work / SOURCE_NAME
    download_source(archive)
    source = extract_source(archive, work)
    build = work / f"build-{sys.platform}"
    jobs = args.jobs or min(8, select_build_jobs())
    run(*configure_command(source, build, prefix, sys.platform))
    run("cmake", "--build", build, "--parallel", jobs)
    run("cmake", "--install", build)
    shutil.copytree(source / "LICENSES", prefix / "LICENSES", dirs_exist_ok=True)
    if sys.platform == "darwin":
        install_framework_headers(prefix)
    manifest = prefix / MANIFEST
    manifest.write_text(json.dumps(build_manifest(sys.platform), indent=2) + "\n", encoding="utf-8")
    try:
        validate_inputs(prefix, sys.platform)
    except Exception:
        manifest.unlink(missing_ok=True)
        raise
    print(f"Public Qt link inputs ready: {prefix}")


if __name__ == "__main__":
    main()
