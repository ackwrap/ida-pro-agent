#!/usr/bin/env python3
"""Build and package the minimal Windows x64 ida-agent release."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

from build_parallel import positive_jobs, select_build_jobs


ROOT = Path(__file__).resolve().parents[1]
BUILD_ROOT = ROOT / "build" / "release"
DIST_ROOT = ROOT / "release" / "dist"
VERSION = (ROOT / "ida-mcp" / "VERSION").read_text(encoding="ascii").strip()
PACKAGE_NAME = f"ida-agent-{VERSION}-windows-x64"
SETUP_NAME = f"{PACKAGE_NAME}-setup"
GO_WINRES_VERSION = "v0.3.3"


RELEASE_README = rf"""ida-agent {VERSION} Windows x64

Windows x64 only. Requires IDA Professional 9.4 and its bundled Qt 6.8.2.
No IDA installation files or Qt runtime DLLs are bundled.

Contents:
  ida-mcp.exe                   MCP Gateway and local configuration manager
  ida-agent.ico                 Shared product icon
  plugins/ida-agent-plugin.dll   IDA plugin with built-in AI
  skills/                       Optional client skills
  SHA256SUMS.txt                Per-file checksums

Fresh installation:
  Close IDA and clients using the previous Gateway. Uninstall the old package
  and remove its MCP client entries. No legacy aliases or automatic migration
  are provided. Install the matching Plugin and Gateway from this package.
  For portable use, copy plugins/ida-agent-plugin.dll to the IDA plugins directory.
  Run ida-mcp.exe -web to add the ida-mcp entry for Codex, OpenCode, Claude Code,
  Antigravity CLI, Grok Build, or ZCode. Restart the client after configuration.

Debugger:
  Select and configure the debugger in IDA or through the MCP debugger tools.
  The first debugger request asks for permission in IDA. Approval covers every
  MCP client on the current Pipe. Approval expires when the Pipe is recreated
  or the IDA database closes.
  Most runtime inspection requires a suspended target. An accepted request
  may still be pending; query debugger.info to confirm the resulting state.
  Headless MCP debugger requests are denied because approval requires IDA UI.

String search:
  string.search and string.search_regex reuse the current IDB string list.
  Set refresh=true to rebuild it; do not combine refresh=true with a cursor.
  Initial list creation and explicit refresh can still take time. These tools
  search the IDB string list, not arbitrary live process memory.

Plugin settings remain in %LOCALAPPDATA%\ida-agent\ai. Uninstalling the package
  does not require deleting providers or chat history. Custom Codex installations
  can set IDA_MCP_CODEX_PATH to the native codex.exe path before starting the manager.

仅支持 Windows x64。Plugin 与 Gateway 必须成套全新安装。
程序和 MCP 配置项名称为 ida-mcp；IDA 插件及发布包名称为 ida-agent。
首次调试请求在 IDA 中授权，当前 Pipe 的全部 MCP 客户端共享临时权限。
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the minimal Windows x64 ida-agent release directory and ZIP."
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="remove the dedicated release build directory before building",
    )
    parser.add_argument(
        "--no-zip",
        action="store_true",
        help="create only the unpacked release directory",
    )
    parser.add_argument(
        "--no-installer",
        action="store_true",
        help="skip the Inno Setup installer and create only portable artifacts",
    )
    parser.add_argument("--jobs", type=positive_jobs, help="parallel build jobs (default: all available CPUs)")
    parser.add_argument("--plugin", type=Path,
                        help="package an already validated Release plugin DLL instead of rebuilding it")
    return parser.parse_args()


def find_inno_compiler() -> Path | None:
    command = shutil.which("ISCC.exe") or shutil.which("ISCC")
    if command:
        return Path(command)
    candidates = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Inno Setup 6" / "ISCC.exe",
        Path(os.environ.get("ProgramFiles(x86)", "")) / "Inno Setup 6" / "ISCC.exe",
        Path(os.environ.get("ProgramFiles", "")) / "Inno Setup 6" / "ISCC.exe",
    ]
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def require_windows_tools(*, installer: bool) -> Path | None:
    if sys.platform != "win32":
        raise RuntimeError("the IDA plugin release can currently only be built on Windows")
    missing = [name for name in ("cmake", "ninja", "go") if shutil.which(name) is None]
    if missing:
        raise RuntimeError("missing required tools on PATH: " + ", ".join(missing))
    compiler = find_inno_compiler()
    if installer and compiler is None:
        raise RuntimeError("Inno Setup 6 ISCC.exe is required unless --no-installer is used")
    return compiler


def run(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    print("+", subprocess.list2cmdline(command), flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def build_plugin(jobs: int) -> Path:
    source_dir = ROOT / "ida-agent-plugin"
    build_dir = BUILD_ROOT / "ida-agent-plugin"
    runtime_dir = BUILD_ROOT / "ida-runtime"
    qt_sdk_dir = ROOT / "qt-sdk" / "qt-6.8.2-win"
    if not (qt_sdk_dir / "include" / "QtCore" / "qconfig.h").is_file():
        raise RuntimeError(f"Qt 6.8.2 development files are missing: {qt_sdk_dir}")
    # Empty by default: use the public SDK imports, including on a fresh CI runner.
    ida_qt_runtime = os.environ.get("IDA_AGENT_IDA_QT_RUNTIME_DIR", "")
    run(
        [
            "cmake",
            "-S",
            str(source_dir),
            "-B",
            str(build_dir),
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DBUILD_TESTING=OFF",
            "-DIDA_AGENT_ENABLE_QT_AI_CONSOLE=ON",
            f"-DIDABIN={runtime_dir}",
            f"-DIDA_AGENT_QT_SDK_DIR={qt_sdk_dir}",
            f"-DIDA_AGENT_IDA_QT_RUNTIME_DIR={ida_qt_runtime}",
        ]
    )
    run(["cmake", "--build", str(build_dir), "--target", "ida_agent_plugin", "--parallel", str(jobs)])

    candidates = sorted((runtime_dir / "plugins").glob("ida-agent-plugin*.dll"))
    if len(candidates) != 1:
        names = ", ".join(path.name for path in candidates) or "none"
        raise RuntimeError(f"expected one plugin DLL, found: {names}")
    return candidates[0]


def build_icon() -> Path:
    output = BUILD_ROOT / "ida-agent.ico"
    output.parent.mkdir(parents=True, exist_ok=True)
    run(
        ["go", "run", "./cmd/ida-agent-icon", "-output", str(output)],
        cwd=ROOT / "ida-mcp",
    )
    if not output.is_file() or output.stat().st_size < 1024:
        raise RuntimeError("icon generation did not produce a valid ida-agent.ico")
    return output


def windows_version() -> str:
    parts = VERSION.split(".")
    if not 1 <= len(parts) <= 4 or any(not part.isdigit() for part in parts):
        raise RuntimeError(f"VERSION is not numeric: {VERSION}")
    return ".".join(parts + ["0"] * (4 - len(parts)))


def generate_gateway_resources(icon: Path, resource: Path) -> None:
    gateway_source = ROOT / "ida-mcp"
    prefix = gateway_source / "zz_ida_agent_resource"
    run(
        [
            "go",
            "run",
            f"github.com/tc-hib/go-winres@{GO_WINRES_VERSION}",
            "simply",
            "--arch",
            "amd64",
            "--out",
            str(prefix),
            "--product-version",
            windows_version(),
            "--file-version",
            windows_version(),
            "--manifest",
            "cli",
            "--file-description",
            "ida-mcp Gateway and local configuration manager",
            "--product-name",
            "ida-mcp",
            "--original-filename",
            "ida-mcp.exe",
            "--icon",
            str(icon),
        ],
        cwd=gateway_source,
    )
    if not resource.is_file():
        raise RuntimeError("go-winres did not produce the amd64 Gateway resource")


def build_gateway(icon: Path) -> Path:
    output = BUILD_ROOT / "ida-mcp.exe"
    output.parent.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update({"CGO_ENABLED": "0", "GOOS": "windows", "GOARCH": "amd64"})
    gateway_source = ROOT / "ida-mcp"
    resource = gateway_source / "zz_ida_agent_resource_windows_amd64.syso"
    if resource.exists():
        raise RuntimeError(f"refusing to overwrite existing generated resource: {resource}")
    try:
        generate_gateway_resources(icon, resource)
        run(
            [
                "go",
                "build",
                "-trimpath",
                "-buildvcs=false",
                "-ldflags=-s -w",
                "-o",
                str(output),
                ".",
            ],
            cwd=gateway_source,
            env=environment,
        )
    finally:
        resource.unlink(missing_ok=True)
    if not output.is_file():
        raise RuntimeError("Gateway build did not produce ida-mcp.exe")
    return output


def copy_release_files(staging: Path, gateway: Path, plugin: Path, icon: Path) -> None:
    staging.mkdir(parents=True)
    shutil.copy2(gateway, staging / gateway.name)
    shutil.copy2(icon, staging / "ida-agent.ico")
    plugin_dir = staging / "plugins"
    plugin_dir.mkdir()
    shutil.copy2(plugin, plugin_dir / plugin.name)
    shutil.copytree(ROOT / "skills", staging / "skills")
    (staging / "README.txt").write_text(RELEASE_README, encoding="utf-8", newline="\n")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_checksums(package_dir: Path) -> None:
    files = sorted(path for path in package_dir.rglob("*") if path.is_file())
    lines = [f"{sha256(path)}  {path.relative_to(package_dir).as_posix()}" for path in files]
    (package_dir / "SHA256SUMS.txt").write_text(
        "\n".join(lines) + "\n", encoding="ascii", newline="\n"
    )


def create_zip(package_dir: Path, archive: Path) -> None:
    archive.unlink(missing_ok=True)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as target:
        for path in sorted(package_dir.rglob("*")):
            if path.is_file():
                target.write(path, (Path(package_dir.name) / path.relative_to(package_dir)).as_posix())


def build_installer(package_dir: Path, compiler: Path) -> Path:
    installer = DIST_ROOT / f"{SETUP_NAME}.exe"
    installer.unlink(missing_ok=True)
    run(
        [
            str(compiler),
            "/Qp",
            f"/DAppVersion={VERSION}",
            f"/DAppWindowsVersion={windows_version()}",
            f"/DPackageDir={package_dir}",
            f"/DOutputDir={DIST_ROOT}",
            f"/DOutputBaseFilename={SETUP_NAME}",
            f"/DIconPath={package_dir / 'ida-agent.ico'}",
            f"/DPluginSHA256={sha256(package_dir / 'plugins' / 'ida-agent-plugin.dll')}",
            str(ROOT / "release" / "installer.iss"),
        ]
    )
    if not installer.is_file():
        raise RuntimeError("Inno Setup did not produce the installer")
    checksum = installer.with_suffix(installer.suffix + ".sha256")
    checksum.write_text(f"{sha256(installer)}  {installer.name}\n", encoding="ascii", newline="\n")
    return installer


def assemble_release(
    gateway: Path, plugin: Path, icon: Path, *, create_archive: bool
) -> tuple[Path, Path | None]:
    DIST_ROOT.mkdir(parents=True, exist_ok=True)
    package_dir = DIST_ROOT / PACKAGE_NAME
    staging = DIST_ROOT / f".{PACKAGE_NAME}.tmp"
    archive = DIST_ROOT / f"{PACKAGE_NAME}.zip"
    shutil.rmtree(staging, ignore_errors=True)
    copy_release_files(staging, gateway, plugin, icon)
    write_checksums(staging)
    shutil.rmtree(package_dir, ignore_errors=True)
    staging.replace(package_dir)
    if create_archive:
        create_zip(package_dir, archive)
        return package_dir, archive
    archive.unlink(missing_ok=True)
    return package_dir, None


def main() -> int:
    args = parse_args()
    try:
        jobs = select_build_jobs(args.jobs)
        compiler = require_windows_tools(installer=not args.no_installer)
        plugin = args.plugin.resolve(strict=True) if args.plugin else None
        if plugin is not None:
            if plugin.suffix.lower() != ".dll" or not plugin.is_file():
                raise RuntimeError("--plugin must point to a validated Release plugin DLL")
            with plugin.open("rb") as source:
                if source.read(2) != b"MZ":
                    raise RuntimeError("--plugin is not a Windows PE binary")
            if args.clean and plugin.is_relative_to(BUILD_ROOT.resolve()):
                raise RuntimeError("--plugin must be outside the directory removed by --clean")
        if args.clean:
            shutil.rmtree(BUILD_ROOT, ignore_errors=True)
        if plugin is None:
            plugin = build_plugin(jobs)
        icon = build_icon()
        gateway = build_gateway(icon)
        package_dir, archive = assemble_release(
            gateway, plugin, icon, create_archive=not args.no_zip
        )
        installer = None if args.no_installer else build_installer(package_dir, compiler)
    except (OSError, RuntimeError, subprocess.CalledProcessError, argparse.ArgumentTypeError) as error:
        print(f"release build failed: {error}", file=sys.stderr)
        return 1

    print(f"release directory: {package_dir}")
    if archive is not None:
        print(f"release archive:   {archive}")
    if installer is not None:
        print(f"release installer: {installer}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
