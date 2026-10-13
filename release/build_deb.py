#!/usr/bin/env python3
"""Build the Ubuntu 24.04+ / Debian 13+ amd64 desktop package from a Linux staging directory."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LINUX = ROOT / "release/linux"
DEPENDENCIES = ("libc6 (>= 2.38), libstdc++6 (>= 12), libgcc-s1, "
                "libssl3t64 | libssl3, ca-certificates, python3 (>= 3.10), "
                "python3-tk, xdg-utils, hicolor-icon-theme")
ICONS = (16, 24, 32, 48, 64, 128, 256)


def run(*command):
    subprocess.run([str(item) for item in command], check=True)


def validate_version(version):
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("The package version must contain three numeric components.")


def validate_abi(plugin):
    versions = subprocess.check_output(["readelf", "--version-info", str(plugin)],
                                       env=dict(os.environ, LC_ALL="C"), text=True)
    for prefix, maximum in (("GLIBC", (2, 38)), ("GLIBCXX", (3, 4, 30))):
        required = [tuple(map(int, value.split(".")))
                    for value in re.findall(rf"\b{prefix}_([0-9]+(?:\.[0-9]+)+)\b", versions)]
        if required and max(required) > maximum:
            raise RuntimeError(f"The plugin requires {prefix}_{'.'.join(map(str, max(required)))}; "
                               "rebuild on the supported Linux baseline before packaging.")


def copy_file(source, destination):
    if source.is_symlink() or not source.is_file() or source.stat().st_size == 0:
        raise ValueError(f"Missing or invalid package input: {source.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def assemble_tree(package, version, stage):
    validate_version(version)
    payload = stage / "usr/lib/ida-agent"
    for relative in ("ida-mcp", "plugins/ida-agent-plugin.so", "idat-with-agent"):
        copy_file(package / relative, payload / relative)
    skills = package / "skills"
    if not skills.is_dir() or skills.is_symlink() or any(path.is_symlink() for path in skills.rglob("*")):
        raise ValueError("The staged client skills must be an ordinary directory tree.")
    shutil.copytree(skills, payload / "skills")
    for filename in ("ida-agent-setup", "ida_agent_installer.py", "ida_agent_installer_gui.py"):
        copy_file(LINUX / filename, payload / filename)
    (payload / "VERSION").write_text(version + "\n", encoding="ascii")
    binaries = stage / "usr/bin"
    binaries.mkdir(parents=True)
    for filename in ("ida-mcp", "idat-with-agent", "ida-agent-setup"):
        (binaries / filename).symlink_to(f"../lib/ida-agent/{filename}")
    desktop = stage / "usr/share/applications/io.github.ackwrap.ida-agent.desktop"
    copy_file(LINUX / desktop.name, desktop)
    metadata = stage / "usr/share/metainfo/io.github.ackwrap.ida-agent.metainfo.xml"
    copy_file(LINUX / metadata.name, metadata)
    svg = stage / "usr/share/icons/hicolor/scalable/apps/ida-agent.svg"
    copy_file(ROOT / "ida-mcp/webmanager/static/icon.svg", svg)
    for size in ICONS:
        png = stage / f"usr/share/icons/hicolor/{size}x{size}/apps/ida-agent.png"
        png.parent.mkdir(parents=True, exist_ok=True)
        run("rsvg-convert", "--width", size, "--height", size, "--output", png, svg)
        if size == 128:
            shutil.copyfile(png, payload / "ida-agent.png")
    documentation = stage / "usr/share/doc/ida-agent"
    documentation.mkdir(parents=True)
    copy_file(LINUX / "INSTALL.md", documentation / "README.md")
    copy_file(ROOT / "LICENSE", documentation / "copyright")
    copy_file(ROOT / "THIRD_PARTY_NOTICES.md", documentation / "THIRD_PARTY_NOTICES.md")
    copy_file(package / "licenses/curl-COPYING.txt", documentation / "curl-COPYING.txt")
    executable_paths = {payload / name for name in ("ida-mcp", "idat-with-agent", "ida-agent-setup",
                                                   "plugins/ida-agent-plugin.so")}
    for path in stage.rglob("*"):
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() or path in executable_paths else 0o644)
    stage.chmod(0o755)
    control = stage / "DEBIAN"
    control.mkdir(mode=0o755)
    files = sorted(path for path in stage.rglob("*") if path.is_file() and not path.is_symlink()
                   and control not in path.parents)
    installed_size = (sum(path.stat().st_size for path in files) + 1023) // 1024
    (control / "control").write_text(
        f"Package: ida-agent\nVersion: {version}\nSection: devel\nPriority: optional\n"
        f"Architecture: amd64\nMaintainer: ackwrap <ackwrap@users.noreply.github.com>\n"
        f"Installed-Size: {installed_size}\nDepends: {DEPENDENCIES}\n"
        "Homepage: https://github.com/ackwrap/ida-pro-agent\n"
        "Description: AI Chat and MCP integration for IDA Professional\n"
        " Includes the MCP Gateway, client skills, and the full AI Chat plugin.\n"
        " Open IDA Agent from the application menu to activate the plugin for your user.\n"
        " Requires separately installed IDA Professional 9.4 with its bundled Qt 6.8.2.\n",
        encoding="utf-8")
    (control / "md5sums").write_text("".join(
        f"{hashlib.md5(path.read_bytes(), usedforsecurity=False).hexdigest()}  {path.relative_to(stage).as_posix()}\n"
        for path in files), encoding="utf-8")
    for path in control.iterdir():
        path.chmod(0o644)
    run("desktop-file-validate", desktop)
    run("appstreamcli", "validate", "--no-net", metadata)
    return payload


def build_deb(package, version, output):
    from build_linux import validate_plugin
    validate_version(version)
    validate_plugin(package / "plugins/ida-agent-plugin.so")
    validate_abi(package / "plugins/ida-agent-plugin.so")
    for tool in ("dpkg-deb", "rsvg-convert", "desktop-file-validate", "appstreamcli"):
        if shutil.which(tool) is None:
            raise RuntimeError(f"Install the build dependency providing {tool}.")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="linux-deb-", dir=output) as temporary:
        root = Path(temporary)
        stage = root / "package"
        stage.mkdir()
        assemble_tree(package, version, stage)
        candidate = root / f"ida-agent-{version}-linux-x64.deb"
        run("dpkg-deb", "--root-owner-group", "-Zxz", "--build", stage, candidate)
        actual_version = subprocess.check_output(["dpkg-deb", "--field", str(candidate), "Version"], text=True).strip()
        if actual_version != version:
            raise RuntimeError("The generated Debian package has the wrong version.")
        target = output / candidate.name
        os.replace(candidate, target)
        target.with_suffix(".deb.sha256").write_text(
            f"{hashlib.sha256(target.read_bytes()).hexdigest()}  {target.name}\n", encoding="ascii")
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-dir", type=Path, required=True, help="validated portable Linux staging directory")
    parser.add_argument("--version", default=(ROOT / "ida-mcp/VERSION").read_text().strip())
    parser.add_argument("--output", type=Path, default=ROOT / "release/dist")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Run dpkg-deb on Linux")
    try:
        print(build_deb(args.package_dir.resolve(), args.version, args.output.resolve()))
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Debian packaging failed: {error}\n")


if __name__ == "__main__":
    main()
