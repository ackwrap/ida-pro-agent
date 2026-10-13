#!/usr/bin/env python3
"""Inspect a real .deb, and optionally exercise installation in a disposable CI container."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
from uuid import uuid4
import struct
import subprocess
import tarfile
import tempfile


def run(*command, **kwargs):
    return subprocess.run([str(item) for item in command], check=True, **kwargs)


def inspect_package(package):
    for field, expected in (("Package", "ida-agent"), ("Architecture", "amd64")):
        value = subprocess.check_output(["dpkg-deb", "--field", str(package), field], text=True).strip()
        assert value == expected, (field, value)
    content = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(package)])
    with tarfile.open(fileobj=io.BytesIO(content)) as archive:
        members = {item.name.removeprefix("./"): item for item in archive}
        for item in members.values():
            assert item.uid == 0 and item.gid == 0, item.name
            assert not Path(item.name).is_absolute() and ".." not in Path(item.name).parts, item.name
            assert not (item.mode & 0o6000), item.name
            assert not Path(item.name).name.startswith(("libQt", "libida", "libcurl", "libsqlite")), item.name
        for binary in ("ida-mcp", "ida-agent-setup", "idat-with-agent"):
            link = members[f"usr/bin/{binary}"]
            assert link.issym() and link.linkname == f"../lib/ida-agent/{binary}"
            assert members[f"usr/lib/ida-agent/{binary}"].mode & 0o111
        for size in (16, 24, 32, 48, 64, 128, 256):
            path = f"usr/share/icons/hicolor/{size}x{size}/apps/ida-agent.png"
            header = archive.extractfile(members[path]).read(24)
            assert header[:8] == b"\x89PNG\r\n\x1a\n"
            assert struct.unpack(">II", header[16:24]) == (size, size)
        desktop = "usr/share/applications/io.github.ackwrap.ida-agent.desktop"
        assert desktop in members
        assert "StartupWMClass=Idaagent" in archive.extractfile(members[desktop]).read().decode("utf-8")
        assert "usr/share/metainfo/io.github.ackwrap.ida-agent.metainfo.xml" in members
        for skill in ("ida-reverse-analysis", "idapython"):
            assert f"usr/lib/ida-agent/skills/{skill}/SKILL.md" in members
    with tempfile.TemporaryDirectory(prefix="ida-deb-control-") as temporary:
        run("dpkg-deb", "--control", package, temporary)
        assert not any((Path(temporary) / name).exists() for name in ("preinst", "postinst", "prerm", "postrm"))
    print(f"Verified package files, icons and ownership: {package.name}", flush=True)


def exercise_installation(package):
    if os.geteuid() != 0 or os.environ.get("IDA_AGENT_PACKAGE_TEST") != "1":
        raise RuntimeError("--install requires root and IDA_AGENT_PACKAGE_TEST=1 in a disposable test container.")
    if subprocess.run(["dpkg-query", "--show", "ida-agent"], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode == 0:
        raise RuntimeError("Refusing to replace an existing ida-agent installation in the test environment.")
    run("apt-get", "install", "-y", package.resolve())
    run("dpkg", "--verify", "ida-agent")
    run("desktop-file-validate", "/usr/share/applications/io.github.ackwrap.ida-agent.desktop")
    run("appstreamcli", "validate", "--no-net", "/usr/share/metainfo/io.github.ackwrap.ida-agent.metainfo.xml")
    username = f"ida-agent-test-{uuid4().hex[:8]}"
    run("useradd", "--create-home", username)
    user_home = Path("/home") / username
    user_directory = user_home / "IDA's user directory"
    state = user_home / ".local/state"
    environment = {"IDAUSR": str(user_directory), "XDG_CONFIG_HOME": str(user_home / ".config"),
                   "XDG_STATE_HOME": str(state), "BROWSER": "true"}
    def as_user(*command, **kwargs):
        return run("runuser", "-u", username, "--", "env", *(f"{key}={value}" for key, value in environment.items()),
                   *command, **kwargs)
    target = user_directory / "plugins/ida-agent-plugin.so"
    as_user("ida-agent-setup", "--install-plugin")
    source = Path("/usr/lib/ida-agent/plugins/ida-agent-plugin.so")
    assert target.is_symlink() and target.resolve() == source
    before = hashlib.sha256(target.read_bytes()).hexdigest()
    as_user("ida-agent-setup", "--manager")
    cache = state / "ida-agent/desktop/manager.json"
    first = json.loads(cache.read_text())
    as_user("ida-agent-setup", "--manager")
    assert json.loads(cache.read_text()) == first, "Desktop startup must reuse the running manager"
    as_user("ida-agent-setup", "--stop-manager")
    probe = user_home / "gui_probe.py"
    probe.write_text(
        "import sys, tkinter as tk\nfrom pathlib import Path\n"
        "sys.path.insert(0, '/usr/lib/ida-agent')\n"
        "from ida_agent_installer_gui import InstallerWindow\n"
        "root = tk.Tk(className='Idaagent')\n"
        "window = InstallerWindow(root, Path('/usr/lib/ida-agent'), Path.home() / \"IDA's user directory\")\n"
        "root.update()\nassert root.winfo_class() == 'Idaagent'\nassert window.icon.width() == 128\n"
        "assert window.directory.get().endswith(\"IDA's user directory\")\n"
        "root.destroy()\n", encoding="utf-8")
    for language in ("C.UTF-8", "zh_CN.UTF-8"):
        as_user("env", f"LC_MESSAGES={language}", "xvfb-run", "-a", "python3", probe)
    run("apt-get", "install", "--reinstall", "-y", package.resolve())
    assert target.is_symlink() and hashlib.sha256(target.read_bytes()).hexdigest() == before
    with tempfile.TemporaryDirectory(prefix="ida-deb-upgrade-") as temporary:
        tree = Path(temporary) / "tree"
        run("dpkg-deb", "--raw-extract", package, tree)
        version = subprocess.check_output(["dpkg-deb", "--field", str(package), "Version"], text=True).strip()
        upgrade_version = version + "+package-test"
        control = tree / "DEBIAN/control"
        control.write_text(control.read_text().replace(f"Version: {version}\n", f"Version: {upgrade_version}\n"))
        upgrade = Path(temporary) / "upgrade.deb"
        run("dpkg-deb", "--root-owner-group", "--build", tree, upgrade)
        run("apt-get", "install", "-y", upgrade)
        actual_version = subprocess.check_output(["dpkg-query", "--show", "--showformat=${Version}", "ida-agent"], text=True)
        assert actual_version == upgrade_version
        run("dpkg", "--verify", "ida-agent")
        assert target.is_symlink() and hashlib.sha256(target.read_bytes()).hexdigest() == before
        as_user("ida-agent-setup", "--manager")
        assert json.loads(cache.read_text())["pid"] != first["pid"]
        as_user("ida-agent-setup", "--stop-manager")
    as_user("ida-agent-setup", "--remove-plugin")
    assert not os.path.lexists(target)
    run("apt-get", "purge", "-y", "ida-agent")
    assert not source.exists() and cache.exists()
    print("Verified apt installation, GUI, manager reuse and stop, reinstall, upgrade, plugin removal and package purge.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args()
    inspect_package(args.package)
    if args.install:
        exercise_installation(args.package)


if __name__ == "__main__":
    main()
