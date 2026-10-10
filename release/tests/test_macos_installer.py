#!/usr/bin/env python3
"""Mount a DMG and verify installation, upgrade, refusal and gateway startup."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import urllib.request


def invoke(executable, *arguments, success=True):
    result = subprocess.run([str(executable), *map(str, arguments)], text=True,
                            capture_output=True, timeout=30)
    if (result.returncode == 0) != success:
        raise AssertionError(f"Installer exit {result.returncode}: {result.stdout}{result.stderr}")
    return result


def verify_bundle(bundle, root):
    executable = bundle / "Contents/MacOS/Installer"
    payload = bundle / "Contents/Resources/payload"
    invoke(executable, "--verify-payload")
    ida_user, gateway_dir = root / "user's IDA", root / "user's gateway"
    result = json.loads(invoke(executable, "--install", ida_user, gateway_dir).stdout)
    plugin, gateway, launcher = map(Path, (result["plugin"], result["gateway"], result["launcher"]))
    for source, target in ((payload / "ida-agent-plugin.dylib", plugin), (payload / "ida-mcp", gateway)):
        assert hashlib.sha256(source.read_bytes()).digest() == hashlib.sha256(target.read_bytes()).digest()
        assert target.stat().st_mode & 0o777 == 0o755
    assert result["backups"] == []
    previous = {}
    for path in (plugin, gateway, launcher):
        previous[str(path)] = ("previous " + path.name).encode()
        path.write_bytes(previous[str(path)])
    upgraded = json.loads(invoke(executable, "--install", ida_user, gateway_dir).stdout)
    assert len(upgraded["backups"]) == 3
    for backup in map(Path, upgraded["backups"]):
        assert backup.read_bytes() == previous[str(backup).split(".backup-", 1)[0]]

    # A bad second destination must leave the previously installed plugin intact.
    original = plugin.read_bytes()
    victim = root / "untouched"
    victim.write_text("keep me")
    gateway.unlink()
    gateway.symlink_to(victim)
    invoke(executable, "--install", ida_user, gateway_dir, success=False)
    assert plugin.read_bytes() == original and victim.read_text() == "keep me"
    assert not list(root.rglob("*.new-*"))
    gateway.unlink()
    invoke(executable, "--install", ida_user, gateway_dir)

    damaged = root / "Damaged.app"
    shutil.copytree(bundle, damaged)
    with (damaged / "Contents/Resources/payload/ida-mcp").open("ab") as output:
        output.write(b"tampered")
    invoke(damaged / "Contents/MacOS/Installer", "--install", root / "refused-user", root / "refused-bin", success=False)
    assert not (root / "refused-user").exists()

    # Use an owned harmless process with IDA's executable name; never touch user IDA.
    fake_ida = root / "ida"
    subprocess.run(["xcrun", "clang", "-x", "c", "-o", str(fake_ida), "-"],
                   input="#include <unistd.h>\nint main(void) { sleep(30); return 0; }\n", text=True, check=True)
    process = subprocess.Popen([str(fake_ida)])
    try:
        assert process.poll() is None, "owned IDA process fixture exited early"
        assert "Close all IDA" in invoke(executable, "--install", ida_user, gateway_dir, success=False).stderr
    finally:
        process.terminate()
        process.wait(timeout=5)

    # Exercise quoting in the actual Finder launcher, including an apostrophe.
    environment = dict(os.environ, HOME=str(root / "clean-home"))
    process = subprocess.Popen([str(launcher)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, env=environment)
    lines = queue.Queue()
    reader = threading.Thread(target=lambda: [lines.put(line) for line in process.stdout], daemon=True)
    reader.start()
    try:
        while True:
            line = lines.get(timeout=10)
            match = re.search(r"http://127\.0\.0\.1:\d+", line)
            if match:
                client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with client.open(match.group(0), timeout=5) as response:
                    assert response.status == 200 and b"ida-mcp" in response.read().lower()
                break
    finally:
        process.send_signal(signal.SIGINT)
        process.wait(timeout=10)
        reader.join(timeout=2)
    print("payload=install=upgrade=backup=symlink-refusal=tamper-refusal=running-ida-guard=launcher=ok")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dmg", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ida-installer-test-") as directory:
        root = Path(directory)
        mount = root / "mounted"
        mount.mkdir()
        subprocess.run(["hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", str(mount), str(args.dmg.resolve())], check=True)
        try:
            verify_bundle(mount / "IDA Agent Installer.app", root)
        finally:
            subprocess.run(["hdiutil", "detach", str(mount)], check=True)


if __name__ == "__main__":
    main()
