"""Per-user plugin activation and desktop manager startup for the Linux package."""
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.request import ProxyHandler, build_opener
from uuid import uuid4
import webbrowser


def default_user_directory():
    return Path(os.environ.get("IDAUSR") or Path.home() / ".idapro").expanduser().absolute()


def plugin_path(user_directory):
    return Path(user_directory).expanduser().absolute() / "plugins/ida-agent-plugin.so"


def is_managed_link(target, source):
    if not target.is_symlink():
        return False
    linked = Path(os.readlink(target))
    if not linked.is_absolute():
        linked = target.parent / linked
    return linked.resolve() == source.resolve()


def plugin_status(payload, user_directory):
    target = plugin_path(user_directory)
    if is_managed_link(target, payload / "plugins/ida-agent-plugin.so"):
        return "installed"
    return "conflict" if os.path.lexists(target) else "missing"


def require_normal_user():
    if os.geteuid() == 0:
        raise RuntimeError("Run IDA Agent as your normal desktop user, without sudo.")


def require_ida_closed():
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid == os.geteuid() and (entry / "comm").read_text().strip() in {
                    "ida", "ida64", "idat", "idat64"}:
                raise RuntimeError("Close IDA and IDAT before changing the plugin installation.")
        except (OSError, UnicodeError):
            continue


def install_plugin(payload, user_directory, *, replace=False):
    source = payload / "plugins/ida-agent-plugin.so"
    if not source.is_file():
        raise RuntimeError("The packaged IDA plugin is unavailable. Reinstall the Debian package.")
    target = plugin_path(user_directory)
    if is_managed_link(target, source):
        return target, None
    if os.path.lexists(target) and not replace:
        raise FileExistsError("An existing plugin occupies the destination. Use --replace to back it up.")
    if target.is_dir() and not target.is_symlink():
        raise RuntimeError("The plugin destination is a directory; select another IDA user directory.")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    pending = target.with_name(f".ida-agent-plugin-{uuid4().hex}.tmp")
    backup = None
    try:
        pending.symlink_to(source.resolve())
        if os.path.lexists(target):
            backup = target.with_name(f"ida-agent-plugin.so.backup-{uuid4().hex}")
            os.replace(target, backup)
        try:
            os.replace(pending, target)
        except OSError:
            if backup is not None and not os.path.lexists(target):
                os.replace(backup, target)
            raise
    finally:
        pending.unlink(missing_ok=True)
    return target, backup


def remove_plugin(payload, user_directory):
    target = plugin_path(user_directory)
    if not os.path.lexists(target):
        return target
    if not is_managed_link(target, payload / "plugins/ida-agent-plugin.so"):
        raise RuntimeError("This plugin is not managed by the Debian package; it was left in place.")
    target.unlink()
    return target


def manager_state_directory():
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state")
    return base / "ida-agent/desktop"


def _running_manager(cache, gateway):
    try:
        pid = cache["pid"]
        if type(pid) is not int or pid <= 0:
            return False
        process = Path(f"/proc/{pid}")
        if process.stat().st_uid != os.geteuid():
            return False
        if (process / "exe").resolve() != gateway.resolve():
            return False
        if b"-web" not in (process / "cmdline").read_bytes().split(b"\0")[1:]:
            return False
        url = cache["url"]
        if not re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}", url):
            return False
        opener = build_opener(ProxyHandler({}))
        # The status API requires its CSRF token and probes every installed client.
        # Check the public landing page after verifying the process identity instead.
        with opener.open(url, timeout=2) as response:
            if response.geturl().rstrip("/") != url:
                return False
            page = response.read(65536).decode("utf-8")
            policy = response.headers.get("Content-Security-Policy", "")
        token = re.search(r'<meta name="ida-mcp-token" content="([A-Za-z0-9_-]{43})">', page)
        return bool(token and f"script-src 'nonce-{token[1]}'" in policy
                    and "<title>IDA MCP - connections</title>" in page)
    except (OSError, ValueError, KeyError, TypeError):
        return False


def _read_manager_cache(cache_path):
    try:
        return json.loads(cache_path.read_text()) if cache_path.stat().st_size <= 4096 else {}
    except (OSError, ValueError):
        return {}


def stop_manager(payload, *, state_directory=None):
    """Stop only the manager recorded for this package and the current user."""
    import fcntl
    import select
    import signal

    state = state_directory or manager_state_directory()
    if not state.is_dir():
        return False
    descriptor = os.open(state / "manager.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        cache = _read_manager_cache(state / "manager.json")
        if not isinstance(cache, dict) or type(cache.get("pid")) is not int or cache["pid"] <= 0:
            return False
        try:
            process_descriptor = os.pidfd_open(cache["pid"])
        except ProcessLookupError:
            return False
        try:
            if not _running_manager(cache, payload / "ida-mcp"):
                return False
            signal.pidfd_send_signal(process_descriptor, signal.SIGTERM)
            if not select.select([process_descriptor], [], [], 5)[0]:
                raise RuntimeError("The manager is still stopping. Retry before upgrading or removing the package.")
        finally:
            os.close(process_descriptor)
    return True


def open_manager(payload, *, state_directory=None, browser=None):
    """Start one detached manager, retaining its URL in a private, locked state file."""
    import fcntl

    gateway = payload / "ida-mcp"
    if not gateway.is_file():
        raise RuntimeError("The packaged Gateway is unavailable. Reinstall the Debian package.")
    state = state_directory or manager_state_directory()
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    cache_path = state / "manager.json"
    descriptor = os.open(state / "manager.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        cache = _read_manager_cache(cache_path)
        if _running_manager(cache, gateway):
            url = cache["url"]
        else:
            log_path = state / "manager.log"
            descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w") as log:
                process = subprocess.Popen([str(gateway), "-web"], stdin=subprocess.DEVNULL,
                                           stdout=log, stderr=log, start_new_session=True)
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError(f"The manager exited. See {log_path}.")
                    with log_path.open(encoding="utf-8", errors="replace") as output:
                        text = output.read(65536)
                    match = re.search(r"manager listening at (http://127\.0\.0\.1:[1-9][0-9]{0,4})", text)
                    if match:
                        url = match[1]
                        break
                    time.sleep(0.05)
                else:
                    raise RuntimeError(f"The manager did not start. See {log_path}.")
                temporary = state / f".manager-{uuid4().hex}.json"
                try:
                    with temporary.open("x", encoding="utf-8") as output:
                        temporary.chmod(0o600)
                        json.dump({"pid": process.pid, "url": url}, output)
                    os.replace(temporary, cache_path)
                finally:
                    temporary.unlink(missing_ok=True)
            except Exception:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                raise
    (browser or webbrowser.open)(url)
    return url
