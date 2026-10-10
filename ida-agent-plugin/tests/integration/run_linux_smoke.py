#!/usr/bin/env python3
"""Exercise a real Linux IDA plugin through stdio and HTTP MCP Gateways.

All IDBs and plugin/user settings are isolated in a private temporary directory.
The installed IDA must already have a valid license.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request


class StdioClient:
    def __init__(self, executable, instances, log):
        self.process = subprocess.Popen(
            [str(executable), "-instance-dir", str(instances)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
            text=True, encoding="utf-8", bufsize=1)
        self.messages = queue.Queue()
        self.next_id = 0

        def read():
            try:
                for line in self.process.stdout:
                    self.messages.put(json.loads(line))
            except Exception as error:
                self.messages.put(error)
            finally:
                self.messages.put(EOFError("Gateway stdout closed"))

        threading.Thread(target=read, daemon=True).start()

    def send(self, message):
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def request(self, method, params):
        self.next_id += 1
        request_id = self.next_id
        self.send(dict(jsonrpc="2.0", id=request_id, method=method, params=params))
        deadline = time.monotonic() + 45
        while True:
            message = self.messages.get(timeout=max(0.01, deadline - time.monotonic()))
            if isinstance(message, Exception):
                raise message
            if message.get("id") == request_id:
                if "error" in message:
                    raise RuntimeError(message["error"])
                return message["result"]

    def call(self, domain, method, arguments):
        result = self.request("tools/call", {"name": "ida_" + domain, "arguments": {
            "action": "call", "method": method, "arguments": arguments}})
        if result.get("isError"):
            raise RuntimeError(f"{method}: {result}")
        return result["structuredContent"]["result"]

    def close(self):
        self.process.stdin.close()
        try:
            result = self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise RuntimeError("Gateway did not exit after stdin EOF")
        if result:
            raise RuntimeError(f"Gateway exited with {result}")


class HTTPClient(StdioClient):
    def __init__(self, executable, instances, log):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        self.url = f"http://127.0.0.1:{port}/mcp"
        self.process = subprocess.Popen([str(executable), "-instance-dir", str(instances),
            "-transport", "http", "-listen", f"127.0.0.1:{port}"], stdout=log, stderr=log)
        self.session = None
        self.next_id = 0
        self.messages = queue.Queue()
        deadline = time.monotonic() + 10
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                if self.process.poll() is not None or time.monotonic() >= deadline:
                    self.process.kill()
                    self.process.wait()
                    raise RuntimeError("HTTP Gateway did not start")
                time.sleep(0.05)

    def send(self, message):
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-06-18"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        request = urllib.request.Request(self.url, data=json.dumps(message).encode(), headers=headers)
        with urllib.request.urlopen(request, timeout=45) as response:
            self.session = response.headers.get("Mcp-Session-Id", self.session)
            payload = response.read()
        if payload:
            self.messages.put(json.loads(payload))

    def close(self):
        self.process.terminate()
        try:
            result = self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise RuntimeError("HTTP Gateway ignored SIGTERM")
        if result:
            raise RuntimeError(f"HTTP Gateway exited with {result}")


def verify(client, ready):
    client.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "linux-smoke", "version": "1"}})
    client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    tools = client.request("tools/list", {})["tools"]
    expected = {"ida_" + name for name in (
        "instances", "database", "functions", "search", "symbols", "types",
        "analysis", "changes", "patch", "debugger", "scripts")}
    expected.update({
        "ida_list_instances", "ida_select_instance", "ida_database_info",
        "ida_get_function", "ida_search_functions", "ida_decompile_function",
        "ida_disassemble_function", "ida_function_callers", "ida_function_callees",
        "ida_query_xrefs", "ida_search_strings", "ida_read_memory",
    })
    assert {tool["name"] for tool in tools} == expected
    listed = client.call("instances", "ida.instances.list", {})["instances"]
    assert len(listed) == 1, listed
    instance = listed[0]["instanceId"]
    client.call("instances", "ida.instances.select", {"instanceId": instance})
    database = client.call("database", "database.info", {})
    assert database["addressBits"] == 64, database
    address = ready["functionAddress"]
    function = client.call("functions", "function.get", {"address": address})
    assert function, function
    listing = client.call("functions", "function.disassemble", {"address": address, "limit": 8})
    assert listing["items"], listing
    functions = client.call("functions", "function.search", {"name": "main", "limit": 8})
    assert functions["items"], functions
    xrefs = client.call("search", "xref.query", {"address": address,
        "direction": "outgoing", "category": "all", "includeFlow": True, "limit": 8})
    assert xrefs["items"], xrefs
    decompiler = "unavailable"
    if listed[0]["capabilities"]["decompiler"]:
        pseudocode = client.call("functions", "function.decompile", {"address": address})
        assert pseudocode["pseudocode"], pseudocode
        decompiler = "ok"
    strings = client.call("search", "string.search", {"query": "linux-mcp-smoke", "refresh": True, "limit": 8})
    assert strings["items"], strings
    segments = client.call("database", "database.segments", {"limit": 1})
    assert segments["items"], segments
    if segments.get("hasMore"):
        next_page = client.call("database", "database.segments", {"limit": 1, "cursor": segments["nextCursor"]})
        assert next_page["items"] != segments["items"]
    transport = "http" if isinstance(client, HTTPClient) else "stdio"
    print(f"mcp_{transport}=ok tools=23 database=ok functions=ok disassembly=ok xrefs=ok "
        f"decompiler={decompiler} strings=ok pagination=ok", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ida-dir", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--gateway", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--functional", action="store_true", help="Run the full shared plugin RPC contract suite")
    mode.add_argument("--crash-recovery", action="store_true", help="Verify discovery cleanup after killing the owned IDAT")
    args = parser.parse_args()
    args.ida_dir = args.ida_dir.resolve()
    args.plugin = args.plugin.resolve()
    args.gateway = args.gateway.resolve()
    # Keep socket paths under Linux's 108-byte sockaddr_un limit.
    root = Path(tempfile.mkdtemp(prefix="ida-posix-", dir="/tmp")).resolve()
    print(f"artifacts={root}", flush=True)
    user = root / "user"
    plugins = user / "plugins"
    plugins.mkdir(parents=True, mode=0o700)
    # Preserve the same user's existing EULA acceptance; never synthesize it.
    # All subsequent settings (including Python selection) stay in the test copy.
    existing_user = Path(os.environ.get("IDAUSR", str(Path.home() / ".idapro")))
    existing_registry = existing_user / "ida.reg"
    if existing_registry.is_file():
        shutil.copy2(existing_registry, user / "ida.reg")
    deployed = plugins / ("ida-agent-plugin.dylib" if sys.platform == "darwin" else "ida-agent-plugin.so")
    shutil.copy2(args.plugin, deployed)
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    assert digest(args.plugin) == digest(deployed)
    print(f"plugin_sha256={digest(deployed)}", flush=True)
    source = root / "sample.c"
    source.write_text('#include <stdio.h>\nvolatile int marker; char buffer[128];\n'
        '__attribute__((noinline)) int square(int n) { int sum=0; for(int i=0;i<n;i++) sum+=i; marker=sum; return n*n; }\n'
        'int main(int argc, char **argv) { puts("linux-mcp-smoke"); return square(argc+7)+(argv[0][0]==0); }\n')
    sample = root / "sample"
    platform_flags = [] if sys.platform == "darwin" else ["-fno-pie", "-no-pie"]
    subprocess.run(["cc", "-g", "-O0", *platform_flags, "-o", str(sample), str(source)], check=True)
    instances = root / "instances"
    ready = root / "ready.json"
    release = root / "release"
    environment = dict(os.environ, IDAUSR=str(user), IDA_AGENT_INSTANCE_DIR=str(instances),
        IDA_AGENT_TEST_READY_FILE=str(ready), IDA_AGENT_TEST_RELEASE_FILE=str(release),
        IDA_AGENT_TEST_DIAGNOSTICS="1")
    driver = Path(__file__).with_name("ida_bridge_hold.py" if args.functional else "linux_hold.py").resolve()
    with (root / "idat.stdout.log").open("w") as log, (root / "gateway.log").open("w") as gateway_log:
        from linux_test_environment import configure_linux_user
        configure_linux_user(args.ida_dir, user, environment, log)
        ida = subprocess.Popen([str(args.ida_dir / "idat"), "-A", "-c", f"-L{root / 'ida.log'}",
            f"-o{root / 'sample.i64'}", f"-S{driver}", str(sample)], cwd=args.ida_dir,
            env=environment, stdout=log, stderr=subprocess.STDOUT)
        client = None
        try:
            deadline = time.monotonic() + 60
            while not ready.exists() or not list(instances.glob("*.json")):
                if ida.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f"IDA did not become ready; inspect {root / 'ida.log'}")
                time.sleep(0.1)
            descriptor = json.loads(next(instances.glob("*.json")).read_text())
            assert descriptor["version"] == 2 and descriptor["endpoint"]["kind"] == "unix"
            assert instances.stat().st_mode & 0o777 == 0o700
            assert Path(descriptor["endpoint"]["path"]).stat().st_mode & 0o777 == 0o600
            client = StdioClient(args.gateway, instances, gateway_log)
            verify(client, json.loads(ready.read_text()))
            if args.functional:
                from linux_mcp_checks import verify_functional_mcp
                verify_functional_mcp(client, json.loads(ready.read_text()), root)
            client.close()
            client = None
            if args.functional:
                subprocess.run(["python3", str(Path(__file__).with_name("verify_plugin_rpc.py")),
                    "--instance-file", str(next(instances.glob("*.json"))),
                    "--fixture-file", str(ready)], check=True, timeout=150)
            client = HTTPClient(args.gateway, instances, gateway_log)
            verify(client, json.loads(ready.read_text()))
            if args.functional:
                verify_functional_mcp(client, json.loads(ready.read_text()), root)
            client.close()
            client = None
            if args.crash_recovery:
                ida.kill()
                assert ida.wait(timeout=10) == -signal.SIGKILL
                assert list(instances.glob("*.json")), "crash did not leave a registry to recover"
                assert list(instances.glob("*.sock")), "crash did not leave a socket to recover"
                recovery = StdioClient(args.gateway, instances, gateway_log)
                try:
                    recovery.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "linux-recovery", "version": "1"}})
                    recovery.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
                    recovered = recovery.call("instances", "ida.instances.list", {})
                    assert recovered["instances"] == [], recovered
                    assert not list(instances.iterdir()), "discovery did not remove stale registry/socket"
                finally:
                    recovery.close()
                print("crash_recovery=ok killed_owned_idat=ok stale_instance_cleanup=ok", flush=True)
        finally:
            if client is not None:
                client.process.kill()
                client.process.wait()
            release.touch()
            try:
                result = ida.wait(timeout=15)
            except subprocess.TimeoutExpired:
                ida.kill()
                ida.wait()
                raise RuntimeError("IDA did not exit after release")
        assert result == (-signal.SIGKILL if args.crash_recovery else 0), f"IDA exit code: {result}"
        assert not list(instances.iterdir()), "registry or socket remained after IDA exit"
        print(f"ida_exit={result} socket_cleanup=ok registry_cleanup=ok gateway_eof=ok", flush=True)


if __name__ == "__main__":
    main()
