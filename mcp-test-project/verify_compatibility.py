"""No-IDA MCP interoperability checks; no model API or client credentials used."""
import argparse
import json
from pathlib import Path
import queue
import socket
import subprocess
import tempfile
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from verify_stdio import EXPECTED_TOOLS

VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")


class Stdio:
    def __init__(self, gateway, directory):
        self.process = subprocess.Popen(
            [str(gateway), "-instance-dir", directory, "-diagnostics"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8",
        )
        self.responses = queue.Queue()
        self.stderr = []
        self.reader = threading.Thread(target=self.read_stdout, daemon=True)
        self.logger = threading.Thread(target=self.read_stderr, daemon=True)
        self.reader.start()
        self.logger.start()

    def read_stdout(self):
        for line in self.process.stdout:
            try:
                self.responses.put(json.loads(line))
            except ValueError as error:
                self.responses.put(error)
        self.responses.put(EOFError("Gateway stdout closed"))

    def read_stderr(self):
        self.stderr.extend(self.process.stderr)

    def send(self, message):
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()
        if "id" not in message:
            return None
        deadline = time.monotonic() + 8
        while True:
            response = self.responses.get(timeout=max(0.01, deadline - time.monotonic()))
            if isinstance(response, Exception):
                raise response
            if response.get("method"):
                raise AssertionError(f"Unexpected notification: {response['method']}")
            assert response.get("id") == message["id"], response
            return response

    def close(self, check=True):
        try:
            if self.process.poll() is None:
                self.process.stdin.close()
                code = self.process.wait(timeout=5)
                if check:
                    assert code == 0, f"EOF exit code {code}"
            self.logger.join(timeout=2)
            if check:
                for line in self.stderr:
                    entry = json.loads(line)
                    assert set(entry) <= {"tool", "method", "stage", "durationMs", "code", "retries", "phaseMs"}, entry
                    phases = entry.get("phaseMs", {})
                    assert set(phases) <= {"execute", "admission", "resolve", "discovery", "connect", "handshake", "rpc"}, entry
                    assert all(isinstance(value, (int, float)) and value >= 0 for value in phases.values()), entry
                assert "SECRET-input" not in "".join(self.stderr)
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=5)


class HTTP:
    def __init__(self, gateway, directory, gateway_args=None, stderr=None):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{port}/mcp"
        self.session = None
        self.version = None
        prefix = gateway_args if gateway_args is not None else ["-instance-dir", directory]
        self.process = subprocess.Popen(
            [str(gateway), *prefix, "-transport", "http", "-listen", f"127.0.0.1:{port}"],
            stdout=subprocess.DEVNULL, stderr=stderr or subprocess.PIPE, text=True, encoding="utf-8",
        )
        self.stderr = []
        self.logger = threading.Thread(target=lambda: self.stderr.extend(self.process.stderr or []), daemon=True)
        self.logger.start()
        deadline = time.monotonic() + 8
        while True:
            if self.process.poll() is not None:
                raise RuntimeError("HTTP Gateway exited on startup")
            try:
                with urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as response:
                    assert json.load(response)["status"] == "ok"
                break
            except URLError:
                if time.monotonic() > deadline:
                    self.close(False)
                    raise TimeoutError("HTTP Gateway startup")
                time.sleep(0.05)

    def send(self, message):
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        if self.version:
            headers["MCP-Protocol-Version"] = self.version
        request = Request(self.endpoint, data=json.dumps(message).encode(), headers=headers)
        with urlopen(request, timeout=8) as response:
            self.session = response.headers.get("Mcp-Session-Id", self.session)
            data = response.read()
            return json.loads(data) if data else None

    def close(self, check=True):
        try:
            if self.session and self.process.poll() is None:
                headers = {"Mcp-Session-Id": self.session, "MCP-Protocol-Version": self.version}
                try:
                    with urlopen(Request(self.endpoint, method="DELETE", headers=headers), timeout=2):
                        pass
                except HTTPError as error:
                    if check:
                        raise error
        finally:
            if self.process.poll() is None:
                self.process.terminate()
                self.process.wait(timeout=5)
            self.logger.join(timeout=2)


def check_result(response, error=None):
    assert "error" not in response, response
    result = response["result"]
    structured = result["structuredContent"]
    text = result["content"]
    assert len(text) == 1 and text[0]["type"] == "text", text
    assert json.loads(text[0]["text"]) == structured, result
    assert bool(result.get("isError")) == (error is not None), result
    if error:
        assert structured["code"] == error and structured["hint"], structured
        assert "SECRET-input" not in json.dumps(structured), structured
    return structured


def verify(client, version):
    next_id = 0

    def request(method, params):
        nonlocal next_id
        next_id += 1
        return client.send({"jsonrpc": "2.0", "id": next_id, "method": method, "params": params})

    initialized = request("initialize", {"protocolVersion": version, "capabilities": {},
        "clientInfo": {"name": "ida-compatibility-verifier", "version": "1"}})
    assert "error" not in initialized, initialized
    negotiated = initialized["result"]["protocolVersion"]
    assert negotiated in VERSIONS, negotiated
    client.version = negotiated
    assert initialized["result"]["capabilities"]["tools"].get("listChanged", False) is False
    # Fixed catalog works even for clients listing before the initialized notification.
    tools = request("tools/list", {})["result"]["tools"]
    assert len(tools) == 23 and {tool["name"] for tool in tools} == EXPECTED_TOOLS
    for tool in tools:
        schema = tool["inputSchema"]
        assert schema["type"] == "object" and schema["additionalProperties"] is False
        assert not ({"oneOf", "anyOf", "allOf", "not"} & schema.keys()), tool
        assert "." not in tool["name"]
    client.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def call(tool, arguments, error=None):
        return check_result(request("tools/call", {"name": tool, "arguments": arguments}), error)

    assert call("ida_list_instances", {})["instances"] == []
    assert call("ida_instances", {"action": "call", "method": "ida.instances.list", "arguments": {}})["result"]["instances"] == []
    cases = [
        ("ida_get_function", {}, "arguments.address", "required"),
        ("ida_get_function", {"address": 123}, "arguments.address", "type"),
        ("ida_get_function", {"address": "0x401000", "instanceId": None}, "arguments.instanceId", "type"),
        ("ida_search_functions", {"name": "main", "limit": "SECRET-input"}, "arguments.limit", "type"),
        ("ida_get_function", {"address": "0x401000", "extra": "SECRET-input"}, "arguments.extra", "additionalProperties"),
        ("ida_functions", {"action": "call", "method": "function.get", "arguments": "SECRET-input"}, "arguments.arguments", "type"),
        ("ida_functions", {"action": "wrong"}, "arguments.action", "enum"),
    ]
    for tool, args, field, rule in cases:
        error = call(tool, args, "INVALID_ARGUMENT")
        assert any(issue["field"] == field and issue["rule"] == rule for issue in error["issues"]), error
    call("ida_functions", {"action": "call", "method": "function.get"}, "INVALID_ARGUMENT")
    call("ida_functions", {"action": "describe", "method": "function.does_not_exist"}, "NOT_FOUND")
    call("ida_database_info", {}, "NOT_FOUND")
    unknown = request("tools/call", {"name": "ida_unknown_tool", "arguments": {}})
    assert "error" in unknown, "Unknown tool must remain a protocol error"
    # A valid call after the errors confirms the session is usable.
    assert call("ida_list_instances", {})["instances"] == []
    assert call("ida_functions", {"action": "describe", "method": "function.get"})["description"]["method"] == "function.get"
    print(f"{type(client).__name__}: requested={version} negotiated={negotiated} catalog=23 recovery/text+structured=passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gateway", type=Path)
    parser.add_argument("--http", action="store_true", help="Also verify loopback Streamable HTTP")
    args = parser.parse_args()
    gateway = args.gateway.resolve()
    if not gateway.is_file():
        parser.error(f"Gateway does not exist: {gateway}")
    with tempfile.TemporaryDirectory(prefix="ida-compatibility-") as directory:
        for version in VERSIONS:
            client = Stdio(gateway, directory)
            passed = False
            try:
                verify(client, version)
                passed = True
            finally:
                client.close(passed)
        if args.http:
            for version in VERSIONS:
                client = HTTP(gateway, directory)
                passed = False
                try:
                    verify(client, version)
                    passed = True
                finally:
                    client.close(passed)
    print("No-IDA protocol/SDK compatibility checks passed; no real Agent/model behavior was tested.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
