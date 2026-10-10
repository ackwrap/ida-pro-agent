"""SIMULATED IDA: real registry/Unix RPC boundary, shared protocol fixtures.

Never implements MCP or IDA APIs. Only the read methods needed by client tests
are supported. Windows uses the live-IDA entry point instead of this fixture.
"""
import copy
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
A = "11111111-1111-4111-8111-111111111111"
B = "22222222-2222-4222-8222-222222222222"
BUSY, TIMEOUT, SLOW = "0x401100", "0x401200", "0x401400"
FIXTURES = {
    "instance.info": "instance-info", "database.info": "database-info",
    "function.get": "function-get", "function.search": "function-search",
    "function.decompile": "function-decompile",
    "function.disassemble": "function-disassemble",
    "function.callers": "function-callers", "function.callees": "function-callees",
    "xref.query": "xref-query", "string.search": "string-search",
    "memory.read": "memory-read", "database.save": "database-save",
}


def read_exact(connection, length):
    data = bytearray()
    while len(data) < length:
        part = connection.recv(length - len(data))
        if not part:
            raise EOFError()
        data.extend(part)
    return bytes(data)


def read_frame(connection):
    header = read_exact(connection, 9)
    assert header[:5] == b"IMCP\x01", header
    length = struct.unpack(">I", header[5:])[0]
    assert 0 < length <= 1 << 20
    return json.loads(read_exact(connection, length))


def write_frame(connection, data):
    payload = json.dumps(data).encode()
    connection.sendall(b"IMCR\x01" + struct.pack(">I", len(payload)) + payload)


class MockIDA:
    def __init__(self):
        if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
            raise RuntimeError("SIMULATED Unix IDA requires Linux/macOS; use live IDA on Windows")
        # Short, private path required by the production Unix transport.
        self.temp = tempfile.TemporaryDirectory(prefix="ida-client-", dir="/tmp")
        # macOS /tmp is a symlink; production's private-directory walker rejects it.
        self.directory = Path(self.temp.name).resolve()
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.listeners, self.threads, self.events, self.errors = [], [], [], []
        self.active, self.busy = {}, {}
        self.delay = 0.4
        self.gate = None
        self.fixtures = {method: json.loads((ROOT / "protocol/testdata/valid" /
                         f"response-{name}.json").read_text())["result"]
                         for method, name in FIXTURES.items()}

    def __enter__(self):
        for instance in (A, B):
            name = f"ida-agent-{os.getpid()}-{instance[:8]}.sock"
            endpoint = self.directory / name
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(str(endpoint))
            endpoint.chmod(0o600)
            listener.listen(64)
            listener.settimeout(0.1)
            self.listeners.append(listener)
            descriptor = {"version": 2, "protocol_version": "ida-rpc/1",
                "instance_id": instance, "pid": os.getpid(), "ida_version": "9.4-simulated",
                "database": self.marker(instance), "input_file": "simulated.bin",
                "processor": "metapc", "bitness": 64, "arch": "x86_64",
                "started_at": int(time.time() * 1000),
                "capabilities": {"decompiler": True, "debugger": False, "ui": False, "address_bits": 64},
                "endpoint": {"kind": "unix", "path": str(endpoint)}}
            registry = self.directory / f"{os.getpid()}-{instance[:8]}.json"
            registry.write_text(json.dumps(descriptor))
            registry.chmod(0o600)
            thread = threading.Thread(target=self.accept, args=(listener, instance), daemon=True)
            thread.start()
            self.threads.append(thread)
        return self

    @staticmethod
    def marker(instance):
        return "SIMULATED-A.i64" if instance == A else "SIMULATED-B.i64"

    def accept(self, listener, instance):
        while not self.stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            thread = threading.Thread(target=self.serve, args=(connection, instance), daemon=True)
            with self.lock:
                self.threads.append(thread)
            thread.start()

    def serve(self, connection, instance):
        with connection:
            connection.settimeout(25)
            try:
                hello = read_frame(connection)
                assert hello == {"method": "hello", "params": {"protocol": 1, "client": "ida-mcp"}}
                write_frame(connection, {"product": "ida-agent-plugin", "protocol": 1,
                            "instance_id": instance, "pid": os.getpid()})
                try:
                    request = read_frame(connection)
                except EOFError:  # hello-only probes are legitimate.
                    return
                assert request["sessionId"] == instance
                method, params = request["method"], request["params"]
                response = {key: request[key] for key in ("protocolVersion", "requestId", "sessionId")}
                if method == "instance.info":
                    result = copy.deepcopy(self.fixtures[method])
                    result.update(instance_id=instance, pid=os.getpid(), database=self.marker(instance))
                    response["result"] = result
                else:
                    response.update(self.business(instance, method, params))
                write_frame(connection, response)
            except (BrokenPipeError, ConnectionResetError, EOFError, socket.timeout):
                pass  # Client deadline/cancellation may close an accepted RPC.
            except Exception as error:
                with self.lock:
                    self.errors.append(repr(error))

    def business(self, instance, method, params):
        key = (instance, method)
        address = params.get("address")
        with self.lock:
            self.active[instance] = self.active.get(instance, 0) + 1
            self.events.append({"phase": "start", "instance": instance, "method": method,
                                "address": address, "time": time.monotonic(),
                                "active": self.active[instance]})
        try:
            if method == "function.get" and address == BUSY:
                with self.lock:
                    attempt = self.busy.get(key, 0) + 1
                    self.busy[key] = attempt
                if attempt <= 2:
                    return self.failure("IDA_BUSY", True)
            if address == TIMEOUT or method == "database.save":
                return self.failure("TIMEOUT", True)
            if address == SLOW:
                if self.gate is not None:
                    self.gate.wait(timeout=20)
                else:
                    self.stop.wait(self.delay)
            if method not in self.fixtures:
                return self.failure("CAPABILITY_UNAVAILABLE", False)
            result = copy.deepcopy(self.fixtures[method])
            if method == "database.info":
                result["database"] = self.marker(instance)
            if method == "function.get":
                result["name"] = self.marker(instance)
                result["entryAddress"] = address
                result["addressRange"] = {"start": address, "end": hex(int(address, 16) + 128)}
            if method == "memory.read":
                result["address"] = address
            if method == "xref.query":
                field = "to" if params["direction"] == "incoming" else "from"
                for item in result["items"]:
                    item[field] = address
            if method in ("function.search", "string.search", "xref.query"):
                result.update(nextCursor=None, hasMore=False)
            return {"result": result}
        finally:
            with self.lock:
                self.active[instance] -= 1
                self.events.append({"phase": "finish", "instance": instance, "method": method,
                                    "address": address, "time": time.monotonic(),
                                    "active": self.active[instance]})

    @staticmethod
    def failure(code, retryable):
        return {"error": {"code": code, "message": "SIMULATED fault", "retryable": retryable}}

    def snapshot(self):
        with self.lock:
            return {"backend": "simulated_ida_unix_rpc", "events": list(self.events),
                    "errors": list(self.errors)}

    def __exit__(self, *_):
        self.stop.set()
        if self.gate is not None:
            self.gate.set()
        for listener in self.listeners:
            listener.close()
        for thread in list(self.threads):
            thread.join(timeout=1)
        self.temp.cleanup()
