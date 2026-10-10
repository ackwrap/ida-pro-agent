import ctypes
import json
import os
import re
import socket
import struct
import sys
from ctypes import wintypes


MAX_PAYLOAD = 1 << 20
REQUEST_HEADER = struct.Struct(">4sBI")
RESPONSE_HEADER = struct.Struct(">4sBI")
ADDRESS_PATTERN = re.compile(r"^0x[0-9a-f]{1,16}$")


def fail(message):
    raise AssertionError(message)


def require(condition, message):
    if not condition:
        fail(message)


def require_keys(value, keys, context, exact=False):
    require(isinstance(value, dict), "%s must be an object" % context)
    missing = set(keys) - set(value)
    require(not missing, "%s is missing fields: %s" % (context, sorted(missing)))
    if exact:
        extra = set(value) - set(keys)
        require(not extra, "%s has unexpected fields: %s" % (context, sorted(extra)))


def require_address(value, context):
    require(isinstance(value, str) and ADDRESS_PATTERN.fullmatch(value) is not None,
            "%s must be a canonical lowercase address" % context)


def require_page(result, context, cursor="nextCursor"):
    require_keys(result, {"items", cursor, "hasMore"}, context, exact=True)
    require(isinstance(result["items"], list), "%s.items must be an array" % context)
    require(isinstance(result["hasMore"], bool), "%s.hasMore must be boolean" % context)


def load_json(path, context):
    try:
        with open(path, "r", encoding="utf-8") as source:
            value = json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AssertionError("failed to read %s: %s" % (context, error)) from error
    require(isinstance(value, dict), "%s must contain a JSON object" % context)
    return value


class PipeApi:
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    ERROR_PIPE_BUSY = 231
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    def __init__(self):
        require(sys.platform == "win32", "Named Pipe verifier requires Windows")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel32.CreateFileW.argtypes = (
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
        self.kernel32.CreateFileW.restype = wintypes.HANDLE
        self.kernel32.WaitNamedPipeW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD)
        self.kernel32.WaitNamedPipeW.restype = wintypes.BOOL
        self.kernel32.ReadFile.argtypes = (
            wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID)
        self.kernel32.ReadFile.restype = wintypes.BOOL
        self.kernel32.WriteFile.argtypes = (
            wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID)
        self.kernel32.WriteFile.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        self.kernel32.CloseHandle.restype = wintypes.BOOL

    def connect(self, pipe_name):
        if not self.kernel32.WaitNamedPipeW(pipe_name, 30000):
            raise ctypes.WinError(ctypes.get_last_error())
        handle = self.kernel32.CreateFileW(
            pipe_name,
            self.GENERIC_READ | self.GENERIC_WRITE,
            0,
            None,
            self.OPEN_EXISTING,
            0,
            None,
        )
        if handle == self.INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def close(self, handle):
        if handle is not None:
            self.kernel32.CloseHandle(handle)

    def write_all(self, handle, data):
        offset = 0
        while offset < len(data):
            chunk = data[offset:]
            buffer = ctypes.create_string_buffer(chunk)
            written = wintypes.DWORD()
            if not self.kernel32.WriteFile(handle, buffer, len(chunk), ctypes.byref(written), None):
                raise ctypes.WinError(ctypes.get_last_error())
            require(written.value > 0, "Named Pipe write made no progress")
            offset += written.value

    def read_exact(self, handle, size):
        output = bytearray()
        while len(output) < size:
            remaining = size - len(output)
            buffer = ctypes.create_string_buffer(remaining)
            received = wintypes.DWORD()
            if not self.kernel32.ReadFile(handle, buffer, remaining, ctypes.byref(received), None):
                raise ctypes.WinError(ctypes.get_last_error())
            require(received.value > 0, "Named Pipe closed before the frame was complete")
            output.extend(buffer.raw[:received.value])
        return bytes(output)


class UnixApi:
    """Unix test transport; verify the same kernel peer identity as the Gateway."""
    def __init__(self, pid):
        self.pid = pid

    def connect(self, path):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(35)
            connection.connect(path)
            if sys.platform == "darwin":
                # Darwin sys/un.h: SOL_LOCAL=0, LOCAL_PEERPID=2. getpeereid
                # returns the effective UID/GID without interpreting xucred.
                pid = connection.getsockopt(0, 2)
                uid, gid = ctypes.c_uint(), ctypes.c_uint()
                libc = ctypes.CDLL(None, use_errno=True)
                require(libc.getpeereid(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)) == 0,
                        "Unix peer credentials unavailable")
                uid = uid.value
            else:
                pid, uid, _ = struct.unpack("3i", connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            require(pid == self.pid and uid == os.getuid(), "Unix peer identity mismatch")
            return connection
        except BaseException:
            connection.close()
            raise

    def close(self, connection):
        if connection is not None:
            connection.close()

    def write_all(self, connection, data):
        connection.sendall(data)

    def read_exact(self, connection, size):
        output = bytearray()
        while len(output) < size:
            chunk = connection.recv(size - len(output))
            require(chunk, "Unix socket closed before the frame was complete")
            output.extend(chunk)
        return bytes(output)


class RpcVerifier:
    def __init__(self, descriptor):
        require_keys(descriptor, {"instance_id", "pid"}, "registry descriptor")
        require(isinstance(descriptor["instance_id"], str) and descriptor["instance_id"],
                "registry instance_id is invalid")
        require(isinstance(descriptor["pid"], int) and descriptor["pid"] > 0,
                "registry pid is invalid")
        self.instance_id = descriptor["instance_id"]
        self.pid = descriptor["pid"]
        if descriptor.get("version") == 2:
            endpoint = descriptor.get("endpoint", {})
            require(endpoint.get("kind") == "unix" and os.path.isabs(endpoint.get("path", "")),
                    "registry Unix locator is invalid")
            require(sys.platform in ("linux", "darwin"), "Unix verifier requires Linux or macOS")
            self.pipe_name = endpoint["path"]
            self.api = UnixApi(self.pid)
        else:
            require(isinstance(descriptor.get("pipe"), str) and descriptor["pipe"].startswith("\\\\.\\pipe\\"),
                    "registry pipe locator is invalid")
            self.pipe_name = descriptor["pipe"]
            self.api = PipeApi()
        capabilities = descriptor.get("capabilities", {})
        require(isinstance(capabilities, dict), "registry capabilities are invalid")
        self.debugger_available = capabilities.get("debugger") is True
        self.decompiler_available = capabilities.get("decompiler") is True
        self.sequence = 0
        self.coverage = set()

    def _send_json(self, handle, value):
        payload = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        require(0 < len(payload) <= MAX_PAYLOAD, "request payload size is invalid")
        self.api.write_all(handle, REQUEST_HEADER.pack(b"IMCP", 1, len(payload)) + payload)

    def _receive_json(self, handle, context):
        magic, version, size = RESPONSE_HEADER.unpack(self.api.read_exact(handle, RESPONSE_HEADER.size))
        require(magic == b"IMCR", "%s response framing magic mismatch" % context)
        require(version == 1, "%s response framing version mismatch" % context)
        require(0 < size <= MAX_PAYLOAD, "%s response payload size is invalid" % context)
        payload = self.api.read_exact(handle, size)
        try:
            result = json.loads(payload.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise AssertionError("%s returned invalid JSON: %s" % (context, error)) from error
        require(isinstance(result, dict), "%s response must be an object" % context)
        return result

    def call_response(self, method, params):
        self.sequence += 1
        request_id = "verify-%04d" % self.sequence
        handle = None
        try:
            handle = self.api.connect(self.pipe_name)
            self._send_json(handle, {"method": "hello", "params": {
                "protocol": 1, "client": "ida-mcp"}})
            hello = self._receive_json(handle, "%s hello" % method)
            require_keys(hello, {"product", "protocol", "instance_id", "pid"},
                         "%s hello" % method, exact=True)
            require(hello == {"product": "ida-agent-plugin", "protocol": 1,
                              "instance_id": self.instance_id, "pid": self.pid},
                    "%s hello identity does not match the registry" % method)
            self._send_json(handle, {
                "protocolVersion": "ida-rpc/1",
                "requestId": request_id,
                "sessionId": self.instance_id,
                "method": method,
                "params": params,
                "timeoutMs": 30000,
            })
            response = self._receive_json(handle, method)
        finally:
            self.api.close(handle)
        require_keys(response, {"protocolVersion", "requestId", "sessionId"}, method)
        require(response["protocolVersion"] == "ida-rpc/1", "%s protocolVersion mismatch" % method)
        require(response["requestId"] == request_id, "%s requestId correlation mismatch" % method)
        require(response["sessionId"] == self.instance_id, "%s sessionId correlation mismatch" % method)
        has_result = "result" in response
        has_error = "error" in response
        require(has_result != has_error, "%s must return exactly one of result or error" % method)
        require(set(response) == {"protocolVersion", "requestId", "sessionId",
                                  "result" if has_result else "error"},
                "%s response contains unexpected envelope fields" % method)
        self.coverage.add(method)
        if has_result:
            require(isinstance(response["result"], dict), "%s result must be an object" % method)
        else:
            require_keys(response["error"], {"code", "message", "retryable"},
                         "%s error" % method, exact=True)
            require(isinstance(response["error"]["message"], str) and response["error"]["message"],
                    "%s error message must be non-empty" % method)
            require(isinstance(response["error"]["retryable"], bool),
                    "%s error retryable must be boolean" % method)
        return response

    def call(self, method, params):
        response = self.call_response(method, params)
        if "error" in response:
            fail("%s unexpectedly failed with %s: %s" % (
                method, response["error"]["code"], response["error"]["message"]))
        return response["result"]

    def call_error(self, method, params, expected_codes):
        response = self.call_response(method, params)
        require("error" in response, "%s unexpectedly succeeded" % method)
        error = response["error"]
        require(error["code"] in expected_codes,
                "%s returned %s, expected one of %s" % (method, error["code"], sorted(expected_codes)))
        return error


def matching_item(items, field, value):
    return next((item for item in items if isinstance(item, dict) and item.get(field) == value), None)
