"""Local SSE / WS / TLS and authenticated proxy fixtures. No external endpoints."""
import asyncio
import base64
import hashlib
import http.server
import logging
import os
from pathlib import Path
import select
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

from websockets.legacy.server import serve
from websockets.frames import OP_TEXT, OP_CONT

logging.getLogger("websockets.server").setLevel(logging.CRITICAL)
seen = []
proxied_ports = set()
proxy_authorization = "Basic " + base64.b64encode(b"user:proxy-fixture-secret").decode()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        if self.path == "/upload-stall":
            time.sleep(3)
            return
        self.request_body = self.rfile.read(int(self.headers["Content-Length"]))
        self.do_GET()

    def do_GET(self):
        seen.append((self.path, dict(self.headers)))
        if self.path in ("/badaccept", "/raw-idle", "/no-close", "/no-read"):
            self.send_response(101)
            self.send_header("Connection", "Upgrade")
            self.send_header("Upgrade", "websocket")
            accept = base64.b64encode(hashlib.sha1((self.headers["Sec-WebSocket-Key"] +
                "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            self.send_header("Sec-WebSocket-Accept", "invalid" if self.path == "/badaccept" else accept)
            self.end_headers()
            time.sleep(3)
            self.close_connection = True
            return
        if self.path == "/idle-headers":
            time.sleep(3)
        status = 401 if self.path == "/status" else 302 if self.path == "/redirect" else 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json" if self.path == "/wrong-type" else "text/event-stream; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.send_header("Transfer-Encoding", "chunked")
        if status == 302:
            self.send_header("Location", "/redirect-target")
        self.end_headers()
        self.close_connection = True
        try:
            if self.path == "/idle-body":
                self.write_chunk(b": connected\n\n")
                time.sleep(3)
            elif self.path == "/heartbeat":
                # Sleep can overshoot on shared runners. Bound the stream by
                # elapsed time so scheduler delays do not multiply 30 times.
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    self.write_chunk(b": heartbeat\r\n\r\n")
                    time.sleep(min(0.05, max(0, deadline - time.monotonic())))
            elif self.path == "/large":
                self.write_chunk(b"data: " + b"x" * 4096 + b"\n\n")
            elif self.path == "/flood":
                self.write_chunk(b"data: x\n\n" * 1500)
            elif self.path == "/byte-flood":
                self.write_chunk(b"data: 01234567890123456789\n\n" * 10)
            elif self.path == "/truncated":
                self.wfile.write(b"100\r\ndata: incomplete\n\n")
                self.wfile.flush()
                return
            elif self.path == "/post":
                self.write_chunk(b"data: " + self.request_body + b"\n\n")
            else:
                body = "\ufeff: heartbeat\r\nid: 7\r\nevent: text\r\nretry: 50\r\ndata: 中\r\ndata: second\r\n\r\ndata: end\n\n".encode()
                for byte in body:
                    self.write_chunk(bytes([byte]))
                    time.sleep(0.001)
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def write_chunk(self, value):
        self.wfile.write(f"{len(value):x}\r\n".encode() + value + b"\r\n")
        self.wfile.flush()


class Proxy(Handler):
    def authenticated(self):
        seen.append(("proxy", dict(self.headers)))
        if self.headers.get("Proxy-Authorization") == proxy_authorization:
            return True
        self.send_response(407)
        self.send_header("Proxy-Authenticate", 'Basic realm="local"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def relay(self, upstream):
        peers = [self.connection, upstream]
        while True:
            ready, _, _ = select.select(peers, [], [], 4)
            if not ready:
                return
            for peer in ready:
                data = peer.recv(65536)
                if not data:
                    return
                (upstream if peer is self.connection else self.connection).sendall(data)

    def do_CONNECT(self):
        if not self.authenticated():
            return
        host, port = self.path.rsplit(":", 1)
        port = int(port)
        assert host in ("provider.invalid", "127.0.0.1", "localhost")
        assert port in (tls.server_port, wss_port, ws_port, plain.server_port)
        proxied_ports.add(port)
        with socket.create_connection(("127.0.0.1", port), 3) as upstream:
            self.send_response(200, "Connection Established")
            self.end_headers()
            self.relay(upstream)
        self.close_connection = True

    def do_GET(self):
        if not self.authenticated():
            return
        url = urlsplit(self.path)
        assert url.hostname in ("127.0.0.1", "provider.invalid") and url.port in (plain.server_port, ws_port)
        proxied_ports.add(url.port)
        with socket.create_connection(("127.0.0.1", url.port), 3) as upstream:
            header = f"GET {url.path} HTTP/1.1\r\n" + "".join(f"{key}: {value}\r\n"
                for key, value in self.headers.items() if key.lower() not in ("proxy-authorization", "proxy-connection"))
            upstream.sendall((header + "\r\n").encode())
            self.relay(upstream)
        self.close_connection = True


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, *args):
        pass  # Intentional socket cancellation.


class StallHandshake(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        time.sleep(3)


async def websocket_handler(ws, path):
    seen.append((path, dict(ws.request_headers)))
    if path == "/fragment":
        encoded = "中text".encode()
        await ws.write_frame(False, OP_TEXT, encoded[:1])
        pong = await ws.ping(b"check")
        await asyncio.wait_for(pong, 2)
        await ws.write_frame(True, OP_CONT, encoded[1:])
        await ws.send([b"\x00\xff", b"binary"])
        await ws.send("pong-ok")
        await ws.close(1000, "done")
    elif path == "/large":
        await ws.send("x" * 4096)
    elif path == "/invalid":
        await ws.write_frame(True, OP_TEXT, b"\xff")
    elif path == "/abrupt":
        ws.transport.abort()
    elif path == "/idle":
        await ws.wait_closed()
    elif path == "/flood":
        # Exceed the former fixed startup sleep before producing queued data.
        await asyncio.sleep(0.4)
        for _ in range(1500):
            await ws.send("x")
    elif path == "/ping-upload":
        async def ping_during_upload():
            for _ in range(5):
                await asyncio.sleep(0.005)
                pong = await ws.ping(b"upload")
                await asyncio.wait_for(pong, 1)
        heartbeat = asyncio.create_task(ping_during_upload())
        message = await ws.recv()
        await heartbeat
        await ws.send(message)
        async for message in ws:
            await ws.send(message)
    else:
        async for message in ws:
            await ws.send(message)


async def run_websockets(context, ready):
    global ws_port, wss_port
    async with serve(websocket_handler, "127.0.0.1", 0, compression=None, ping_interval=None, max_size=40 * 1024 * 1024) as ws, \
            serve(websocket_handler, "127.0.0.1", 0, ssl=context, compression=None, ping_interval=None) as wss:
        ws_port, wss_port = ws.sockets[0].getsockname()[1], wss.sockets[0].getsockname()[1]
        ready.set()
        await asyncio.Future()


with tempfile.TemporaryDirectory(prefix="ida-stream-") as directory:
    if sys.platform == "darwin":
        dynamic = subprocess.check_output(["otool", "-L", sys.argv[1]], text=True)
        assert all(name not in dynamic for name in ("libcurl", "libssl", "libcrypto", "libsqlite3"))
        assert "Foundation.framework" in dynamic and "Security.framework" in dynamic
    else:
        dynamic = subprocess.check_output(["readelf", "-d", sys.argv[1]], text=True)
        assert "libcurl.so" not in dynamic and "libsqlite3.so" not in dynamic, "private libraries must be statically linked"
        assert "libssl.so.3" in dynamic and "libcrypto.so.3" in dynamic, "TLS must use system OpenSSL 3"
    root = Path(directory)
    cert, key = root / "cert.pem", root / "key.pem"
    subprocess.run([sys.argv[2], "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
        "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,DNS:provider.invalid",
        "-addext", "extendedKeyUsage=serverAuth"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    ready = threading.Event()
    threading.Thread(target=lambda: asyncio.run(run_websockets(context, ready)), daemon=True).start()
    assert ready.wait(5), "WebSocket fixture startup failed"
    plain, tls, proxy = [Server(("127.0.0.1", 0), handler) for handler in (Handler, Handler, Proxy)]
    tls.socket = context.wrap_socket(tls.socket, server_side=True)
    stall = socketserver.ThreadingTCPServer(("127.0.0.1", 0), StallHandshake)
    stall.daemon_threads = True
    servers = [plain, tls, proxy, stall]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    environment = {key: value for key, value in os.environ.items()
        if key.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "ssl_cert_file", "ssl_cert_dir")}
    endpoints = [f"http://127.0.0.1:{plain.server_port}", f"https://localhost:{tls.server_port}",
        f"ws://127.0.0.1:{ws_port}", f"wss://localhost:{wss_port}", str(proxy.server_port),
        f"127.0.0.1:{stall.server_address[1]}"]
    try:
        subprocess.run([sys.argv[1], "normal", *endpoints], env=environment, check=True, timeout=45)
        subprocess.run([sys.argv[1], "trusted", *endpoints], env=dict(environment, SSL_CERT_FILE=str(cert)), check=True, timeout=15)
        if sys.platform != "darwin":
            subprocess.run([sys.argv[1], "system-proxy", *endpoints], env=dict(environment,
                http_proxy=f"http://user:proxy-fixture-secret@127.0.0.1:{proxy.server_port}",
                all_proxy=f"http://user:proxy-fixture-secret@127.0.0.1:{proxy.server_port}"), check=True, timeout=15)
        assert all("Proxy-Authorization" not in headers for path, headers in seen if path != "proxy")
        assert proxied_ports == {plain.server_port, tls.server_port, ws_port, wss_port}, "a protocol bypassed its proxy"
        assert not any(path == "/redirect-target" for path, _ in seen)
        print("Linux SSE / WS / WSS / proxy / TLS / streaming limits: passed")
    except subprocess.CalledProcessError:
        print("fixture requests:", [path for path, _ in seen], flush=True)
        raise
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
