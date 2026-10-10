"""Loopback-only HTTP/TLS/proxy fixtures; all credentials and CA files are synthetic."""
import base64
import http.server
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

events = []
proxy_auth = "Basic " + base64.b64encode(b"proxy-user:test-secret-proxy").decode()
models = b'{"data":[{"id":"local-model"}]}'


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, code, body, headers=None):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def do_GET(self):
        events.append((self.path, dict(self.headers)))
        if self.path in ("/stall-headers", "/cancel", "/shutdown"):
            time.sleep(2)
        if self.path == "/redirect":
            self.reply(302, b"", {"Location": "/redirect-target"})
        elif self.path == "/status":
            self.reply(401, b"denied")
        elif self.path == "/v1/models":
            self.reply(200, models)
        elif self.path == "/large":
            self.reply(200, b"x" * 16384)
        elif self.path in ("/stall-body", "/trickle"):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", "24")
            self.end_headers()
            if self.path == "/stall-body":
                time.sleep(2)
            try:
                for _ in range(24):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.1)
            except (BrokenPipeError, ConnectionResetError):
                pass
        else:
            self.reply(200, b"ok")

    def do_POST(self):
        if self.path == "/upload-stall":
            time.sleep(2)
            self.close_connection = True
            return
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.reply(200, body)


class Proxy(Handler):
    def authenticated(self):
        events.append(("proxy", dict(self.headers)))
        if self.headers.get("Proxy-Authorization") == proxy_auth:
            return True
        self.reply(407, b"", {"Proxy-Authenticate": 'Basic realm="local-test"'})
        return False

    def do_GET(self):
        if self.authenticated():
            assert self.path in ("http://provider.invalid/v1/models",
                f"http://127.0.0.2:{plain.server_port}/v1/models")
            self.reply(200, models)

    def do_CONNECT(self):
        if not self.authenticated():
            return
        targets = {f"provider.invalid:{tls.server_port}": tls.server_port, "provider.invalid:80": plain.server_port}
        assert self.path in targets, "proxy tunnel escaped the fixture"
        with socket.create_connection(("127.0.0.1", targets[self.path]), timeout=3) as upstream:
            self.send_response(200, "Connection Established")
            self.end_headers()
            peers = [self.connection, upstream]
            while True:
                ready, _, _ = select.select(peers, [], [], 3)
                if not ready:
                    break
                for peer in ready:
                    try:
                        data = peer.recv(65536)
                        if not data:
                            return
                        (upstream if peer is self.connection else self.connection).sendall(data)
                    except (OSError, ssl.SSLError):
                        return
        self.close_connection = True


class StallTls(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        time.sleep(2)


class QuietServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, *args):
        pass  # Tests deliberately cancel established sockets.


with tempfile.TemporaryDirectory(prefix="ida-http-") as directory:
    root = Path(directory)
    certificate, key = root / "cert.pem", root / "key.pem"
    subprocess.run([sys.argv[2], "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(certificate), "-days", "1", "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,DNS:provider.invalid", "-addext", "extendedKeyUsage=serverAuth"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    plain = QuietServer(("127.0.0.1", 0), Handler)
    tls = QuietServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    tls.socket = context.wrap_socket(tls.socket, server_side=True)
    proxy = QuietServer(("127.0.0.1", 0), Proxy)
    stall = socketserver.ThreadingTCPServer(("127.0.0.1", 0), StallTls)
    stall.daemon_threads = True
    servers = [plain, tls, proxy, stall]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    environment = {key: value for key, value in os.environ.items()
        if key.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "ssl_cert_file", "ssl_cert_dir")}
    endpoints = [f"http://127.0.0.1:{plain.server_port}", f"https://localhost:{tls.server_port}",
        str(proxy.server_port), f"https://127.0.0.1:{stall.server_address[1]}"]
    try:
        subprocess.run([sys.argv[1], "normal", *endpoints], env=environment, check=True, timeout=25)
        subprocess.run([sys.argv[1], "trusted-tls", *endpoints],
            env=dict(environment, SSL_CERT_FILE=str(certificate)), check=True, timeout=10)
        if sys.platform != "darwin":
            subprocess.run([sys.argv[1], "system-proxy", *endpoints], env=dict(environment,
                http_proxy=f"http://proxy-user:test-secret-proxy@127.0.0.1:{proxy.server_port}"), check=True, timeout=10)
        assert not any(path == "/redirect-target" for path, _ in events), "redirect forwarded a request"
        assert all("Proxy-Authorization" not in headers for path, headers in events if path != "proxy"), "proxy credential reached origin"
        assert any(path == "/cancel" for path, _ in events), "cancel test never reached the server"
        assert any(path == "/shutdown" for path, _ in events), "shutdown test never reached the server"
        print("linux HTTP/TLS/proxy/discovery/limits/timeouts/cancellation: passed")
    except subprocess.CalledProcessError:
        print("fixture requests:", [(path, "Proxy-Authorization" in headers) for path, headers in events], flush=True)
        raise
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
