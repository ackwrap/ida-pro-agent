#!/usr/bin/env python3
"""Real IDA Qt panel smoke test with an isolated user and a loopback AI provider."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time


class Provider(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        body = json.dumps({"data": [{"id": "linux-panel-test"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def event(self, delta, finish=None):
        body = {"choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
        self.wfile.write(("data: " + json.dumps(body, ensure_ascii=False) + "\n\n").encode())
        self.wfile.flush()

    def do_POST(self):
        try:
            assert self.path == "/v1/chat/completions", self.path
            size = int(self.headers["Content-Length"])
            assert 0 < size < 2 * 1024 * 1024
            request = json.loads(self.rfile.read(size))
            self.server.requests.append(request)
            assert request["stream"] and request["model"] == "linux-panel-test"
            messages = request["messages"]
            user = next(m for m in reversed(messages) if m["role"] == "user")
            prompt = str(user["content"])
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            if "cancel-check" in prompt:
                self.event({"content": "Waiting for cancellation"})
                for _ in range(100):
                    time.sleep(0.1)
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                return
            if "panel-check" in prompt and "ida_file_mutate" not in {t["function"]["name"] for t in request["tools"]}:
                self.event({"tool_calls": [{"index": 0, "id": "panel-discover", "type": "function", "function": {
                    "name": "ida_tool_search", "arguments": json.dumps({"query": "ida_file_mutate", "limit": 1})}}]}, "tool_calls")
            elif "panel-check" in prompt and not any(m.get("tool_call_id") == "panel-file" for m in messages):
                advertised = {t["function"]["name"] for t in request["tools"]}
                assert {"ida_database_info", "ida_file_mutate"} <= advertised
                calls = [{"index": index, "id": ident, "type": "function", "function": {
                    "name": name, "arguments": json.dumps(arguments)}} for index, (ident, name, arguments) in enumerate([
                        ("panel-db", "ida_database_info", {}),
                        ("panel-file", "ida_file_mutate", {"path": "panel-note.txt", "mode": "create_file", "content": "Linux panel tool OK\n"}),
                    ])]
                self.event({"tool_calls": calls}, "tool_calls")
            else:
                if "panel-check" in prompt:
                    replies = [m for m in messages if m["role"] == "tool"]
                    assert {m["tool_call_id"] for m in replies} >= {"panel-db", "panel-file"}
                    assert "addressBits" in str(replies)
                    self.server.tools_ok = True
                for chunk in ("Linux ", "面板已连通", " — streamed reply OK"):
                    self.event({"content": chunk})
                    time.sleep(0.08)
                self.event({}, "stop")
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as error:
            self.server.errors.append(repr(error))


def private_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ida-dir", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    args = parser.parse_args()
    args.ida_dir = args.ida_dir.resolve()
    root = Path(tempfile.mkdtemp(prefix="ida-panel-", dir="/tmp")).resolve()
    print(f"artifacts={root}", flush=True)
    user = root / "user"
    plugins = user / "plugins"
    plugins.mkdir(parents=True, mode=0o700)
    registry = Path(os.environ.get("IDAUSR", str(Path.home() / ".idapro"))) / "ida.reg"
    if registry.is_file():
        shutil.copy2(registry, user / "ida.reg")
    deployed = plugins / ("ida-agent-plugin.dylib" if sys.platform == "darwin" else "ida-agent-plugin.so")
    shutil.copy2(args.plugin, deployed)
    assert hashlib.sha256(args.plugin.read_bytes()).digest() == hashlib.sha256(deployed.read_bytes()).digest()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    server.requests, server.errors, server.tools_ok = [], [], False
    threading.Thread(target=server.serve_forever, daemon=True).start()
    config = root / "config"
    state = root / "state"
    for directory in (config, state):
        directory.mkdir(mode=0o700)
        (directory / "ida-agent").mkdir(mode=0o700)
    settings = config / "ida-agent/ai"
    private_json(settings / "providers.json", {"version": 1, "activeProfileId": "custom-1", "nextCustomId": 2,
        "profiles": [{"id": "custom-1", "builtIn": False, "settings": {
            "displayName": "Linux Panel Test", "protocol": "openai", "openAiApiMode": "chatCompletions",
            "baseUrl": f"http://127.0.0.1:{server.server_port}/v1", "model": "linux-panel-test", "apiKey": "local-test-only"},
            "models": [{"id": "linux-panel-test", "enabled": True, "capabilities": "tools", "contextLength": 128000,
                "maxOutputTokens": 4096, "reasoningEffort": "default", "reasoningSummary": "visible"}],
            "headers": [], "proxy": {"mode": "direct", "host": "", "port": 0, "username": "", "password": "", "bypassLocal": True}}]})
    private_json(settings / "settings.json", {"version": 2, "openChatOnDatabaseOpen": True,
        "focusInputOnAutoOpen": False, "loadChatHistory": True, "saveChatHistory": True,
        "debugLogging": False, "networkLogging": False})
    source = root / "sample.c"
    source.write_text('int main(void) { return 42; }\n')
    sample = root / "sample"
    subprocess.run(["cc", "-g", "-O0", "-o", str(sample), str(source)], check=True)
    environment = dict(os.environ, IDAUSR=str(user), XDG_CONFIG_HOME=str(config), XDG_STATE_HOME=str(state),
        IDA_AGENT_INSTANCE_DIR=str(root / "instances"), IDA_AGENT_PANEL_TEST_ROOT=str(root),
        IDA_AGENT_TEST_DIAGNOSTICS="1")
    driver = Path(__file__).with_name("linux_panel_driver.py").resolve()
    try:
        with (root / "python.log").open("w") as log:
            from linux_test_environment import configure_linux_user
            configure_linux_user(args.ida_dir, user, environment, log)
        for phase in ("exercise", "restore"):
            environment["IDA_AGENT_PANEL_TEST_PHASE"] = phase
            command = [str(args.ida_dir / "ida"), "-A", f"-L{root / (phase + '.ida.log')}", f"-S{driver}"]
            command += (["-c", f"-o{root / 'sample.i64'}", str(sample)] if phase == "exercise" else [str(root / "sample.i64")])
            with (root / (phase + ".stdout.log")).open("w") as log:
                process = subprocess.Popen(command, cwd=args.ida_dir, env=environment, stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 100
                    while process.poll() is None:
                        report_path = root / (phase + ".json")
                        if report_path.exists():
                            report = json.loads(report_path.read_text())
                            if not report["ok"]:
                                raise RuntimeError(f"Panel failed: {report}; inspect {root}")
                        if time.monotonic() >= deadline:
                            raise RuntimeError(f"Panel test timed out; inspect {root}")
                        time.sleep(0.1)
                    result = process.returncode
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
            assert result == 0, f"IDA {phase} exit={result}; inspect {root}"
            report = json.loads((root / (phase + ".json")).read_text())
            assert report["ok"], report
        assert server.tools_ok and not server.errors, server.errors
        assert (root / "panel-note.txt").read_text() == "Linux panel tool OK\n"
        assert (root / "panel-note.txt").stat().st_mode & 0o777 == 0o600
        database = state / "ida-agent/ai/chat.db"
        with sqlite3.connect(database) as connection:
            rows = connection.execute("SELECT history_json FROM chat_sessions").fetchall()
        assert any("streamed reply OK" in row[0] for row in rows), rows
        assert database.stat().st_mode & 0o777 == 0o600
        assert not list((root / "instances").iterdir()), "instance leaked after GUI exit"
        print("panel=settings=streaming=tools=approval=cancel=history=restore=clean_exit=ok", flush=True)
    finally:
        server.shutdown()
        server.server_close()
        (root / "provider-requests.json").write_text(json.dumps(server.requests, ensure_ascii=False, indent=2))
        (root / "provider-errors.json").write_text(json.dumps(server.errors))


if __name__ == "__main__":
    main()
