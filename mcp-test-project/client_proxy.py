"""Transparent stdio tee. Evidence is derived from wire traffic, never model text."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time


class Evidence:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.pending = {}
        self.connection = f"{os.getpid()}-{time.time_ns()}"

    def record(self, direction, message):
        with self.lock:
            entry = {"connection": self.connection, "time": time.monotonic(), "direction": direction}
            if direction == "request":
                entry.update(id=message.get("id"), method=message.get("method"))
                params = message.get("params", {})
                if entry["method"] == "initialize":
                    entry["clientInfo"] = params.get("clientInfo")
                if entry["method"] == "tools/call":
                    entry["tool"] = params.get("name")
                    # Store safe routing/contract fields, never scripts or arbitrary results.
                    args = params.get("arguments", {})
                    if isinstance(args, dict):
                        entry["arguments"] = {k: v for k, v in args.items() if k in
                            {"instanceId", "address", "format", "length", "action", "method"}}
                if "id" in message:
                    self.pending[message["id"]] = dict(entry)
            else:
                request = self.pending.pop(message.get("id"), {})
                entry.update(id=message.get("id"), method=request.get("method"),
                             tool=request.get("tool"), arguments=request.get("arguments", {}))
                if request:
                    entry["durationMs"] = (entry["time"] - request["time"]) * 1000
                if "error" in message:
                    entry["protocolError"] = message["error"].get("code")
                result = message.get("result", {})
                if entry["method"] == "tools/list":
                    entry["tools"] = [{"name": t["name"], "inputSchema": t["inputSchema"]}
                                      for t in result.get("tools", [])]
                if entry["method"] == "tools/call" and "error" not in message:
                    body = result.get("structuredContent")
                    text = result.get("content", [])
                    try:
                        entry["textMatchesStructured"] = (body is not None and len(text) == 1 and
                            text[0]["type"] == "text" and json.loads(text[0]["text"]) == body)
                    except (KeyError, TypeError, ValueError):
                        entry["textMatchesStructured"] = False
                    entry["isError"] = bool(result.get("isError"))
                    entry["resultSha256"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
                    if isinstance(body, dict):
                        entry["code"] = body.get("code")
                        entry["retryable"] = body.get("retryable")
                        entry["executionState"] = body.get("executionState")
                        entry["hasHint"] = bool(body.get("hint"))
                        entry["issues"] = body.get("issues", [])
                        entry["instanceIds"] = [i["instanceId"] for i in body.get("instances", [])]
                        # Synthetic markers only; no live database names are persisted.
                        for field in ("name", "database"):
                            if isinstance(body.get(field), str):
                                entry[field + "Sha256"] = hashlib.sha256(body[field].encode()).hexdigest()
                            if body.get(field) in ("SIMULATED-A.i64", "SIMULATED-B.i64"):
                                entry["marker"] = body[field]
            with self.path.open("a", encoding="utf-8") as output:
                output.write(json.dumps(entry) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("gateway command is required after --")
    evidence = Evidence(args.evidence)
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def relay(source, destination, direction):
        try:
            for line in source:
                try:
                    evidence.record(direction, json.loads(line))
                except (ValueError, TypeError, KeyError, AttributeError):
                    # Bad stdout remains visible to the real client's parser.
                    pass
                destination.write(line)
                destination.flush()
        except (BrokenPipeError, OSError):
            pass

    reader = threading.Thread(target=relay, args=(child.stdout, sys.stdout.buffer, "response"), daemon=True)
    reader.start()
    try:
        relay(sys.stdin.buffer, child.stdin, "request")
        child.stdin.close()
        try:
            code = child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            code = child.wait(timeout=5)
        reader.join(timeout=2)
        return code
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
