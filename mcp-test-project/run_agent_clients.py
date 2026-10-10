"""Run installed Codex/Claude Code/OpenCode with wire-based regression evidence.

CLI/model credentials remain in their normal locations. No user configuration
is written. Exit 0 means the required Agent checks passed; 1 failed, 2 blocked.
Optional concurrency/deadline observations are reported separately.
"""
import argparse
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

from agent_evidence import assess, read_events
from mock_ida import A, B, MockIDA
from memory_ida import MemoryIDA
from verify_client_sdk import DIRECT
from verify_stdio import EXPECTED_TOOLS

HERE = Path(__file__).resolve().parent


def configuration(client, proxy_command, directory, model=None):
    server = "ida_regression"
    environment = {}
    if client == "codex":
        args = ["exec", "--skip-git-repo-check", "--ignore-user-config", "--ephemeral",
                "--sandbox", "read-only", "--json", "-c", 'approval_policy="never"',
                "-c", f"mcp_servers.{server}.command={json.dumps(proxy_command[0])}",
                "-c", f"mcp_servers.{server}.args={json.dumps(proxy_command[1:])}",
                "-c", f"mcp_servers.{server}.tool_timeout_sec=20"]
    elif client == "claude":
        path = directory / "claude-mcp.json"
        path.write_text(json.dumps({"mcpServers": {server: {"command": proxy_command[0],
                                   "args": proxy_command[1:]}}}, indent=2))
        args = ["-p", "--strict-mcp-config", "--mcp-config", str(path),
                "--no-session-persistence", "--output-format", "stream-json", "--verbose",
                "--allowedTools", f"mcp__{server}"]
    else:
        path = directory / "opencode.json"
        path.write_text(json.dumps({"$schema": "https://opencode.ai/config.json",
            "mcp": {server: {"type": "local", "command": proxy_command, "enabled": True, "timeout": 20000}},
            "permission": {"*": "deny", f"{server}_*": "allow"}}, indent=2))
        environment["OPENCODE_CONFIG"] = str(path)
        args = ["run", "--format", "json"]
    if model:
        args += ["--model", model]
    return args, environment


def prompt(args):
    instances = (args.instance_a, args.instance_b)
    direct = {name: {**params} for name, params in DIRECT.items()}
    for params in direct.values():
        if "instanceId" in params:
            params["instanceId"] = instances[0]
        if "address" in params:
            params["address"] = args.address
    domains = sorted(EXPECTED_TOOLS - DIRECT.keys())
    text = f"""This is an MCP client regression. Use only ida_regression MCP tools;
do not run shell commands, create files, delegate, or invent results.
The backend is {args.backend}. Perform every step using actual tool calls.
1. Call all 12 direct tools with these exact JSON argument objects:
{json.dumps(direct, indent=2)}
2. Call each of these 11 domain tools with {{"action":"list"}}:
{json.dumps(domains)}. Do not call mutation, debugger, script, or patch methods.
3. Deliberately call ida_read_memory with instanceId={instances[0]},
address={args.address}, format="bytes", omitting length. This combination passes
the public schema but should produce INVALID_ARGUMENT. Read the structured hint,
then call again with length=4 and confirm success.
4. Select {instances[0]} with ida_select_instance. Call ida_database_info with {{}};
then with {{"instanceId":"{instances[1]}"}}; then with {{}} again, sequentially.
The expected database basenames in order are {args.database_a}, {args.database_b}, {args.database_a}.
"""
    if args.backend != "live_ida":
        text += f"""5. Call ida_get_function with instanceId={instances[0]}, address="0x401100".
The simulated plugin rejects two attempts with IDA_BUSY; gateway retry should succeed.
6. Call ida_get_function at address="0x401200" on that instance once. Observe TIMEOUT.
Recover by calling ida_get_function at {args.address}. Do not retry the timeout address.
7. Submit SIX ida_get_function calls on {instances[0]} at address="0x401400" in
parallel in ONE tool-call batch if your client supports it. All six must finish.
Do not call subagents or shell tools to emulate parallel calls. If unavailable, report that.
"""
    return text + "Report observed success/errors and any unsupported steps. Your text alone is not test evidence."


def terminate_group(process):
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gateway", type=Path)
    parser.add_argument("--client", choices=("codex", "claude", "opencode"), required=True)
    parser.add_argument("--executable", help="Installed CLI path, recorded in report")
    parser.add_argument("--model", help="Optional pinned model, e.g. provider/model for OpenCode")
    parser.add_argument("--backend", choices=("simulated_ida_unix_rpc", "simulated_ida_inmemory_rpc", "live_ida"),
                        default="simulated_ida_unix_rpc")
    parser.add_argument("--instance-dir", type=Path)
    parser.add_argument("--instance-a", default=A)
    parser.add_argument("--instance-b", default=B)
    parser.add_argument("--database-a", default="SIMULATED-A.i64")
    parser.add_argument("--database-b", default="SIMULATED-B.i64")
    parser.add_argument("--address", default="0x401000")
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--output", type=Path, required=True, help="New, empty run directory")
    parser.add_argument("--client-arg", action="append", default=[], help="Extra CLI argument; repeat with --client-arg=value")
    args = parser.parse_args()
    args.gateway = args.gateway.resolve()
    args.output = args.output.resolve()
    if not args.gateway.is_file():
        parser.error("gateway executable does not exist")
    if args.output.exists() and any(args.output.iterdir()):
        parser.error("output must be empty; do not mix evidence from different runs")
    if args.backend == "live_ida" and (args.instance_a == A or args.instance_b == B or
            args.database_a.startswith("SIMULATED") or args.database_b.startswith("SIMULATED")):
        parser.error("live tests require real discovered instance IDs, database basenames and a valid --address")
    args.output.mkdir(parents=True, exist_ok=True)
    executable = shutil.which(args.executable or args.client)
    report = {"kind": "real_agent_client", "client": args.client, "backend": args.backend,
        "model_requested": args.model, "gatewaySha256": hashlib.sha256(args.gateway.read_bytes()).hexdigest(),
        "unverified": ["real IDA"] if args.backend != "live_ida" else [], "status": "blocked"}
    report_path = args.output / "report.json"
    def save():
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"status": report["status"], "report": str(report_path)}))
    if not executable:
        report["reason"] = "client_cli_not_installed"
        save()
        return 2
    report["executable"] = executable
    try:
        version = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=10)
        report["client_version"] = version.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as error:
        report["reason"] = type(error).__name__
        save()
        return 2
    fixture_context = MockIDA() if args.backend == "simulated_ida_unix_rpc" else \
        MemoryIDA() if args.backend == "simulated_ida_inmemory_rpc" else nullcontext(None)
    try:
        with fixture_context as fixture:
            gateway_args = []
            if fixture is not None:
                gateway_args = getattr(fixture, "arguments", ["-instance-dir", str(fixture.directory)])
            elif args.instance_dir:
                gateway_args = ["-instance-dir", str(args.instance_dir.resolve())]
            wire = args.output / "wire.jsonl"
            proxy = [sys.executable, str(HERE / "client_proxy.py"), "--evidence", str(wire),
                     "--", str(args.gateway), *gateway_args]
            cli_args, environment = configuration(args.client, proxy, args.output, args.model)
            task = prompt(args)
            (args.output / "prompt.txt").write_text(task)
            # Codex explicitly supports '-' for stdin. A closed input pipe avoids
            # implicit "append additional stdin" handling for positional prompts.
            command = [executable, *cli_args, *args.client_arg, "-" if args.client == "codex" else task]
            (args.output / "command.json").write_text(json.dumps(command, indent=2) + "\n")
            start = time.monotonic()
            with (args.output / "client.stdout.jsonl").open("w") as stdout, \
                    (args.output / "client.stderr.log").open("w") as stderr:
                process = subprocess.Popen(command, cwd=args.output, env={**os.environ, **environment},
                    stdout=stdout, stderr=stderr,
                    stdin=subprocess.PIPE if args.client == "codex" else subprocess.DEVNULL,
                    start_new_session=os.name == "posix")
                try:
                    if args.client == "codex":
                        process.stdin.write(task.encode("utf-8"))
                        process.stdin.close()
                    report["exit_code"] = process.wait(timeout=args.timeout)
                except subprocess.TimeoutExpired:
                    report["reason"] = "client_run_deadline"
                finally:
                    terminate_group(process)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        if os.name == "posix":
                            os.killpg(process.pid, signal.SIGKILL)
                        else:
                            process.kill()
                        process.wait(timeout=5)
            report["durationSeconds"] = time.monotonic() - start
            events = read_events(wire)
            rpc_events = fixture.snapshot()["events"] if isinstance(fixture, MockIDA) else []
            if isinstance(fixture, MemoryIDA):
                for line in (args.output / "client.stderr.log").read_text().splitlines():
                    try:
                        entry = json.loads(line)
                        if entry.get("source") == "simulated_rpc":
                            rpc_events.append(entry)
                    except ValueError:
                        pass
            report["checks"] = assess(events, args.backend != "live_ida", rpc_events,
                args.instance_a, args.instance_b, args.database_a, args.database_b)
            report["rpc_events"] = rpc_events
            report["unverified"] += [key for key, value in report["checks"].items() if value == "not_observed"]
            report["clientInfo"] = [e["clientInfo"] for e in events if e.get("clientInfo")]
            if args.backend == "simulated_ida_inmemory_rpc":
                report["unverified"] += ["OS IPC", "registry discovery"]
            if report.get("exit_code") == 0 and all(v != "failed" for v in report["checks"].values()):
                report["status"] = "passed"
            elif any(e.get("method") == "tools/call" for e in events):
                report["status"] = "failed"
            else:
                report["reason"] = report.get("reason", "client_execution_or_model_unavailable")
            save()
            return {"passed": 0, "failed": 1, "blocked": 2}[report["status"]]
    except (OSError, RuntimeError) as error:
        report["reason"] = f"{type(error).__name__}: {error}"
        save()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
