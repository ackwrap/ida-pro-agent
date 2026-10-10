import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def wait_until(predicate, timeout, message, process=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"{message}; process exited with {process.returncode}")
        time.sleep(0.1)
    raise TimeoutError(message)


def start_ida(
    ida_exe, plugin, input_file, driver, root, instance_dir, database, create_database
):
    ida_user = root / "ida-user"
    plugin_dir = ida_user / "plugins"
    plugin_dir.mkdir(parents=True)
    shutil.copy2(plugin, plugin_dir / "ida-agent-plugin.dll")

    ready = root / "ready.json"
    release = root / "release"
    log = root / "ida.log"
    stdout = (root / "stdout.log").open("w", encoding="utf-8")
    stderr = (root / "stderr.log").open("w", encoding="utf-8")
    env = os.environ.copy()
    env.update(
        {
            "IDAUSR": str(ida_user),
            "IDA_AGENT_INSTANCE_DIR": str(instance_dir),
            "IDA_AGENT_TEST_RELEASE_FILE": str(release),
            "IDA_AGENT_TEST_READY_FILE": str(ready),
            "IDA_AGENT_TEST_DIAGNOSTICS": "1",
            "IDA_AGENT_TEST_HOLD_SECONDS": "600",
        }
    )
    if create_database:
        args = [
            str(ida_exe),
            "-A",
            "-c",
            f"-L{log}",
            f"-o{database}",
            f"-S{driver}",
            str(input_file),
        ]
    else:
        args = [str(ida_exe), "-A", f"-L{log}", f"-S{driver}", str(database)]

    process = subprocess.Popen(
        args,
        cwd=root,
        env=env,
        stdout=stdout,
        stderr=stderr,
        creationflags=CREATE_NO_WINDOW,
    )
    process._m4_files = (stdout, stderr)
    wait_until(ready.is_file, 120, f"IDA did not become ready; log: {log}", process)
    return {"process": process, "ready": ready, "release": release, "log": log}


def stop_ida(instance):
    instance["release"].write_text("release", encoding="ascii")
    process = instance["process"]
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
    for stream in process._m4_files:
        stream.close()


def ensure_seed(ida_exe, plugin, input_file, driver, seed):
    if seed.is_file():
        return
    seed.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ida-agent-m4-seed-") as temporary:
        root = Path(temporary)
        instance_dir = root / "instances"
        instance_dir.mkdir()
        database = root / "m4-seed.i64"
        instance = start_ida(
            ida_exe, plugin, input_file, driver, root, instance_dir, database, True
        )
        stop_ida(instance)
        if not database.is_file():
            raise RuntimeError("IDA did not create the M4 seed database")
        shutil.copy2(database, seed)


def run_checked(args, cwd, timeout=180):
    result = subprocess.run(
        args,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
        creationflags=CREATE_NO_WINDOW,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {args[0]}\n{result.stdout}\n{result.stderr}"
        )
    return result


def start_client(args, cwd, output_path, error_path, env=None):
    output = output_path.open("w", encoding="utf-8")
    error = error_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        args,
        cwd=cwd,
        stdout=output,
        stderr=error,
        env=env,
        creationflags=CREATE_NO_WINDOW,
    )
    process._m4_files = (output, error)
    return process


def finish_client(process, timeout):
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
        raise TimeoutError(f"External client timed out: {process.args[0]}")
    finally:
        for stream in process._m4_files:
            stream.close()


def main():
    parser = argparse.ArgumentParser(description="Run isolated M4 external-client acceptance")
    parser.add_argument("--ida-dir", default=os.environ.get("IDA_INSTALL_DIR", ""))
    args = parser.parse_args()
    if not args.ida_dir:
        parser.error("set IDA_INSTALL_DIR or pass --ida-dir")

    test_project = Path(__file__).resolve().parent
    repository = test_project.parent
    ida_batch = Path(args.ida_dir) / "idat.exe"
    plugin = repository / "build/ida-agent-plugin/ida-runtime/plugins/ida-agent-plugin.dll"
    batch_driver = repository / "ida-agent-plugin/tests/integration/ida_bridge_hold.py"
    gateway_dir = repository / "ida-mcp"
    for required in (
        ida_batch,
        plugin,
        batch_driver,
        gateway_dir / "go.mod",
    ):
        if not required.exists():
            raise FileNotFoundError(required)

    go = shutil.which("go")
    opencode = shutil.which("opencode.exe") or shutil.which("opencode")
    node = shutil.which("node")
    codex_cmd = Path(shutil.which("codex.cmd") or "")
    if not go or not opencode or not node or not codex_cmd.is_file():
        raise RuntimeError("go, opencode, node, and codex.cmd must be available on PATH")
    codex_js = codex_cmd.parent / "node_modules/@openai/codex/bin/codex.js"
    if not codex_js.is_file():
        raise FileNotFoundError(codex_js)

    runtime = test_project / ".runtime"
    runtime.mkdir(exist_ok=True)
    seed = runtime / "seed/plugin-seed.i64"
    ensure_seed(ida_batch, plugin, plugin, batch_driver, seed)

    run_root = runtime / (time.strftime("%Y%m%d-%H%M%S") + f"-{time.time_ns() % 1_000_000:06d}")
    instance_dir = run_root / "instances"
    instance_dir.mkdir(parents=True)
    instances = []
    clients = []
    try:
        instance_root = run_root / "ida-a"
        instance_root.mkdir()
        database = instance_root / "m4-a.i64"
        shutil.copy2(seed, database)
        instances.append(
            start_ida(
                ida_batch,
                plugin,
                database,
                batch_driver,
                instance_root,
                instance_dir,
                database,
                False,
            )
        )
        wait_until(
            lambda: len(list(instance_dir.glob("*.json"))) == 1,
            10,
            "The IDA instance registry entry was not published",
        )

        ping = run_checked(
            [
                go,
                "run",
                "./cmd/ida-agent-rpc-ping",
                "-instance-dir",
                str(instance_dir),
                "-timeout",
                "20s",
                "-database-info",
            ],
            gateway_dir,
            90,
        )
        (run_root / "rpc-ping.log").write_text(ping.stdout + ping.stderr, encoding="utf-8")
        if ping.stdout.count("databaseInfo=") != 1:
            raise RuntimeError("RPC discovery did not return the live IDA instance")

        gateway_exe = run_root / "ida-mcp.exe"
        run_checked([go, "build", "-o", str(gateway_exe), "."], gateway_dir, 120)
        opencode_prompt = (
            "Use only ida-mcp MCP domain tools. Use action=call with the named method and nested arguments. "
            "Call ida.instances.list through ida_instances, select database ida-agent-plugin.dll with "
            "ida.instances.select, then call database.info through ida_database without instanceId. "
            "Call function.search through ida_functions to obtain an entry address, then call "
            "function.disassemble, function.basic_blocks, and function.callees through ida_functions. "
            "Do not inspect files or run shell commands. On success finish with OPENCODE_M4_PASS."
        )
        codex_prompt = (
            "Use only ida-mcp MCP domain tools. Use action=call with the named method and nested arguments. "
            "Call ida.instances.list through ida_instances, select database ida-agent-plugin.dll with "
            "ida.instances.select, then call database.info through ida_database without instanceId. "
            "Call function.search through ida_functions to obtain an entry address, then call "
            "function.disassemble, function.basic_blocks, and function.callees through ida_functions. "
            "Do not inspect files or run shell commands. On success finish with CODEX_M4_PASS."
        )
        open_output = run_root / "opencode.jsonl"
        open_error = run_root / "opencode-error.log"
        codex_output = run_root / "codex.jsonl"
        codex_error = run_root / "codex-error.log"
        client_env = os.environ.copy()
        client_env["IDA_AGENT_INSTANCE_DIR"] = instance_dir.as_posix()
        clients.append(
            start_client(
                [opencode, "run", "--format", "json", opencode_prompt],
                test_project,
                open_output,
                open_error,
                client_env,
            )
        )
        clients.append(
            start_client(
                [
                    node,
                    str(codex_js),
                    "exec",
                    "--ephemeral",
                    "--ignore-user-config",
                    "-C",
                    str(test_project),
                    "-s",
                    "read-only",
                    "-c",
                    f'mcp_servers.ida-agent.command="{gateway_exe.as_posix()}"',
                    "-c",
                    f'mcp_servers.ida-agent.args=["-instance-dir","{instance_dir.as_posix()}"]',
                    "--json",
                    codex_prompt,
                ],
                test_project,
                codex_output,
                codex_error,
                client_env,
            )
        )

        return_codes = [finish_client(client, 300) for client in clients]
        clients.clear()
        open_text = open_output.read_text(encoding="utf-8")
        codex_text = codex_output.read_text(encoding="utf-8")
        if return_codes[0] != 0 or "OPENCODE_M4_PASS" not in open_text:
            raise RuntimeError(f"OpenCode acceptance failed; evidence: {open_output}")
        if return_codes[1] != 0 or "CODEX_M4_PASS" not in codex_text:
            raise RuntimeError(f"Codex acceptance failed; evidence: {codex_output}")
        open_tools = (
            "ida-agent_ida_instances",
            "ida-agent_ida_database",
            "ida-agent_ida_functions",
        )
        codex_tools = (
            "ida_instances",
            "ida_database",
            "ida_functions",
        )
        if any(tool not in open_text for tool in open_tools):
            raise RuntimeError("OpenCode did not emit all required MCP tool events")
        if any(tool not in codex_text for tool in codex_tools):
            raise RuntimeError("Codex did not emit all required MCP tool events")
        for forbidden in ('"token"', '"endpoint"', '"pipe"'):
            if forbidden in open_text or forbidden in codex_text:
                raise RuntimeError(f"External client output exposed forbidden field {forbidden}")

        print(
            "M4 external clients passed against headless IDA: "
            "OpenCode=ida-agent-plugin.dll Codex=ida-agent-plugin.dll"
        )
        print(f"Evidence={run_root}")
        return 0
    except Exception:
        print(f"M4 evidence retained at {run_root}", file=sys.stderr)
        raise
    finally:
        for client in clients:
            if client.poll() is None:
                client.kill()
                client.wait(timeout=10)
            for stream in client._m4_files:
                stream.close()
        for instance in instances:
            stop_ida(instance)


if __name__ == "__main__":
    raise SystemExit(main())
