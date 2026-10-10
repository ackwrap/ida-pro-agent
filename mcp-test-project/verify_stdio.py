import argparse
import json
from pathlib import Path
import subprocess
import tempfile


DOMAIN_TOOLS = {
    "ida_instances", "ida_database", "ida_functions", "ida_search",
    "ida_symbols", "ida_types", "ida_analysis", "ida_changes",
    "ida_patch", "ida_debugger", "ida_scripts",
}
DIRECT_TOOLS = {
    "ida_list_instances",
    "ida_select_instance",
    "ida_database_info",
    "ida_get_function",
    "ida_search_functions",
    "ida_decompile_function",
    "ida_disassemble_function",
    "ida_function_callers",
    "ida_function_callees",
    "ida_query_xrefs",
    "ida_search_strings",
    "ida_read_memory",
}
EXPECTED_TOOLS = DOMAIN_TOOLS | DIRECT_TOOLS


def send(process, message):
    process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
    process.stdin.flush()


def receive(process, request_id):
    while True:
        line = process.stdout.readline()
        if not line:
            stderr = process.stderr.read()
            raise RuntimeError(f"Gateway closed before response {request_id}: {stderr}")
        message = json.loads(line)
        if message.get("id") == request_id:
            if "error" in message:
                raise RuntimeError(f"MCP request {request_id} failed: {message['error']}")
            return message["result"]


def main():
    parser = argparse.ArgumentParser(description="Verify the built Gateway stdio lifecycle without IDA")
    parser.add_argument("gateway", type=Path)
    args = parser.parse_args()
    if not args.gateway.is_file():
        parser.error(f"Gateway does not exist: {args.gateway}")

    with tempfile.TemporaryDirectory(prefix="ida-agent-stdio-") as instance_dir:
        process = subprocess.Popen(
            [str(args.gateway), "-instance-dir", instance_dir],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        try:
            send(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "stdio-verifier", "version": "1"},
                    },
                },
            )
            receive(process, 1)
            send(process, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
            send(process, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            tools = receive(process, 2).get("tools", [])
            expected_names = EXPECTED_TOOLS
            if len(tools) != len(expected_names) or {tool["name"] for tool in tools} != expected_names:
                raise RuntimeError(f"unexpected tools/list names: {[tool['name'] for tool in tools]}")
            send(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "ida_instances",
                        "arguments": {
                            "action": "call",
                            "method": "ida.instances.list",
                            "arguments": {},
                        },
                    },
                },
            )
            result = receive(process, 3)
            structured = result.get("structuredContent", {}).get("result", {})
            if structured.get("instances") != []:
                raise RuntimeError(f"unexpected empty discovery result: {structured}")
            process.stdin.close()
            if process.wait(timeout=5) != 0:
                raise RuntimeError(f"Gateway exited with {process.returncode}: {process.stderr.read()}")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    print("stdio initialize/23 direct and domain tools/empty discovery/EOF exit passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
