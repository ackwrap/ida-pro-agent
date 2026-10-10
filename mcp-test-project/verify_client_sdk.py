"""Official Python MCP SDK against the production gateway + SIMULATED Unix IDA.

This is SDK integration, not an Agent/model test. Reuses protocol fixtures and
the existing HTTP launcher; it does not implement a second MCP protocol client.
"""
import argparse
import asyncio
from contextlib import asynccontextmanager
from datetime import timedelta
import importlib.metadata
import json
from pathlib import Path
import threading
import time
import httpx

from jsonschema import Draft202012Validator
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client

from mock_ida import A, B, BUSY, TIMEOUT, SLOW, MockIDA
from memory_ida import MemoryIDA
from verify_compatibility import HTTP
from verify_stdio import EXPECTED_TOOLS

DIRECT = {
    "ida_list_instances": {}, "ida_select_instance": {"instanceId": A},
    "ida_database_info": {"instanceId": A},
    "ida_get_function": {"instanceId": A, "address": "0x401000"},
    "ida_search_functions": {"instanceId": A, "name": "main"},
    "ida_decompile_function": {"instanceId": A, "address": "0x401000"},
    "ida_disassemble_function": {"instanceId": A, "address": "0x401000"},
    "ida_function_callers": {"instanceId": A, "address": "0x401000"},
    "ida_function_callees": {"instanceId": A, "address": "0x401000"},
    "ida_query_xrefs": {"instanceId": A, "address": "0x401000", "direction": "incoming"},
    "ida_search_strings": {"instanceId": A, "query": "hello"},
    "ida_read_memory": {"instanceId": A, "address": "0x401000", "format": "bytes", "length": 4},
}


@asynccontextmanager
async def connect(gateway, fixture, transport):
    if transport == "stdio":
        params = StdioServerParameters(command=str(gateway),
                                      args=getattr(fixture, "arguments", ["-instance-dir", str(fixture.directory)]))
        import sys
        async with stdio_client(params, errlog=getattr(fixture, "stream", sys.stderr)) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=20)) as session:
                await session.initialize()
                yield session
    else:
        process = HTTP(gateway, str(fixture.directory), getattr(fixture, "arguments", None),
                       getattr(fixture, "stream", None))
        try:
            async with streamablehttp_client(process.endpoint,
                httpx_client_factory=lambda **kw: httpx.AsyncClient(trust_env=False, **kw)) as (read, write, _):
                async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=20)) as session:
                    await session.initialize()
                    yield session
        finally:
            process.close(False)


async def call(session, tool, arguments, code=None):
    result = await session.call_tool(tool, arguments)
    assert result.isError == (code is not None), (tool, result)
    body = result.structuredContent
    assert len(result.content) == 1 and result.content[0].type == "text"
    assert json.loads(result.content[0].text) == body
    if code:
        assert body["code"] == code and body["hint"], body
    return body


async def exercise(session, fixture):
    tools = (await session.list_tools()).tools
    assert len(tools) == 23 and {t.name for t in tools} == EXPECTED_TOOLS
    for tool in tools:
        Draft202012Validator.check_schema(tool.inputSchema)
    for tool, args in DIRECT.items():
        body = await call(session, tool, args)
        if tool == "ida_list_instances":
            assert {i["instanceId"] for i in body["instances"]} == {A, B}
    for tool in sorted(EXPECTED_TOOLS - DIRECT.keys()):
        await call(session, tool, {"action": "list"})
    # Schema-valid but semantically incomplete: real models can submit this.
    invalid = dict(DIRECT["ida_read_memory"])
    invalid.pop("length")
    await call(session, "ida_read_memory", invalid, "INVALID_ARGUMENT")
    await call(session, "ida_read_memory", DIRECT["ida_read_memory"])
    # Real gateway retry policy, observed below the MCP layer.
    before = len(fixture.events)
    await call(session, "ida_get_function", {"instanceId": A, "address": BUSY})
    attempts = [e for e in fixture.events[before:] if e["phase"] == "start" and e["address"] == BUSY]
    assert len(attempts) == 3, attempts
    before = len(fixture.events)
    await call(session, "ida_get_function", {"instanceId": A, "address": TIMEOUT}, "TIMEOUT")
    assert len([e for e in fixture.events[before:] if e["phase"] == "start"]) == 1
    write = await call(session, "ida_database", {"action": "call", "method": "database.save",
                       "arguments": {"instanceId": A}}, "TIMEOUT")
    assert write["executionState"] == "unknown" and write["retryable"] is False
    assert len([e for e in fixture.events if e["phase"] == "start" and e["method"] == "database.save"]) == 1
    # Selected route A, explicit B, then selected A must not change.
    for args, marker in (({}, fixture.marker(A)), ({"instanceId": B}, fixture.marker(B)),
                         ({}, fixture.marker(A))):
        assert (await call(session, "ida_database_info", args))["database"] == marker
    await call(session, "ida_select_instance", {"instanceId": B})
    assert (await call(session, "ida_database_info", {}))["database"] == fixture.marker(B)
    await call(session, "ida_select_instance", {"instanceId": A})

    # Exercise admission through the production BridgeBackend, not a fake MCP backend.
    fixture.gate = threading.Event() if isinstance(fixture, MockIDA) else None
    started = len(fixture.events)
    tasks = [asyncio.create_task(call(session, "ida_get_function",
              {"instanceId": A, "address": SLOW})) for _ in range(11)]
    try:
        deadline = time.monotonic() + 3
        while sum(e["phase"] == "start" and e["address"] == SLOW
                  for e in fixture.events[started:]) < 2:
            assert time.monotonic() < deadline, "RPC workers did not enter"
            await asyncio.sleep(0.01)
        # While A's workers are blocked, B must still complete.
        await asyncio.wait_for(call(session, "ida_database_info", {"instanceId": B}), 2)
        # Give all 11 MCP calls and bounded automatic busy retries time to arrive.
        await asyncio.sleep(0.6)
        assert any(task.done() for task in tasks), "Queue overflow was not rejected"
    finally:
        if fixture.gate is not None:
            fixture.gate.set()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    # call() expects success, so overflow deliberately manifests as an assertion.
    rejected = [r for r in results if isinstance(r, AssertionError)]
    assert len(rejected) == 1, results
    error_result = rejected[0].args[0][1]
    assert error_result.structuredContent["code"] == "IDA_BUSY"
    starts = [e for e in fixture.events[started:] if e["phase"] == "start" and e["address"] == SLOW]
    assert len(starts) == 10 and max(e["active"] for e in starts) == 2, starts
    fixture.gate = None

    # Actual MCP cancellation of a running slow request, then reuse this session.
    fixture.delay = 0.5
    try:
        await asyncio.wait_for(session.call_tool("ida_get_function", {"instanceId": A, "address": SLOW}), 0.05)
        raise AssertionError("Slow call did not reach the client deadline")
    except asyncio.TimeoutError:
        pass
    await call(session, "ida_database_info", {"instanceId": B})
    # The plugin may continue accepted work after cancellation: allow it to finish.
    await asyncio.sleep(0.85)
    assert not fixture.errors, fixture.errors
    return {"catalog_schemas": 23, "successful_direct_tools": 12, "domain_list_calls": 11,
        "semantic_error_recovery": "passed", "busy_attempts": 3,
        "write_timeout_unknown": "passed", "multi_instance_routing": "passed",
        "queue_overflow": 1, "max_active_per_instance": 2,
        "client_deadline_and_recovery": "passed"}


async def main_async(args):
    report = {"kind": "official_sdk_integration", "backend": args.backend,
              "sdk": f"mcp-python/{importlib.metadata.version('mcp')}", "transports": {}}
    report["unverified"] = ["Agent/model behavior", "real IDA APIs"]
    if args.backend == "simulated_ida_inmemory_rpc":
        report["unverified"] += ["OS IPC", "registry discovery"]
    for transport in ("stdio", "http"):
        with (MockIDA() if args.backend == "simulated_ida_unix_rpc" else MemoryIDA()) as fixture:
            async with connect(args.gateway.resolve(), fixture, transport) as session:
                report["transports"][transport] = await exercise(session, fixture)
                if transport == "http":
                    async with connect(args.gateway.resolve(), fixture, transport) as other:
                        # A separate gateway has independent active state.
                        await call(other, "ida_database_info", {}, "NOT_FOUND")
            report["transports"][transport]["fixture"] = fixture.snapshot()
    report["status"] = "passed"
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Official SDK stdio/HTTP + {args.backend} passed; no Agent/model or real IDA verified.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gateway", type=Path)
    parser.add_argument("--backend", choices=("simulated_ida_unix_rpc", "simulated_ida_inmemory_rpc"),
                        default="simulated_ida_unix_rpc")
    parser.add_argument("--report", type=Path, default=Path("mcp-test-project/.runtime/sdk-report.json"))
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"kind": "official_sdk_integration", "backend": args.backend,
                                      "status": "running"}, indent=2) + "\n")
    try:
        asyncio.run(main_async(args))
    except Exception as error:
        args.report.write_text(json.dumps({"kind": "official_sdk_integration", "backend": args.backend,
            "status": "blocked" if isinstance(error, (PermissionError, FileNotFoundError)) else "failed",
            "reason": f"{type(error).__name__}: {error}"}, indent=2) + "\n")
        raise


if __name__ == "__main__":
    main()
