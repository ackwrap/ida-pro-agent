# MCP stdio/HTTP + Named Pipe multi-instance test cases

**English** | [简体中文](TEST_CASES.zh-CN.md)

## 1. No-IDA initialization

1. The client starts the `ida-mcp.exe` stdio subprocess.
2. Call MCP `initialize` and `tools/list`.
3. Call `ida.instances.list`.

Expected: the first two steps do not scan the registry or wait for a Pipe; the third returns `{"instances":[]}` and the Gateway does not start HTTP.

Repeat initialize/tools.list/list for an explicit `-transport http -listen 127.0.0.1:<port>`; expected to likewise not depend on IDA, and to verify that a non-loopback listener, a remote Origin and an oversized body are rejected.

## 2. IDA started first

1. Start IDA and confirm the standalone Pipe and the `%LOCALAPPDATA%\ida-agent\instances` entry exist.
2. Start OpenCode/Codex hours later.
3. Call `ida.instances.list`, `ida.instances.select(instanceId)`, `database.info`.

Expected: hello and `instance.info` verify successfully; when a business Tool omits `instanceId` it routes to the active instance.

## 3. Gateway started first

1. Start the Gateway and confirm `ida.instances.list` is empty.
2. Start IDA.
3. Call `ida.instances.list` again.

Expected: the new instance is discovered without restarting the Gateway, and MCP initialize is never affected by IDA's state.

## 4. Explicit multi-instance routing

1. Start two IDAs at the same time and confirm different UUIDs, PIDs/Pipes and databases.
2. After list, select A and call `function.search/get/decompile` with `instanceId` omitted.
3. On the same Gateway, call the same Tools against B with an explicit `instanceId`.

Expected: active routing belongs to A and explicit routing to B with no cross-talk; a cursor cannot be reused across instances.

## 5. Multiple Gateways

OpenCode and Codex each start their own Gateway stdio subprocess and access the same IDA at the same time.

Expected: the Plugin's multiple Pipe instances accept concurrent connections; each Gateway's active-instance state is not shared; each Gateway executes at most 2 requests per instance, and the remaining requests wait in FIFO order for at most 8 requests and 5 seconds, and responses honor call cancellation and deadlines; a full queue or an expired wait returns a retryable `IDA_BUSY`. Read-only busy work is retried automatically at most twice; side-effect operations are not retried automatically.

## 6. Shutdown and crashes

- Closing the client: the Gateway exits and IDA/Pipe/registry continue to exist.
- Closing IDA: the Pipe worker is canceled, the registry handle is closed and the entry disappears.
- taskkill/crash IDA: the OS reclaims the Pipe and the delete-on-close HANDLE; if an entry remains, the Gateway judges it stale through PID + hello and does not return that instance.
- Half-open Pipe client: it must not block other workers, and Plugin stop must complete within 2 seconds.

## 7. Full domain paths

`tools/list` returns a fixed 12 direct tools and 11 domain entries; through domain `call`, all 98 callable methods are actually invoked in turn, verifying search/xref/inventory HMAC cursors, decompilation offset continuation, ChangeSet, the apply/rollback of the direct patch facades, Debugger state, script execution in the ordinary side-effect-tool form, `analysis.wait` complete/timeout/cancel, `analysis.plan` queueing, precise local xref and local ChangeSet mark/restore, timeout and output budget. This path must run once each on the official Go MCP Client's Streamable HTTP and on a real `ida-mcp.exe` stdio subprocess. MCP output may include PIDs and business instance information but must not include tokens, Pipe locators, internal stacks or unredacted absolute sensitive paths.

The current automation entry point is the explicitly enabled CTest `ida_agent_gateway_ping`. It reuses one real IDA 9.4/Hex-Rays session to complete direct RPC, HTTP and stdio acceptance; the default fast CTest does not register this slow test.

## 8. No-IDA compatibility black box

Run `python mcp-test-project/verify_compatibility.py <gateway-executable> --http`. The script uses an isolated instance directory and checks stdio/HTTP across four MCP protocol versions, the simple public schema of the 23 tools, field errors and session recovery, JSON text/structured-result consistency, redacted diagnostics and stdio EOF. Also run `verify_stdio.py` for basic lifecycle acceptance.

Direct-tool tests should cover single-instance automatic routing, multi-instance explicit selection, all fixed aliases and pagination; queue tests cover FIFO, a full queue, cancellation and authorization-slot contention; retry tests cover the same overall deadline and single execution of writes/scripts/debugger control. Protocol/SDK automation is not equivalent to an actual Agent/model test; real IDA and client paths must be recorded separately.

## 9. Real Agent client regression

See [CLIENT_REGRESSION.md](CLIENT_REGRESSION.md). `run_agent_clients.py` directly starts an installed Codex, Claude Code or OpenCode and uses a transparent stdio tee to record actual tool discovery, calls and responses. Verdicts come from MCP wire evidence and simulated RPC traces, not from model self-reports, CLI exit codes or static configuration. `verify_client_sdk.py` uses a pinned version of the official Python MCP SDK and is a cross-process SDK integration test; it cannot be recorded as a real Agent test. Results from simulated IDA, real IDA, a client not started, or no observed concurrency are recorded separately.
