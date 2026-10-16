# IDA Agent Plugin

**English** | [简体中文](README.zh-CN.md)

`ida-agent-plugin` is a C++ IDA plugin that provides built-in AI chat, model provider configuration, tool calls and approvals, and exposes IDA/Hex-Rays analysis services through Internal RPC, a Named Pipe server, an instance registry and `IdaExecutor`. The built-in AI uses a separate HTTP/SSE client to connect to providers; the MCP protocol is carried by the external Gateway, and the Plugin does not need to find, connect to, or register with a Gateway.

The current interface contract and field definitions are in the [protocol documentation](../protocol/README.md); callable methods are defined by the Gateway's `list` / `describe` results.

Linux/WSL2 already supports basic MCP and an optional full AI panel; see [Linux build, installation and testing](README-LINUX.md). Windows continues to include AI/Qt by default. The Named Pipe and Windows integration-test notes below apply to Windows; Linux uses a Unix socket, registry v2 and a separate real-IDA smoke runner. The standalone Linux AI backend already supports HTTP, SSE, WS/WSS and chat-session logic; libcurl and SQLite are statically embedded at pinned versions, and OpenSSL uses the system library. With `IDA_AGENT_ENABLE_AI=ON`, AI Chat, provider settings, tool approvals and history are available; Qt runtime libraries are provided by Linux IDA 9.4.

AI Chat in source builds supports role layering, Markdown, code blocks and message/code copy, with performance budgets for streaming refresh and long conversations. An **Effort** reasoning-strength selector sits beside the input row and follows the current model's settings and request format. See [CHAT.md](CHAT.md) for usage and compatibility.

## Analysis memory and evidence-backed workflows

Current source builds add `/memory` to save, search and manage analysis notes per binary; `/workflow protection`, `/workflow function` and `/workflow types` provide protection-strength assessment, function and data-flow investigation, and type-recovery preparation respectively. The selected model must have **Tools** enabled. Conclusions retain evidence addresses and provenance, stale evidence must be re-verified, and reports check coverage against actually successful tool calls. Agent memory writes and deletions follow the conversation approval policy, and storage is outside the IDB.

See the [command, storage, limits and IDA 9.5 acceptance reference](ANALYSIS.md). Windows adds a strict 9.5 ABI preflight and an explicit experimental build configuration; live 9.5 acceptance is still pending, and the stably supported UI ABI remains IDA 9.4 / Qt 6.8.2. These memory tools belong to the built-in agent, and the external MCP tool catalog is unchanged.

## Lifecycle

After database initialization, the Plugin reads fixed metadata once on IDA's main thread, creates a ready Pipe and starts the registry publisher, then returns immediately:

```text
IDA main: generate UUID -> create ready overlapped Pipe/workers -> start publisher -> return
publisher: write/flush/rename registry -> acquire delete-on-close lease
```

`ConnectNamedPipe`, `ReadFile`, `WriteFile`, registry file I/O and client waits all happen on worker threads and never block Plugin init or the IDA UI. When no Gateway exists, the Pipe worker waits normally; when the Gateway exits, IDA, the Pipe and the registry continue to exist. A registry publish failure quiesces the Executor and stops the Pipe worker, and never leaves a half-running Bridge without a registry.

Each instance's Pipe name is `\\.\pipe\ida-agent-{pid}-{uuid-short}` and supports multiple Pipe instances. The Pipe DACL allows only the current user and rejects remote clients. Each connection completes hello first, then handles one `ida-rpc/1` request. Pipe workers do not call the IDA SDK; after the Dispatcher, all IDA/Hex-Rays operations go uniformly through `IdaExecutor::ReadFor` and `execute_sync`.

`script.execute` runs UTF-8 inline IDAPython or IDC source through IDA extlang; Internal RPC does not accept a path. An MCP `path` input is read once by the Gateway and converted to the same inline contract. The Plugin re-validates the language, NUL, the 32 KiB source limit and the output budget, and executes through an `IdaExecutor` write context. The Gateway implements no extra authorization or dialog; call permission is controlled by the MCP client, and Internal RPC remains within the current user's Pipe trust boundary. Python stdout/stderr and the IDC result are returned bounded, and a timeout does not interrupt a script that has already started.

The read-only function analysis RPCs include `function.disassemble`, `function.basic_blocks` and `function.callees`. Their argument parsing, handlers and error mapping live in a separate `bridge/function_analysis_handlers.cpp`; `FunctionService` behavior and the Plugin/Gateway process boundary are unchanged. Consecutive disassembly pagination reuses the next instruction position; basic-block and callee pagination reuse a bounded snapshot and are invalidated when the IDB or references change.

AI streaming events are consumed with a budget of at most 64 events per 8 ms; tool-argument fragments also keep the queue moving. Chat-history encoding and SQLite writes run on a dedicated background thread that merges the latest snapshot of the same session within a 100 ms window; switching, clearing and normal shutdown wait for pending records to finish, and write failures are shown in the panel.

On normal unload, the Pipe workers are signaled/canceled/closed first, then the held registry handle is closed. The registry writes the complete temporary file, flushes it, performs a same-directory atomic rename, and immediately holds a `FILE_FLAG_DELETE_ON_CLOSE` lease; normal exit or the vast majority of process crashes let Windows delete the file. The very short crash window between rename and lease is covered by the Gateway's PID and hello stale validation; the file alone cannot be trusted.

Default registry:

```text
%LOCALAPPDATA%\ida-agent\instances\{pid}-{uuid-short}.json
```

The path is obtained through `SHGetKnownFolderPath(FOLDERID_LocalAppData)`. Tests can set `IDA_AGENT_INSTANCE_DIR`; production code does not hard-code the user directory.

## Build And Test

In a Windows environment where MSVC 2022 and the IDA SDK can be found:

```shell
cmake -S ida-agent-plugin -B build/ida-agent-plugin -G Ninja
cmake --build build/ida-agent-plugin
ctest --test-dir build/ida-agent-plugin --output-on-failure
```

The default DLL is at `build/ida-agent-plugin/ida-runtime/plugins`. The default CTest does not register the five time-consuming real-IDA integration tests. When they are needed, reconfigure with an explicit `-DIDA_AGENT_ENABLE_INTEGRATION_TESTS=ON -DIDA_INSTALL_DIR=<ida-install-dir>`; CTest then runs the real `idat.exe` lifecycle, Named Pipe discovery/hello, the 92 Plugin RPC entries, ChangeSet apply/rollback, database save, the no-process Debugger error path, and the Gateway's existing read-only RPCs. Gateway integration runs in the same real IDA session through in-process Streamable HTTP and a real Gateway stdio subprocess, calling all 98 callable methods through the 11 domain entries. `/Od` and `/O2` fixed samples additionally verify call-argument tracing and guard evidence, as well as cross-function two-level argument origins, multiple callers and recursion boundaries; type declarations in tests are written only to an isolated IDB. Without an IDA/Hex-Rays license, all pure unit tests should still run and the real integration gap should be reported explicitly. Gateway integration also covers per-item/random pagination, cache invalidation after rename and reference add/delete, function-boundary adjustment and shared-tail continuation.

### Real debugger acceptance

With `IDA_AGENT_ENABLE_INTEGRATION_TESTS` enabled, `ida_debugger_integration` starts an isolated `idat.exe` and uses a separate `IDAUSR`, a temporary IDB, and a limited-lifetime sample process built in this compilation to check local Windows debugger selection, configuration read/write, launch, breakpoints, run-to-address, single-step, register/memory reads, continue, suspend, exit, attach, detach and state conflicts. After detaching it also confirms the target process is still alive before the test cleans it up.

```shell
cmake --build build/ida-agent-plugin --target ida_debugger_integration_driver ida_debugger_integration_sample
ctest --test-dir build/ida-agent-plugin -R "^ida_debugger_integration$" --output-on-failure
```

This test driver is built only when integration tests are enabled; it directly reuses the production C++ debugger handlers, IdaExecutor and services and is called from the isolated IDA main thread. It creates no Pipe/network interface, is not shipped with the release package, and does not change the production plugin's authorization rules. `ida_agent_plugin_lifecycle` and `ida_agent_gateway_ping` separately verify the production DLL's real Pipe and HTTP/stdio paths and its `PERMISSION_DENIED` response without a GUI. Debugger service success paths, transport paths and permission gating are therefore accepted separately; real GUI authorization dialogs, background request-queuing timing and remote debugger connections still need separate verification.

Results are kept in `%TEMP%/ida-debugger-integration-*/debugger-results.json` and include call results, assertions and failure reasons. Tests do not attach to the user's existing processes and do not overwrite an installed plugin.

## Version upgrade

Configuration and chat history uniformly use `%LOCALAPPDATA%\ida-agent\ai`, with no fallback to reading an old-named directory; see the [installation notes](../docs/UPGRADING.md).
