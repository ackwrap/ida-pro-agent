# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

@AGENTS.md

`AGENTS.md` (imported above) is authoritative for directory boundaries, branch workflow (`devel` only, fast-forward promotion to `main`), documentation boundaries, the 800/1500-line C++ file limits, cross-boundary RPC rules, Windows build/validation, and release steps. The sections below add what it does not cover.

## Linux development commands

This checkout is often built on Linux. Full details live in `ida-agent-plugin/README-LINUX.md`.

```sh
git submodule update --init ida-sdk
export IDASDK="$PWD/ida-sdk/src"

# Basic plugin (no Qt/AI), unit tests only; no IDA install or license needed
cmake -S ida-agent-plugin -B build/linux-plugin -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DIDA_AGENT_ENABLE_AI=OFF \
  -DIDA_AGENT_DEPLOY_DEBUG_USER_PLUGIN=OFF -DBUILD_TESTING=ON
cmake --build build/linux-plugin --parallel "$(nproc)"
ctest --test-dir build/linux-plugin --output-on-failure
ctest --test-dir build/linux-plugin -R '^ida_ai_' --output-on-failure   # AI backend subset

# Gateway binary
go -C ida-mcp build -o ../build/linux/ida-mcp .
python3 mcp-test-project/verify_stdio.py build/linux/ida-mcp
```

- AI panel build: `-DIDA_AGENT_ENABLE_AI=ON -DIDA_AGENT_IDA_QT_RUNTIME_DIR=<ida-9.4-dir>` into `build/linux-panel`. It needs the Qt 6.8.2 headers extracted into `qt-sdk/qt-6.8.2-linux` (the README gives the download and checksum).
- Real-IDA tests (opt-in): `python3 ida-agent-plugin/tests/integration/run_linux_smoke.py --ida-dir … --plugin … --gateway …`, or configure with `-DIDA_AGENT_ENABLE_INTEGRATION_TESTS=ON -DIDA_INSTALL_DIR=…` and run `ctest -L integration`.
- Run the gateway manually with `-transport http -listen 127.0.0.1:8743`, `-instance-dir <dir>` (tests only), `-diagnostics`, or `-web` (local client-configuration manager).

## Architecture big picture

```
MCP client ──stdio / loopback HTTP──> ida-mcp (Go) ──Named Pipe (Win) / Unix socket (Linux, macOS)──> ida-agent-plugin (C++) ──IdaExecutor──> IDA main thread
```

- **Discovery, not registration.** Each plugin instance writes a registry JSON file (Windows v1 `pipe`, Linux v2 `endpoint`) and listens on its own pipe or socket. The gateway rediscovers instances on demand (`ida-mcp/ida/discovery`), validates the PID and owner, then runs a `hello` handshake before each `ida-rpc/1` request. The registry file alone is never trusted. MCP `initialize`/`tools/list` never touch IDA.
- **Instance routing.** Business calls take an optional `instanceId`. Without one, the gateway uses the per-MCP-session selection from `ida.instances.select` (`mcp/instance_manager.go`). Internal RPC always carries an explicit `sessionId` (= instance UUID). "Active instance" state never crosses into the plugin.
- **Tool surface.** `tools/list` is a fixed set of 23 tools: 12 direct tools (`mcp/direct_tools.go`) plus 11 domain tools (`mcp/domain_tools.go`, `domain_catalog*.go`). Domain tools use progressive discovery (`list` → `describe` → `call`) over a static method catalog. Every method is bound to a typed handler, so there is no generic forwarding.
- **Gateway layers** (`ida-mcp/ida/`):
  - `rpc/` holds the envelope, strict decoding, and address/schema validation, and is tested against `protocol/testdata`.
  - `bridge/` holds the typed per-method RPC clients and framing.
  - `bridge_backend_*.go` and `model_*.go` hold the backend interfaces and DTOs consumed by `mcp/`.
- **Plugin layers** (`ida-agent-plugin/`):
  - `bridge/transport` holds the pipe/socket workers, which never call the IDA SDK.
  - `bridge/rpc` is the dispatcher.
  - `bridge/*_handlers.cpp` parse arguments and map errors.
  - `services/*` hold the IDA/Hex-Rays logic and run only through `IdaExecutor` (`bridge/ida_executor.hpp`).
  - `plugin.cpp` wires the services and handler registration together.
- **Mutations** go through ChangeSets (`services/changeset_*`): preview, then apply, which returns a `changeId` that can be rolled back. Even the single-shot `patch.write_*` facades in the gateway use ChangeSets internally.
- **Built-in AI** (`ida-agent-plugin/ai/`) is independent of the MCP gateway. It talks to model providers directly over its own HTTP/SSE/WS client (WinHTTP on Windows, libcurl on Linux, native APIs on macOS). The agent loop and tool registry are in `agent_*`, the Qt chat UI is in `chat_*` and `ai_menu*`, and per-binary analysis memory is in `analysis_memory/`. Its tools call the same in-process services; they do not go through the pipe.
- **Cursors.** The plugin returns raw continuations. The gateway wraps them in process-random HMAC cursors (`mcp/cursor.go`) bound to the instance, method, and normalized filters.

## Adding or changing an RPC method

Touch all of these together (see also AGENTS.md "Changes Across Boundaries"):

1. `protocol/schema/methods/*.schema.json` and the valid/invalid fixtures in `protocol/testdata`.
2. Plugin: the service in `services/`, the handler in `bridge/*_handlers.cpp`, and its registration in `plugin.cpp`.
3. Gateway: the DTO and client in `ida/bridge/`, `ida/model_*.go`, and the backend interface in `ida/bridge_backend_*.go`.
4. MCP: the catalog entry, schema, and typed handler in `mcp/`, plus tests (catalog tests assert fixed method counts).

## Skills and test harness

- `skills/` (`idapython`, `ida-reverse-analysis`) is reference material shipped to MCP clients. It is tracked public documentation.
- `mcp-test-project/` holds Python harnesses (`mock_ida.py`, `verify_stdio.py`, `verify_compatibility.py`, client regression runners) that exercise the gateway without IDA.
