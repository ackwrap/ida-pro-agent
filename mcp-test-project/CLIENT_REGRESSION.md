# Reproducible Agent client regression (0.4.5)

## Coverage audit

| Existing entry | Verified scope | Does not establish |
| --- | --- | --- |
| `verify_stdio.py` | Initialization, fixed 23 names, empty discovery, EOF | Agent/model invocation, live IDA |
| `verify_compatibility.py --http` | Four protocol versions, stdio/HTTP, simple schemas, structured/text errors, recovery, diagnostics | Provider schema conversion, Agent retries/concurrency, live IDA |
| `ida-mcp/mcp/compatibility_test.go` | Official Go SDK with fake backend: all aliases, routing, cursors, validation, retry limits/shared deadlines, side-effect timeout policy | Agent CLI behavior, OS IPC, IDA APIs |
| `ida-mcp/ida/admission_test.go` | FIFO, capacity, cancellation, grant race, per-instance isolation | A real client's scheduling; controller wait expiry was not separately exercised |
| Opt-in `ida_agent_gateway_ping` CTest | Official Go SDK with live IDA over HTTP/stdio; 98 domain methods | Codex/Claude Code/OpenCode model calls |

Reuse the existing tests rather than rewriting MCP initialization/version/framing checks.
The new `admission_expiry_test.go` covers the controller's own five-second wait budget;
existing tests covered earlier caller deadlines. No production compatibility fix is implied
by a failed environment prerequisite.

## Layers and evidence

1. `verify_client_sdk.py`: official Python SDK 1.25.0, production MCP server,
   production BridgeBackend/admission/retry code, simulated RPC peer. Checks 23 schemas,
   12 direct successes, 11 domain `list` calls, semantic error recovery, three busy
   attempts, no timeout retry, write timeout `executionState=unknown`, selected/explicit
   routing, 2 running + 8 queued + 1 rejected, instance isolation and client cancellation.
   FIFO and queue wait expiry remain deterministic Go tests, not model claims.
2. `run_agent_clients.py`: actual installed CLI and actual configured model. Records
   CLI version, executable, gateway SHA-256, prompt/argv, client events, wire JSONL and
   RPC trace. It must observe discovery and successful calls through all 23 tools,
   matching structured/text results, an invalid memory call followed by a repaired call
   in the same session, and selected A / explicit B / selected A database identities.
   Simulated runs also require bounded busy retry and tool-level timeout recovery.
3. Client-issued parallel batches and the Agent's **own request deadline** are separate
   observations. A serialized batch is `not_observed`, never a queue pass. The SDK proves
   MCP cancellation/recovery; it does not prove an Agent's configured timeout behavior.
   The injected RPC `TIMEOUT` is not a real hung IDA operation.

`passed` means required checks passed; read `checks` for optional `not_observed` fields.
Exit codes are 0=required checks passed, 1=failed with actual calls, 2=blocked prerequisite
or client/model startup. No wire traffic is never a successful Agent test.

## Setup

From the repository root (Go 1.25+, Python 3.10+):

```sh
go -C ida-mcp build -o ../build/ida-mcp .
go -C ida-mcp build -o ../build/ida-agent-client-fixture ./cmd/ida-agent-client-fixture
python -m venv .venv-clients
# Windows: .venv-clients\Scripts\python.exe instead of .venv-clients/bin/python
.venv-clients/bin/python -m pip install -r mcp-test-project/requirements-clients.txt
.venv-clients/bin/python -m unittest discover -s mcp-test-project -p 'test_agent_evidence.py'
```

The two direct dependency versions are pinned. Save `pip freeze`, Go/OS versions, CLI
versions and an explicit `--model` with each run to control transitive/model drift.
The generated output must be a new empty directory for every attempt.

### Simulated Unix IDA with the production executable (Linux/macOS)

```sh
.venv-clients/bin/python mcp-test-project/verify_client_sdk.py build/ida-mcp \
  --report mcp-test-project/.runtime/sdk-unix.json
.venv-clients/bin/python mcp-test-project/run_agent_clients.py build/ida-mcp \
  --client codex --model YOUR_MODEL --output mcp-test-project/.runtime/codex-unix-001
```

`mock_ida.py` uses the shared protocol response fixtures, two private registry-v2
entries, real Unix sockets, process identity/hello and typed BridgeClient validation.
The mock marks results `SIMULATED-A.i64` / `SIMULATED-B.i64`. It provides no IDA APIs,
real disassembly, decompiler correctness, Windows Named Pipe or GUI/license validation.
An unavailable Unix socket is reported as blocked; there is no silent downgrade.

### Explicit in-memory RPC fallback (also usable on Windows)

```sh
.venv-clients/bin/python mcp-test-project/verify_client_sdk.py build/ida-agent-client-fixture \
  --backend simulated_ida_inmemory_rpc --report mcp-test-project/.runtime/sdk-memory.json
.venv-clients/bin/python mcp-test-project/run_agent_clients.py build/ida-agent-client-fixture \
  --backend simulated_ida_inmemory_rpc --client codex \
  --output mcp-test-project/.runtime/codex-memory-001
```

`ida-agent-client-fixture` is a **test-only executable**, not a production mock flag.
It replaces InstanceSource and PipeDialer with static descriptors and `net.Pipe`,
retaining the production server, typed bridge DTO validation, admission and retries.
It explicitly excludes registry discovery, OS peer validation and all IDA behavior.
Do not ship this executable in release packages.

The CI matrix runs the memory fixture on all three operating systems and additionally
runs the production executable with the Unix mock on Linux/macOS. The Unix fixture
resolves macOS's `/tmp` symlink before publishing registry/socket paths, as required by
the production directory walker.

Replace `--client codex` with `--client claude` or `--client opencode` (OpenCode 2); use `--executable`
for a CLI outside PATH and `--model provider/model` for OpenCode. CLI/model credentials
use normal client configuration; the harness never reads, copies or saves credentials.
Codex uses command-line MCP overrides and `--ignore-user-config` (auth still uses the
normal Codex home), Claude uses `--strict-mcp-config`, and OpenCode uses an isolated
working directory plus `OPENCODE_CONFIG` and `--standalone` to avoid reusing a background server. OpenCode can still merge global/provider
configuration; only `ida_regression_*` tools are allowed in the generated permission
policy. Pin client versions; later CLI versions may need adapter updates.

Command shapes were checked against installed `codex exec --help` and official docs:
[Claude CLI](https://code.claude.com/docs/en/cli-reference),
[OpenCode 2 CLI](https://opencode.ai/v2/docs/cli/commands/),
[OpenCode 2 MCP](https://opencode.ai/v2/docs/mcp-servers/).
These documents are configuration references, not evidence that those clients passed.

### Real IDA follow-up

Start two disposable IDA databases with the **production** 0.4.5 plugin. Use the existing
RPC ping/instance list to obtain their UUIDs. Supply a readable function address shared
by the test databases, working Hex-Rays licenses, and exact database basenames:

```sh
.venv-clients/bin/python mcp-test-project/run_agent_clients.py build/ida-mcp \
  --client codex --backend live_ida --model YOUR_MODEL \
  --instance-a ACTUAL_UUID_A --instance-b ACTUAL_UUID_B \
  --database-a sample-a.i64 --database-b sample-b.i64 --address 0x401000 \
  --output mcp-test-project/.runtime/codex-live-001
```

Optional `--instance-dir` selects a test registry. This mode never injects fault
addresses or invokes writes/scripts/debugger methods; domain tools only use `list`.
Actual busy/timeout/concurrency behavior remains `not_observed` unless separately
captured. Repeat for every CLI/model pair and Windows/Linux/macOS before claiming
full compatibility. Live domain-method behavior stays in the existing opt-in IDA CTest.

## Data and limitations

`wire.jsonl` keeps schemas, safe routing fields, response hashes, error issues and
timings. It excludes script source and result bodies; live database names are hashed.
`client.stdout.jsonl`/stderr are the client's native diagnostic output and can contain
live IDB data or provider diagnostics: keep raw artifacts local and review before sharing.
Run directories are ignored by Git. Do not aggregate multiple runs into one evidence file.
The ten oracle/tee tests use synthetic evidence and byte forwarding checks, not Agent behavior.
No claim about provider schema strictness is based on schema compilation alone: the
actual CLI/model must accept and invoke the tool definitions.
