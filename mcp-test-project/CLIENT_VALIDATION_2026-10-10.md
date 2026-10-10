# Client regression validation — 2026-10-10

## Source provenance

Private source base: `ackwrap/ida-agent` master `a9d16fa06946d5168b86c2e45f6ccbf3846a37f9`.
The gateway compatibility implementation is unchanged from
`e1aa340e84846b8546eaba93a848c9646628c0b5`; the released 0.4.5 commit is
`cb7d932b7c43c3b801d161dcf8038f461ae91a3d`.

Private Git clone credentials were unavailable in this execution environment. The
GitHub connector read the private tree and source; the public source snapshot
`ackwrap/ida-pro-agent` `3d484121434d6dad17e2de331d8b4441d1116a20` was cloned locally.
All 746 gateway/protocol/test files were checked against private-source Git blob
hashes. Only `ida-mcp/README.md` and `ida-mcp/VERSION` differed from the earlier
development commit, matching the release preparation changes. This patch changes
test infrastructure and documentation only; no production MCP contract was modified.

## Actually executed

Environment: Linux amd64, Go 1.25.3, Python 3.12.14, official Python MCP SDK 1.25.0,
JSON Schema validator 4.25.1. Raw execution artifacts are under ignored `.runtime/`.

| Check | Result | Scope |
| --- | --- | --- |
| `go vet ./...`, `go build ./...` | Passed | All gateway packages and new test executable |
| Existing `verify_stdio.py` | Passed | Production 0.4.5 gateway; 23 tools, no IDA, EOF |
| Existing `verify_compatibility.py --http` | Passed | Production gateway; four versions × stdio/HTTP |
| New SDK stdio/HTTP regression | Passed | Production server/bridge/admission/retries, **in-memory simulated IDA** |
| Ten oracle/tee tests | Passed | Synthetic evidence, failure detection and transparent byte forwarding |
| Five-second queue expiry regression | Passed | Real controller budget, no slot leak |
| `go test -race ./mcp ./ida` | Passed | Original and new gateway/controller tests |
| Complete `go test ./...` | Environment-limited | Three existing Unix/identity tests failed; details below |
| Go suite excluding those three tests | Passed | Explicit exclusion, not a full-suite pass |
| Workflow YAML parsing | Passed | Syntax only; GitHub Actions results are separate |
| Fixture cross-compilation | Passed | Windows amd64 and macOS arm64; execution not established by compilation |

The SDK regression observed all 12 direct tools and 11 domain `list` calls,
23 compiled schemas, structured/text consistency, semantic error correction,
three busy attempts, no automatic timeout retry, write timeout unknown state,
selected A / explicit B / selected A, 10 accepted plus one queue-overflow rejection,
at most two running per instance, instance B progressing while A was occupied,
and client deadline/cancellation followed by successful reuse.

The environment denies Unix sockets (`socket: operation not permitted`). The original
`TestUnixSocketIdentityPermissionsAndDeadline` and `TestUnixDiscoveryRemovesStaleSocket`
failed for that reason. `TestUnixRegistryRejectsPublicFilesAndSymlinks` rejected the
current process in the managed PID/permission environment. Those tests were not
changed or silently skipped in source. Their explicit exclusion during local validation
was: `-skip 'TestUnixRegistryRejectsPublicFilesAndSymlinks|TestUnixDiscoveryRemovesStaleSocket|TestUnixSocketIdentityPermissionsAndDeadline'`.
The new Unix IDA mock could not start and is **not verified here**.

## Real Agent attempts

| Client | Observed result | What this proves |
| --- | --- | --- |
| Codex 0.159.2 | Blocked at 240-second harness deadline; no MCP request | CLI version/start attempt only |
| Codex 0.158.0 | Blocked at 35-second harness deadline; no MCP request | CLI version/start attempt only |
| Codex 0.159.2, explicit stdin pipe | Blocked at 35-second harness deadline; no MCP request | Alternative CLI input handling attempted |
| Claude Code | Blocked: CLI absent | No client/model behavior verified |
| OpenCode | Blocked: CLI absent | No client/model behavior verified |

The first two Codex attempts emitted `Reading additional input from stdin...` and produced no
MCP `initialize`, `tools/list` or `tools/call` evidence. This is a startup/environment
observation, not evidence of an ida-mcp incompatibility. No real Agent/model test passed.
The third attempt supplied the prompt through an explicitly closed stdin pipe (`-`);
it also timed out without MCP evidence. That input form is now used by the runner.

## Remaining verification

- Run the three installed, authenticated CLI/model pairs with the documented runner.
- Observe actual provider schema acceptance through successful calls, Agent error
  correction, client-issued parallel calls and the client's own request deadline.
- Run the Unix fixture on an environment with Unix sockets; validate real Windows
  Named Pipe and registry identity through the existing live IDA integration.
- Run two actual IDA/Hex-Rays databases on Windows/Linux/macOS with the live entry point.
- Treat future SDK CI results as SDK + simulated IDA results, never real Agent/IDA passes.

No concrete production compatibility defect was established by the executed tests.
The patch adds regression coverage and reproducible entry points; it does not claim
that all named Agents are already compatible.
