# ida-mcp Gateway

**English** | [简体中文](README.zh-CN.md)

`ida-mcp.exe` is a standalone Go MCP server. By default an MCP client starts it on demand as a stdio subprocess; it can also be launched explicitly over secure, loopback-only Streamable HTTP. Neither mode requires IDA to be running at startup.

For the macOS Universal 2 build, see the [macOS guide](../ida-agent-plugin/README-MACOS.md). The Gateway connects to IDA over a same-user Unix socket, and the plugin uses native macOS networking APIs; neither has an OpenSSL/libcurl runtime dependency.

The native Linux Gateway already supports connecting to IDA under the same Linux user over a Unix socket; see the [Linux/WSL2 basic build](../ida-agent-plugin/README-LINUX.md). Linux `-web` stays in the foreground, opens the configuration page from the loopback URL in the log, and exits on Ctrl+C/SIGTERM without relying on a system tray.

```text
OpenCode / Codex / Claude
        | MCP stdio (default) or loopback HTTP (explicitly enabled)
        v
ida-mcp.exe
        | Windows Named Pipe
        v
one or more IDA Plugin instances
```

## Lifecycle

- stdio: the client creates the Gateway subprocess; the Gateway exits when stdin closes, when the client exits, or when it receives a termination signal.
- HTTP: listens on a numeric loopback address only with `-transport http`, and performs a graceful shutdown after a termination signal.
- Web manager: `-web` starts the local configuration page on a random loopback port and stays in the Windows system tray; it does not carry MCP directly, and configures a default stdio Gateway subprocess for each AI client.
- MCP `initialize` and `tools/list` perform no instance discovery and do not connect to the Pipe.
- Without IDA, calling `ida.instances.list` through `ida_instances` immediately returns `{"instances":[]}`.
- The Gateway rediscovers IDA on every start; IDA does not need to register itself, and no cross-process active state is persisted.

## Domain Tools

As of 0.4.5, `tools/list` returns a fixed catalog of 23 tools: 12 direct entries plus the 11 domain entries below. Older v0.4.4 provides only the 11 domain tools.

- `ida_instances`
- `ida_database`
- `ida_functions`
- `ida_search`
- `ida_symbols`
- `ida_types`
- `ida_analysis`
- `ida_changes`
- `ida_patch`
- `ida_debugger`
- `ida_scripts`

Each entry supports a progressive-discovery flow: the model first uses `list` to get the method index, then `describe` for the selected method's exact parameter contract and budget, and only then `call` with arguments that match the returned schema. The public tool schema explicitly requires not guessing method names or argument fields and uses a simple object schema; the required/forbidden fields for the three actions are validated by the Gateway, which returns tool errors. `call` only executes methods that are in state `callable` and bound to a typed handler. The static catalog has 98 entries in total: 6 Gateway methods (3 instance methods, `analysis.wait`, and two ChangeSet-backed patch facades) and 92 Plugin RPCs; all 98 methods are callable. `patch.write_bytes` and `patch.write_integer` target single direct patches, still run ChangeSet preview/apply internally, and return a rollback-able `changeId`; batch edits or edits that need separate review continue to use `ida_changes`.

```json
{"action":"describe","method":"function.search"}
```

```json
{"action":"call","method":"function.search","arguments":{"name":"main","limit":20}}
```

The `arguments.instanceId` of a business method is optional. When provided, it routes explicitly; when omitted, it uses the active instance selected in the current MCP session through `ida.instances.select`. The underlying `BridgeBackend` always receives an explicit `instance_id`; active state never enters Internal RPC or the Plugin. HTTP client sessions store their selection separately and release it on disconnect; a transient discovery failure does not clear an existing selection or switch to another database automatically. A business request with a specified instance validates the registry file and process identity for that target first, then verifies the connection through the RPC handshake, avoiding a repeated probe of every instance.

The three function analysis methods continue to use the protocol-defined integer `offset` continuation, with `address`, an optional `offset` (default 0) and `limit` (default 20) as input, and reuse the same explicit/active instance routing and output budget. This extension has not changed the MCP transport, the Gateway lifecycle, or the Named Pipe architecture.

The new callable catalog contract includes `system.ping/methods`, `instance.info`, `database.survey/save`, and `function.callers/callgraph/profile/export/analyze/analyze_batch/stack_frame`. Each is invoked through a static typed Backend/Bridge method; a domain entry cannot submit an arbitrary RPC method. `database.save` accepts only `compact`/`backup` and saves the current IDB, with the `filesystem_write` side effect; it never accepts `target`. `instance.info` returns only the safe basename of the database/input and never a Pipe locator. `function.profile` wraps the Plugin continuation in a process-random HMAC cursor bound to the instance, method and all filters.

The remaining 18 Plugin RPCs also use explicit typed DTOs and per-domain Backend interfaces: `memory.search_bytes`, `instruction.search/query`, `listing.search/search_text`, `string.search_regex`, `signature.make/xrefs`, `xref.struct_field`, `global.value`, the six `type.*` methods and two `analysis.*` methods. The internal cursors of `instruction.search/query`, `listing.search_text` and `string.search_regex` are wrapped with a process-random HMAC by the Gateway and bound to the instance, the public method and all defaulted filters; tampering, a restart, a parameter change, or reusing an alias across methods all return `INVALID_ARGUMENT`. `listing.search` exposes only the existing single-page contract (`items/truncated`) and does not fake a submittable cursor; `type.search/query` call their static RPCs respectively and expose the ordinal continuation directly; `analysis.trace_data_flow` explicitly returns `model=xref_bfs`.

`analysis.trace_argument` and `analysis.guard_evidence` use Hex-Rays microcode and provide, within a single function, call-argument origin tracing and comparison-condition/necessary-branch evidence respectively. Input is a real `callAddress` and a zero-based `argumentIndex`; results retain value conversions, origin joins and unknown boundaries, and do not output program safety conclusions. See the [argument tracing and guard evidence contract](../protocol/semantic-analysis.md).

`analysis.trace_argument_callers` further traces upward from a formal parameter's origins to known direct callers, two levels by default, retaining each call context and validating prototypes and ABI argument positions. It supports a shared budget and explicit recursion/unknown boundaries. See the [cross-function argument origin contract](../protocol/argument-callers.md).

P1 adds 11 static read-only RPCs: `source.files/lines`, `name.demangle`, `comment.get`, `bookmark.list`, `type.xrefs`, `decompiler.locals/ctree/local_xrefs`, and `debugger.threads/modules`. On the MCP side, all lists expose only HMAC cursors bound to the instance, method, normalized filters and effective limit; source and module file names return only the basename, and source text, full paths, raw continuations, microcode and SDK-internal layouts are never returned.

Database metadata edits continue to use ChangeSets: `segment.rename/permissions`, `function.flags`, `xref.code.add/delete` and `xref.data.add/delete` must all be applied after preview and can be rolled back through `changeId`. xref deletion only permits user-defined references; it never deletes automatic-analysis references whose source cannot be precisely restored. Both ends of a code xref must be existing code items, and a call target must already belong to a function, so that apply cannot implicitly create a function that cannot be rolled back. `function.end` only adjusts the end of the entry chunk corresponding to a stable function entry; `function.chunk.add/delete` use `value`/`subject` for the hexadecimal start/end address of the tail and reject hidden tails; delete only accepts non-owner references to a shared tail.

`ida_scripts` provides `script.execute`, which accepts `python|idc` plus either at most 32 KiB of UTF-8 inline `code` or an external script `path`. It is an `arbitrary_code_execution` side-effect tool; the Gateway implements no extra authorization interaction or separate authorization state, and whether it may be called is decided entirely by the MCP client's permission system. Paths are normalized, an ordinary file is read once and converted to inline source; the path never enters Internal RPC, and the call arguments have no `confirmed/scope` field. A script can modify the IDB, access the local machine or network, and block IDA; a timeout does not stop code that has already started, nor does it guarantee that an already-started operating-system path access stops. Streamable HTTP and stdio use the same contract.

## Run And Client Configuration

The Windows x64 release package also provides the Inno Setup installer `ida-agent-<version>-windows-x64-setup.exe`. The installer installs the Gateway under `%LOCALAPPDATA%\Programs\ida-agent` with current-user permissions by default, and automatically deploys the Plugin to `%APPDATA%\Hex-Rays\IDA Pro\plugins`. The Start menu shortcut and the optional desktop shortcut both use the unified ida-agent icon and run `ida-mcp.exe -web`; the manager can be launched directly when installation finishes. Close IDA before installing; if the Plugin DLL is in use, the installer schedules a replacement after reboot. If the target directory already contains a same-named Plugin that the installer does not manage, Setup backs it up first and restores it on uninstall; if the installed Plugin was replaced by the user, the uninstaller identifies it by SHA256 and keeps the user's version. Setup rejects installation/uninstallation outright for reparse paths in the application and packaged skills, so that recursive file operations cannot enter external directories.

Build:

```shell
go build -o ida-mcp.exe .
python ../mcp-test-project/verify_stdio.py ./ida-mcp.exe
```

Optional HTTP:

```shell
ida-mcp.exe -transport http -listen 127.0.0.1:8743
```

HTTP provides `/mcp` and `/healthz`, allows loopback Origins only, and sets request-body, header, and read/write/idle timeouts. Non-loopback listeners are rejected until remote authentication is implemented.

Windows Web manager:

```shell
ida-mcp.exe -web
```

This mode automatically opens the local configuration page with the ida-agent icon and provides an Open/Exit system-tray menu. The page supports detection, install/update and removal for Codex, OpenCode 2, Antigravity CLI and Claude Code: Codex maintains `~/.codex/config.toml` through the official `codex mcp list/add/remove` CLI; OpenCode 2 only applies a structured patch to the highest-priority global `opencode.jsonc/json`; when neither exists, it falls back to an existing `config.json`. The IDA entry is written to `mcp.servers.ida-mcp` with `disabled: false`, `codemode: false`, `protocol: "legacy"`, and separately configured catalog/execution timeouts. The old `mcp.ida-mcp` is migrated only when the IDA configuration is updated; removal clears the IDA entry in both formats and preserves other fields and comments. Antigravity CLI maintains `~/.gemini/config/mcp_config.json`; Claude Code maintains `~/.claude.json`, or `.claude.json` under the directory set by `CLAUDE_CONFIG_DIR`. The latter two only modify the fixed `ida-agent` entry in the top-level `mcpServers` and preserve other fields (including Claude Code's `projects`). All Web APIs listen only on a random `127.0.0.1` port, and write operations require both a process-random token and a same-origin request. A configuration written directly by the user is checked for external modification before being written back, and conflicting changes are refused; external processes that do not honor file-sharing locks can still produce a very narrow race between the check and the atomic replacement. Restart the corresponding AI client after changing its configuration.

OpenCode 2 is installed first through Scoop's `versions/opencode2` or npm's `@opencode/cli@2`, and is still launched with `opencode`. The manager page's **Install MCP** writes the MCP configuration. See the [OpenCode 2 setup guide](../USAGE.md#opencode-2-setup).

Grok Build also supports MCP install/update, removal, and Skills linking. Install the CLI and add it to PATH first; the manager detects the `gork`, `agent`, and `grok` executables in turn. The manager maintains `~/.grok/config.toml` through `grok mcp add/remove --scope user` and does not modify project configuration. Skills links live under `~/.grok/skills`, and both the configuration and the Skills path honor `GROK_HOME` overrides. Status comes from `grok mcp list --json`; entries blocked by project overrides, a disabled state, or organizational policy are not shown as ready.

All modes use the original Grok-compatible behavior by default: the 11 external domain tools all use underscore names such as `ida_instances` and `ida_functions`, and tool-list change notifications (`tools.listChanged`) are disabled. The tool catalog is fixed when the Gateway starts, so no change notification is needed. Grok installation configurations use a normal stdio launch with no `--grok`; a `--grok` in an old configuration is still accepted but does not change behavior. The `action`, specific `method` and argument structure are unchanged, for example `method: "ida.instances.list"`. Reconnect or start a new Grok session after updating the Gateway; refreshing the page alone cannot replace a running old Gateway process.

When installing Antigravity MCP, a missing or blank configuration file is first initialized to `{}`; non-JSON or non-object content is first backed up to `mcp_config.json.invalid.bak` in the same directory, then re-initialized and written. An existing backup is not overwritten, and the original configuration is not overwritten if backing up fails. Reading status and removal operations do not automatically rebuild the file.

Each client card can also install the `ida-reverse-analysis` and `idapython` skills. On Windows, rather than copying documents for each client, the manager creates directory junctions under Codex's `%USERPROFILE%\.codex\skills`, OpenCode's `%USERPROFILE%\.config\opencode\skills`, Antigravity CLI's `%USERPROFILE%\.gemini\antigravity-cli\skills`, and Claude Code's `%USERPROFILE%\.claude\skills`, sharing the single source in the installation directory; Claude Code's skills also follow `CLAUDE_CONFIG_DIR`. Skill content is unified immediately after installing or upgrading the Gateway; a client still needs a restart to reload it. The manager does not overwrite existing real directories or other links, and removal and uninstallation only delete junctions that point exactly at the current ida-agent installation directory.

OpenCode 2 project configuration example:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "ida-mcp": {
        "type": "local",
        "command": ["D:/tools/ida-mcp.exe"],
        "disabled": false,
        "codemode": false,
        "protocol": "legacy",
        "timeout": {"catalog": 120000, "execution": 120000}
      }
    }
  }
}
```

The test environment can override the default `%LOCALAPPDATA%\ida-agent\instances` with `-instance-dir <path>` or `IDA_AGENT_INSTANCE_DIR`. Production configurations normally need no argument.

## Discovery And Routing

`ida.instances.list` scans the current user's registry, strictly parses fields, validates PID lifecycle, and then concurrently performs a bounded Named Pipe connect, hello and `instance.info`. Only instances whose identity and protocol both match are returned. When a target call fails to connect, the next list/select refreshes again; each RPC uses a new Pipe connection and can safely reconnect after a disconnect. The registry never exposes a Pipe locator to MCP; there is no longer a bearer token or TCP endpoint.

## Verify

```shell
gofmt -w <changed-go-files>
go vet ./...
go test ./...
go build ./...
```

Real-IDA diagnostics:

```shell
go run ./cmd/ida-agent-rpc-ping -instance-dir <path> -database-info
```

Full automated acceptance is explicitly enabled through Plugin CTest. `ida_agent_gateway_ping` verifies, within one real IDA session, direct Go RPC, Streamable HTTP through the official Go MCP client, and a real `ida-mcp.exe` stdio subprocess started by `CommandTransport`; both HTTP and stdio call all 98 callable methods through domain entries, including 92 Plugin RPCs, 6 Gateway methods, the ChangeSet lifecycle, cursor continuation, read-only assembly, before/after diff, the Debugger capability/no-process branches, and script execution. The real debugger success path is verified separately by `ida_debugger_integration` in an isolated idat that reuses the C++ handlers; a GUI-less MCP debugger call must still be denied authorization.

## Naming And Debug Permissions

This component is named `ida-mcp`, its program is `ida-mcp.exe`, and its client configuration entry is `ida-mcp`; the IDA plugin keeps the name `ida-agent`. 0.4.0 does not migrate old MCP configurations and provides no alias for the old program name; install the complete package fresh. After IDA confirms the first debugger call, all MCP clients on the current Pipe share temporary authorization; it is cleared when the Pipe is rebuilt or the database closes. The authorization wait and debugger calls have a 120-second limit.

## Agent compatibility

The following changes are available from 0.4.5. The older v0.4.4 package provides only the original 11 domain tools; check the actual `tools/list` before using direct tools. Reconnect the client after replacing the Gateway to refresh the cached tool catalog and skills.

The fixed catalog now has 23 underscore tools: the 12 direct tools in the table below plus the original 11 domain tools. A direct tool's business parameters sit at the top level and it returns the business result directly; domain calls keep the `method`/`result` wrapper and `list` → `describe` → `call`. MCP tool names use underscores; specific method identifiers keep their dots.

| Direct tool | Method |
| --- | --- |
| `ida_list_instances` | `ida.instances.list` |
| `ida_select_instance` | `ida.instances.select` |
| `ida_database_info` | `database.info` |
| `ida_get_function` | `function.get` |
| `ida_search_functions` | `function.search` |
| `ida_decompile_function` | `function.decompile` |
| `ida_disassemble_function` | `function.disassemble` |
| `ida_function_callers` | `function.callers` |
| `ida_function_callees` | `function.callees` |
| `ida_query_xrefs` | `xref.query` |
| `ida_search_strings` | `string.search` |
| `ida_read_memory` | `memory.read` |

Common reads prefer the schema provided by the direct tools. `ida_search_functions` searches by `name`, and an empty string lists functions; look up by address with `ida_get_function`. Advanced analysis, modification, debugging and scripts continue to use the domain entries. Memory `bytes`/`string` must pass `length`, `integer` must pass `widthBits`, and `pointer` accepts neither. A string `refresh=true` cannot be combined with `cursor`.

The following are MCP `tools/call` argument objects:

```json
{"name":"ida_list_instances","arguments":{}}
```

```json
{"name":"ida_search_functions","arguments":{"name":"main","limit":20}}
```

```json
{"name":"ida_decompile_function","arguments":{"address":"0x401000","maxBytes":32768}}
```

Direct read tools can use the selected instance or the sole available instance. With several databases, select one with `ida_select_instance`, or pass the `instanceId` returned by discovery; HTTP multi-session setups should prefer explicit routing to avoid shared active state. Existing domain calls still require a selected instance or an explicit one. Pagination must keep the same instance and filters; direct and domain tools share a cursor bound to the specific method.

Argument or business errors return `isError:true`, with JSON text consistent with `structuredContent`. Errors include `code`, `message`, `retryable`, `hint`, an optional `method`, and at most 8 `issues` with field, rule and expected contract. For example, a limit type error points out that `arguments.limit` should be an integer and does not echo the erroneous input value. Fix the fields as hinted and do not wrap the JSON object as a string. Unknown tools and malformed JSON-RPC requests still return protocol errors.

Each Gateway executes at most 2 requests per instance, and a FIFO queue waits for at most 8 requests, up to 5 seconds; different Gateways have independent limits. Read-only, explicitly retryable `IDA_BUSY` is retried automatically at most 2 times, and all attempts share the method's overall deadline. Writes, scripts, debugger control and timeouts are never retried automatically. A timed-out side-effect operation returns `executionState:"unknown"`, `retryable:false`; check the IDA state or a ChangeSet audit before submitting again.

Add `-diagnostics` to the Gateway to enable call diagnostics:

```powershell
.\ida-mcp.exe -diagnostics
```

Logs go to stderr and include only the tool, method, phase, elapsed time, error code and retry count, never argument values or result bodies, while stdout remains MCP JSON. `phaseMs` accumulates the elapsed time in milliseconds for `execute`, `admission`, `resolve`, `discovery`, `connect`, `handshake` and `rpc`; only phases actually passed are recorded, and nested phases and concurrent probes cannot simply be added together as the total time. When troubleshooting, keep the Gateway/client versions, the tool name and the redacted error object. Check `tools/list` and `ida_list_instances` in turn, then call `ida_database_info` with an explicit instance to distinguish catalog, routing and execution-phase problems.

The repository's `python mcp-test-project/verify_compatibility.py <gateway-executable> --http` checks 4 protocol versions and both transports in an isolated, IDA-free environment, covering catalog, recoverable errors, session recovery, text/structured consistency, diagnostics and stdio EOF. It verifies protocol and SDK behavior; it does not mean that a specific Agent or model's actual calling ability has been verified.
