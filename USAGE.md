# Usage guide

[English](USAGE.md) | [简体中文](USAGE.zh-CN.md) | [Download releases](https://github.com/ackwrap/ida-pro-agent/releases)

This guide describes ida-agent 0.4.7. Use the plugin and Gateway from the same release package.

### Automatic update checks

The Qt plugin and local Web manager check the public [`ackwrap/ida-pro-agent` stable releases](https://github.com/ackwrap/ida-pro-agent/releases) in the background, at most once every 24 hours. In IDA, use **Edit → Plugins → IDA Agent → Check for Updates...**, or **Settings... → Software Updates**, to see the installed version, check now, open the release page, or disable automatic checks. The Web manager has the same controls. Manual checks have a one-minute cooldown; network failures preserve the previous release information and permit later retries.

The two interfaces share `update-settings.json` and `update-cache.json` in `%LOCALAPPDATA%\ida-agent\ai` on Windows, `${XDG_CONFIG_HOME:-$HOME/.config}/ida-agent/ai` on Linux, and `~/Library/Application Support/ida-agent/ai` on macOS. These files are separate from IDBs and provider credentials. Drafts and prereleases are ignored. Requests contain the application version, without database or chat contents. The plugin uses its existing system proxy mode; the Web manager follows `HTTPS_PROXY` and `NO_PROXY`. Checks do not require a GitHub account. Headless plugins and stdio/HTTP MCP processes do not run update checks.

For an available update, open the release page, choose your platform package, close IDA, and install the matching plugin and Gateway together. Update checks do not install packages automatically. This feature is included in 0.4.7 and later packages.

## 1. Install and open a database

Use IDA Professional 9.4 for your platform with its bundled Qt 6.8.2. Pseudocode and semantic argument analysis also need a compatible Hex-Rays decompiler and license. Packages do not include IDA or Qt. Linux and macOS have not been comprehensively tested.

| Platform | Installation | Gateway |
| --- | --- | --- |
| Windows x64 | Close IDA and run the `*-windows-x64-setup.exe` installer. For the ZIP, copy `plugins/ida-agent-plugin.dll` to `%APPDATA%\Hex-Rays\IDA Pro\plugins`. | Installer default: `%LOCALAPPDATA%\Programs\ida-agent\ida-mcp.exe` |
| Linux x64, Ubuntu 24.04 baseline | Extract the tar.gz, run `sha256sum -c SHA256SUMS.txt`, and copy `plugins/ida-agent-plugin.so` to `${IDAUSR:-$HOME/.idapro}/plugins/` with IDA closed. Install system OpenSSL 3 and CA certificates. | Keep the extracted `ida-mcp` and `skills/` in a stable directory. |
| macOS 15+, Intel and Apple Silicon | Open the DMG, run **IDA Agent Installer.app**, and click **Install**. The default plugin directory is `~/.idapro/plugins/`; select your `IDAUSR` if customized. | `~/Library/Application Support/ida-agent/bin/ida-mcp` |

Start IDA and open a binary or IDB. The plugin appears under **Edit → Plugins → IDA Agent**. A database must remain open for live analysis. Use the Gateway under the same OS user as IDA.

For Linux headless use, launch through the package's wrapper so IDAT can find its matching Qt libraries:

```sh
./idat-with-agent /absolute/path/to/ida-9.4/idat [your usual IDA arguments]
```

macOS packages use ad-hoc signatures and are not Developer ID notarized. See the installation instructions included in each package for platform details.

## 2. Choose a way to use the plugin

- **Built-in AI Chat:** configure a model provider inside IDA. The built-in agent connects directly to that provider and does not require the Gateway.
- **External MCP client:** use your client's model/provider settings and connect it to the Gateway. Configuring a provider in IDA is not required for this route.

### Built-in AI Chat

1. Open **Edit → Plugins → IDA Agent → Provider Settings...**.
2. Select the OpenAI or Claude preset, or add a custom provider. Set the API mode, Base URL and API key.
3. Use **Test Connection**, then **Refresh Models**. If model discovery is unavailable, use **Add Model...** with the provider's exact model ID.
4. Enable the model, set a default model and provider, then save with **Apply** or **OK**.
5. Open **Edit → Plugins → IDA Agent → Open AI Chat** and request an analysis.

| API mode | Base URL example | Operation appended by the plugin |
| --- | --- | --- |
| Responses | `https://api.openai.com/v1` | `/responses` |
| Chat Completions | The compatible service's API prefix, for example `https://api.example.com/v1` | `/chat/completions` |
| Anthropic Messages | `https://api.anthropic.com/v1` | `/messages` |

Enter the API prefix, without the operation suffix. Select a mode and model that your provider actually supports. **Test Connection** checks model discovery; verify chat, streaming and tool calling with a short analysis request.

API keys and saved proxy passwords are stored as plaintext in user-private files. Default provider settings locations are:

- Windows: `%LOCALAPPDATA%\ida-agent\ai\providers.json`
- Linux: `${XDG_CONFIG_HOME:-$HOME/.config}/ida-agent/ai/providers.json`
- macOS: `~/Library/Application Support/ida-agent/ai/providers.json`

The selected provider receives conversation content and relevant analysis context/results. Remove credentials before sharing configuration or logs.

### External MCP client: configuration manager

On Windows, open the installed shortcut or run:

```powershell
& "$env:LOCALAPPDATA\Programs\ida-agent\ida-mcp.exe" -web
```

For portable Windows use, run `ida-mcp.exe -web` from the extracted directory. On Linux, run `./ida-mcp -web`; keep the terminal open and use the local URL printed in its log. On macOS, open **Open IDA Agent.command** beside the installed Gateway, then open the local URL shown in Terminal.

The manager supports Codex, OpenCode 2, Claude Code, Antigravity CLI, Grok Build and ZCode. Use **Install MCP** / **Update MCP** on the relevant client card to install/update the `ida-mcp` entry. Where available, link the optional skills:

- `ida-reverse-analysis`: method discovery, analysis workflows and evidence interpretation.
- `idapython`: IDAPython scripting through the `ida_scripts` tool.

Restart the client after changing its configuration or skills. The manager's `-web` mode configures clients; each configured client launches its own stdio Gateway.

### OpenCode 2 setup

With Scoop already installed on Windows, install the v2 package from the versions bucket:

```powershell
scoop bucket add versions
scoop install versions/opencode2
opencode --version
```

If Scoop's v1 `opencode` package is installed, close OpenCode and run `scoop uninstall opencode` first. Keep your configuration and follow the [official migration guide](https://opencode.ai/v2/docs/migrate-v1/). Both versions use the `opencode` command; the version output should show `2.x`. See the [Scoop v2 manifest](https://github.com/ScoopInstaller/Versions/blob/master/bucket/opencode2.json).

Alternatively, install v2 with `npm install -g @opencode/cli@2`. Remove a previous npm `opencode-ai` installation before switching. See the [official OpenCode 2 installation guide](https://opencode.ai/v2/docs/).

Open the manager and use **Install MCP** / **Update MCP** on **OpenCode 2**. The manager writes the highest-priority global `~/.config/opencode/opencode.jsonc` or `opencode.json`, honoring `OPENCODE_CONFIG_DIR`. It uses `mcp.servers.ida-mcp`, `disabled: false`, separate catalog/execution timeouts, and `codemode: false` so the 23 IDA tools appear directly. The classic MCP handshake uses `protocol: "legacy"`. See the [OpenCode 2 MCP reference](https://opencode.ai/v2/docs/mcp-servers/).

Existing v1 IDA entries show **update needed**. Updating moves only `mcp.ida-mcp` into the v2 server map and preserves other servers, settings, and comments. **Remove** clears the IDA entry in both formats. Skills remain under `~/.config/opencode/skills`. If a background server is running, use `opencode reload` to reload its configuration, then use `opencode mcp list` to verify the connection.

### Manual stdio configuration

For clients that use a JSON `mcpServers` object, replace the command with your actual absolute path:

```json
{
  "mcpServers": {
    "ida-mcp": {
      "command": "C:/tools/ida-agent/ida-mcp.exe",
      "args": []
    }
  }
}
```

On Linux/macOS, use the absolute path to `ida-mcp` without `.exe`. Expand `~` to the full home directory in client configuration. Other clients use different configuration formats; use the manager when available. Stdio is the default and needs no special launch flag, including for Grok.

### Optional local HTTP

Start the Gateway explicitly:

```powershell
.\ida-mcp.exe -transport http -listen 127.0.0.1:8743
```

On Linux/macOS, use `./ida-mcp` with the same arguments. Set the client's MCP URL to `http://127.0.0.1:8743/mcp`. This is loopback Streamable HTTP; non-loopback listeners are rejected. `-web` starts a separate configuration page.

## 3. Discover tools and run an analysis

The Gateway exposes 23 MCP tools: 12 [common direct tools](#gateway-compatibility-in-045) and these 11 domain tools:

| Tool | Purpose |
| --- | --- |
| `ida_instances` | Discover and select open IDA databases |
| `ida_database` | Database information, survey, segments and saving |
| `ida_functions` | Function lookup, pseudocode, disassembly and call relationships |
| `ida_search` | Strings, bytes, instructions, listings and cross-references |
| `ida_symbols` | Imports, exports, symbols and global values |
| `ida_types` | Types, structures and typed values |
| `ida_analysis` | Argument origins, caller tracing and guard evidence |
| `ida_changes` | ChangeSet preview, apply, rollback and audit |
| `ida_patch` | Assembly and reversible byte/integer patches |
| `ida_debugger` | Debugger configuration, process control and inspection |
| `ida_scripts` | IDAPython or IDC script execution |

**MCP tool names use underscores; method identifiers retain dots.** For example, `ida_functions` is a tool and `function.search` is a method. Follow `list` → `describe` → `call`: discover methods, obtain the current input schema, then execute with matching arguments.

The examples below are the `params` objects for MCP `tools/call`, not complete JSON-RPC requests.

Discover the instance methods, then describe `ida.instances.list`:

```json
{"name":"ida_instances","arguments":{"action":"list"}}
```

```json
{"name":"ida_instances","arguments":{"action":"describe","method":"ida.instances.list"}}
```

List open databases:

```json
{"name":"ida_instances","arguments":{"action":"call","method":"ida.instances.list","arguments":{}}}
```

Use an actual `instanceId` from the result. Discover/describe `ida.instances.select` before selecting it:

```json
{"name":"ida_instances","arguments":{"action":"describe","method":"ida.instances.select"}}
```

```json
{"name":"ida_instances","arguments":{"action":"call","method":"ida.instances.select","arguments":{"instanceId":"00000000-0000-4000-8000-000000000000"}}}
```

The UUID above is a placeholder; replace it with the ID returned by discovery. Selection belongs to this Gateway process. Alternatively, pass the real `instanceId` in each operation's inner `arguments`.

Discover function methods and describe a search:

```json
{"name":"ida_functions","arguments":{"action":"list"}}
```

```json
{"name":"ida_functions","arguments":{"action":"describe","method":"function.search"}}
```

Search the selected database:

```json
{"name":"ida_functions","arguments":{"action":"call","method":"function.search","arguments":{"name":"main","limit":20}}}
```

Use `describe` for exact arguments, budgets and continuation fields. Addresses use hexadecimal strings such as `0x140001000`. Do not invent method names or copy a cursor across Gateway restarts.

Example prompts for either AI route:

- “List the open IDA databases, select the one for this binary, and summarize its imports and entry points.”
- “Find the parsing function, inspect its pseudocode and callers, and cite the relevant addresses.”
- “Trace argument 0 at this call address through known direct callers and separate recovered evidence from unknown boundaries.”
- “Preview a rename for this function and show the proposed change before applying it.”

Supported IDB edits use ChangeSet preview → apply → rollback. Debugger requests require the IDA permission dialog and a compatible process state; headless IDA cannot grant that GUI permission. Arbitrary scripts are not sandboxed or automatically reversible. Partial traces and guard evidence do not establish safety or exploitability.

## 4. Upgrade to 0.4.4

1. Close IDA and stop clients using the old Gateway. Install the complete new package.
2. Update custom scripts and tool allowlists from dotted public tool names such as `ida.functions` to `ida_functions`. Keep dotted method identifiers such as `function.search` and `ida.instances.list` unchanged.
3. Refresh/relink packaged skills if used, then restart the Gateway and MCP client so they load the new catalog and instructions.

The fixed catalog and Grok compatibility behavior are now defaults in stdio and HTTP. No `--grok` flag is required. Existing `--grok` arguments are accepted as a deprecated no-op. Tool-list change notifications are disabled; reconnect after upgrading.

For upgrades from before the 0.4.0 component rename, remove the old MCP entry and configure `ida-mcp`; old executable/configuration aliases and automatic migration are not provided.

## 5. Troubleshooting

| Symptom | Check |
| --- | --- |
| No IDA Agent menu | Verify IDA 9.4, the plugin file in the active user plugin directory, and the matching platform package. Restart IDA after installation. |
| Instance list is empty | Open a database, confirm the plugin loaded, and run the Gateway as the same user and in the same OS environment as IDA. |
| Client still shows dotted tool names | Stop the old Gateway and reconnect/restart the client. Update custom tool allowlists. Refreshing the configuration page does not replace an existing client process. |
| Method or argument rejected | Use `list` and `describe` on the correct domain tool; keep dotted method identifiers and match the returned schema. |
| Provider test succeeds but chat fails | Check API mode, Base URL prefix, exact model ID, streaming/tool support and proxy settings. |
| Windows chat reports `WinHttpQueryDataAvailable` error 12019 | Upgrade to 0.4.6 and restart IDA. This release fixes request cancellation during gaps in streamed responses; configured idle and overall deadlines still apply. |
| External history cannot be saved before the database is packed | Upgrade to 0.4.6. Windows now resolves an unpacked database through its existing parent directory; also check access to the external history directory. |
| Pseudocode unavailable | Verify the required Hex-Rays decompiler/license and the target architecture. |
| Debugger request fails | Check the IDA permission dialog, selected debugger and process state. |

Report reproducible problems in [Issues](https://github.com/ackwrap/ida-pro-agent/issues) with OS/CPU, IDA and ida-agent versions, steps and relevant logs with credentials removed.

## Chat fixes and client regression in 0.4.6

Install the complete 0.4.6 package with IDA closed, then restart IDA and reconnect MCP clients. Windows streamed chat now waits asynchronously across delayed response headers and SSE frames, while cancellation, idle deadlines and overall deadlines remain effective. This fixes the request-state failure that could surface as WinHTTP error 12019.

Windows can also save external chat history while a database's `.i64` file has not yet been packed. The history key remains consistent after packing, and chat history stays outside the IDB.

The [client regression guide](mcp-test-project/CLIENT_REGRESSION.md) documents the official Python SDK tests and reproducible Codex, Claude Code and OpenCode entry points. CI exercises SDK calls against simulated RPC peers on Windows, Linux and macOS. Actual Agent/model calls and licensed IDA integration require separate evidence. The public catalog remains the same 23 tools introduced in 0.4.5.

## Gateway compatibility in 0.4.5

These additions are available from 0.4.5. Older v0.4.4 packages expose the original 11 domain tools; check the running `tools/list` response before using a direct tool. Reconnect the client after replacing the Gateway so it refreshes its cached catalog and skills.

The fixed catalog has 23 underscore-named tools: 12 direct tools below and the existing 11 domain tools. Direct tools accept the operation parameters at the top level and return the operation result directly. Domain calls keep their `method`/`result` envelope and `list` → `describe` → `call` workflow. MCP names contain underscores; domain method identifiers keep dots.

| Direct tool / 直接工具 | Method / 方法 |
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

For common reads, use the direct tool's advertised schema. `ida_search_functions` takes `name` (an empty string lists functions); use `ida_get_function` to resolve an address. Advanced analysis, writes, debugging and scripts continue through the domain tools. For memory reads, `bytes`/`string` require `length`, `integer` requires `widthBits`, and `pointer` accepts neither. String `refresh=true` cannot be combined with a cursor.

The following objects are MCP `tools/call` parameters:

```json
{"name":"ida_list_instances","arguments":{}}
```

```json
{"name":"ida_search_functions","arguments":{"name":"main","limit":20}}
```

```json
{"name":"ida_decompile_function","arguments":{"address":"0x401000","maxBytes":32768}}
```

Only direct read tools can use the sole available instance without prior selection. With multiple databases, use `ida_select_instance` or pass a discovered `instanceId`; explicit routing also avoids shared active-instance state in HTTP sessions. The domain workflow still requires selection or an explicit instance. Keep the same instance and filters when continuing pages; aliases use the same method-bound cursors as domain calls.

Tool argument and operation errors return `isError:true`, with matching JSON text and `structuredContent`. Errors include `code`, `message`, `retryable`, `hint`, optional `method`, and up to eight `issues` containing a field, rule and expected contract. For example, an invalid limit identifies `arguments.limit` and its expected integer type without echoing the input value. Correct those fields rather than encoding an object as a JSON string. Unknown tools and malformed JSON-RPC messages remain protocol errors.

Each Gateway keeps two active requests per instance, with a FIFO queue of at most eight waiting requests for at most five seconds. This limit is per Gateway process. Only a read-only, explicitly retryable `IDA_BUSY` gets up to two automatic retries under the same method deadline. Writes, scripts, debugger control and timeouts are not automatically retried. A side-effecting timeout reports `executionState:"unknown"` and `retryable:false`; inspect the IDA state or ChangeSet audit before resubmitting it.

For call diagnostics, add `-diagnostics` to the Gateway arguments:

```powershell
.\ida-mcp.exe -diagnostics
```

Diagnostics go to stderr and contain only tool, method, stage, duration, error code and retry count. They exclude input values and result content; stdout remains MCP JSON. To investigate failures, record the Gateway version, client version, tool name and redacted error object. Start by checking `tools/list`, `ida_list_instances`, then `ida_database_info` with an explicit instance. This separates catalog, instance routing and execution failures.

The repository provides `python mcp-test-project/verify_compatibility.py <gateway-executable> --http` for isolated no-IDA protocol checks across four protocol versions and both transports. It checks the catalog, correctable errors, session recovery, text/structured consistency, diagnostics and stdio EOF. This is protocol/SDK validation; it does not prove a particular Agent or model chooses valid calls.
