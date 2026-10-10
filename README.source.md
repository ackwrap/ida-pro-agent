# ida-agent

**English** | [简体中文](README.source.zh-CN.md)

> [!IMPORTANT]
> **Windows x64 desktop, Linux/WSL2 x86_64 and macOS Universal 2 source builds.**
> The supported host is **IDA Professional 9.4**, with its bundled **Qt 6.8.2** runtime. Ubuntu 24.04 x86_64 supports MCP and the opt-in AI Chat panel; see [Linux build and usage](ida-agent-plugin/README-LINUX.md). macOS Universal 2 source builds and packaging are described in [macOS build and usage](ida-agent-plugin/README-MACOS.md). Linux packaging remains unsupported.

An IDA security analysis assistant with two entry points:

- **Built-in AI:** chat inside IDA, configure model providers, attach analysis context, and let the agent discover and call analysis tools. The built-in agent connects directly to your provider and works without the Gateway.
- **MCP Gateway:** connect an external AI client to running IDA databases through a separate executable. Supports stdio and explicitly enabled loopback Streamable HTTP.

Both use the same IDA/Hex-Rays analysis services. IDA and any required Hex-Rays decompiler licenses must be provided separately.

[Features](#features) · [Install](#install) · [AI providers](#configure-ai-providers) · [MCP](#connect-an-mcp-client) · [Limitations](#current-limitations) · [Build](#build-from-source)

## Features

- Inspect functions, disassembly, pseudocode, cross-references, strings, types, and database metadata.
- Trace the origin of a call argument within a function, or follow parameter dependencies upward through known direct callers with separate calling contexts.
- Extract comparison conditions, required control-flow branches, and their relationship to the selected call argument.
- Preview, apply, and roll back supported IDB changes through ChangeSets; inspect byte patches and before/after differences.
- Run IDAPython/IDC scripts and use debugger tools when the corresponding IDA capabilities are available.
- Use the built-in AI Console, or connect external clients to 12 common direct MCP tools and 11 domain tools. Domain tools use progressive `list` → `describe` → `call` discovery. Available methods and exact arguments come from the running tool catalog.

Analysis output includes evidence, uncertainty, and budget limits. See [Current limitations](#current-limitations) before interpreting a result as a security finding.

## Install

### Requirements for use

| Component | Requirement |
| --- | --- |
| Operating system | Windows x64; Ubuntu 24.04 x86_64; macOS 15+ Universal 2 (arm64 runtime validation pending) |
| IDA | **IDA Professional 9.4**; the AI UI uses its bundled Qt 6.8.2 |
| Decompiler | A compatible, licensed Hex-Rays decompiler for pseudocode, argument tracing, and guard evidence |
| Built-in AI | Access to an API provider and a model that supports the selected API mode, streaming, and tool calling |
| External MCP | Gateway and IDA in the same OS/user account; Windows clients can launch the Linux Gateway through wsl.exe |

Build tools are only needed when compiling from source.

### Installer or portable package

Use the Windows artifacts for the release you are installing:

- `ida-agent-<version>-windows-x64-setup.exe`: per-user installer; installs the Gateway and deploys the plugin to the IDA user plugin directory.
- `ida-agent-<version>-windows-x64.zip`: portable package containing the Gateway, `plugins/ida-agent-plugin.dll`, and optional client skills.

1. Close IDA before installing or replacing the DLL.
2. Run the installer. The default Gateway directory is `%LOCALAPPDATA%\Programs\ida-agent`. For portable use, extract the package and copy `plugins/ida-agent-plugin.dll` to `%APPDATA%\Hex-Rays\IDA Pro\plugins`.
3. Start IDA and open a database. Find **Edit → Plugins → IDA Agent**.
4. Choose **Provider Settings...** for built-in AI, or configure an external MCP client as described below.

Version 0.4.0 requires a fresh installation of both components. Uninstall the previous package, remove its MCP entry from your clients, and configure the new `ida-mcp` entry. See [installation notes](docs/UPGRADING.md).

Source builds include daily background update checks in the Qt plugin and the local `-web` manager. **Edit → Plugins → IDA Agent → Check for Updates...** opens the update controls; **Settings... → Software Updates** and the Web manager share an automatic-check preference and cache outside the IDB. Checks use published stable releases from [`ackwrap/ida-pro-agent`](https://github.com/ackwrap/ida-pro-agent/releases), compare numeric versions, and keep offline failures out of analysis and MCP responses. Manual checks have a one-minute cooldown. Open the release page, close IDA, and install the matching plugin/Gateway package when a newer version is available. Headless plugins and stdio/HTTP MCP processes do not check for updates.

## Configure AI providers

These settings belong to the **built-in IDA AI Console**. External MCP clients use their own model-provider settings.

1. Open **Edit → Plugins → IDA Agent → Provider Settings...**.
2. Select the **OpenAI** or **Claude** preset, or click **Add...** to create a custom provider. Set **Name**, **Type**, **API Mode**, **Base URL**, and **API Key**.
3. Click **Test Connection**, then **Refresh Models**. If model discovery is unavailable, use **Add Model...** and enter the exact model ID supplied by your provider.
4. Enable the model and choose **Set Default**. Select the provider and choose **Set as Default**. Use **Edit Metadata...** to align context length, maximum output, and optional reasoning settings with the model's actual capabilities.
5. Click **Apply** or **OK**, then choose **Edit → Plugins → IDA Agent → Open AI Chat**.

### API modes and Base URL

The following values describe the application's built-in presets and routing:

| Provider setup | Type | API Mode | Base URL | Chat endpoint appended by ida-agent |
| --- | --- | --- | --- | --- |
| OpenAI preset | `OpenAI Compatible` | `Responses` | `https://api.openai.com/v1` | `/responses` |
| OpenAI-compatible service | `OpenAI Compatible` | `Chat Completions` or `Responses`, as supported by the service | The service's API prefix, for example `https://api.example.com/v1` | `/chat/completions` or `/responses` |
| Claude preset | `Anthropic Messages` | `Messages` | `https://api.anthropic.com/v1` | `/messages` |

**Base URL is the API prefix, not the full operation URL.** Do not append `/chat/completions`, `/responses`, `/messages`, or `/models`. Model discovery appends `/models` to the same prefix. A custom provider defaults to Chat Completions; select Responses only if that service implements it.

- OpenAI-compatible requests use `Authorization: Bearer <API Key>`; Anthropic requests use `x-api-key` and an `anthropic-version` header by default. Custom headers can be configured under **Advanced**.
- **Test Connection checks the model-list endpoint.** It does not validate chat generation, streaming, tool calling, or every model capability. Verify those with a short chat and a simple analysis request after saving.
- A service without model discovery may still work with a manually added model. Compatibility depends on its request format, streaming events, and tool-call responses; the “OpenAI Compatible” label alone is not a guarantee.
- **Advanced → Proxy** offers System Proxy, Direct Connection, or HTTP(S) Proxy. HTTP proxies can carry HTTPS through CONNECT; SOCKS and TLS connections to the proxy itself are not supported.

Provider settings normally live in `%LOCALAPPDATA%\ida-agent\ai\providers.json`. **API keys and saved proxy passwords are stored as plaintext**, with current-user file permissions; they are not encrypted at rest. Do not publish that file in a repository or issue. See the [installation notes](docs/UPGRADING.md) for current directory rules.

The built-in agent sends chat content and the analysis context/tool results used in that conversation to the selected provider. Choose a provider appropriate for the binaries and data you analyze.

## Connect an MCP client

Version 0.4.5 adds 12 direct tools alongside the 11 domain tools; earlier v0.4.4 packages expose only the domain tools. See [Gateway compatibility details](ida-mcp/README.md#agent-compatibility).

Keep IDA open with a database loaded. The Gateway discovers plugin instances for the current Windows user; the Gateway does not need to be placed in the IDA installation directory.

### Local configuration manager

For the default installer location, run:

```powershell
& "$env:LOCALAPPDATA\Programs\ida-agent\ida-mcp.exe" -web
```

For a portable installation, run `ida-mcp.exe -web` from its extracted directory. The local page can configure Codex, OpenCode, Claude Code, Antigravity CLI, Grok Build, and ZCode, and link the optional `ida-reverse-analysis` and `idapython` skills. Restart the client after changing its configuration.

On Windows, Codex detection also checks common npm/Scoop installations and the Codex desktop app's bundled CLI when the manager's inherited `PATH` is stale. npm launchers are resolved to their native `codex.exe`, so detection and MCP configuration do not depend on Node.js being in `PATH`. For a custom installation, set `IDA_MCP_CODEX_PATH` to the absolute path of `codex.exe` and restart the manager.

ZCode uses the native user-level `~/.zcode/cli/config.json` (`mcp.servers`) and `~/.zcode/skills/`, without requiring a CLI in `PATH`. Existing settings and other MCP servers are preserved. When `.agents/mcp.json` is the active fallback, its servers are copied into the native configuration before adding ida-mcp so they remain available; the shared file is left intact. If removal would reactivate a shared ida-mcp entry, a disabled native entry (`enable: false`) is kept to prevent that. See [ZCode MCP configuration rules](https://zcode.z.ai/en/docs/mcp-services).

`-web` runs the configuration manager and system tray; it is not the MCP HTTP server. Configured clients start their own stdio Gateway process.

### Manual stdio configuration

For clients that use an `mcpServers` JSON object, adapt the absolute executable path:

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

Other clients use different configuration formats; see the [Gateway documentation](ida-mcp/README.md). Stdio is the default and needs no extra arguments. Updated source builds also offer `ida_list_instances` and `ida_select_instance` to discover and select a database; an empty list means no usable instance was found.

### Optional loopback HTTP

From the Gateway directory:

```powershell
.\ida-mcp.exe -transport http -listen 127.0.0.1:8743
```

Configure the client's MCP URL as `http://127.0.0.1:8743/mcp`. Non-loopback listeners are rejected; remote authenticated MCP hosting is not implemented.

## Current limitations

| Area | Current boundary |
| --- | --- |
| Platform and host | Windows x64 supports the full desktop plugin. Ubuntu 24.04 x86_64 supports MCP and an opt-in AI panel with Linux IDA 9.4. macOS 15+ supports Universal 2 builds; arm64 runtime validation is pending. Linux release packages remain unsupported. |
| Hex-Rays and target coverage | Pseudocode and semantic argument/guard analysis require a compatible decompiler and license. Semantic integration fixtures cover Windows x64 targets with `/Od` and `/O2`; they do not validate every processor architecture or binary pattern. |
| Cross-function tracing | `analysis.trace_argument_callers` expands known direct callers, defaults to 2 levels, and permits at most 5. It does not recover unknown indirect callers, native tail calls, callee-return summaries, or heap aliases. Recursion and prototype/ABI mismatches stop expansion. Known caller coverage is not proof of a complete caller set. |
| Guard evidence | `analysis.guard_evidence` is function-local. Comparisons and required CFG edges do not prove sufficient validation, runtime path feasibility, safety, or exploitability. There is no symbolic path solver or loop-invariant solver. |
| Other data-flow tools | `analysis.trace_data_flow` uses cross-reference BFS (`xref_bfs`); it is not semantic taint analysis. Use the argument-tracing tools for their explicitly bounded microcode model. |
| String search | `string.search` and `string.search_regex` reuse IDA's string list by default. Set `refresh: true` on the first page to rebuild; it cannot accompany `cursor`. First-time list construction and explicit refreshes may be slow, especially during debugging. Pagination is not a snapshot; restart after the list changes. |
| Budgets and cancellation | Traces can be partial or truncated. Deadlines limit waiting, but cannot preempt SDK microcode generation or a script that has already started inside IDA. |
| Writes and scripts | Only supported ChangeSet actions have preview/apply/rollback behavior. Arbitrary scripts are not sandboxed and are not automatically reversible; they can modify the IDB, access the host/network, or block IDA. Built-in AI uses session approval policies; MCP execution permissions belong to the external client. |
| Providers and credentials | Only OpenAI-style Responses/Chat Completions and Anthropic-style Messages are implemented. Provider/model compatibility varies. Model-list success does not prove tool support. Saved credentials are plaintext on disk. |
| Local connectivity and debugging | Same-user discovery uses Windows Named Pipes or Linux Unix sockets; HTTP is loopback-only. Local Linux ELF debugger services have real-IDA coverage; Linux GUI consent and remote debugging remain unvalidated. Operations depend on the selected backend and process state. |

For exact evidence semantics and budgets, read the [local argument/guard contract](protocol/semantic-analysis.md) and [caller-tracing contract](protocol/argument-callers.md). Treat `partial`, `truncated`, unknown boundaries, and inferred IDB types as part of the result.

## Build from source

### Build environment

| Dependency | Requirement |
| --- | --- |
| Host | Windows x64 |
| Compiler | Visual Studio 2022 or Build Tools 2022, with Desktop development with C++, MSVC x64 tools, and a Windows SDK; project code uses C++17 |
| CMake and generator | CMake **3.25+** and Ninja |
| Go | **1.25.0+** for the Gateway |
| Python | Python 3; **3.10+ recommended** for the build and packaging scripts |
| IDA SDK | The repository's pinned `ida-sdk` submodule |
| Qt development files | The tracked Qt **6.8.2** headers and configuration under `qt-sdk/qt-6.8.2-win` |
| Qt import libraries | Included in the pinned `ida-sdk/src/lib/x64_win_qt`; compiling and packaging do not require an IDA installation |
| Installer only | Inno Setup **6** (`ISCC.exe`); not needed for a portable-only package |
| Real IDA integration tests | PowerShell **7**, `idat.exe`, and valid IDA/Hex-Rays licenses, in addition to the build tools |

Use an x64 Native Tools shell for VS 2022 with PowerShell, and make `cmake`, `ninja`, `go`, and `python` available on `PATH`. The first build may download Go modules and `nlohmann/json` 3.12.0 if it is not already available.

Go 1.25 or newer is required because Windows Named Pipe deadlines rely on asynchronous-handle support in `os.NewFile`.

### Compile and run unit tests

After cloning the repository, run from its root. An IDA installation is not required for this build or the unit tests:

```powershell
git submodule update --init ida-sdk

cmake -S ida-agent-plugin -B build/ida-agent-plugin -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DBUILD_TESTING=ON
cmake --build build/ida-agent-plugin
ctest --test-dir build/ida-agent-plugin --output-on-failure

go -C ida-mcp vet ./...
go -C ida-mcp test ./...
go -C ida-mcp build -o ../build/ida-mcp.exe .
```

The plugin is written to `build/ida-agent-plugin/ida-runtime/plugins/ida-agent-plugin.dll`, and the command above puts the Gateway at `build/ida-mcp.exe`. Release builds do not deploy the DLL to IDA automatically; close IDA before copying it into the user plugin directory.

CMake checks the Qt 6.8.2 headers and links the official `QT`-namespaced import libraries from the pinned IDA SDK. The plugin uses IDA's bundled Qt DLLs when loaded; the build and release package do not include Qt runtime DLLs. Stock Qt binaries use different symbols and cannot replace IDA's Qt. With the AI Console enabled, even Debug builds use the matching Release DLL CRT (`/MD`).

For an explicit local rebuild of the import libraries, pass `-DIDA_AGENT_IDA_QT_RUNTIME_DIR=<ida-dir>` to CMake, or set the environment variable of the same name for the release script. This optional path validates the installed IDA 9.4 / Qt 6.8.2 versions and `QT` namespace. Clear the CMake cache setting with `-DIDA_AGENT_IDA_QT_RUNTIME_DIR=` to return to SDK imports.

### Optional integration tests

To include real IDA tests, reconfigure the same build directory and run CTest:

```powershell
cmake -S ida-agent-plugin -B build/ida-agent-plugin `
  -DIDA_AGENT_ENABLE_INTEGRATION_TESTS=ON `
  '-DIDA_INSTALL_DIR=C:/Program Files/IDA Professional 9.4'
cmake --build build/ida-agent-plugin
ctest --test-dir build/ida-agent-plugin -L integration --output-on-failure
```

Default CTest runs unit tests only. `mcp-test-project/verify_stdio.py <gateway-executable>` checks the 23 underscore-named direct and domain tools, empty discovery, and clean stdio shutdown without IDA. For a live plugin check, with IDA open, use:

```powershell
go -C ida-mcp run ./cmd/ida-agent-rpc-ping -database-info
```

### Package a release

Run validation first: the packaging script intentionally disables plugin tests.

```powershell
python release/build_release.py --clean
```

Use `--no-installer` to build only the portable directory and ZIP without Inno Setup. Intermediate files go to `build/release/`; release artifacts go to `release/dist/`. Both locations are ignored by Git.

## GitHub Actions

The Windows workflows validate the Gateway, build the full plugin with its AI UI, and run C++ unit tests; version tags or manual release runs also build the portable ZIP and installer. The Linux workflow builds the basic MCP plugin and independent AI backend and runs Go/C++ tests, including Agent and panel models, on Ubuntu 24.04. The real Linux Qt panel test runs locally with a licensed IDA installation and a GUI session. See [Linux environment requirements](ida-agent-plugin/README-LINUX.md#linux-environment-requirements) for toolchain and system dependencies. These CI builds use public SDK dependencies and need no private download URL or installed IDA; cross-repository publishing uses the separate token described below. See the [Actions setup guide](release/README.md) for triggers and artifact download steps.

Project-owned source is licensed under [MIT](LICENSE) and automatically synchronized from `ackwrap/ida-agent` master to the public [`ackwrap/ida-pro-agent`](https://github.com/ackwrap/ida-pro-agent) main branch. Public Windows/Linux workflows build and test the synchronized source. Complete release packages are built in the private development repository using its platform-specific Qt inputs. Version tags automatically publish packaged binaries to the public [`ackwrap/ida-pro-agent`](https://github.com/ackwrap/ida-pro-agent/releases) repository after validation; manual runs publish only when **publish** is selected. Configure the private repository secret `IDA_AGENT_RELEASE_TOKEN` with Contents write access to that public repository. Synchronization preserves the public repository history and existing release tags; credentials, local plans and private Qt link bundles are excluded. Third-party terms are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). See the [publishing setup](release/README.md#configure-public-publishing). Hosted builds do not run licensed IDA integration tests.

## Repository and documentation

| Path | Purpose |
| --- | --- |
| [`ida-agent-plugin/`](ida-agent-plugin/README.md) | IDA plugin, built-in AI, analysis services, and Internal RPC |
| [`ida-mcp/`](ida-mcp/README.md) | MCP transport, instance discovery, and local client configuration |
| [`protocol/`](protocol/README.md) | Shared protocol contracts, schemas, and fixtures |
| [`skills/`](skills/) | External-client IDA analysis and IDAPython skills |
| [`release/`](release/) | Windows packaging and installer scripts |
| [`docs/UPGRADING.md`](docs/UPGRADING.md) | Fresh installation and naming rules |
| [`AGENTS.md`](AGENTS.md) | Repository development and validation rules |

The IDA plugin and installer use `ida-agent`; the Gateway executable, MCP server, and client configuration entry use `ida-mcp`. MCP tools use underscore names such as `ida_functions`; Internal RPC method names retain their dots. Some detailed component documents are currently in Chinese; the two root READMEs cover the same installation, configuration, build, and limitation information.

## MCP debugger permission

The first `debugger.*` call displays a confirmation dialog inside IDA. Allowing it grants all MCP clients access to debugging through that IDA instance's current Pipe, including process control, breakpoints, and process-memory writes. Later calls do not prompt again. The decision is stored only in memory and resets when the Pipe is recreated or the database closes. Denial also lasts for that Pipe. Headless IDA cannot approve and denies access.

After approval, use `debugger.backends` and `debugger.select` to choose a debugger, or select one in IDA. Register, stack, thread, module, and memory operations require a suspended target. `instance.info` refreshes debugger availability on each request. Tools allow up to 120 seconds for the initial confirmation and operation. Built-in AI retains its own conversation permission policy.

`capabilities.ui=false` means MCP UI inspection/control tools (such as cursor or selection access) are not available. It does not mean IDA has no GUI, and it does not prevent the debugger permission dialog. A paused target reports `state=suspended`, `running=false`, and `suspended=true`.

### Debugger setup and process control

Call these methods through `ida_debugger` with `action: "call"`; use `action: "describe"` to inspect each schema. Supply `instanceId` when no active instance is selected.

| Method | Purpose | Required process state |
| --- | --- | --- |
| `debugger.backends` | List installed debugger `name`/`remote` pairs and current selection | No active process; works before debugger selection |
| `debugger.select` | Load the exact `name`/`remote` pair returned above | No active process |
| `debugger.configuration` | Read launch and remote options, with `hasPassword` instead of a password | Any state; works before debugger selection |
| `debugger.configure` | Set `path`, `arguments`, `directory`, `host`, `port`, or `password` | No active process |
| `debugger.processes` | List candidate PIDs using the selected local or remote debugger | No active process |
| `debugger.attach` | Attach to an explicit `pid` | No active process |
| `debugger.suspend` | Request a pause | Running |
| `debugger.detach` | Detach without terminating the target | Suspended |

To launch: `backends` → `select` → `configure` → `start` → `info`. To attach: `select` → configure remote options if needed → `processes` → `attach` → `info`. Pause a running target and wait for `state: "suspended"` before stepping, reading registers, or detaching. Existing `debugger.control` supports `continue`, `step_into`, `step_over`, `step_until_return`, and `run_to`; `debugger.breakpoints` supports adding, deleting, enabling/disabling, and conditions.

`configure` requires at least one field. Omitted fields are preserved, empty strings clear fields, and `port: -1` restores the backend's default port; other valid ports are 1–65535. Changing options does not start a process. Paths are interpreted by IDA/the selected debugger, including remote backend rules. Passwords are not returned in results or displayed in built-in AI approval summaries. Built-in AI uses corresponding `ida_debugger_*` tools and its existing conversation side-effect policy.

`processes.limit` defaults to 100 and is capped at 1000. Results include `total` and `truncated`; there is no pagination. The limit bounds returned entries, **not** the time IDA spends enumerating processes, particularly on a remote server. `accepted: true` is a request receipt; inspect `debugger.info` for subsequent state and do not blindly retry a timed-out mutation. Remote server availability, permissions, target architecture, and debugger support still determine whether launch/attach succeeds. Register writes, data watchpoints, and an event subscription stream are not exposed by these methods.
