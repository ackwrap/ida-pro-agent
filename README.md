# ida-agent

[English](#english) | [中文](#中文)

> **Windows x64, Linux x64 and macOS Universal 2 / Windows、Linux、macOS 三平台发布**
>
> The Windows packages described below require **IDA Professional 9.4 for Windows**, with its bundled **Qt 6.8.2**. Linux and macOS versions have not been comprehensively tested; please [report bugs](https://github.com/ackwrap/ida-pro-agent/issues). Check each release's assets for available platforms.
>
> 下文的 Windows 安装包需要 **Windows 版 IDA Professional 9.4** 及其自带的 **Qt 6.8.2**。**Linux 和 macOS 版本尚未经过全面测试，如遇问题请[提交 Bug / Issue](https://github.com/ackwrap/ida-pro-agent/issues)。** 可用平台以各次发布的附件为准。

[Download releases / 下载发布版本](https://github.com/ackwrap/ida-pro-agent/releases) · [Usage guide](USAGE.md) · [中文使用指南](USAGE.zh-CN.md)

| Platform / 平台 | Package / 下载包 |
| --- | --- |
| Windows x64 | `*-windows-x64-setup.exe` or `*-windows-x64.zip` |
| Linux x64, Ubuntu 24.04 baseline | `*-linux-x64.tar.gz`, including full AI Chat / 包含完整 AI Chat |
| macOS 15+, Intel and Apple Silicon | `*-macos-universal2.dmg` or `*-macos-universal2.zip` |

## English

ida-agent combines an IDA plugin, an MCP Gateway for external AI clients, and a built-in AI Console. It supports function and cross-reference inspection, pseudocode, bounded argument tracing across direct callers, guard evidence extraction, and supported IDB edits through ChangeSets.

This repository contains the ida-agent source, usage guides and binary releases. Project-owned code is licensed under [MIT](LICENSE); dependencies retain their own terms in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Source and usage updates are automatically synchronized to `main`, where Windows/Linux build and test workflows run. See the [source build guide](README.source.md#build-from-source). Older release tags created before source publication keep their original documentation snapshots; clone `main` for current source or use the named release assets to install ida-agent.

### Install

1. Download `ida-agent-<version>-windows-x64-setup.exe` from Releases and close IDA before installing or upgrading. The installer installs for the current Windows user and deploys the IDA plugin.
2. Alternatively, extract `ida-agent-<version>-windows-x64.zip`, then copy `plugins/ida-agent-plugin.dll` into your IDA user plugin directory. Keep the Gateway and skills together in the extracted directory.
3. Start IDA and load a database. Open **Edit → Plugins → IDA Agent**.
4. When upgrading from before 0.4.0, uninstall the old package and remove its old client entry before configuring `ida-mcp`. For 0.4.4 tool-name changes, follow the upgrade section in the [usage guide](USAGE.md#4-upgrade-to-044).

The installer has a separate `.sha256` file; the portable ZIP includes per-file `SHA256SUMS.txt`. IDA itself and Qt runtime DLLs are not bundled.

For **Linux**, extract the tar.gz, verify `SHA256SUMS.txt`, and copy
`plugins/ida-agent-plugin.so` into `${IDAUSR:-$HOME/.idapro}/plugins/` with IDA closed.
Keep `ida-mcp` and `skills/` together. OpenSSL 3 and CA certificates are system
dependencies; Qt comes from Linux IDA 9.4. See the archive's `README.md`.
For headless use, run `./idat-with-agent /absolute/path/to/ida-9.4/idat` with your
usual IDA arguments so IDAT can find its matching Qt libraries.

For **macOS**, open the DMG and run **IDA Agent Installer.app**. It installs the
Universal 2 plugin and Gateway for the current user. The `.command` launcher opens
the configuration manager. macOS uses native networking and needs no OpenSSL.
The binaries use ad-hoc signatures without Developer ID notarization. See the
included installation instructions. Close IDA before installing either platform.

### Configure a provider

Open **Provider Settings...**, select the OpenAI or Claude preset, or add a custom provider. Set the API mode, Base URL, and API key. Use **Refresh Models** or **Add Model...**, choose a default model/provider, save, then open **Open AI Chat**.

| API mode | Base URL example | Endpoint appended by the plugin |
| --- | --- | --- |
| OpenAI Responses | `https://api.openai.com/v1` | `/responses` |
| OpenAI-compatible Chat Completions | Your provider's API prefix, such as `https://api.example.com/v1` | `/chat/completions` |
| Anthropic Messages | `https://api.anthropic.com/v1` | `/messages` |

Enter the API prefix, not a complete operation URL. **Test Connection** checks model discovery, not chat, streaming, or tool-calling compatibility. Providers without model discovery may work with a manually added model.

API keys and saved proxy passwords are stored as plaintext with current-user file permissions, normally in `%LOCALAPPDATA%\ida-agent\ai\providers.json`. The built-in AI sends conversation content and relevant analysis results to the selected provider. External MCP clients use their own provider settings.

### MCP clients

Run `ida-mcp.exe -web` for the local client configuration manager, or configure your MCP client to start `ida-mcp.exe` with no arguments for stdio. Keep IDA open with the database loaded. Optional HTTP transport binds only to loopback; authenticated remote hosting is not implemented.

The configuration manager supports Codex, OpenCode, Claude Code, Antigravity CLI, Grok Build, and ZCode. ZCode uses the user-level `~/.zcode/cli/config.json` (`mcp.servers`), with optional skills under `~/.zcode/skills/`.

On Windows, the manager also discovers Codex in common npm/Scoop installations and the desktop app's bundled CLI when PATH is outdated. It runs the native executable without requiring Node.js in PATH. For custom installations, set `IDA_MCP_CODEX_PATH` to the absolute path of `codex.exe` and restart the manager.

### Limits and build environment

- Pseudocode and semantic analysis require a compatible Hex-Rays decompiler and license. Caller tracing expands known direct callers, defaults to two levels, and permits at most five. Unknown indirect calls, native tail calls, callee-return summaries, and heap aliases are not recovered.
- Guard evidence is function-local and does not prove safety, exploitability, or complete input validation. General cross-reference tracing is not semantic taint analysis. Results may be partial or truncated.
- Only supported ChangeSet edits offer preview/apply/rollback. Arbitrary scripts are not sandboxed or automatically reversible.
- The Windows build configuration uses MSVC 2022 x64, Windows SDK, CMake 3.25+, Ninja, Go 1.25.0+, Python 3.11, and Inno Setup 6. It links public IDA SDK import libraries against Qt 6.8.2 headers; runtime Qt comes from IDA.
- CI checks compilation and unit tests. Those checks do not replace live IDA UI or licensed integration testing.

## 中文

ida-agent 包含 IDA 插件、供外部 AI 客户端使用的 MCP Gateway，以及内置 AI Console。支持函数与交叉引用检查、伪代码、沿直接调用者进行有限层级的参数回溯、校验证据提取，以及通过 ChangeSet 执行支持的 IDB 修改。

本仓库包含 ida-agent 源码、使用说明和二进制版本。项目自有源码采用 [MIT 许可证](LICENSE)，第三方依赖保留各自许可，见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。源码与使用文档自动同步到 `main`，公开运行 Windows/Linux 构建和测试，编译步骤见[中文源码说明](README.source.zh-CN.md#源码编译)。公开源码之前创建的发布标签保留原文档快照；获取当前源码请克隆 `main`，安装软件请使用带有 `ida-agent` 名称的发布附件。

### 安装

1. 从 Releases 下载 `ida-agent-<版本>-windows-x64-setup.exe`，安装或升级前关闭 IDA。安装器按当前 Windows 用户安装，并部署 IDA 插件。
2. 也可以解压 `ida-agent-<版本>-windows-x64.zip`，将 `plugins/ida-agent-plugin.dll` 复制到 IDA 用户插件目录。Gateway 与技能目录保留在便携目录中。
3. 启动 IDA 并加载数据库，在 **Edit → Plugins → IDA Agent** 中使用插件。
4. 从 0.4.0 之前的版本升级时，先卸载旧包并移除旧客户端条目，再配置 `ida-mcp`。0.4.4 的工具名变化见[使用指南中的升级说明](USAGE.zh-CN.md#4-升级到-044)。

安装器附带独立 `.sha256` 校验文件，便携 ZIP 内含逐文件 `SHA256SUMS.txt`。发布包不包含 IDA 或 Qt 运行时 DLL。

**Linux**：解压 tar.gz，校验 `SHA256SUMS.txt`，关闭 IDA 后将
`plugins/ida-agent-plugin.so` 放入 `${IDAUSR:-$HOME/.idapro}/plugins/`，保留
`ida-mcp` 与 `skills/`。系统需安装 OpenSSL 3 和 CA 证书，Qt 使用 Linux IDA 9.4
自带版本；详细步骤见包内 `README.md`。
无界面模式使用包内 `idat-with-agent /绝对路径/ida-9.4/idat` 并附加原有 IDA 参数，
以便 IDAT 加载对应的 Qt 库。

**macOS**：打开 DMG，运行 **IDA Agent Installer.app**，按当前用户安装 Intel /
Apple Silicon 通用插件和 Gateway。安装后的 `.command` 启动配置管理页。使用系统
原生网络接口，无需 OpenSSL；二进制采用临时签名，未做 Developer ID 公证。
安装前关闭 IDA，详细步骤见包内说明。

### 配置供应商

打开 **Provider Settings...**，选择 OpenAI、Claude 预设或添加自定义供应商，填写 API 模式、Base URL 和 API Key。通过 **Refresh Models** 获取模型，或用 **Add Model...** 手动添加模型 ID，设置默认模型和供应商，保存后打开 **Open AI Chat**。

支持 OpenAI 风格的 **Responses / Chat Completions** 和 Anthropic 风格的 **Messages**。Base URL 填 API 前缀，例如 `https://api.openai.com/v1`，不要附加 `/responses`、`/chat/completions` 或 `/messages`，插件会自动追加。**Test Connection** 只检查模型列表接口，不能证明聊天、流式输出和工具调用均兼容；不支持模型列表的服务可尝试手动添加模型。

API Key 和已保存的代理密码使用当前用户文件权限保护，但以明文保存，通常位于 `%LOCALAPPDATA%\ida-agent\ai\providers.json`。内置 AI 会向选定供应商发送会话内容与相关分析结果。外部 MCP 客户端使用其自己的模型供应商配置。

### MCP 客户端

运行 `ida-mcp.exe -web` 打开本地配置管理页，或让 MCP 客户端以无参数方式启动 `ida-mcp.exe` 使用 stdio。使用时保持 IDA 与数据库打开。可选 HTTP 模式仅监听本机回环地址，尚未实现带认证的远程服务。

配置管理页支持 Codex、OpenCode、Claude Code、Antigravity CLI、Grok Build 和 ZCode。ZCode 使用用户级 `~/.zcode/cli/config.json` 中的 `mcp.servers`，可选技能位于 `~/.zcode/skills/`。

Windows 下，管理页也会检查常见 npm/Scoop 安装位置及 Codex 桌面应用自带的 CLI，避免旧 PATH 导致检测失败；优先运行原生程序，不依赖 PATH 中的 Node.js。自定义安装位置可通过 `IDA_MCP_CODEX_PATH` 指定 `codex.exe` 的绝对路径，设置后重启管理页。

### 当前限制与编译环境

- 伪代码和语义分析需要对应的 Hex-Rays 反编译器与许可。跨函数追踪只展开已知直接调用者，默认两层、最多五层；不恢复未知间接调用、原生尾调用、被调函数返回值摘要或堆别名。
- 校验证据仅覆盖函数内部，不能证明安全、可利用性或输入校验完备。普通交叉引用追踪不是语义污点分析，结果可能不完整或被预算截断。
- 只有支持的 ChangeSet 修改提供预览、应用和回滚；任意脚本没有沙箱，也不会自动回滚。
- Windows 构建配置使用 MSVC 2022 x64、Windows SDK、CMake 3.25+、Ninja、Go 1.25.0+、Python 3.11 和 Inno Setup 6。编译使用 Qt 6.8.2 头文件与公开 IDA SDK 导入库，运行时使用 IDA 自带 Qt。
- CI 编译与单元测试通过，不能替代真实 IDA 的 UI 或需要许可的集成测试。

### Source builds / 源码构建

Source builds add automatic stable-release checks to the Qt plugin and local Web manager, with shared daily caching, an opt-out, manual checks, and a release-page link. See the [usage guide](USAGE.md#update-checks-in-source-builds). Published 0.4.6 binaries predate this feature.

源码构建新增正式版自动更新检测：Qt 插件和本地 Web 管理页共享每日检查缓存，支持关闭自动检测、手动检查和打开下载页面。详见[使用指南](USAGE.zh-CN.md#源码构建中的更新检测)。已发布的 0.4.6 安装包尚未包含此功能。

### Version 0.4.6 / 0.4.6 版本

Windows streamed chat now waits asynchronously through delayed headers and SSE frames, fixing the request-state failure that could produce WinHTTP error 12019. External history also works before an IDB's `.i64` is packed and retains the same database identity afterward. Install the complete package with IDA closed and restart IDA.

This version adds official Python SDK regression tests across Windows/Linux/macOS and reproducible Codex, Claude Code and OpenCode test entry points. SDK runs use simulated RPC peers; actual Agent/model and licensed IDA results are recorded separately. The 23-tool catalog and existing RPC contracts are preserved. See the [release notes](release/notes/0.4.6.md) and [client regression guide](mcp-test-project/CLIENT_REGRESSION.md).

Windows 流式聊天改为异步等待延迟响应头及 SSE 数据，修复可能触发 WinHTTP 12019 的请求状态错误。数据库 `.i64` 尚未打包时也能保存外部聊天历史，打包后仍使用同一数据库标识。升级时关闭 IDA、安装完整发布包，再重启 IDA。

本版增加 Windows/Linux/macOS 官方 Python SDK 回归，以及 Codex、Claude Code、OpenCode 的可复现测试入口。SDK 使用模拟 RPC 后端；真实 Agent/模型和需要许可的 IDA 结果单独记录。23 个工具及既有 RPC 合同保持兼容，详见[发布说明](release/notes/0.4.6.md)和[客户端回归说明](mcp-test-project/CLIENT_REGRESSION.md)。

### Version 0.4.4 / 0.4.4 版本

All clients now use the same 11 underscore-named MCP tools, including `ida_instances`, `ida_functions`, and `ida_scripts`. The fixed catalog and former Grok compatibility behavior are defaults in both stdio and HTTP; no `--grok` flag is needed. Existing flags are accepted as a deprecated no-op.

Update custom tool allowlists/scripts from names such as `ida.functions` to `ida_functions`, refresh packaged skills, and restart the Gateway and client. Specific method identifiers such as `function.search` and `ida.instances.list` keep their dots. Follow `list` → `describe` → `call`; see the [English usage guide](USAGE.md) for configuration, all 11 tools, dispatch examples and troubleshooting.

所有客户端现在统一使用 11 个下划线 MCP 工具名，包括 `ida_instances`、`ida_functions` 和 `ida_scripts`。stdio 与 HTTP 默认使用固定目录和原 Grok 兼容行为，无需 `--grok`；旧参数仍作为已弃用的空操作接受。

将自定义工具允许列表、脚本中的 `ida.functions` 等旧工具名改为 `ida_functions`，刷新包内技能，再重启 Gateway 与客户端。`function.search`、`ida.instances.list` 等具体方法标识保留点号。使用 `list` → `describe` → `call`；安装、配置、全部 11 个工具、调用示例和常见问题见[中文使用指南](USAGE.zh-CN.md)。

### Version 0.4.5 / 0.4.5 版本

The Gateway now exposes 23 fixed underscore-named tools: 12 common direct tools plus the existing 11 domain tools. Direct reads use a simple parameter schema and can route to the sole available instance. Argument failures return field-level tool errors and recovery hints. Bounded per-instance waiting and read-only busy retries reduce transient failures; writes, scripts and debugger control are never automatically retried. Optional `-diagnostics` writes metadata to stderr.

Restart the Gateway and reconnect the client to refresh its catalog, skill copies and tool allowlists. Direct tools return the operation result directly; existing domain calls keep their `method`/`result` envelope. See the [English guide](USAGE.md#gateway-compatibility-in-045) and [中文指南](USAGE.zh-CN.md#gateway-兼容性优化045) for examples and timeout recovery.

Gateway 固定目录增加为 23 个下划线工具：12 个常用直接入口及原有 11 个领域入口。直接读取工具使用简单参数 schema，并支持唯一实例自动路由；参数错误包含具体字段与修正提示。每实例有界等待和只读忙碌重试减少瞬时失败；修改、脚本和调试控制不会自动重试。`-diagnostics` 可向 stderr 输出脱敏元数据。

更新后重启 Gateway 并重连客户端，刷新目录、技能和工具允许列表。直接工具返回业务结果，既有领域调用保持 `method`/`result` 包装。超时不代表已启动操作被撤销，恢复方式见使用指南。

## Build from source / 从源码编译

```sh
git clone --recurse-submodules https://github.com/ackwrap/ida-pro-agent.git
cd ida-pro-agent
go -C ida-mcp build ./...
```

The public SDK stays pinned as a submodule. Full Windows plugin builds use the
tracked Qt headers and public SDK imports; Linux basic MCP/backend tests require
no private Qt bundle. Full Linux/macOS AI panel builds require the Qt inputs from
your IDA 9.4 installation. Detailed toolchains, build commands and testing are in
[English source documentation](README.source.md#build-from-source),
[中文源码文档](README.source.zh-CN.md#源码编译),
[Linux instructions](ida-agent-plugin/README-LINUX.md), and
[macOS instructions](ida-agent-plugin/README-MACOS.md).

公开 SDK 以固定版本子模块提供。Windows 完整插件使用仓库内 Qt 头文件和公开 SDK
导入库；Linux 基础 MCP/AI 后端测试不需要私有 Qt 包。Linux/macOS 完整 AI 面板编译
需要从自己的 IDA 9.4 安装准备 Qt 输入，详细步骤见上述源码文档。
