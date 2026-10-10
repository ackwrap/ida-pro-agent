# 使用指南

[English](USAGE.md) | [简体中文](USAGE.zh-CN.md) | [下载发布版本](https://github.com/ackwrap/ida-pro-agent/releases)

本文对应 ida-agent 0.4.6。插件与 Gateway 请使用同一发布包中的版本。

## 1. 安装并打开数据库

需要对应平台的 IDA Professional 9.4 及其自带的 Qt 6.8.2。伪代码和语义参数分析还需要对应的 Hex-Rays 反编译器与许可。发布包不包含 IDA 或 Qt；Linux 和 macOS 版本尚未经过全面测试。

| 平台 | 安装方式 | Gateway 位置 |
| --- | --- | --- |
| Windows x64 | 关闭 IDA，运行 `*-windows-x64-setup.exe`。使用 ZIP 时，将 `plugins/ida-agent-plugin.dll` 复制到 `%APPDATA%\Hex-Rays\IDA Pro\plugins`。 | 安装器默认位置：`%LOCALAPPDATA%\Programs\ida-agent\ida-mcp.exe` |
| Linux x64，Ubuntu 24.04 基线 | 解压 tar.gz，执行 `sha256sum -c SHA256SUMS.txt`，关闭 IDA 后将 `plugins/ida-agent-plugin.so` 放入 `${IDAUSR:-$HOME/.idapro}/plugins/`。系统需安装 OpenSSL 3 和 CA 证书。 | 将解压后的 `ida-mcp` 和 `skills/` 保留在固定目录。 |
| macOS 15+，Intel / Apple Silicon | 打开 DMG，运行 **IDA Agent Installer.app** 并点击 **Install**。默认插件目录为 `~/.idapro/plugins/`；自定义用户目录时选择对应的 `IDAUSR`。 | `~/Library/Application Support/ida-agent/bin/ida-mcp` |

启动 IDA，打开二进制或 IDB，在 **Edit → Plugins → IDA Agent** 中使用插件。实时分析时保持数据库打开，Gateway 与 IDA 使用同一操作系统用户。

Linux 无界面模式使用包内启动脚本，以便 IDAT 加载对应的 Qt 库：

```sh
./idat-with-agent /absolute/path/to/ida-9.4/idat [原有 IDA 参数]
```

macOS 包使用临时签名，未做 Developer ID 公证。各平台安装细节也可参阅发布包内的说明。

## 2. 选择使用方式

- **IDA 内置 AI Chat**：在 IDA 中配置模型供应商，内置 Agent 直接连接供应商，无需运行 Gateway。
- **外部 MCP 客户端**：使用客户端自己的模型与供应商配置，通过 Gateway 连接 IDA；不要求先配置 IDA 内置供应商。

### 使用内置 AI Chat

1. 打开 **Edit → Plugins → IDA Agent → Provider Settings...**。
2. 选择 OpenAI、Claude 预设，或添加自定义供应商，填写 API 模式、Base URL 和 API Key。
3. 点击 **Test Connection**，再用 **Refresh Models** 获取模型。不支持模型列表时，使用 **Add Model...** 填写供应商提供的准确模型 ID。
4. 启用模型，设置默认模型与默认供应商，通过 **Apply** 或 **OK** 保存。
5. 打开 **Edit → Plugins → IDA Agent → Open AI Chat**，发送分析请求。

| API 模式 | Base URL 示例 | 插件追加的操作路径 |
| --- | --- | --- |
| Responses | `https://api.openai.com/v1` | `/responses` |
| Chat Completions | 兼容服务的 API 前缀，例如 `https://api.example.com/v1` | `/chat/completions` |
| Anthropic Messages | `https://api.anthropic.com/v1` | `/messages` |

Base URL 填 API 前缀，不要附加操作路径。API 模式与模型须由供应商实际支持。**Test Connection** 只检查模型列表；保存后用一次简短分析请求验证聊天、流式输出和工具调用。

API Key 和保存的代理密码以明文存放在当前用户私有文件中。供应商配置的默认位置：

- Windows：`%LOCALAPPDATA%\ida-agent\ai\providers.json`
- Linux：`${XDG_CONFIG_HOME:-$HOME/.config}/ida-agent/ai/providers.json`
- macOS：`~/Library/Application Support/ida-agent/ai/providers.json`

所选供应商会收到会话内容与相关分析上下文、工具结果。分享配置或日志前请移除凭据。

### 外部 MCP 客户端：使用配置管理页

Windows 可打开安装后的快捷方式，或运行：

```powershell
& "$env:LOCALAPPDATA\Programs\ida-agent\ida-mcp.exe" -web
```

Windows 便携包在解压目录运行 `ida-mcp.exe -web`。Linux 运行 `./ida-mcp -web`，保持终端打开，并访问日志中的本地网址。macOS 双击 Gateway 所在目录的 **Open IDA Agent.command**，再打开终端中显示的本地网址。

管理页支持 Codex、OpenCode、Claude Code、Antigravity CLI、Grok Build 和 ZCode。在对应客户端卡片中安装或更新 `ida-mcp` 配置；提供技能链接的卡片还可安装：

- `ida-reverse-analysis`：方法发现、逆向分析流程与证据解释。
- `idapython`：通过 `ida_scripts` 工具执行 IDAPython 脚本。

修改配置或技能后重启客户端。`-web` 模式负责配置管理，每个配置完成的客户端会启动自己的 stdio Gateway。

### 手动配置 stdio

对于使用 JSON `mcpServers` 的客户端，将 `command` 替换为实际绝对路径：

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

Linux/macOS 填写不带 `.exe` 的 `ida-mcp` 绝对路径，配置中将 `~` 展开为完整用户目录。不同客户端配置格式可能不同，可优先使用管理页。stdio 是默认模式，无需专用启动参数，Grok 也一样。

### 可选本机 HTTP

显式启动 Gateway：

```powershell
.\ida-mcp.exe -transport http -listen 127.0.0.1:8743
```

Linux/macOS 将程序改为 `./ida-mcp`，其余参数相同。客户端 MCP URL 填 `http://127.0.0.1:8743/mcp`。这是本机回环 Streamable HTTP，程序拒绝非回环监听地址。`-web` 启动的是独立配置页。

## 3. 发现工具并开始分析

Gateway 对外提供 23 个 MCP 工具：12 个[常用直接工具](#gateway-兼容性优化045)，以及以下 11 个领域工具：

| 工具 | 用途 |
| --- | --- |
| `ida_instances` | 发现并选择已打开的 IDA 数据库 |
| `ida_database` | 数据库信息、概览、段与保存 |
| `ida_functions` | 函数查询、伪代码、汇编与调用关系 |
| `ida_search` | 字符串、字节、指令、列表与交叉引用 |
| `ida_symbols` | 导入、导出、符号与全局值 |
| `ida_types` | 类型、结构体与带类型的值 |
| `ida_analysis` | 参数来源、调用者追踪与校验证据 |
| `ida_changes` | ChangeSet 预览、应用、回滚与审计 |
| `ida_patch` | 汇编与可回滚的字节、整数补丁 |
| `ida_debugger` | 调试器配置、进程控制与检查 |
| `ida_scripts` | IDAPython 或 IDC 脚本执行 |

**MCP 工具名使用下划线，具体方法标识保留点号。** 例如工具为 `ida_functions`，方法为 `function.search`。遵循 `list` → `describe` → `call`：先发现方法，再获取当前参数 schema，最后按 schema 调用。

以下 JSON 是 MCP `tools/call` 的 `params` 内容，不是完整 JSON-RPC 请求。

发现实例方法，再查看 `ida.instances.list` 的参数：

```json
{"name":"ida_instances","arguments":{"action":"list"}}
```

```json
{"name":"ida_instances","arguments":{"action":"describe","method":"ida.instances.list"}}
```

列出已打开的数据库：

```json
{"name":"ida_instances","arguments":{"action":"call","method":"ida.instances.list","arguments":{}}}
```

从返回结果获取真实 `instanceId`，查看 `ida.instances.select` 后选择实例：

```json
{"name":"ida_instances","arguments":{"action":"describe","method":"ida.instances.select"}}
```

```json
{"name":"ida_instances","arguments":{"action":"call","method":"ida.instances.select","arguments":{"instanceId":"00000000-0000-4000-8000-000000000000"}}}
```

上面的 UUID 仅为占位符，须替换为发现结果中的 ID。选择结果只属于当前 Gateway 进程；也可以在每次业务调用的内层 `arguments` 中明确传入真实 `instanceId`。

发现函数方法并查看查询参数：

```json
{"name":"ida_functions","arguments":{"action":"list"}}
```

```json
{"name":"ida_functions","arguments":{"action":"describe","method":"function.search"}}
```

在选定数据库中搜索函数：

```json
{"name":"ida_functions","arguments":{"action":"call","method":"function.search","arguments":{"name":"main","limit":20}}}
```

准确字段、预算和分页方式以 `describe` 返回值为准。地址使用 `0x140001000` 这样的十六进制字符串，不要猜方法名，也不要在 Gateway 重启后复用旧 cursor。

内置 AI 或外部客户端均可尝试这些自然语言请求：

- “列出当前打开的 IDA 数据库，选择这个二进制对应的实例，概览导入和入口点。”
- “查找解析函数，查看伪代码和调用者，并给出相关地址作为证据。”
- “从这个调用地址追踪第 0 个参数，沿已知直接调用者回溯，区分已恢复的证据与未知边界。”
- “预览这个函数的重命名，先展示修改内容，再应用。”

支持的 IDB 修改使用 ChangeSet 预览 → 应用 → 回滚。调试请求需要在 IDA 弹窗授权，并满足调试器和进程状态要求；无界面 IDA 无法授予这项 GUI 权限。任意脚本没有沙箱，也不会自动回滚。部分追踪结果与校验证据不能直接证明安全性或可利用性。

## 4. 升级到 0.4.4

1. 关闭 IDA，并停止使用旧 Gateway 的客户端，安装完整新包。
2. 将自定义脚本和工具允许列表中的 `ida.functions` 等旧工具名改为 `ida_functions`；保留 `function.search`、`ida.instances.list` 等点号方法标识。
3. 使用技能时刷新或重新链接包内技能，再重启 Gateway 与 MCP 客户端，加载新工具目录和指令。

stdio 与 HTTP 默认均使用固定工具目录和原 Grok 兼容行为，无需 `--grok`。旧配置中的 `--grok` 仍作为已弃用的空操作参数接受。工具列表变更通知默认关闭，升级后需要重连。

从 0.4.0 之前的组件命名升级时，请移除旧 MCP 配置项并配置 `ida-mcp`；不提供旧程序名、配置名别名或自动迁移。

## 5. 常见问题

| 现象 | 检查步骤 |
| --- | --- |
| 没有 IDA Agent 菜单 | 检查 IDA 9.4、当前用户插件目录和对应平台插件文件，安装后重启 IDA。 |
| 实例列表为空 | 打开数据库，确认插件加载；Gateway 与 IDA 应使用同一用户并处于同一操作系统环境。 |
| 客户端仍显示点号工具名 | 停止旧 Gateway，重新连接或重启客户端，并更新自定义允许列表。刷新配置页不能替换现有客户端进程。 |
| 方法或参数被拒绝 | 在正确领域工具中使用 `list`、`describe`，保留点号方法标识，并严格匹配返回的 schema。 |
| 供应商测试通过但聊天失败 | 检查 API 模式、Base URL 前缀、准确模型 ID、流式输出、工具支持和代理设置。 |
| Windows 聊天出现 `WinHttpQueryDataAvailable` 错误 12019 | 升级到 0.4.6 并重启 IDA。本版修复流式响应间隔期间请求被取消的问题；配置的空闲期限和总期限仍然有效。 |
| 数据库尚未打包时无法保存外部聊天记录 | 升级到 0.4.6。Windows 现在通过已存在的父目录解析未打包数据库路径；同时检查外部历史目录的访问权限。 |
| 无法获取伪代码 | 检查对应的 Hex-Rays 反编译器、许可与目标架构。 |
| 调试请求失败 | 检查 IDA 授权弹窗、已选择的调试器与进程状态。 |

可在 [Issues](https://github.com/ackwrap/ida-pro-agent/issues) 提交问题，附上系统/CPU、IDA 与 ida-agent 版本、复现步骤及已移除凭据的相关日志。

## 0.4.6 聊天修复与客户端回归

关闭 IDA 后安装完整的 0.4.6 发布包，随后重启 IDA 并重连 MCP 客户端。Windows 流式聊天改为异步等待延迟响应头和 SSE 数据，取消、空闲期限和总期限继续生效，修复可能表现为 WinHTTP 12019 的请求状态错误。

数据库的 `.i64` 尚未打包到磁盘时，Windows 也能保存外部聊天历史；打包前后的历史键保持一致，聊天记录仍保存在 IDB 之外。

[客户端回归说明](mcp-test-project/CLIENT_REGRESSION.md) 提供官方 Python SDK 测试，以及 Codex、Claude Code 和 OpenCode 的可复现运行入口。CI 在 Windows、Linux、macOS 上使用模拟 RPC 后端验证 SDK 调用；真实 Agent/模型与需要许可的 IDA 联调仍需单独记录证据。公开目录继续使用 0.4.5 引入的 23 个工具。

## Gateway 兼容性优化（0.4.5）

以下改动从 0.4.5 起提供。旧版 v0.4.4 安装包仅提供原有 11 个领域工具；使用直接工具前先检查实际 `tools/list`。替换 Gateway 后重连客户端，刷新缓存的工具目录和技能。

固定目录现在有 23 个下划线工具：下表的 12 个直接工具，以及原有 11 个领域工具。直接工具的业务参数放在顶层，直接返回业务结果；领域调用继续采用 `method`/`result` 包装与 `list` → `describe` → `call`。MCP 工具名使用下划线，具体 method 标识保留点号。

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

常用读取优先使用直接工具提供的 schema。`ida_search_functions` 按 `name` 搜索，空字符串列出函数；按地址查询使用 `ida_get_function`。高级分析、修改、调试及脚本继续使用领域入口。内存 `bytes`/`string` 必须传 `length`，`integer` 必须传 `widthBits`，`pointer` 不接受这两个参数。字符串 `refresh=true` 不能同时传 `cursor`。

下面是 MCP `tools/call` 的参数对象：

```json
{"name":"ida_list_instances","arguments":{}}
```

```json
{"name":"ida_search_functions","arguments":{"name":"main","limit":20}}
```

```json
{"name":"ida_decompile_function","arguments":{"address":"0x401000","maxBytes":32768}}
```

直接读取工具可以使用已选实例，或者唯一可用实例。多个数据库时，用 `ida_select_instance` 选择，或传入发现返回的 `instanceId`；HTTP 多会话优先显式路由，避免共享 active state。原有领域调用仍要求选择实例或显式传入。分页必须保持相同实例和过滤条件；直接工具与领域工具共用绑定到具体 method 的 cursor。

参数或业务错误返回 `isError:true`，JSON 文本与 `structuredContent` 一致。错误包含 `code`、`message`、`retryable`、`hint`，可选 `method`，以及最多 8 条带有字段、规则和预期合同的 `issues`。例如 limit 类型错误会指出 `arguments.limit` 应为整数，不回显错误输入值。按提示修正字段，不要把 JSON 对象包装成字符串。未知工具和格式错误的 JSON-RPC 请求仍返回协议错误。

每个 Gateway 对每个实例最多执行 2 个请求，FIFO 队列最多等待 8 个请求、最长 5 秒；不同 Gateway 的限额独立。只读、明确可重试的 `IDA_BUSY` 最多自动重试 2 次，所有尝试共用方法总期限。修改、脚本、调试控制及超时均不自动重试。有副作用操作超时会返回 `executionState:"unknown"`、`retryable:false`，再次提交前检查 IDA 状态或 ChangeSet audit。

给 Gateway 增加 `-diagnostics` 可启用调用诊断：

```powershell
.\ida-mcp.exe -diagnostics
```

日志输出到 stderr，仅包含工具、方法、阶段、耗时、错误码和重试次数，不包含参数值或结果正文，stdout 保持 MCP JSON。排错时保留 Gateway/客户端版本、工具名和脱敏后的错误对象。依次检查 `tools/list`、`ida_list_instances`，再显式传实例调用 `ida_database_info`，区分目录、路由和执行阶段的问题。

仓库中的 `python mcp-test-project/verify_compatibility.py <gateway-executable> --http` 在隔离的无 IDA 环境检查 4 个协议版本与两种传输，覆盖目录、可恢复错误、会话恢复、文本/结构化一致性、诊断和 stdio EOF。它验证协议与 SDK 行为，不代表具体 Agent 或模型的实际调用能力已验证。
