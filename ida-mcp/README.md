# ida-mcp Gateway

`ida-mcp.exe` 是独立 Go MCP Server。默认由 MCP Client 按需以 stdio 子进程启动；也可
显式使用安全的 loopback Streamable HTTP。两种模式都不要求启动时已有 IDA。

macOS Universal 2 构建参见 [macOS 说明](../ida-agent-plugin/README-MACOS.md)。网关通过同用户 Unix socket 连接 IDA，插件网络使用 macOS 原生 API；两者均无 OpenSSL/libcurl 运行依赖。

Linux 原生 Gateway 已支持通过 Unix socket 连接同一 Linux 用户下的 IDA；
参见 [Linux/WSL2 基础版](../ida-agent-plugin/README-LINUX.md)。Linux `-web` 在前台驻留，
从日志中的 loopback URL 打开配置页，Ctrl+C/SIGTERM 退出，不依赖系统托盘。

```text
OpenCode / Codex / Claude
        | MCP stdio（默认）或 loopback HTTP（显式启用）
        v
ida-mcp.exe
        | Windows Named Pipe
        v
one or more IDA Plugin instances
```

## Lifecycle

- stdio：Client 创建 Gateway 子进程；stdin 关闭、Client 退出或收到终止信号时 Gateway 退出。
- HTTP：仅 `-transport http` 时监听数值 loopback，收到终止信号后 graceful shutdown。
- Web manager：`-web` 在随机 loopback 端口启动本地配置页并驻留 Windows 系统托盘；它不直接
  承载 MCP，会为每个 AI Client 配置默认 stdio Gateway 子进程。
- MCP `initialize` 和 `tools/list` 不进行 instance discovery，也不连接 Pipe。
- 没有 IDA 时通过 `ida_instances` 调用 `ida.instances.list` 立即返回 `{"instances":[]}`。
- Gateway 每次启动都重新发现 IDA，不需要 IDA 主动注册，也不保存跨进程 active state。

## Domain Tools

0.4.5 中，`tools/list` 固定返回 23 个工具：12 个直接入口及以下 11 个领域入口。旧版 v0.4.4 仅提供 11 个领域工具。

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

每个入口支持渐进式发现流程：模型先用 `list` 获取 method 索引，再用 `describe` 获取选定 method
的精确参数合同和预算，最后才用 `call` 提交符合返回 schema 的参数。公共 tool schema 明确要求不要
猜测 method 名或参数字段，使用简单对象 schema；三种 action 的必填/禁止字段由 Gateway 执行校验并返回工具错误。`call` 只执行状态为
`callable` 且绑定 typed handler 的 method。静态
目录共 98 条：6 个 Gateway 方法（3 个实例方法、`analysis.wait` 和两个 ChangeSet-backed patch
门面）及 92 个 Plugin RPC；全部 98 个 method 均可调用。`patch.write_bytes` 和
`patch.write_integer` 面向单次直接补丁，内部仍执行 ChangeSet preview/apply 并返回可回滚的
`changeId`；批量或需单独审阅的修改继续使用 `ida_changes`。

```json
{"action":"describe","method":"function.search"}
```

```json
{"action":"call","method":"function.search","arguments":{"name":"main","limit":20}}
```

业务 method 的 `arguments.instanceId` 可选。提供时直接显式路由；省略时使用当前 Gateway 进程中通过
`ida.instances.select` 选定的 active instance。底层 `BridgeBackend` 始终接收显式
`instance_id`，active state 不进入 Internal RPC 或 Plugin。

三个 function analysis method 继续使用协议定义的整数 `offset` continuation，输入为
`address`、可选 `offset`（默认 0）和 `limit`（默认 20），并复用相同的显式/active instance
路由与输出预算。该扩展没有改变 MCP transport、Gateway 生命周期或 Named Pipe 架构。

新增 callable catalog 合同包括 `system.ping/methods`、`instance.info`、`database.survey/save`
以及 `function.callers/callgraph/profile/export/analyze/analyze_batch/stack_frame`。每项都经过静态
typed Backend/Bridge 方法调用；领域入口不能提交任意 RPC method。`database.save` 只接受
`compact`/`backup` 并保存当前 IDB，side effect 为 `filesystem_write`，绝不接受 `target`。
`instance.info` 只返回 database/input 的安全 basename，不返回 Pipe locator。`function.profile`
将 Plugin continuation 包装为绑定 instance、method 和全部筛选条件的进程随机 HMAC cursor。

其余 18 个 Plugin RPC 也使用显式 typed DTO 和分领域 Backend interface：`memory.search_bytes`、
`instruction.search/query`、`listing.search/search_text`、`string.search_regex`、
`signature.make/xrefs`、`xref.struct_field`、`global.value`、六个 `type.*` 以及两个
`analysis.*`。`instruction.search/query`、`listing.search_text` 和 `string.search_regex`
的 Internal cursor 会由 Gateway 进程随机 HMAC 包装，并绑定 instance、公开 method 与全部
默认化筛选；篡改、重启、参数变化或 alias 跨 method 复用均返回 `INVALID_ARGUMENT`。
`listing.search` 只公开现有单页合同（`items/truncated`），不伪造可提交的 cursor；
`type.search/query` 分别调用静态 RPC，并直接公开 ordinal continuation；
`analysis.trace_data_flow` 明确返回 `model=xref_bfs`。

`analysis.trace_argument` 和 `analysis.guard_evidence` 使用 Hex-Rays microcode，分别提供单函数内
调用参数来源回溯、比较条件与必经分支证据。输入为真实 `callAddress` 和从 0 开始的
`argumentIndex`，结果保留值转换、来源汇合和未知边界；不输出程序安全结论。详见
[参数回溯与校验证据合同](../protocol/semantic-analysis.md)。

`analysis.trace_argument_callers` 进一步沿形参来源向上追踪已知直接调用者，默认 2 层，
保留每个调用上下文，并校验原型及 ABI 参数位置。支持共享预算和明确的递归/未知边界。
详见[跨函数参数来源合同](../protocol/argument-callers.md)。

P1 增加 11 个静态只读 RPC：`source.files/lines`、`name.demangle`、`comment.get`、
`bookmark.list`、`type.xrefs`、`decompiler.locals/ctree/local_xrefs`、`debugger.threads/modules`。
所有列表在 MCP 侧只暴露绑定 instance、method、规范化过滤条件和有效 limit 的 HMAC cursor；
源码和模块文件名只返回 basename，源码文本、完整路径、raw continuation、microcode 和 SDK 内部布局均不返回。

数据库元数据修改继续使用 ChangeSet：`segment.rename/permissions`、`function.flags`、
`xref.code.add/delete` 和 `xref.data.add/delete` 都必须 preview 后 apply，并可通过 `changeId` rollback。
xref 删除仅允许 user-defined 引用；不会删除无法精确恢复来源的自动分析引用。
code xref 两端必须是现有 code item，call target 还必须已属于函数，避免 apply 隐式创建不可回滚的函数。
`function.end` 只调整稳定函数入口对应的 entry chunk 末端；`function.chunk.add/delete` 使用
`value`/`subject` 表示 tail 的十六进制起止地址，并拒绝 hidden tail；delete 只接受 shared tail 的非 owner 引用。

`ida_scripts` 提供 `script.execute`，接受 `python|idc`，以及二选一的最多 32 KiB UTF-8 内联 `code`
或外部脚本 `path`。它是 `arbitrary_code_execution` 副作用工具，Gateway 不实现额外授权交互或独立授权
状态，是否允许调用完全由 MCP 客户端的权限系统决定。路径会被规范化，只读取一次普通文件并转换为内联
源码；路径不会进入 Internal RPC，调用参数没有 `confirmed/scope` 字段。脚本可以修改 IDB、访问本机
或网络并阻塞 IDA；timeout 不会停止已开始的代码，也不保证已经开始的操作系统路径访问停止。
Streamable HTTP 与 stdio 使用相同合同。

## Run And Client Configuration

Windows x64 发布包同时提供 Inno Setup 安装器 `ida-agent-<version>-windows-x64-setup.exe`。安装器
默认以当前用户权限将 Gateway 安装到 `%LOCALAPPDATA%\Programs\ida-agent`，并自动将 Plugin
释放到 `%APPDATA%\Hex-Rays\IDA Pro\plugins`。开始菜单快捷方式和可选桌面快捷方式均使用
统一 ida-agent 图标并执行 `ida-mcp.exe -web`；安装结束可直接启动管理器。安装前应关闭
IDA，若 Plugin DLL 正被占用，安装器会安排重启后替换。
若目标目录已有非安装器管理的同名 Plugin，Setup 会先备份，卸载时恢复；安装后的 Plugin 若被
用户替换，卸载器会按 SHA256 识别并保留用户版本。Setup 对应用及 packaged skills 的 reparse
path 直接拒绝安装/卸载，避免递归文件操作进入外部目录。

构建：

```shell
go build -o ida-mcp.exe .
python ../mcp-test-project/verify_stdio.py ./ida-mcp.exe
```

可选 HTTP：

```shell
ida-mcp.exe -transport http -listen 127.0.0.1:8743
```

HTTP 提供 `/mcp` 和 `/healthz`，只允许 loopback Origin，并设置请求体、header、read/write/idle
timeout。未实现远程认证前拒绝非 loopback listener。

Windows Web manager：

```shell
ida-mcp.exe -web
```

该模式自动打开带 ida-agent 图标的本地配置页，并提供系统托盘的 Open/Exit 菜单。页面支持 Codex、
OpenCode、Antigravity CLI 与 Claude Code 的检测、安装/更新和移除：Codex 通过官方
`codex mcp list/add/remove` CLI 维护 `~/.codex/config.toml`；OpenCode 只对最高优先级的全局
`opencode.jsonc/json` 执行结构化 patch，并保留其他字段和注释；Antigravity CLI 维护
`~/.gemini/config/mcp_config.json`；Claude Code 维护 `~/.claude.json`，设置
`CLAUDE_CONFIG_DIR` 时改用该目录下的 `.claude.json`。后两者只修改顶层 `mcpServers` 中固定的
`ida-agent` entry，并保留其他字段（包括 Claude Code 的 `projects`）。所有 Web API 仅监听
`127.0.0.1` 随机端口，写操作同时要求进程随机 token 与同源请求。直接写入的配置在写回前会检测
外部修改并在冲突时拒绝覆盖；不遵守文件协作锁的外部进程仍可能在检查与原子替换之间产生极窄竞态。
修改配置后需要重启对应 AI Client。

Grok Build 同样支持 MCP 安装/更新、移除和 Skills 链接。需要先安装 CLI 并加入 PATH；
管理器依次检测 `gork`、`agent`、`grok` 可执行文件。
管理器通过 `grok mcp add/remove --scope user` 维护 `~/.grok/config.toml`，不修改项目配置。
Skills 链接位于 `~/.grok/skills`，配置及 Skills 路径均支持 `GROK_HOME` 覆盖。状态来自
`grok mcp list --json`；项目覆盖、禁用或组织策略阻止的条目不会显示为就绪。

所有模式默认采用原 Grok 兼容行为：11 个对外域工具均使用 `ida_instances`、`ida_functions`
等下划线名称，并关闭工具列表变更通知（`tools.listChanged`）。工具目录在 Gateway 启动时固定，
无需变更通知。Grok 安装配置使用普通 stdio 启动，不再添加 `--grok`；旧配置中的 `--grok`
仍被接受，但不改变行为。
`action`、具体 `method` 和参数结构不变，例如仍传入 `method: "ida.instances.list"`。
更新 Gateway 后需重连或新建 Grok 会话；仅刷新页面不能替换正在运行的旧 Gateway 进程。

安装 Antigravity MCP 时，缺失或空白的配置文件会先初始化为 `{}`；非 JSON 或非对象的内容会先
备份到同目录的 `mcp_config.json.invalid.bak`，再重新初始化并写入配置。已有备份不会被覆盖，
备份失败时也不会覆盖原配置。读取状态和移除操作不会自动重建文件。

每个 Client 卡片还可以安装 `ida-reverse-analysis` 与 `idapython` skill。Windows 上不会为各 Client
复制文档，而是在 Codex 的 `%USERPROFILE%\.codex\skills`、OpenCode 的
`%USERPROFILE%\.config\opencode\skills`、Antigravity CLI 的
`%USERPROFILE%\.gemini\antigravity-cli\skills` 和 Claude Code 的 `%USERPROFILE%\.claude\skills`
下创建目录联接，共享安装目录中的唯一 source；Claude Code 的 skills 也会跟随
`CLAUDE_CONFIG_DIR`。安装、升级 Gateway 后 skill 内容会立即统一；Client 仍需重启后重新加载。
管理器不会覆盖已有真实目录或其他链接，移除及卸载也只删除精确指向当前 ida-agent 安装目录的
junction。

OpenCode 项目配置示例：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "ida-mcp": {
      "type": "local",
      "command": ["D:/tools/ida-mcp.exe"],
      "enabled": true
    }
  }
}
```

测试环境可使用 `-instance-dir <path>` 或 `IDA_AGENT_INSTANCE_DIR` 覆盖默认的
`%LOCALAPPDATA%\ida-agent\instances`。生产配置通常不需要参数。

## Discovery And Routing

`ida.instances.list` 扫描当前用户 registry，严格解析字段、校验 PID 生命周期，然后并发执行
有界 Named Pipe connect、hello 和 `instance.info`。只有身份与协议均匹配的实例才会返回。
目标调用连接失败时，下次 list/select 会重新 refresh；RPC 每次使用新 Pipe connection，断开后
可安全重连。Registry 不向 MCP 输出 Pipe locator；不再存在 bearer token 或 TCP endpoint。

## Verify

```shell
gofmt -w <changed-go-files>
go vet ./...
go test ./...
go build ./...
```

真实 IDA 诊断：

```shell
go run ./cmd/ida-agent-rpc-ping -instance-dir <path> -database-info
```

完整自动化验收由 Plugin CTest 显式启用。`ida_agent_gateway_ping` 在一个真实 IDA 会话内依次验证
direct Go RPC、官方 Go MCP Client 的 Streamable HTTP，以及由 `CommandTransport` 启动的真实
`ida-mcp.exe` stdio 子进程；HTTP 和 stdio 均通过领域入口调用全部 98 个 callable method，
包括 92 个 Plugin RPC、6 个 Gateway 方法、ChangeSet 生命周期、cursor continuation、
只读汇编、before/after diff、Debugger capability/no-process 分支和脚本执行。调试服务的真实成功路径另由
`ida_debugger_integration` 在隔离 idat 中复用 C++ handlers 验证；无 GUI 的 MCP 调试调用仍应拒绝授权。

## 名称与调试权限

本组件名称为 `ida-mcp`，程序为 `ida-mcp.exe`，客户端配置项为 `ida-mcp`；IDA 插件保留 `ida-agent`。0.4.0 不迁移旧 MCP 配置，不提供旧程序名别名，请成套全新安装。首次调试调用在 IDA 确认后，当前 Pipe 的所有 MCP 客户端共享临时授权；Pipe 重建或数据库关闭时清空。授权等待及调试调用上限为 120 秒。

## Agent compatibility

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
