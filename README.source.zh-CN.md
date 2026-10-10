# ida-agent

[English](README.source.md) | **简体中文**

> [!IMPORTANT]
> **支持 Windows x64 桌面版、Linux/WSL2 x86_64 和 macOS Universal 2 源码构建。**
> 支持的宿主为 **IDA Professional 9.4**，使用其自带的 **Qt 6.8.2**。Ubuntu 24.04 x86_64 支持 MCP 和可选的 AI Chat 面板，见 [构建与使用说明](ida-agent-plugin/README-LINUX.md)。macOS 双架构构建与打包见 [macOS 说明](ida-agent-plugin/README-MACOS.md)；Linux 安装包尚未支持。

面向 IDA 的安全分析助手，提供两个使用入口：

- **内置 AI**：直接在 IDA 中聊天、配置模型供应商、添加分析上下文，让 Agent 检索并调用分析工具。内置 Agent 直接连接供应商，不依赖 Gateway。
- **MCP Gateway**：通过独立程序，让外部 AI 客户端访问运行中的 IDA 数据库。支持 stdio，以及显式启用的 loopback Streamable HTTP。

两个入口共用 IDA/Hex-Rays 分析服务。用户需自行准备 IDA 和所需的 Hex-Rays 反编译器许可。

[主要功能](#主要功能) · [安装](#安装) · [供应商配置](#配置-ai-供应商) · [MCP 接入](#连接-mcp-客户端) · [当前限制](#当前限制) · [源码编译](#源码编译)

## 主要功能

- 查看函数、汇编、伪代码、交叉引用、字符串、类型和数据库元数据。
- 在函数内回溯调用参数来源，或沿形参依赖向上追踪已知直接调用方，并保留不同调用上下文。
- 提取比较条件、必经控制流分支，以及条件与选定调用参数之间的关系。
- 通过 ChangeSet 预览、应用和回滚受支持的 IDB 修改，查看字节补丁及修改前后的差异。
- 在 IDA 对应能力可用时执行 IDAPython/IDC 脚本、使用调试工具。
- 使用内置 AI Console，或连接外部客户端使用 12 个常用直接 MCP 工具及 11 个领域工具。领域工具支持渐进式 `list` → `describe` → `call` 发现流程。可用方法与准确参数以运行中的工具目录为准。

分析结果包含证据、不确定性和预算限制。将结果解释为安全问题前，请先了解[当前限制](#当前限制)。

## 安装

### 运行要求

| 组件 | 要求 |
| --- | --- |
| 操作系统 | Windows x64；Ubuntu 24.04 x86_64；macOS 15+ Universal 2（arm64 实机验收待完成） |
| IDA | **IDA Professional 9.4**；AI UI 使用其自带的 Qt 6.8.2 |
| 反编译器 | 伪代码、参数回溯和校验证据需要对应架构的 Hex-Rays 反编译器及有效许可 |
| 内置 AI | 可访问的 API 供应商，以及支持所选 API 模式、流式输出和工具调用的模型 |
| 外部 MCP | Gateway 与 IDA 运行在同一系统、同一用户下；Windows 客户端可通过 wsl.exe 启动 Linux Gateway |

只有从源码编译时才需要安装构建工具。

### 安装器或便携包

使用待安装版本对应的 Windows 发布产物：

- `ida-agent-<version>-windows-x64-setup.exe`：当前用户安装器，安装 Gateway 并将插件部署到 IDA 用户插件目录。
- `ida-agent-<version>-windows-x64.zip`：便携包，包含 Gateway、`plugins/ida-agent-plugin.dll` 和可选的客户端技能。

1. 安装或替换 DLL 前先关闭 IDA。
2. 运行安装器，Gateway 默认安装到 `%LOCALAPPDATA%\Programs\ida-agent`。便携使用时，解压发布包，将 `plugins/ida-agent-plugin.dll` 复制到 `%APPDATA%\Hex-Rays\IDA Pro\plugins`。
3. 启动 IDA 并打开数据库，找到 **Edit → Plugins → IDA Agent**。
4. 使用内置 AI 时选择 **Provider Settings...**；使用外部 MCP 时按下文配置客户端。

0.4.0 按全新安装处理：先卸载旧包、移除客户端中的旧 MCP 条目，再安装本版并添加 `ida-mcp`。Plugin 与 Gateway 必须成套安装，详见[安装说明](docs/UPGRADING.md)。

0.4.7 新增自动更新检测：Qt 插件和本地 `-web` 管理页默认每 24 小时查询公开仓库的正式 Release。使用 **Edit → Plugins → IDA Agent → Check for Updates...**，或 **Settings... → Software Updates**，可手动检查、关闭自动检测并打开下载页面。插件和 Web 管理页共享 IDB 之外的设置与缓存；检测请求不携带数据库、聊天内容或供应商凭据。发现新版本后，关闭 IDA 并成套更新插件与 Gateway。无界面插件、stdio 和 HTTP MCP 进程不执行更新检测。

## 配置 AI 供应商

这里配置的是 **IDA 内置 AI Console**。外部 MCP 客户端使用各自的模型供应商配置。

1. 打开 **Edit → Plugins → IDA Agent → Provider Settings...**。
2. 选择 **OpenAI** 或 **Claude** 预设，或点击 **Add...** 新建自定义供应商。填写 **Name**、**Type**、**API Mode**、**Base URL** 和 **API Key**。
3. 点击 **Test Connection**，再点击 **Refresh Models**。如果供应商不提供模型发现接口，使用 **Add Model...** 手动填写供应商给出的准确模型 ID。
4. 启用模型并点击 **Set Default**；选择供应商后点击 **Set as Default**。通过 **Edit Metadata...** 按模型实际能力设置上下文长度、最大输出和可选的推理参数。
5. 点击 **Apply** 或 **OK** 保存，再选择 **Edit → Plugins → IDA Agent → Open AI Chat**。

### API 模式与 Base URL

下表说明应用内置预设及请求路径的组装方式：

| 供应商配置 | Type | API Mode | Base URL | ida-agent 自动追加的聊天接口路径 |
| --- | --- | --- | --- | --- |
| OpenAI 预设 | `OpenAI Compatible` | `Responses` | `https://api.openai.com/v1` | `/responses` |
| OpenAI 兼容服务 | `OpenAI Compatible` | 按服务实际支持选择 `Chat Completions` 或 `Responses` | 服务的 API 前缀，例如 `https://api.example.com/v1` | `/chat/completions` 或 `/responses` |
| Claude 预设 | `Anthropic Messages` | `Messages` | `https://api.anthropic.com/v1` | `/messages` |

**Base URL 填 API 前缀，不是完整的操作接口地址。** 不要追加 `/chat/completions`、`/responses`、`/messages` 或 `/models`；模型发现会在同一前缀后自动追加 `/models`。自定义供应商默认使用 Chat Completions，只有服务确实实现 Responses 时才选择该模式。

- OpenAI 兼容请求默认使用 `Authorization: Bearer <API Key>`；Anthropic 请求默认使用 `x-api-key` 和 `anthropic-version`。可在 **Advanced** 中配置自定义请求头。
- **Test Connection 检查的是模型列表接口。** 它不验证聊天生成、流式输出、工具调用或每个模型的能力。保存后可用一次简短聊天和简单分析请求验证这些能力。
- 不支持模型发现的服务仍可能通过手动添加模型使用。兼容性取决于请求格式、流式事件和工具调用响应，不能仅凭“OpenAI Compatible”标签判断。
- **Advanced → Proxy** 支持 System Proxy（系统代理）、Direct Connection（直连）和 HTTP(S) Proxy。HTTP 代理可以通过 CONNECT 承载 HTTPS；不支持 SOCKS，也不支持与代理服务器本身建立 TLS 连接。

供应商配置通常位于 `%LOCALAPPDATA%\ida-agent\ai\providers.json`。**API Key 和保存的代理密码以明文存储**，文件使用当前用户权限控制，并未加密落盘。不要将该文件发布到仓库或 Issue。当前目录规则见[安装说明](docs/UPGRADING.md)。

内置 Agent 会把聊天内容及会话使用的分析上下文、工具结果发送给所选供应商。请按待分析二进制和数据的要求选择供应商。

## 连接 MCP 客户端

0.4.5 新增 12 个常用直接工具，保留 11 个领域工具；旧版 v0.4.4 仅提供领域入口。参见 [Gateway 兼容性说明](ida-mcp/README.md#agent-compatibility)。

保持 IDA 运行并打开数据库。Gateway 自动发现当前 Windows 用户的插件实例，不需要放入 IDA 安装目录。

### 本地配置管理器

使用安装器默认路径时运行：

```powershell
& "$env:LOCALAPPDATA\Programs\ida-agent\ida-mcp.exe" -web
```

便携安装时，在解压目录运行 `ida-mcp.exe -web`。本地页面可配置 Codex、OpenCode、Claude Code、Antigravity CLI、Grok Build 和 ZCode，并链接可选的 `ida-reverse-analysis`、`idapython` 技能。修改配置后需要重启客户端。

Windows 下，如果管理页继承的 `PATH` 尚未更新，程序也会检查常见 npm/Scoop 安装位置，以及 Codex 桌面应用自带的 CLI。npm 启动脚本会解析到原生 `codex.exe`，检测和 MCP 配置不依赖 `PATH` 中的 Node.js。自定义安装位置可通过 `IDA_MCP_CODEX_PATH` 指定 `codex.exe` 的绝对路径，设置后重启管理页。

ZCode 使用原生用户级配置 `~/.zcode/cli/config.json` 中的 `mcp.servers`，技能目录为 `~/.zcode/skills/`，不要求 `PATH` 中存在 CLI。添加时会保留已有设置和其他 MCP 服务。如果当前使用 `.agents/mcp.json` 作为回退配置，会先将其中的服务复制到 ZCode 原生配置，再添加 ida-mcp，保证已有服务继续可用，共享文件保持原样。如果移除后会重新启用共享配置中的 ida-mcp，则保留 `enable: false` 的原生条目阻止其重新生效。参见 [ZCode 官方 MCP 配置规则](https://zcode.z.ai/cn/docs/mcp-services)。

`-web` 启动的是配置页面和系统托盘，不是 MCP HTTP 服务。配置好的客户端会各自启动 stdio Gateway 子进程。

### 手动配置 stdio

对于使用 `mcpServers` JSON 对象的客户端，可参考以下配置并修改可执行文件绝对路径：

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

其他客户端的格式可能不同，详见 [Gateway 文档](ida-mcp/README.md)。默认使用 stdio，不需要额外参数。通过 `ida_instances` 发现并选择数据库；空列表表示未找到可用实例。

### 可选的 loopback HTTP

在 Gateway 目录运行：

```powershell
.\ida-mcp.exe -transport http -listen 127.0.0.1:8743
```

客户端的 MCP URL 填 `http://127.0.0.1:8743/mcp`。非 loopback 监听会被拒绝；当前没有实现带认证的远程 MCP 服务托管。

## 当前限制

| 范围 | 当前边界 |
| --- | --- |
| 平台与宿主 | Windows x64 支持完整桌面插件；Ubuntu 24.04 x86_64 与 Linux IDA 9.4 支持 MCP 和可选 AI 面板。macOS 15+ 支持 Universal 2 构建，arm64 运行验收待完成；Linux 发布包尚未支持。 |
| Hex-Rays 与目标覆盖 | 伪代码和语义参数/校验分析需要兼容的反编译器及许可。语义集成样本覆盖 Windows x64 目标的 `/Od`、`/O2` 编译结果，并未验证所有处理器架构或二进制模式。 |
| 跨函数追踪 | `analysis.trace_argument_callers` 只沿已知直接调用方展开，默认 2 层，最多 5 层。不恢复未知间接调用者、原生尾调用、被调函数返回值摘要或堆别名；递归及原型/ABI 不匹配会停止展开。已知调用者全部处理完毕也不代表调用者集合完整。 |
| 校验证据 | `analysis.guard_evidence` 仅在单个函数内工作。比较条件和必经 CFG 分支不能证明校验充分、运行路径可行、程序安全或漏洞可利用；当前没有符号路径求解器或循环不变量求解器。 |
| 其他数据流工具 | `analysis.trace_data_flow` 使用交叉引用 BFS（`xref_bfs`），不是语义污点分析。参数回溯工具使用独立且有明确边界的 microcode 分析模型。 |
| 字符串搜索 | `string.search` 和 `string.search_regex` 默认复用 IDA 字符串列表。第一页可设 `refresh: true` 重建，但不能同时传 `cursor`。首次构建和显式刷新仍可能耗时，尤其在调试期间。分页没有快照保证，列表变化后应从第一页重新搜索。 |
| 预算与取消 | 回溯结果可能部分完成或被截断。超时限制等待时间，但不能抢占 SDK 的 microcode 生成，也不能中断已在 IDA 内开始执行的脚本。 |
| 修改与脚本 | 只有受支持的 ChangeSet 操作提供预览、应用和回滚。任意脚本没有沙箱，也不会自动回滚，可以修改 IDB、访问本机或网络、阻塞 IDA。内置 AI 使用会话审批策略；MCP 的执行权限由外部客户端控制。 |
| 供应商与凭据 | 当前只实现 OpenAI 风格的 Responses/Chat Completions 和 Anthropic 风格的 Messages。供应商和模型兼容性各异；模型列表成功不代表支持工具调用。保存的凭据在磁盘上为明文。 |
| 本地连接与调试 | 同用户实例发现使用 Windows Named Pipe 或 Linux Unix socket，HTTP 仅限 loopback。Linux 本地 ELF 调试服务已通过真实 IDA 测试；Linux GUI 授权和远程调试仍待验收。操作取决于所选后端和进程状态。 |

准确的证据语义与预算见[函数内参数/校验证据合同](protocol/semantic-analysis.md)和[跨函数追踪合同](protocol/argument-callers.md)。解读结果时必须同时考虑 `partial`、`truncated`、未知边界，以及 IDB 中推断类型带来的假设。

## 源码编译

### 编译环境

| 依赖 | 要求 |
| --- | --- |
| 宿主系统 | Windows x64 |
| 编译器 | Visual Studio 2022 或 Build Tools 2022，安装“使用 C++ 的桌面开发”、MSVC x64 工具和 Windows SDK；项目代码使用 C++17 |
| CMake 与生成器 | CMake **3.25+**、Ninja |
| Go | Gateway 需要 **1.25.0+** |
| Python | Python 3；构建与打包脚本**建议使用 3.10+** |
| IDA SDK | 仓库固定版本的 `ida-sdk` 子模块 |
| Qt 开发文件 | 仓库已跟踪的 `qt-sdk/qt-6.8.2-win` 中的 Qt **6.8.2** 头文件与配置 |
| Qt 导入库 | 固定版本的 `ida-sdk/src/lib/x64_win_qt` 已包含；编译和打包无需安装 IDA |
| 仅安装器打包需要 | Inno Setup **6**（`ISCC.exe`）；只打便携包时不需要 |
| 真实 IDA 集成测试 | 除构建工具外，还需要 PowerShell **7**、`idat.exe` 及有效的 IDA/Hex-Rays 许可 |

在 VS 2022 的 x64 Native Tools 环境中使用 PowerShell，确保 `cmake`、`ninja`、`go`、`python` 位于 `PATH`。首次构建可能下载 Go 模块，以及本地尚未提供的 `nlohmann/json` 3.12.0。

Go 必须为 1.25 或以上版本：Windows Named Pipe 的超时处理依赖 `os.NewFile` 对异步句柄的支持。

### 编译并运行单元测试

克隆仓库后，在仓库根目录运行；编译和单元测试无需安装 IDA：

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

插件输出到 `build/ida-agent-plugin/ida-runtime/plugins/ida-agent-plugin.dll`，上述命令将 Gateway 输出到 `build/ida-mcp.exe`。Release 构建不会自动部署插件，需要先关闭 IDA，再把 DLL 复制到用户插件目录。

CMake 检查 Qt 6.8.2 头文件，并链接固定版本 IDA SDK 中使用 `QT` 命名空间的官方导入库。插件加载时使用 IDA 自带的 Qt DLL，构建与发布包均无需包含 Qt 运行时 DLL。普通 Qt 二进制文件的符号不同，不能替换 IDA 的 Qt。启用 AI Console 时，Debug 构建也使用匹配的 Release DLL CRT（`/MD`）。

如需在本地重新生成导入库，可向 CMake 显式传入 `-DIDA_AGENT_IDA_QT_RUNTIME_DIR=<ida-dir>`，或在运行发布脚本时设置同名环境变量。这条可选路径会校验已安装的 IDA 9.4 / Qt 6.8.2 版本和 `QT` 命名空间。向 CMake 传入 `-DIDA_AGENT_IDA_QT_RUNTIME_DIR=` 可清空旧缓存设置，恢复使用 SDK 导入库。

### 可选的集成测试

需要真实 IDA 测试时，重新配置同一构建目录并运行 CTest：

```powershell
cmake -S ida-agent-plugin -B build/ida-agent-plugin `
  -DIDA_AGENT_ENABLE_INTEGRATION_TESTS=ON `
  '-DIDA_INSTALL_DIR=C:/Program Files/IDA Professional 9.4'
cmake --build build/ida-agent-plugin
ctest --test-dir build/ida-agent-plugin -L integration --output-on-failure
```

默认 CTest 只运行单元测试。`mcp-test-project/verify_stdio.py <gateway-executable>` 无需 IDA，即可验证 11 个下划线领域工具、空实例发现和 stdio 正常退出。要检查正在运行的插件，可在打开 IDA 后执行：

```powershell
go -C ida-mcp run ./cmd/ida-agent-rpc-ping -database-info
```

### 打包发布

先完成验证再打包：发布脚本会刻意禁用插件测试。

```powershell
python release/build_release.py --clean
```

加上 `--no-installer` 可以只构建便携目录和 ZIP，无需 Inno Setup。中间产物位于 `build/release/`，最终发布产物位于 `release/dist/`，两处均已被 Git 忽略。

## GitHub Actions

Windows 工作流验证 Gateway、构建包含 AI UI 的完整插件并运行 C++ 单元测试；版本标签或手动发布构建还会生成便携 ZIP 和安装器。Linux 工作流在 Ubuntu 24.04 上构建基础 MCP 插件与独立 AI 后端，并运行包含 Agent 和面板模型的 Go/C++ 测试；真实 Linux Qt 面板测试在本地使用已授权的 IDA 和图形会话运行。工具链和系统依赖见 [Linux 环境要求](ida-agent-plugin/README-LINUX.md#linux-environment-requirements)。这些 CI 构建使用公开的 SDK 依赖，无需私有下载地址或已安装的 IDA；跨仓库发布使用下文说明的独立令牌。触发与下载产物的步骤见 [Actions 配置说明](release/README.md#中文配置说明)。

项目自有源码采用 [MIT 许可证](LICENSE)，从 `ackwrap/ida-agent` 的 master 自动同步到公开仓库 [`ackwrap/ida-pro-agent`](https://github.com/ackwrap/ida-pro-agent) 的 main。公开仓库运行 Windows/Linux 源码构建与测试；完整三平台发布包继续在开发仓库中使用对应平台的 Qt 构建输入生成。版本标签会在验证后自动将二进制包发布到公开仓库 [`ackwrap/ida-pro-agent`](https://github.com/ackwrap/ida-pro-agent/releases)；手动运行只有勾选 **publish** 才会发布。请在私有仓库配置 Secret `IDA_AGENT_RELEASE_TOKEN`，授权写入公开仓库的 Contents。同步保留公开仓库历史和已有发布标签，排除凭据、本地计划与私有 Qt 链接包。第三方许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)，同步与发布配置详见 [发布配置说明](release/README.md#中文配置说明)。官方 runner 不运行需要许可的真实 IDA 集成测试。

## 仓库与文档

| 路径 | 用途 |
| --- | --- |
| [`ida-agent-plugin/`](ida-agent-plugin/README.md) | IDA 插件、内置 AI、分析服务与 Internal RPC |
| [`ida-mcp/`](ida-mcp/README.md) | MCP 接入、实例发现与本地客户端配置 |
| [`protocol/`](protocol/README.md) | 共享协议合同、schema 与 fixtures |
| [`skills/`](skills/) | 外部客户端使用的 IDA 分析和 IDAPython 技能 |
| [`release/`](release/) | Windows 打包与安装器脚本 |
| [`docs/UPGRADING.md`](docs/UPGRADING.md) | 全新安装与组件命名规则 的说明 |
| [`AGENTS.md`](AGENTS.md) | 仓库开发与验证规则 |

IDA 插件与发布包使用 `ida-agent`；Gateway 程序、MCP 服务和客户端配置项使用 `ida-mcp`，MCP 工具采用 `ida_functions` 等下划线名称，Internal RPC 方法名保留点号。部分组件详细文档目前为中文；两份根目录 README 提供一致的安装、配置、构建与限制说明。

## MCP 调试授权

首次调用任意 `debugger.*` 方法时，IDA 会弹窗确认。允许后，所有连接当前 IDA 实例这条 Pipe 的 MCP 客户端均可执行调试，包括进程控制、断点修改和进程内存写入，后续调试调用不再询问。授权只保存在内存中；Pipe 重建、数据库关闭或 IDA 退出后失效。拒绝也仅对当前 Pipe 生效。无 GUI 的 IDA 无法确认，会拒绝访问。

授权后可以通过 `debugger.backends` 枚举、`debugger.select` 选择调试器，也可以在 IDA 中手动选择。寄存器、调用栈、线程、模块和内存操作要求目标处于暂停状态。`instance.info` 每次请求刷新调试器可用状态。首次确认及操作最多等待 120 秒。内置 AI 仍使用自身的会话权限策略。

`capabilities.ui=false` 表示尚未提供读取光标、选区等 MCP UI 检查或控制工具，不代表 IDA 没有图形界面，也不会阻止调试授权弹窗。目标暂停时返回 `state=suspended`、`running=false`、`suspended=true`。

### 调试器配置与进程控制

以下方法通过 `ida_debugger` 调用，设置 `action: "call"`；可先用 `action: "describe"` 查看参数。没有选定活动实例时，需要传入 `instanceId`。

| 方法 | 功能 | 要求的进程状态 |
| --- | --- | --- |
| `debugger.backends` | 枚举已安装调试器的 `name` / `remote` 组合和当前选择 | 没有活动调试进程；尚未选择调试器也可调用 |
| `debugger.select` | 加载枚举结果中的指定调试器和本地/远程模式 | 没有活动调试进程 |
| `debugger.configuration` | 读取启动及远程配置，密码只返回 `hasPassword` | 任意状态；尚未选择调试器也可调用 |
| `debugger.configure` | 配置 `path`、`arguments`、`directory`、`host`、`port`、`password` | 没有活动调试进程 |
| `debugger.processes` | 通过当前本地或远程调试器列出可附加进程 | 没有活动调试进程 |
| `debugger.attach` | 附加到明确指定的 `pid` | 没有活动调试进程 |
| `debugger.suspend` | 请求主动暂停 | 正在运行 |
| `debugger.detach` | 分离调试器，保留目标进程 | 已暂停 |

主动启动的顺序是 `backends` → `select` → `configure` → `start` → `info`；附加的顺序是 `select` → 按需配置远程连接 → `processes` → `attach` → `info`。运行中的目标先调用 `suspend`，查询到 `state: "suspended"` 后再单步、读取寄存器或分离。已有的 `debugger.control` 支持继续、步入、步过、运行到返回和运行到地址；`debugger.breakpoints` 支持添加、删除、启用/禁用和条件断点。

`configure` 至少传一个字段：省略字段保留原值，空字符串清除对应值，`port: -1` 恢复调试器默认端口，其余端口范围为 1–65535。修改配置不会自动启动进程。路径由 IDA 和所选调试器解释，远程路径遵循对应调试后端的规则。结果和内置 AI 审批摘要不会返回或显示密码。内置 AI 使用对应的 `ida_debugger_*` 工具，并继续遵循会话副作用权限策略。

`processes.limit` 默认 100、最大 1000，结果包含 `total` 和 `truncated`，暂不分页。该参数只限制返回条数，**无法限制 IDA 枚举进程的耗时**，远程连接仍可能等待较久。`accepted: true` 表示请求已接受，实际状态需继续查询 `debugger.info`；发生超时时不要盲目重复执行修改操作。启动和附加能否成功仍取决于远程服务、权限、目标架构与调试后端支持。当前接口仍未提供寄存器写入、数据访问断点和调试事件订阅流。
