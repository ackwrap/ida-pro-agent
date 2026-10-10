# IDA Agent Plugin

`ida-agent-plugin` 是 C++ IDA 插件，提供内置 AI 聊天、模型供应商配置、工具调用与审批，
并通过 Internal RPC、Named Pipe Server、实例 registry 和 `IdaExecutor` 暴露 IDA/Hex-Rays
分析服务。内置 AI 使用独立的 HTTP/SSE 客户端连接供应商；MCP 协议由外部 Gateway 承载，
Plugin 不需要查找、连接或注册 Gateway。

当前接口合同与字段定义见 [协议文档](../protocol/README.md)；可调用方法以
Gateway 的 `list` / `describe` 返回结果为准。

Linux/WSL2 已支持基础 MCP 和可选的完整 AI 面板，见 [Linux 构建、安装与测试](README-LINUX.md)。
Windows 默认继续包含 AI/Qt。以下 Named Pipe 与 Windows 集成测试说明适用于 Windows；
Linux 使用 Unix socket、registry v2 和独立的真实 IDA smoke runner。
Linux 独立 AI 后端已支持 HTTP、SSE、WS/WSS 和聊天会话逻辑；libcurl 与 SQLite
以固定版本静态内嵌，OpenSSL 使用系统库。启用 `IDA_AGENT_ENABLE_AI=ON` 后，
可使用 AI Chat、供应商设置、工具审批和历史记录；Qt 运行库由 Linux IDA 9.4 提供。

## Lifecycle

数据库初始化后，Plugin 在 IDA 主线程读取一次固定元数据、创建 ready Pipe 并启动 registry
publisher，然后立即返回：

```text
IDA main: generate UUID -> create ready overlapped Pipe/workers -> start publisher -> return
publisher: write/flush/rename registry -> acquire delete-on-close lease
```

`ConnectNamedPipe`、`ReadFile`、`WriteFile`、registry 文件 I/O 和客户端等待全部发生在 worker
thread，绝不阻塞 Plugin init 或 IDA UI。Gateway 不存在时，Pipe worker 正常等待；Gateway 退出
时 IDA、Pipe 和 registry 继续存在。Registry 发布失败会 quiesce Executor 并停止 Pipe worker，
不会留下无 registry 的半运行 Bridge。

每个实例的 Pipe 名为 `\\.\pipe\ida-agent-{pid}-{uuid-short}`，支持多个 Pipe instance。Pipe
DACL 只允许当前用户并拒绝远程客户端。每个连接先完成 hello，再处理一个 `ida-rpc/1` 请求。
Pipe worker 不调用 IDA SDK；Dispatcher 后的所有 IDA/Hex-Rays 操作统一通过
`IdaExecutor::ReadFor` 和 `execute_sync`。

`script.execute` 通过 IDA extlang 执行 IDAPython 或 IDC 的 UTF-8 内联源码；Internal RPC 不接受路径。
MCP `path` 输入由 Gateway 读取一次，并转换为相同内联合同。Plugin 重复校验语言、NUL、32 KiB
源码上限和输出预算，并通过 `IdaExecutor` write context 执行。Gateway 不实现额外授权或弹窗；调用
权限由 MCP 客户端控制，Internal RPC 仍属于当前用户 Pipe 信任边界。Python stdout/stderr 和 IDC
result 有界返回，timeout 不会中断已开始的脚本。

只读 function analysis RPC 包含 `function.disassemble`、`function.basic_blocks` 和
`function.callees`。它们的参数解析、handler 与错误映射位于独立的
`bridge/function_analysis_handlers.cpp`，`FunctionService` 行为和 Plugin/Gateway 进程边界未变。
连续反汇编分页复用下一条指令位置；基本块与 callee 分页复用有界快照，并在 IDB 或引用修改时失效。

AI 流式事件按每次最多 64 条、8 ms 的预算消费，工具参数片段也会继续推进队列。
聊天记录的编码和 SQLite 写入在专用后台线程执行，100 ms 窗口内合并同一会话的最新快照；
切换、清空会话及正常关闭前会等待待写入记录完成，写入失败在面板提示。

正常卸载时先 signal/cancel/close Pipe workers，再关闭持有的 registry handle。Registry 使用
临时文件完整写入、flush、同目录原子 rename，再立即持有 `FILE_FLAG_DELETE_ON_CLOSE` lease；
正常退出或绝大多数进程崩溃由 Windows 删除文件。rename/lease 之间的极短 crash 窗口由 Gateway
的 PID 与 hello stale 校验兜底，不能仅信任文件。

默认 registry：

```text
%LOCALAPPDATA%\ida-agent\instances\{pid}-{uuid-short}.json
```

路径通过 `SHGetKnownFolderPath(FOLDERID_LocalAppData)` 获取。测试可设置
`IDA_AGENT_INSTANCE_DIR`，生产代码不硬编码用户目录。

## Build And Test

在可找到 MSVC 2022 和 IDA SDK 的 Windows 环境中：

```shell
cmake -S ida-agent-plugin -B build/ida-agent-plugin -G Ninja
cmake --build build/ida-agent-plugin
ctest --test-dir build/ida-agent-plugin --output-on-failure
```

默认 DLL 位于 `build/ida-agent-plugin/ida-runtime/plugins`。默认 CTest 不注册五个耗时的真实 IDA
集成测试。需要运行时，重新配置并显式传入
`-DIDA_AGENT_ENABLE_INTEGRATION_TESTS=ON -DIDA_INSTALL_DIR=<ida-install-dir>`；CTest 随后运行真实
`idat.exe` 生命周期、Named Pipe discovery/hello、92 个 Plugin RPC 入口、ChangeSet
apply/rollback、数据库保存、无进程 Debugger 错误路径，以及 Gateway 的既有只读 RPC。Gateway
联调在同一个真实 IDA 会话中分别通过进程内 Streamable HTTP 和真实 Gateway stdio 子进程，经
11 个领域入口调用全部 98 个 callable method。另有 `/Od` 和 `/O2` 固定样本验证调用参数回溯和
校验证据，以及跨函数的两层参数来源、多调用者和递归边界；测试中的类型声明仅写入隔离 IDB。缺少 IDA/Hex-Rays 许可时仍应运行全部纯单元测试
并明确报告真实集成缺口。
Gateway 联调还覆盖逐条/随机分页、重命名与引用增删后的缓存失效、函数边界调整和共享尾块续页。

### 真实调试功能验收

启用 `IDA_AGENT_ENABLE_INTEGRATION_TESTS` 后，`ida_debugger_integration` 会启动隔离的
`idat.exe`，使用独立 `IDAUSR`、临时 IDB，以及本次编译的有限寿命样本进程，检查本地 Windows
调试器选择、配置读写、启动、断点、运行到地址、单步、寄存器/内存读取、继续、暂停、退出、
附加、分离及状态冲突。分离后还会确认目标进程仍然存活，再由测试清理它。

```shell
cmake --build build/ida-agent-plugin --target ida_debugger_integration_driver ida_debugger_integration_sample
ctest --test-dir build/ida-agent-plugin -R "^ida_debugger_integration$" --output-on-failure
```

该测试驱动只在启用集成测试时构建，直接复用正式的 C++ 调试 handlers、IdaExecutor 和 services，
由隔离 IDA 的主线程调用；它不创建 Pipe/网络接口、不随发布包分发，也不改变正式插件的授权规则。
`ida_agent_plugin_lifecycle` 与 `ida_agent_gateway_ping` 另行验证正式 DLL 的真实 Pipe、HTTP/stdio
链路和无 GUI 时返回 `PERMISSION_DENIED`。因此，调试服务成功路径、传输链路与权限门禁分别验收；
真实 GUI 授权弹窗、后台请求排队时序及远程调试连接仍需要单独验证。

结果保留在 `%TEMP%/ida-debugger-integration-*/debugger-results.json`，包含调用结果、断言和
失败原因。测试不会附加到用户的现有进程，也不会覆盖已安装插件。

## 版本升级

配置与聊天记录统一使用 `%LOCALAPPDATA%\ida-agent\ai`，不回退读取旧名称目录，详见 [安装说明](../docs/UPGRADING.md)。
