# MCP stdio/HTTP + Named Pipe 多实例测试用例

## 1. 无 IDA 初始化

1. 由 Client 启动 `ida-mcp.exe` stdio 子进程。
2. 调用 MCP `initialize` 和 `tools/list`。
3. 调用 `ida.instances.list`。

预期：前两步不扫描 registry、不等待 Pipe；第三步返回 `{"instances":[]}`，Gateway 不启动 HTTP。

对显式 `-transport http -listen 127.0.0.1:<port>` 重复 initialize/tools.list/list；预期同样不依赖
IDA，并验证非 loopback listener、远程 Origin 和超大 body 被拒绝。

## 2. IDA 先启动

1. 启动 IDA，确认独立 Pipe 和 `%LOCALAPPDATA%\ida-agent\instances` entry 存在。
2. 数小时后启动 OpenCode/Codex。
3. 调用 `ida.instances.list`、`ida.instances.select(instanceId)`、`database.info`。

预期：hello 和 `instance.info` 验证成功；业务 Tool 省略 `instanceId` 时路由到 active instance。

## 3. Gateway 先启动

1. 启动 Gateway 并确认 `ida.instances.list` 为空。
2. 启动 IDA。
3. 再次调用 `ida.instances.list`。

预期：无需重启 Gateway 即可发现新实例，MCP initialize 始终不受 IDA 状态影响。

## 4. 显式多实例路由

1. 同时启动两个 IDA，确认 UUID、PID/Pipe 和数据库不同。
2. list 后 select A，省略 `instanceId` 调用 `function.search/get/decompile`。
3. 在同一 Gateway 对 B 使用显式 `instanceId` 调用相同 Tool。

预期：active 路由属于 A，显式路由属于 B，结果不串线；cursor 不能跨实例复用。

## 5. 多 Gateway

分别由 OpenCode 和 Codex 启动自己的 Gateway stdio 子进程，同时访问同一 IDA。

预期：Plugin 的多个 Pipe instance 可并发连接；每个 Gateway 的 active instance 状态互不共享；
每个 Gateway 对单实例最多执行 2 个请求，其余请求按 FIFO 最多等待 8 个、5 秒，且响应调用取消/期限；队列满或等待到期返回 retryable `IDA_BUSY`。只读忙碌最多自动重试两次，有副作用操作不自动重试。

## 6. 关闭与崩溃

- 关闭 Client：Gateway 退出，IDA/Pipe/registry 继续存在。
- 关闭 IDA：Pipe worker 被 cancel，registry handle 关闭且 entry 消失。
- taskkill/crash IDA：OS 回收 Pipe 和 delete-on-close HANDLE；若残留 entry，Gateway 通过 PID + hello
  判定 stale，不返回该实例。
- 半开 Pipe client：不能阻塞其他 worker，Plugin stop 必须在 2 秒内完成。

## 7. 完整领域链路

`tools/list` 固定返回 12 个直接工具及 11 个领域入口；经领域 `call` 依次实际调用全部 98 个 callable method，
并验证 search/xref/inventory HMAC cursor、反编译 offset continuation、ChangeSet、直接 patch
门面的 apply/rollback、Debugger 状态、
普通副作用工具形式的脚本执行、`analysis.wait` complete/timeout/cancel、`analysis.plan` 排队、local xref 与
local ChangeSet 精确标记恢复、timeout 和输出预算。该链路必须在
官方 Go MCP Client 的 Streamable HTTP 与真实 `ida-mcp.exe` stdio 子进程上各运行一次。
MCP 输出允许 PID 和业务实例信息，但禁止 token、Pipe locator、内部堆栈和未脱敏绝对敏感路径。

当前自动化入口是显式启用的 CTest `ida_agent_gateway_ping`。它复用一个真实 IDA 9.4/Hex-Rays
会话完成 direct RPC、HTTP 和 stdio 验收；默认快速 CTest 不注册该慢测试。

## 8. 无 IDA 兼容性黑盒

运行 `python mcp-test-project/verify_compatibility.py <gateway-executable> --http`。脚本使用隔离实例目录，在四个 MCP 协议版本上检查 stdio/HTTP、23 个工具的简单公开 schema、字段错误与会话恢复、JSON 文本/结构化结果一致性、脱敏诊断与 stdio EOF。另运行 `verify_stdio.py` 做基础生命周期验收。

直接工具测试应覆盖单实例自动路由、多实例显式选择、全部固定别名及分页；队列测试覆盖 FIFO、满队列、取消和授权槽竞争；重试测试覆盖相同总期限及写入/脚本/调试控制单次执行。协议/SDK 自动化不等同于实际 Agent/模型测试；真实 IDA 和客户端链路需独立记录。

## 9. 实际 Agent 客户端回归

参见 [CLIENT_REGRESSION.md](CLIENT_REGRESSION.md)。`run_agent_clients.py` 直接启动已安装的
Codex、Claude Code 或 OpenCode，用透明 stdio tee 记录实际工具发现、调用及响应。
判定来自 MCP wire evidence 和模拟 RPC trace，不采用模型自述、CLI 退出码或静态配置作为成功证据。
`verify_client_sdk.py` 使用固定版本的官方 Python MCP SDK，属于跨进程 SDK 集成测试，不能记为
真实 Agent 测试。所有模拟 IDA、真实 IDA、客户端未启动或未观察到并发的结果分开记录。
