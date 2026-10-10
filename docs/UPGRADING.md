# Installing ida-agent 0.4.0 / 安装 ida-agent 0.4.0

## Component names / 组件名称

| Component / 组件 | Name / 名称 |
|---|---|
| IDA plugin and release package / IDA 插件及发布包 | ida-agent |
| Gateway executable / Gateway 程序 | ida-mcp.exe |
| MCP server and client entry / MCP 服务及客户端配置项 | ida-mcp |
| Gateway source and Go module / Gateway 目录及模块 | ida-mcp |

## Fresh installation / 全新安装

1. Close IDA and clients using the previous Gateway.
2. Uninstall the previous package. Remove the old MCP entry from each client; no alias or automatic migration is provided.
3. Install the complete 0.4.0 package. Keep the Plugin and Gateway from the same package.
4. Run `ida-mcp.exe -web`, add the `ida-mcp` entry, then restart the MCP client.
5. Open IDA and select the debugger. On the first debugger request, approve the dialog in IDA.

1. 关闭 IDA 和正在使用旧 Gateway 的客户端。
2. 卸载旧包，并从各客户端移除旧 MCP 条目。本版不提供别名或自动迁移。
3. 全新安装 0.4.0 完整包，Plugin 与 Gateway 使用同一发布包中的版本。
4. 运行 `ida-mcp.exe -web` 添加 `ida-mcp`，再重启客户端。
5. 打开 IDA、选择调试器，首次调试请求时在 IDA 中确认授权。

The installer remains under `%LOCALAPPDATA%\Programs\ida-agent`. The plugin is deployed to `%APPDATA%\Hex-Rays\IDA Pro\plugins\ida-agent-plugin.dll`. Current plugin settings remain under `%LOCALAPPDATA%\ida-agent\ai`; uninstalling the package does not require deleting provider settings or chat history.

安装目录仍为 `%LOCALAPPDATA%\Programs\ida-agent`，插件位于 `%APPDATA%\Hex-Rays\IDA Pro\plugins\ida-agent-plugin.dll`。现有插件设置目录为 `%LOCALAPPDATA%\ida-agent\ai`；卸载安装包不要求删除供应商设置或聊天记录。

## Debugger approval / 调试授权

One approval applies to every MCP client on the current IDA Pipe. It is not written to disk. Pipe recreation, database closure, or IDA exit clears the decision. Gateway reconnection alone does not clear it. A rejected request does not operate the debugger. Headless IDA denies because no confirmation dialog is available. The first confirmation plus operation can wait up to 120 seconds.

一次允许对当前 IDA Pipe 的全部 MCP 客户端生效，不写入磁盘。Pipe 重建、数据库关闭或 IDA 退出时清空；仅 Gateway 重连不会清空。拒绝后不会操作调试器。无 GUI 的 IDA 无法弹窗确认，会拒绝访问。首次确认与操作最多等待 120 秒。

This package supports **Windows x64 with IDA Professional 9.4 and its bundled Qt 6.8.2 only**. It does not include IDA or Qt DLLs.

本包**仅支持 Windows x64、IDA Professional 9.4 及其自带 Qt 6.8.2**，不包含 IDA 或 Qt DLL。

## MCP tool names / MCP 工具名称

All 11 public domain tools now use underscore names, for example `ida_instances`, `ida_functions`, and `ida_debugger`, in both stdio and HTTP modes. Replace dotted tool names such as `ida.functions` in client scripts and tool allowlists, then restart the Gateway and reconnect the MCP client to refresh its catalog. Method identifiers, such as `function.search` and `ida.instances.list`, and the `list` → `describe` → `call` workflow stay the same. The fixed tool catalog disables change notifications by default. New Grok configurations need no special flag; existing `--grok` arguments are accepted as a deprecated no-op.

stdio 和 HTTP 模式的 11 个对外领域工具现在统一使用下划线名称，例如 `ida_instances`、`ida_functions` 和 `ida_debugger`。请更新客户端脚本及工具允许列表中原有的 `ida.functions` 等点号工具名，重启 Gateway 并重新连接 MCP 客户端以刷新目录。`function.search`、`ida.instances.list` 等方法标识及 `list` → `describe` → `call` 流程保持一致。固定工具目录默认关闭变更通知，Grok 新配置不再需要专用参数；已有的 `--grok` 参数仍作为已弃用的兼容参数接受，不改变行为。

## Agent compatibility in 0.4.5 / 0.4.5 的 Agent 兼容性

The 0.4.5 Gateway adds 12 direct tools while keeping the 11 domain tools and existing RPC protocol. Older v0.4.4 packages retain the domain-only catalog. Reconnect clients after replacing the Gateway and refresh skill copies/tool allowlists. Argument errors now return structured tool failures instead of SDK schema protocol failures. See [Gateway compatibility details](../ida-mcp/README.md#agent-compatibility).

0.4.5 增加 12 个常用直接工具，保留 11 个领域工具和既有 RPC 协议。旧版 v0.4.4 仅提供领域入口。更新 Gateway 后重连客户端并刷新技能、工具允许列表；参数错误现在返回结构化工具错误。参见 [Gateway 兼容性说明](../ida-mcp/README.md#agent-compatibility)。

## Windows chat fixes in 0.4.6 / 0.4.6 的 Windows 聊天修复

Close IDA, install the complete 0.4.6 package, and restart IDA and MCP clients. The release fixes WinHTTP request-state error 12019 during delayed streamed responses and supports external history before the database is packed. Provider settings and external history remain in their existing user directories. The MCP catalog remains 23 tools, with the same RPC contracts as 0.4.5.

关闭 IDA 后安装完整的 0.4.6 发布包，再重启 IDA 与 MCP 客户端。本版修复流式响应延迟期间的 WinHTTP 请求状态错误 12019，并支持数据库打包前保存外部聊天历史。供应商配置和外部历史继续使用现有用户目录。MCP 目录保留 23 个工具，RPC 合同与 0.4.5 一致。
