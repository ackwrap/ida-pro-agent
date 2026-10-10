# IDA RPC Windows Named Pipe Transport

Windows 使用每个 IDA 实例独立的 duplex Named Pipe。Transport 与 MCP stdio/HTTP 及
`ida-rpc/1` JSON envelope 相互独立。

## Pipe Locator

```text
\\.\pipe\ida-agent-{pid}-{instance_id 前 8 个十六进制字符}
```

完整 `instance_id` 是随机 UUID v4，只保存在 registry、hello 和 RPC identity 中。Pipe 名不编码
数据库路径、输入文件、处理器或其他业务信息。Pipe DACL 受保护且仅允许当前用户访问，并使用
`PIPE_REJECT_REMOTE_CLIENTS` 拒绝远程客户端。

## Frame

每个 JSON payload 使用长度前缀 frame：

```text
Request:
offset  size  value
0       4     ASCII "IMCP"
4       1     framing version 1
5       4     unsigned big-endian payload length
9       N     UTF-8 JSON

Response:
offset  size  value
0       4     ASCII "IMCR"
4       1     framing version 1
5       4     unsigned big-endian payload length
9       N     UTF-8 JSON
```

请求 payload 最大 1 MiB；序列化 RPC 响应总预算为 256 KiB，超出后返回 `OUTPUT_LIMIT`。
无效 magic、framing version、长度、不完整输入或超时直接断开。

## Hello

每个新 Pipe connection 的第一组 request/response 必须是 hello，不允许直接发送 RPC：

```json
{"method":"hello","params":{"protocol":1,"client":"ida-mcp"}}
```

```json
{"product":"ida-agent-plugin","protocol":1,"instance_id":"...","pid":18452}
```

Gateway 必须验证 product、protocol、PID，以及 hello `instance_id` 与 registry 完全一致。通过
后，同一 connection 承载一个 `ida-rpc/1` request/response，然后关闭。Gateway 每次调用都可
重新连接，因此断线、Gateway 重启或 Plugin 重载不依赖连接池恢复。

## Timeouts And Shutdown

- Gateway discovery connect/hello/`instance.info` probe 默认每实例 250 ms，并受 caller context 约束。
- Plugin 给完整 hello + request 输入 5 秒；解析后使用 `timeoutMs` 作为执行预算，并预留 2 秒发送响应。
- Pipe Server 使用 overlapped `ConnectNamedPipe`、`ReadFile` 和 `WriteFile`。stop event 与
  `CancelIoEx` 保证卸载时不会卡在 accept/read/write。
- Worker 只处理 framing、hello 和 dispatch；所有 IDA SDK/Hex-Rays 调用继续经过
  `IdaExecutor`/`execute_sync`。
- Server 支持多个 Pipe instance、4 个 I/O worker 和有界 pending queue。Gateway 另按
  `instance_id` 限制最多 2 个并发业务请求，超出立即返回 retryable `IDA_BUSY`。

## Registry Ordering

Registry 只负责发现，Pipe 才负责身份和通信。发布顺序必须为：

```text
UUID -> CreateNamedPipe ready -> atomic registry publish
```

停止顺序必须为：

```text
stop/cancel Pipe workers -> close Pipe -> close delete-on-close registry handle
```
