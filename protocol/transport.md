# IDA RPC Windows Named Pipe Transport

**English** | [简体中文](transport.zh-CN.md)

Windows uses a separate duplex Named Pipe per IDA instance. The transport is independent of MCP stdio/HTTP and of the `ida-rpc/1` JSON envelope.

## Pipe Locator

```text
\\.\pipe\ida-agent-{pid}-{first 8 hex characters of instance_id}
```

The full `instance_id` is a random UUID v4 stored only in the registry, hello and RPC identity. The Pipe name encodes no database path, input file, processor, or other business information. The Pipe DACL is protected, allows access only to the current user, and uses `PIPE_REJECT_REMOTE_CLIENTS` to reject remote clients.

## Frame

Each JSON payload uses a length-prefixed frame:

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

The request payload is at most 1 MiB; the total serialized RPC response budget is 256 KiB, beyond which `OUTPUT_LIMIT` is returned. An invalid magic, framing version or length, incomplete input, or a timeout disconnects immediately.

## Hello

The first request/response of each new Pipe connection must be hello; an RPC cannot be sent directly:

```json
{"method":"hello","params":{"protocol":1,"client":"ida-mcp"}}
```

```json
{"product":"ida-agent-plugin","protocol":1,"instance_id":"...","pid":18452}
```

The Gateway must validate product, protocol and PID, and that the hello `instance_id` exactly matches the registry. After that, the same connection carries one `ida-rpc/1` request/response and then closes. The Gateway can reconnect for every call, so disconnections, Gateway restarts or Plugin reloads do not depend on connection-pool recovery.

## Timeouts And Shutdown

- The Gateway discovery connect/hello/`instance.info` probe defaults to 250 ms per instance and is bounded by the caller's context.
- The Plugin gives a complete hello + request input 5 seconds; after parsing it uses `timeoutMs` as the execution budget and reserves 2 seconds to send the response.
- The Pipe Server uses overlapped `ConnectNamedPipe`, `ReadFile` and `WriteFile`. A stop event and `CancelIoEx` ensure unload cannot hang in accept/read/write.
- Workers handle only framing, hello and dispatch; all IDA SDK/Hex-Rays calls still go through `IdaExecutor`/`execute_sync`.
- The server supports multiple Pipe instances, 4 I/O workers and a bounded pending queue. The Gateway additionally limits each `instance_id` to at most 2 concurrent business requests and immediately returns a retryable `IDA_BUSY` beyond that.

## Registry Ordering

The registry is only responsible for discovery; the Pipe is responsible for identity and communication. The publish order must be:

```text
UUID -> CreateNamedPipe ready -> atomic registry publish
```

The stop order must be:

```text
stop/cancel Pipe workers -> close Pipe -> close delete-on-close registry handle
```
