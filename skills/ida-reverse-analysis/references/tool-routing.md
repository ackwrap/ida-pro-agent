# ida-mcp Tool Routing

Gateways from v0.4.5 expose 12 fixed common direct tools plus 11 domain tools. Check which tools are advertised: packaged v0.4.4 has only domain tools. For an advertised direct tool, use its provided schema and pass parameters at the top level. For advanced operations or older Gateways, choose a domain from the table, use `describe`, then `call` with a JSON object in `arguments`.

All clients use the same fixed `ida_*` tool catalog by default; no `--grok` launch flag is needed. MCP tool names use underscores, such as `ida_functions`; specific operations use dotted method identifiers, such as `function.search` or `ida.instances.list`, in the `method` field. Reconnect the MCP client after a Gateway update to refresh its tool catalog.

## Direct Tools

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

Direct calls return the method result directly, while domain calls return `method` plus `result`. The name-search alias accepts `name`; address lookup uses `ida_get_function`. Direct read tools use an explicit instance, the selected instance, or the sole available instance. With several databases, select one or supply the discovered UUID. Domain tools retain explicit selection/routing. Pagination and output bounds are shared with the underlying method.

```json
{"name":"ida_search_functions","arguments":{"instanceId":"00000000-0000-4000-8000-000000000000","name":"main","limit":20}}
```

Replace the UUID with a discovered instance. For errors, correct `issues` using `hint`. Updated Gateways already perform bounded read-only busy retries; do not add repeated retry loops. Writes, scripts and debugger control are not retried automatically. A timeout with `executionState:"unknown"` requires checking actual state before resubmission.

## Dispatch Examples

List available function methods through the `ida_functions` tool:

```json
{"action":"list"}
```

Describe a function method without connecting to IDA:

```json
{"action":"describe","method":"function.search"}
```

The `tools/call` parameters for a function search with explicit instance routing are:

```json
{
  "name": "ida_functions",
  "arguments": {
    "action": "call",
    "method": "function.search",
    "arguments": {
      "instanceId": "00000000-0000-4000-8000-000000000000",
      "name": "main",
      "limit": 20
    }
  }
}
```

Replace the example UUID with the ID returned by `ida.instances.list`. Never reuse the placeholder.

## Domain Catalog

| MCP tool | Callable methods | Side-effect notes |
|---|---|---|
| `ida_instances` | `ida.instances.list`, `ida.instances.select`, `ida.instances.get_active`, `system.ping`, `system.methods`, `instance.info` | Process-local selection only |
| `ida_database` | `database.info`, `database.segments`, `database.entry_points`, `database.survey`, `database.save` | `database.save` writes the current IDB; no target path |
| `ida_functions` | `function.get`, `function.search`, `function.decompile`, `function.disassemble`, `function.basic_blocks`, `function.callees`, `function.callers`, `function.callgraph`, `function.profile`, `function.export`, `function.analyze`, `function.analyze_batch`, `function.stack_frame` | Read-only; decompile and optional analyze sections may require Hex-Rays |
| `ida_search` | `xref.query`, `memory.read`, `string.search`, `memory.search_bytes`, `instruction.search`, `instruction.query`, `listing.search`, `listing.search_text`, `string.search_regex`, `signature.make`, `signature.xrefs`, `xref.struct_field` | IDB reads only |
| `ida_symbols` | `symbol.imports`, `symbol.exports`, `symbol.search`, `global.value` | IDB reads only |
| `ida_types` | `type.search`, `type.query`, `type.get`, `type.read_value`, `type.read_struct`, `type.infer` | IDB reads only |
| `ida_analysis` | `analysis.component`, `analysis.trace_data_flow`, `analysis.trace_argument`, `analysis.trace_argument_callers`, `analysis.guard_evidence`, `analysis.diff_before_after` | Argument/guard analysis is read-only and requires Hex-Rays; diff temporarily writes one reversible action and rolls it back |
| `ida_changes` | `changeset.preview`, `changeset.apply`, `changeset.rollback`, `changeset.audit` | Apply and rollback write the IDB |
| `ida_patch` | `patch.assemble`, `patch.write_bytes`, `patch.write_integer` | Assembly is read-only; writes are reversible single-operation ChangeSets |
| `ida_debugger` | `debugger.backends`, `debugger.select`, `debugger.configuration`, `debugger.configure`, `debugger.processes`, `debugger.attach`, `debugger.detach`, `debugger.suspend`, `debugger.info`, `debugger.start`, `debugger.exit`, `debugger.control`, `debugger.breakpoints`, `debugger.registers`, `debugger.stacktrace`, `debugger.memory_read`, `debugger.memory_write` | Debugger selection/configuration, process control, breakpoint mutation, and memory write are side effects |
| `ida_scripts` | `script.execute` | Arbitrary IDAPython or IDC; permission is controlled by the MCP client |

## Common Routes

- Database orientation: `database.survey`, then selectively `database.entry_points`, `symbol.imports`, `symbol.exports`, or `string.search`.
- Function comprehension: `function.search` or `function.get`, then `function.analyze`; use `function.decompile`, `function.disassemble`, or `function.basic_blocks` for focused verification.
- Call relationships: `function.callers` and `function.callees` for direct edges; `function.callgraph` or `analysis.component` for bounded multi-hop context.
- Data and reference tracing: `xref.query` for precise incoming or outgoing references; `analysis.trace_data_flow` for bounded xref BFS, followed by pseudocode or disassembly verification.
- Call arguments: `analysis.trace_argument` with an exact `callAddress` and zero-based `argumentIndex`; inspect recovered argument types, dependencies, conversions, and unknown boundaries.
- Caller parameter origins: `analysis.trace_argument_callers` expands known direct callers with separate contexts and shared budgets. ABI mismatches, recursion and incomplete caller coverage remain explicit; callee-return and heap-alias boundaries are not expanded.
- Validation conditions: `analysis.guard_evidence` takes the same inputs and returns comparison operands, required CFG branch edges, and value relations. `same_value` does not establish sufficient validation; `derived_value` can include truncation or arithmetic overflow. Neither a complete trace nor a required edge proves safety or runtime path feasibility.
- Constants and patterns: `memory.read`, `memory.search_bytes`, `instruction.search`, `listing.search_text`, or signature methods.
- Types and structures: `type.search` or `type.get`, then `type.read_value`, `type.read_struct`, `type.infer`, or `xref.struct_field`.
- Function comparison after a potential edit: `analysis.diff_before_after` only for a single reversible action and only when temporary mutation is acceptable.
- Direct patching: use `patch.write_bytes` or `patch.write_integer` for one edit and retain its `changeId`; use `ida_changes` for batches or separately reviewed previews.
- Export for reporting: `function.export` returns bounded content; it does not write a file.

## ChangeSet Workflow

Common reversible operations include `rename`, `comment.set`, `comment.append`, `comment.pseudocode`, `type.apply`, `patch.bytes`, `patch.integer`, `local.rename`, `local.type`, `segment.rename`, `segment.permissions`, `function.flags`, `function.end`, `function.chunk.add/delete`, and `xref.code/data.add/delete`. Use the method schema returned by `describe` as the complete source of truth.

1. Call `changeset.preview` with 1 to 100 operations.
2. Inspect applicability, conflicts, targets, and original values.
3. Obtain user authorization if application was not already explicitly requested.
4. Call `changeset.apply` with the preview ID and exactly the same operations.
5. Keep the returned `changeId`; use `changeset.rollback` if the user requests reversal or verification fails.
6. Use `changeset.audit` for bounded redacted history.

Do not bypass this flow. Unsupported reversible contracts such as bookmarks, function definition, define or undefine bytes, new type declarations, and stack-member creation must not be emulated with scripts unless the user explicitly requests arbitrary scripting and accepts its risks.

## Pagination and Limits

- Addresses are `0x`-prefixed hexadecimal strings.
- Typical list limits default to 20 and are capped at 100; rely on `describe` for the exact method schema.
- Public cursors are bound to Gateway process, instance, method, and normalized filters. A restart or changed filter invalidates them.
- Continuation styles vary: cursor, integer offset, ordinal, or next address. Re-submit the original filters unchanged.
- Gateway output is bounded; prefer method-level continuation over requesting broad dumps.

## Debugger and Scripts

Debugger methods first pass the IDA Pipe permission dialog, shared by all clients on that Pipe. The decision is temporary and resets with the Pipe or database. Bootstrap methods `debugger.backends`, `debugger.select`, `debugger.configuration`, and `debugger.configure` work without a previously selected debugger. Other methods require a loaded debugger and compatible process/thread state. Discovery capability flags are informative; the plugin checks the live state. Client timeout or cancellation does not undo process control, breakpoint changes, or process-memory writes already accepted by IDA.

For launch, discover exact debugger names/modes with `debugger.backends`, select with `debugger.select`, update launch/remote options with `debugger.configure`, then use `debugger.start` and `debugger.info`. For attach, select/configure, list candidate PIDs with `debugger.processes`, and call `debugger.attach` with an explicit PID. Selection, configuration changes, process enumeration, and attachment require no active process. Pause a running process with `debugger.suspend`, wait for `state=suspended`, and then step, read registers/memory, or call `debugger.detach`. Configuration reads return only `hasPassword`, never the password. `accepted=true` is a receipt; do not infer completion. Process enumeration limits returned entries, not SDK enumeration time.

`script.execute` accepts `language` as `python` or `idc` and exactly one of inline `code` or a Gateway-readable `path`, with source limited to 32 KiB. The MCP client decides whether to permit this `arbitrary_code_execution` side effect; the Gateway does not prompt or retain authorization state. A file-backed script is read once during the call and converted to inline source for Internal RPC. The arguments do not contain `confirmed` or `scope` fields. Started scripts may modify the IDB, access files or networks, launch processes, or continue after timeout.

## Known Boundaries

The current Gateway discovers already-running Windows IDA Plugin instances. It does not provide headless IDA, arbitrary binary or IDB opening, MCP Resources, UI cursor or selection access, Unix transport, direct mutation tools, or arbitrary-path database saving.
