# IDA Internal RPC Protocol

`protocol/` is the language-neutral source of truth for communication between the Go
Gateway and the C++ IDA Plugin. MCP messages and IDA SDK-managed types are not valid on
this boundary.

## Version

The first protocol version is `ida-rpc/1`. A peer must reject unsupported versions instead
of attempting an implicit fallback.

## Envelope

Every request contains:

- `protocolVersion`: exactly `ida-rpc/1`.
- `requestId`: an opaque correlation ID, 1 to 128 characters.
- `sessionId`: the explicit target IDA instance UUID. The field name is retained inside
  `ida-rpc/1`; it always equals registry `instance_id` and is never process-global active state.
- `method`: a namespaced semantic method.
- `params`: a JSON object, including when the method has no parameters.
- `timeoutMs`: an integer from 1 through 120000.

Every response echoes `protocolVersion`, `requestId`, and `sessionId`, then contains exactly
one of `result` or `error`. Results are JSON objects. Errors contain a stable `code`, a
human-readable `message`, and `retryable`; an `INTERNAL_ERROR` caused by a retained failed
ChangeSet rollback may additionally contain a bounded `recoveryChangeId`. Errors must not include
Pipe locators, sensitive paths, or internal stack traces.

## Encoding Rules

- Messages use UTF-8 JSON.
- Unknown fields are rejected in every protocol-defined object. `params` and `result` are
  envelope extension points; their fields are rejected by the registered method-specific
  schema once that method is implemented.
- Addresses use strings matching `0x[0-9A-Fa-f]{1,16}` and are parsed as unsigned 64-bit
  values with overflow checks.
- Protocol control fields `timeoutMs`, registry `version`/`pid`/`bitness`/`started_at`, and
  capability address widths are mathematical integers. Equivalent forms
  such as `5000`, `5000.0`, and `5e3` are accepted; fractional, negative, and larger values
  are rejected from the raw token before DOM conversion. Numeric semantics inside `params`
  and `result` belong to their method-specific schemas. Addresses use strings.
- IDs and method names are ASCII and bounded by their schemas.
- Windows instance locators are current-user Named Pipe names. Registry entries contain no
  bearer token and are not proof of liveness; hello is authoritative.
- `instance_id` is a lowercase random UUID v4. Registry version and hello protocol are both
  explicitly versioned independently from `ida-rpc/1`.

## Schemas

### Platform instance registry

Windows continues to publish registry **v1** with the required `pipe` field.
Linux publishes **v2** with the required `endpoint` object and no `pipe` field:
`{"kind":"unix","path":"/tmp/ida-agent-1000/instances/ida-agent-4242-8dd304b5.sock"}`.
Only `kind` and `path` are allowed; v2 currently supports only `unix`. The path is
absolute, normalized, at most 107 UTF-8 bytes, and ends in
`ida-agent-{pid}-{first-eight-instance-id-characters}.sock`. Empty components,
`.`/`..`, control characters, and backslashes are rejected. All other registry
fields retain their v1 meanings. The hello protocol and `ida-rpc/1` are unchanged.

The Linux registry and socket share `/tmp/ida-agent-<uid>/instances` (0700).
Registry files and sockets are 0600 and owned by the current user. Both sides reject
symlinks and unsafe directory ancestors; the Gateway also requires the endpoint
to be inside the discovery directory. The server verifies client UID with
`SO_PEERCRED`; the Gateway verifies server UID and PID before hello, then verifies
the UUID/PID from hello. Registry records alone never authorize a connection.
Discovery checks process ownership and start time against registry publication
time, removes validated dead/stale entries and their sockets, and retains live
instances that temporarily fail an RPC probe. Normal plugin shutdown removes only
its own registry/socket inodes. `IDA_AGENT_INSTANCE_DIR` remains a test override.

Each socket connection carries one hello and one RPC using the existing framing
and budgets. The server has four I/O workers and at most eight queued clients;
invalid framing or hello closes the connection. A partial request has a five-second
input deadline. All IDA/Hex-Rays operations still go through `IdaExecutor` on the
main thread. The current-user trust boundary is the same as on Windows.

### Schema files

- `schema/request.schema.json`
- `schema/response.schema.json`
- `schema/instance.schema.json`
- `schema/hello.request.schema.json`
- `schema/hello.response.schema.json`
- `schema/common.schema.json`
- `schema/methods/instance-info.request.schema.json`
- `schema/methods/instance-info.response.schema.json`
- `schema/methods/database-info.request.schema.json`
- `schema/methods/database-info.response.schema.json`
- `schema/methods/function-get.request.schema.json`
- `schema/methods/function-get.response.schema.json`
- `schema/methods/function-search.request.schema.json`
- `schema/methods/function-search.response.schema.json`
- `schema/methods/function-disassemble.request.schema.json`
- `schema/methods/function-disassemble.response.schema.json`
- `schema/methods/function-basic-blocks.request.schema.json`
- `schema/methods/function-basic-blocks.response.schema.json`
- `schema/methods/function-callees.request.schema.json`
- `schema/methods/function-callees.response.schema.json`
- `schema/methods/xref-query.request.schema.json`
- `schema/methods/xref-query.response.schema.json`
- `schema/methods/memory-read.request.schema.json`
- `schema/methods/memory-read.response.schema.json`
- `schema/methods/function-decompile.request.schema.json`
- `schema/methods/function-decompile.response.schema.json`
- `schema/methods/database-segments.request.schema.json`
- `schema/methods/database-segments.response.schema.json`
- `schema/methods/string-search.request.schema.json`
- `schema/methods/string-search.response.schema.json`
- `schema/methods/symbol-imports.request.schema.json`
- `schema/methods/symbol-imports.response.schema.json`
- `schema/methods/mutation-debugger.schema.json` and independent request/response wrappers for
  `changeset.*`, `patch.assemble`, `analysis.diff_before_after`, and all `debugger.*` methods
- `schema/methods/remaining-callable.schema.json` and independent wrappers for the final 18
  search, signature, type/value, and composite-analysis methods
- `schema/methods/script.schema.json` and strict `script.execute` request/response wrappers
- `schema/methods/readonly-analysis.schema.json` and strict wrappers for instruction items,
  function chunks, fixups, switches, exception regions, and analysis status/problems; `analysis.plan`
  has a separate side-effecting strict schema and wrapper pair
- `schema/methods/inspection-query.schema.json` and 22 strict request/response wrappers for source
  mappings, demangling, comments, bookmarks, type xrefs, bounded decompiler structure, and
  suspended debugger inventories
- `transport.md`

`testdata/valid` and `testdata/invalid` contain shared interoperability fixtures. Go and C++
tests must consume these files rather than maintaining independent examples.

## Implemented Methods

### `instance.info`

`instance.info` accepts empty params and returns the authoritative instance UUID, PID, IDA
version, database, input file, processor, bitness, normalized architecture, and capabilities.
Gateway discovery calls it only after the Named Pipe hello product/protocol/identity check.

### `database.info`

`database.info` accepts an empty `params` object and returns the database root name,
processor module, normalized architecture, address width, aggregate address range, and a
fixed-size segment summary. The segment summary contains counts only, so this method cannot
produce an unbounded list and does not expose the input file's local path.

### `function.get`

`function.get` accepts one hexadecimal `address`. An address inside an entry chunk or tail is
normalized to the owning function entry. The fixed-size result contains the function name,
aggregate address range, stable flags, optional one-line signature, and aggregate size,
instruction, basic-block, and chunk counts. It does not expose instruction or basic-block
lists. Functions larger than 1 MiB or containing more than 1024 chunks return `OUTPUT_LIMIT`
before instruction or control-flow analysis to protect the IDA main thread. Function names above
1024 Unicode code points and signatures above 2048 code points also return `OUTPUT_LIMIT` rather
than crossing the wire with a schema-invalid result.

### `function.search`

`function.search` accepts exactly one name or address filter. An empty name lists functions
in entry-address order. `limit` defaults to 20 and is capped at 100. Each call scans at most
4096 functions and returns an opaque query-bound cursor when more search space remains, so a
selective query can return an empty page with `hasMore: true`. Address search returns zero or
one summary and does not accept a cursor. Empty, invalid UTF-8, or names above the response
schema's 1024-code-point bound are skipped during list scans; an exact address lookup for
such a function returns `OUTPUT_LIMIT` rather than emitting an invalid DTO. Clients must treat
the versioned cursor as opaque; the Internal RPC checksum detects malformed or mismatched cursors. Before exposing a cursor to
MCP, Gateway wraps it in a process-random HMAC-SHA256 signature bound to instance and query;
restart invalidates old public cursors. Call `function.get` for full details.

### `function.disassemble`

`function.disassemble` normalizes an address in any function chunk to the entry and returns
untagged UTF-8 disassembly for code items across all chunks. `offset` counts code items,
defaults to zero, and is capped at 1,000,000; `limit` defaults to 20 and is capped at 100.
Each line is limited to 4096 UTF-8 bytes. Functions above the 1 MiB analysis limit return
`OUTPUT_LIMIT`.

### `function.basic_blocks`

`function.basic_blocks` uses a no-external-block flow chart and returns stable block type names,
address ranges, and successor/predecessor block-start addresses. It uses the same offset/limit
contract as `function.disassemble`; either edge list above 64 entries returns `OUTPUT_LIMIT`.

### `function.callees`

`function.callees` collects only non-flow near/far call xrefs from all function code items.
Targets belonging to a function are normalized to its entry, then targets are deduplicated and
sorted by address. Names fall back to the formatted target address, are limited to 1024 UTF-8
bytes, and the complete unique set is capped at 10,000 entries.

All three methods set `nextOffset` to `offset + items.length` only when another item exists.
Consequently, `hasMore` is true if and only if `nextOffset` is non-null.

### `xref.query`

`xref.query` enumerates incoming or outgoing program-address references with `all`, `code`,
or `data` category filtering. Ordinary execution flow is excluded by default and can be
enabled explicitly. `limit` defaults to 20 and is capped at 100. Results use stable string
types and a query/phase-bound cursor containing the next phase-local index; each page returns
at most `limit` references. Code and data phases retain IDA's deterministic enumeration order.
Continuation is capped at phase index 1,000,000; a larger result returns `OUTPUT_LIMIT` rather
than issuing an unusable cursor.

### `memory.read`

`memory.read` reads only initialized IDB bytes from a normal mapped segment; debugger and
ephemeral segments are rejected. It supports exact byte ranges and bounded NUL-aware UTF-8
strings from 1 to 4096 bytes, unsigned integers with 8/16/32/64-bit widths, and target-width
pointers. Numeric results use hexadecimal strings and explicitly report target byte order.
Phase 1 requires an 8-bit-byte processor and never falls back to debugger process memory.

### `function.decompile`

`function.decompile` normalizes any address inside a function to its entry and requires the
instance's Hex-Rays capability. Pseudocode is returned as untagged UTF-8 text in byte-offset
pages: `maxBytes` defaults to 32768 and is capped at 65536, while `nextOffset` provides the
only continuation value clients should use. Each response includes `returnedSize`,
`originalSize`, and `truncated`; text above 16 MiB returns `OUTPUT_LIMIT`. Hex-Rays busy,
license/capability, and ordinary decompilation failures map to stable RPC errors without
exposing SDK diagnostics.

### R1A bounded inventory methods

`database.segments`, `string.search`, and `symbol.imports` use opaque query-bound Internal RPC
cursors. Every call scans at most 4096 logical entries and returns at most 100 items; therefore a
selective query may return an empty page with `hasMore: true`. Continuation positions above
1,000,000 return `OUTPUT_LIMIT`. Gateway wraps every Internal RPC cursor in a process-random HMAC
cursor bound to the explicit instance and all normalized filters, so tampering, parameter changes,
instance changes, and Gateway restart return `INVALID_ARGUMENT`.

### ChangeSet, assembly, diff, and debugger methods

`changeset.preview/apply/rollback/audit` use typed operation DTOs and bounded results. Patch bytes
remain ChangeSet operations; `patch.assemble` only returns assembled bytes and instruction ranges.
The public `patch.write_bytes` and `patch.write_integer` methods are Gateway composites over a
single ChangeSet operation; they do not add direct-write Internal RPC methods or a second mutation path.
`analysis.diff_before_after` temporarily applies one address-targeting reversible action,
captures bounded before/after pseudocode, and rolls the action back before returning success.
Rollback failure is an RPC error rather than a successful result.
`local.rename` and `local.type` retain the public `subject` contract but snapshot the exact target
locator's saved-info existence, name/type presence, comment, size, and flags. Apply and rollback dirty
and re-decompile the function before verification, without replacing unrelated saved local settings.
If the target attribute has no saved user value, preview returns `CAPABILITY_UNAVAILABLE`: Hex-Rays does
not reliably regenerate the previous automatic value after clearing the marker, so the API does not
claim an inexact rollback.
`analysis.plan` is not a ChangeSet: it requires `confirm=true`, validates a fully mapped half-open range
of at most 16 MiB, queues `AU_USED`, and reports only acceptance.
Database metadata mutations use the same preview/apply/rollback contract. `segment.rename`,
`segment.permissions`, and `function.flags` snapshot stable string projections. `xref.code.add/delete`
and `xref.data.add/delete` accept a hexadecimal target in `value` and a fixed xref type in `subject`;
delete is limited to user-defined xrefs so rollback never changes an automatic xref into a user xref.
Code xrefs require existing code items at both ends, and call targets must already belong to a function,
so applying an xref cannot implicitly create a function outside the ChangeSet rollback scope.
`function.end` identifies an entry chunk by its exact start address and stores the desired hexadecimal end
in `value`; it cannot move the function start. `function.chunk.add/delete` use the exact owner entry in
`address`, tail start in `value`, and tail end in `subject`. Tail ranges are limited to 16 MiB and hidden
tails are rejected because deleting and recreating one would not preserve its hidden attribute exactly.
Delete additionally requires a shared tail reference that is not the current tail owner, so removal never
destroys the tail or transfers its owner; a sole tail created by an add remains removable by that add
operation's stored inverse.

The `debugger.*` methods use debugger-process DTOs distinct from IDB memory. IDA asks for debugger permission once per Pipe, shared by all MCP clients. The decision stays in memory until Pipe recreation or database closure. Gateway does not accept approval arguments or reject calls using a cached debugger capability; the plugin checks the live debugger after approval. A timeout or canceled client wait
does not mean an accepted process-control action or process-memory write was rolled back.

Debugger `running` means the target is executing instructions, matching IDA's `DSTATE_RUN`. A paused target reports `state=suspended`, `running=false`, and `suspended=true`; `not_running` reports both flags as false. The same flags apply to action results. The `ui` capability is reserved for MCP UI inspection/control (for example cursor or selection access), which is currently unavailable. It does not describe the presence of IDA's GUI and does not gate debugger permission dialogs.

### Script execution

The Internal RPC `script.execute` accepts only `language=python|idc` and 1..32768 bytes of inline
UTF-8 source; its schema has no path or confirmation field. The MCP method accepts exactly one of
inline `code` or a Gateway-accessible `path`. The Gateway treats it as an ordinary
`arbitrary_code_execution` side-effecting tool and keeps no authorization state; the MCP client owns
the permission decision. Tool arguments cannot provide confirmation or scope fields. For a path, the
Gateway opens one regular file, reads it once within the source bound, and sends only those inline
bytes through Internal RPC. Python returns bounded stdout/stderr; IDC
returns a bounded textual result. Runtime exceptions use `success=false`; an unavailable language is
`CAPABILITY_UNAVAILABLE`. Cancellation cannot stop source that has already started on the IDA
execution context or guarantee that an operating-system path operation has stopped.

### Callable catalog methods

The Gateway exposes typed contracts for `system.ping/methods`, `instance.info`,
`database.survey/save`, and `function.callers/callgraph/profile/export/analyze/analyze_batch/
stack_frame`. Their method-specific schemas and fixtures live under `schema/methods` and
`testdata`. Gateway `database.save` intentionally omits the Internal RPC `target` field and can
only save the current IDB with optional `compact` and `backup` flags. Public `instance.info`
sanitizes database and input paths to basenames and never includes a Pipe locator. The
`function.profile` Internal RPC cursor remains private; MCP wraps it in a process-random HMAC
cursor bound to the instance, static method ID, and every normalized filter.

The remaining search continuations follow the same boundary. Gateway HMAC-wraps Internal cursors
for `instruction.search`, `instruction.query`, `listing.search_text`, and `string.search_regex`.
The binding includes the explicit instance, public method name, canonical address range, every
normalized filter/source flag, and effective limit. Alias cursors are therefore not interchangeable,
and a Gateway restart invalidates every public cursor. `listing.search` remains a single-page public
contract and exposes only whether that page was truncated; it does not advertise a cursor the method
cannot accept. `type.search` and `type.query` retain their numeric `nextOrdinal` contract and dispatch
to separate static RPC names. `analysis.trace_data_flow` is explicitly the bounded `xref_bfs` model.
`analysis.trace_argument` and `analysis.guard_evidence` use a separate, bounded
Hex-Rays microcode model for a selected call argument. See
[semantic-analysis.md](semantic-analysis.md) for parameters, evidence semantics,
type assumptions, limits, and integration tests.
`analysis.trace_argument_callers` expands parameter dependencies across known
direct callers, preserving separate contexts and checking prototype/ABI agreement.
See [argument-callers.md](argument-callers.md) for its shared budgets and boundaries.

Filters are ASCII-case-insensitive substrings and are limited to 256 Unicode code points and 1024
UTF-8 bytes. `database.segments` orders stable segment DTOs by start address and encodes permissions
as `rwx` triplets. `string.search` orders the existing IDA string list by address, reports
Unicode-code-point `length`, and caps `value` at 4096 UTF-8 bytes while preserving `originalSize`.
Both `string.search` and `string.search_regex` accept optional boolean `refresh` (default `false`).
Only `refresh: true` calls `build_strlist()` before searching, on the IDA execution context.
It cannot be combined with `cursor`; continuation requests must omit `refresh` or set it to `false`.
The flag is a one-shot operation and is not part of the cursor's filter binding. No search snapshot
is retained: restart from the first page after any client or the IDA UI rebuilds or changes the list.
IDA may still build an unavailable list on the first `get_strlist_qty()` call; cold searches and
explicit refreshes can be slow, especially while debugging, and cannot be preempted by an RPC timeout.
These methods do not provide a bounded scan of live process memory.

`symbol.imports` preserves module index and import enumeration order; ordinal-only imports use
`#<ordinal>` as their stable name and also include `ordinal`.

### Debugger setup contract

The setup methods are `debugger.backends`, `debugger.select`, `debugger.configuration`,
`debugger.configure`, `debugger.processes`, `debugger.attach`, `debugger.detach`, and
`debugger.suspend`. They share the Pipe consent gate with other debugger methods, including
queries and the bootstrap calls that work without a selected debugger. Their schemas reside
in `schema/methods/debugger-*.{request,response}.schema.json`; `testdata/debugger-setup-cases.json`
is consumed by both language test suites.

- `backends`: empty params, idle process state. Returns `items` containing exact `name`/`remote`
  pairs, `current` (empty string if no selection), and the current `remote` flag.
- `select`: required nonempty `name` (128 UTF-8 bytes maximum), optional boolean `remote`
  (default false). Must match an enumerated installed debugger. Requires no active process.
- `configuration`: empty params, any state. Returns `path`, `arguments`, `directory`, `host`,
  `port`, and boolean `hasPassword`. A raw `password` response field is invalid.
- `configure`: requires at least one of `path`, `arguments`, `directory` (each <=32768 UTF-8
  bytes), `host` (<=1024 bytes), `password` (<=4096 bytes), or integer `port` (-1 or 1..65535).
  NUL and null fields are rejected. Omission preserves values; an empty string clears a value.
  Port -1 selects the backend default. Existing environment settings are preserved. Requires
  no active process and does not launch one.
- `processes`: optional `limit` (default 100, 1..1000), requires a selected debugger with no
  active process. Returns `items` (`pid`, `name`), `total`, and `truncated`. A PID is in
  1..2147483647; process names are <=32768 UTF-8 bytes each and <=128 KiB in aggregate.
  SDK enumeration itself is synchronous and may exceed the caller's wait budget; the limit
  bounds returned items, not SDK work. No cursor or snapshot continuation is provided.
- `attach`: requires explicit `pid` in 1..2147483647 and a selected idle debugger.
- `suspend`: empty params, requires a running process.
- `detach`: empty params, requires a suspended process; it does not terminate the target.

All five mutations return the existing `debuggerAction` DTO. `accepted` is a receipt, not an
observed process transition. Refresh `debugger.info` before dependent actions. State checks
run again on IDA's main thread immediately before SDK calls. Running-state inspection,
pausing, and exiting use the executor's debugger command path so they do not wait for an
IDB-write-safe suspended state. There is no caller-selected RPC forwarding path.

Internal AI has the equivalent fixed tools. Configuration null placeholders are removed
only at the AI boundary; the Pipe contract remains strict. Mutations use prepared effects
and the existing conversation policy; reads use fixed registry invokers. Password values
are never included in safe approval summaries or results.
