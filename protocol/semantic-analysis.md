# Call argument traces and guard evidence

`analysis.trace_argument` and `analysis.guard_evidence` are read-only methods in
the `ida_analysis` MCP domain. Both require Hex-Rays. The plugin AI Console also
exposes `ida_analysis_trace_argument` and `ida_analysis_guard_evidence` through
its searchable tool catalog.

## Request

```json
{
  "action": "call",
  "method": "analysis.guard_evidence",
  "arguments": {
    "callAddress": "0x140001041",
    "argumentIndex": 0,
    "maxNodes": 200,
    "maxWork": 20000,
    "maxGuards": 32
  }
}
```

Use an actual call instruction address in the selected IDB, and add `instanceId`
when more than one instance is in use. The argument index starts at zero and
refers to **Hex-Rays' recovered argument list**. Inferred prototypes, hidden
arguments, variadic calls, and incorrect IDB types can change that list. Check
`argumentCount`, `argumentType`, and the disassembly before interpreting it.
The service does not apply or repair types. Indirect calls are accepted when
Hex-Rays supplies argument metadata; their targets are not resolved by this tool.

| Parameter | Default | Range |
|---|---:|---:|
| `argumentIndex` | Required | 0–255, less than recovered argument count |
| `maxNodes` | 200 | 1–1000 |
| `maxWork` | 20000 | 1–100000 |
| `maxGuards` | 32 | 1–128 |

Unknown fields are rejected. All addresses and integer constant literals use
hexadecimal strings; 64-bit values never pass through JSON floating point.

## Result and interpretation

Each response identifies its function entry and exact call address and reports
`model=microcode_reaching_definitions`, `maturity=MMAT_CALLS`, and `scope=function`.
The same snapshot supplies the argument trace and, when requested, conditions.
`analysis.trace_data_flow` retains its existing `xref_bfs` model.

`root` is a response-local node ID for the selected argument. `edges` run from a
value to its dependencies. Nodes represent constants, parameters, unclassified
entry values, integer operations, call returns, addresses, memory reads, merges,
or unknown boundaries. Bit widths and operations retain casts and signed versus
unsigned comparisons. Parameter numbers and types follow IDA's prototype, not
an independent ABI proof. `address=null` marks a source or synthetic operation
without a precise instruction address. Interned nodes describe values, not a
complete list of all instruction occurrences that copy them.

`guards` contains conditions that can precede the call in the recovered CFG,
including conditions on other values. Each item contains the comparison address,
operation, width, operand node IDs, and two independent relations:

| Field | Values | Meaning |
|---|---|---|
| `requiredBranch` | `true`, `false` | Removing this edge makes the call unreachable from the function entry in the recovered CFG. |
| | `neither` | Neither edge is individually required; a diamond or bypass can still reach the call. |
| | `unknown` | Incomplete or unsupported control flow prevents this conclusion. |
| `valueRelation` | `same_value` | At least one compared operand is the same traced symbolic value as the argument. |
| | `derived_value` | The comparison and argument share a traced nonconstant dependency, possibly through casts or arithmetic. |
| | `unrelated` | The recovered dependencies do not establish such a relationship; this is not a numerical inequality claim. |
| | `unknown` | An unknown source, memory read, or merged definitions prevents the relationship from being established. |

For `if (n > cap) return; sink(n);`, the comparison normally has a required false
edge and a `same_value` relation. If both branches rejoin before `sink(n)`, neither
edge is required. If `n` is replaced by another value, a check on the old value
does not become a check on the replacement. A signed check followed by a cast can
produce `derived_value`; this does not prove that the converted value is bounded.

`cfgComplete` describes supported edges retained from the recovered CFG. Known
try-block metadata, exception roles, and unsupported indirect control flow cause
conservative unknown branch requirements; missing IDB metadata can still hide
runtime behavior. There is no `safe` result. `complete` means completion within this model, not
absence of vulnerabilities. A CFG path is not proof of runtime feasibility.
These two methods are function-local. For caller parameter expansion, use
[`analysis.trace_argument_callers`](argument-callers.md). No heap alias solver, loop invariant solver, or symbolic
path feasibility solver is included. Memory writes, unknown call effects,
overlapping writes, unsupported instructions, and cycles are handled conservatively.
Unclassified entry values retain symbolic identity but their origin is unknown.
Windows x64 is covered by optimized and unoptimized integration fixtures; other
architectures have not been validated by those fixtures. Low-byte projection of
wider locations is only performed for little-endian snapshots.

## Bounds and failures

`status=partial` and `limitations` identify boundaries. `truncated=true` indicates
a traversal, depth, node, edge, or guard budget limit. Partial output can contain
nodes without a completed root or guard. IDs are valid only within one response;
there is no cursor or cross-request cache. Repeat with a larger bounded budget
only when that can resolve the reported limit.

The extractor caps CFGs at 1024 blocks and uses `maxWork` for its own traversal.
The analysis core separately uses `maxWork`; `visitedStates` counts core work.
Edges are capped at 2000 and serialized output at 256 KiB. If extraction cannot
produce a consistent snapshot or serialization exceeds its cap, the method
returns `OUTPUT_LIMIT` rather than inventing a partial call signature.
Budget checks do not interrupt the SDK's microcode generation. The 60-second
Gateway deadline limits waiting; a started IDA operation may finish afterward.

Missing Hex-Rays or a compatible license returns `CAPABILITY_UNAVAILABLE`.
Unmapped addresses, non-call instructions, missing calls, and out-of-range
argument indices return the existing typed address/not-found/argument errors.
Ambiguous call mappings are rejected. Busy decompilation returns retryable
`IDA_BUSY`; other decompilation failures return `DECOMPILE_FAILED`.

## Verification

Pure C++ tests exercise definitions, casts, overwritten values, merges, loops,
unknown effects, and budgets. Go tests validate shared protocol fixtures, DTOs,
and MCP dispatch. With integration tests enabled, run:

```shell
ctest --test-dir build/ida-agent-plugin -R '^ida_semantic_integration_' --output-on-failure
```

The integration harness builds fixed C++ samples with `/Od` and `/O2`, supplies
their known source declarations only in disposable fixture IDBs, and calls the
built DLL through Named Pipe RPC. It retains results, microcode, and logs in the
printed temporary directory. It does not replace the user's installed plugin.
