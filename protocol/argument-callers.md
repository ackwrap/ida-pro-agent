# Cross-function argument provenance

`analysis.trace_argument_callers` follows a call argument's function-parameter
dependencies upward through known direct call sites. It uses the same
`MMAT_CALLS` reaching-definition analysis as `analysis.trace_argument`, with
separate contexts for each caller and parameter. It is a read-only operation.

## Request

| Field | Default | Allowed range | Meaning |
| --- | --- | --- | --- |
| `callAddress` | required | hex address | Exact machine call instruction |
| `argumentIndex` | required | 0–255 | Zero-based argument at that call |
| `maxDepth` | 2 | 0–5 | Caller edges above the initial function; 0 is local only |
| `maxContexts` | 16 | 1–64 | Context analysis attempts, including initial, failed and recursive attempts |
| `maxCallers` | 8 | 1–32 | Known call sites inspected per expanded parameter |
| `maxNodes` | 1000 | 1–4000 | Shared total of local graph nodes |
| `maxWork` | 100000 | 1–1000000 | Shared extraction, analysis and traversal work |

Gateway callers may also provide `instanceId`. The internal RPC rejects it.
Unknown fields and explicit out-of-range values are rejected. There is no cursor.

```json
{
  "callAddress": "0x140001020",
  "argumentIndex": 0,
  "maxDepth": 2,
  "maxContexts": 16,
  "maxCallers": 8,
  "maxNodes": 1000,
  "maxWork": 100000
}
```

## Evidence structure

The result has `model=microcode_caller_contexts` and
`scope=known_direct_callers`. `contexts[0]` analyzes the requested call.
Each context has an `id`, a caller `depth`, and a `trace` using the existing
[local analysis result](semantic-analysis.md). Local node IDs belong only to
that context. Guard arrays are empty in this operation.

`links` identify `fromContext`, `parameterNode` and `toContext`. For example,
an argument passed by `sink_wrapper(n)` can lead to separate caller contexts
for `first_caller(42)` and `second_caller(99)`. Constants and conversions remain
inside their respective local graphs. Links do not merge these values or claim
that the call paths are feasible together.

A link is emitted only when the caller resolves to the exact callee, the
recovered parameter positions agree with its IDB prototype, and both sides
agree on calling convention, argument count, types, widths and ABI locations.
Unsupported or incomplete prototypes, variadic/user calling conventions, and
scattered argument locations stop at a boundary. User-provided or inferred IDB
types remain assumptions of the analysis; agreement does not prove them correct.

`boundaries` refer to the context, optional parameter node and optional caller
address. Reasons include `prototype_mismatch`, `parameter_abi_unavailable`,
`recursive_call`, `no_known_callers`, `caller_analysis_unavailable`, and explicit
budget names. Native tail jumps and non-call references are not followed.
Resolved indirect machine calls also require a direct microcode call before
they can be linked. Unknown indirect callers and external entry invocations
cannot be enumerated from direct references.

Once parameter expansion is needed, `caller_set_not_proven_complete` is retained
in `limitations` and the result is `partial`, even if all known callers lead to
constants. A local constant may be `complete` within the local model.
`truncated` distinguishes budget exhaustion from other uncertainty.
The result does not establish safety, exploitability or complete program inputs.

## Bounds and failure behavior

The operation shares node and work budgets across every context; `totalNodes`
and `visitedWork` report consumption. A context additionally keeps the local
limits of 1000 nodes, 2000 edges and 100000 extraction/analysis work units.
There are at most 512 boundary records and 256 KiB of serialized output.
Excess output returns `OUTPUT_LIMIT`. Partial graphs may lack a completed root;
a work budget of 1 can return an empty context list with `work_budget`.

Recursive function entries are stopped on the current call path. The same
function can occur in different independent caller contexts. There is no
cross-request cache. Failure to analyze the initial call uses the existing
typed RPC error; failure at an upstream call becomes an explicit boundary.

Work units bound normalized extraction and traversal, not the SDK's internal
microcode generation. The 60-second Gateway deadline limits waiting; it cannot
preempt an already-running IDA operation. These constraints also apply to the
IDA AI tool `ida_analysis_trace_argument_callers`.

This version follows parameters toward callers. Callee-return summaries, heap
alias analysis, indirect-target recovery, tail-call ABI recovery and symbolic
path feasibility remain outside this model.

## Verification

The C++ core and Go DTO/schema tests share the caller request/response fixtures.
Tests cover multiple contexts, two-hop constants, recursion, prototype mismatch,
missing ABI data, malformed graph references and global bounds. The real IDA
integration harness checks `/Od` and `/O2` Windows x64 fixtures, including two
distinct callers and a recursive function. Production analysis does not write
prototypes; fixture declarations are applied only to disposable test IDBs.
