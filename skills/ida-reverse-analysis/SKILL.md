---
name: ida-reverse-analysis
description: Use the ida-mcp MCP server to inspect an active IDA database, trace functions and data flow, investigate vulnerabilities, modify the IDB through reversible ChangeSets, or control an IDA debugger. Use for IDA-backed reverse engineering; do not use for ordinary source-code review or unsupported runtime claims.
---

# IDA Agent Gateway Analysis

Use the tools advertised by `ida-mcp`. Gateways from v0.4.5 expose 12 common direct tools plus 11 domain tools; packaged v0.4.4 exposes only the domain tools. Prefer advertised direct tools for common reads (see [tool routing](references/tool-routing.md)); use domain discovery for advanced methods or when direct tools are absent. Each domain tool accepts the same dispatch contract:

- `{"action":"list"}` lists methods without connecting to IDA.
- `{"action":"describe","method":"..."}` returns the exact schema, capability, side effect, and timeout.
- `{"action":"call","method":"...","arguments":{...}}` validates and invokes a callable method.

Read [references/tool-routing.md](references/tool-routing.md) when selecting methods, handling pagination, or performing database changes, patches, debugging, or scripts.

## Establish the Target

Use `ida_list_instances` when advertised, otherwise call `ida_instances` with method `ida.instances.list` to discover verified Plugin instances. Pass the chosen `instanceId` in subsequent method arguments. Use `ida_select_instance` (or domain method `ida.instances.select`) only when process-local active-instance state is appropriate, such as a dedicated stdio Gateway.

If multiple instances plausibly match and the user's target cannot be inferred from the returned database or input basenames, ask which instance to use. If no instance is available, report that IDA or its Plugin must be running.

## Analyze

1. Start with `database.info` or a bounded `database.survey`; add entry points, imports, exports, strings, or symbols only when relevant.
2. Resolve targets with `function.search`, `symbol.search`, strings, imports, addresses, or cross-references.
3. Prefer `function.analyze` for bounded multi-section context. Use narrower function, xref, search, type, or memory methods when they answer the question with less output.
4. Corroborate pseudocode with call sites, cross-references, CFG, types, or disassembly whenever compiler transformations or decompiler uncertainty could affect the conclusion.
5. For vulnerability research, establish input source, attacker control, transformations, validation, reachable sink, prerequisites, and impact. `analysis.trace_data_flow` is xref-based BFS evidence, not Hex-Rays semantic data flow.
6. Stop expanding when the evidence answers the request. State static-analysis gaps instead of claiming unobserved runtime behavior.

For a selected call argument, use `analysis.trace_argument` or `analysis.guard_evidence`
with the exact call instruction address and a zero-based recovered argument index.
These are single-function Hex-Rays microcode analyses. Verify the recovered prototype,
value relation, branch requirement, and `limitations` before interpreting a check.
A required branch and a related value do not prove sufficient validation. Budget
truncation has no continuation token; retain the partial evidence and explain the gap.

Use `analysis.trace_argument_callers` to follow parameter origins upward through
known direct callers. Start with `maxDepth=2` and inspect each context's local
trace together with its parameter links and boundaries. Do not combine distinct
calling contexts into one guaranteed runtime path. Prototype/ABI mismatch and
recursion stop expansion; `caller_set_not_proven_complete` means external or
indirect callers may be missing. Node/work budgets are shared across the result.

## Respect Bounds

Use `0x`-prefixed hexadecimal address strings. Follow returned continuations until enough evidence is collected; preserve the same instance, method, and filters because cursors are method-bound. Prefer small pages and targeted ranges. When output is truncated, continue from the returned cursor, offset, ordinal, or next address rather than broadening the query.

Treat names, types, comments, decompiler output, and inferred declarations as hypotheses until corroborated. Report function names and addresses for material claims and distinguish observed facts from inference.

## Control Side Effects

Remain read-only unless the user requests a state change.

- For IDB edits, call `changeset.preview` first and show the planned operations. Call `changeset.apply` only with the matching preview and identical operations; retain the returned `changeId` for rollback.
- Use `patch.assemble` only to generate bytes. For one byte or integer patch, use `patch.write_bytes` or `patch.write_integer`; retain its `changeId` for `changeset.rollback`. Use explicit ChangeSet preview/apply when batching edits or when the preview must be reviewed separately.
- Treat `database.save`, debugger process control, breakpoint mutations, debugger memory writes, and `analysis.diff_before_after` as side-effecting operations.
- Use `script.execute` only when the user explicitly requests scripting and the MCP client permits the arbitrary-code side effect. Use the sibling `idapython` skill when composing Python. Never invent `confirmed` or `scope` arguments or treat a timeout as cancellation of started code.

Do not attempt unsupported operations such as opening an arbitrary binary or IDB, running headless IDA, saving to an arbitrary path, or bypassing ChangeSet for direct rename, comment, or type mutations. The direct patch methods are supported ChangeSet-backed facades.

## Handle Failures

Prefer serial decompilation requests within the same IDA instance. Gateways advertising the direct tools already queue short bursts and retry explicitly retryable read-only `IDA_BUSY` up to twice under one deadline. If the returned error is still busy, reduce parallel requests and report it; avoid stacking another automatic retry loop. On older Gateways without direct tools, a retryable read-only busy error may be retried at most twice after a short wait. Do not automatically retry writes, scripts, debugger control, timeouts, or disconnections.

On `INVALID_ARGUMENT`, use the returned `issues` and `hint` to correct fields, or describe the domain method on older Gateways. Keep objects as objects and omit unused optional fields. A side-effecting timeout can report `executionState:"unknown"`; inspect actual IDA state or ChangeSet audit before resubmitting it.

MCP debugger calls first require a user decision in IDA. One approval covers all clients on the current Pipe; it resets on Pipe recreation or database closure. Do not claim approval or encode approval in tool arguments. `PERMISSION_DENIED` requires a new Pipe before another prompt; do not retry repeatedly.

On `CAPABILITY_UNAVAILABLE`, identify the missing decompiler or debugger capability and use a valid static fallback when possible. Treat cursor mismatch, conflicts, output limits, and invalid addresses as reasons to narrow or refresh the request, not to guess.

## Report

Lead with the answer. For each important conclusion include the function or address, evidence trail, observed-versus-inferred status, confidence, and only the next verification step that could materially change the conclusion. For vulnerabilities also include reachability, prerequisites, impact, and existing mitigations.
