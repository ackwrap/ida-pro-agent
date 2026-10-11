# Analysis memory, workflows, and IDA 9.5 acceptance

These features are available in current source builds. They are not included in the previously published v0.4.8 package. Use the built-in **Open AI Chat** with a model whose **Tools** capability is enabled in Provider Manager.

## Analysis memory

Analysis memory stores notes, observations, hypotheses and open questions separately from chat transcripts. The selected provider receives the relevant records retrieved for each tool-enabled chat request. A saved record is not a verified conclusion.

| Command | Purpose |
| --- | --- |
| `/memory` or `/memory list` | Show the first 20 records for this binary |
| `/memory search <text>` | Search literal UTF-8 text; narrow the search when more records exist |
| `/memory add <note>` | Save a global note |
| `/memory add-local <note>` | Save a note for the selected function, or the current address outside a function |
| `/memory update <id> <note>` | Replace a record with a user note; previous machine evidence is removed |
| `/memory reject <id>` | Retain a finding as rejected so the assistant can avoid repeating it |
| `/memory forget <id>` | Delete a single record |
| `/memory clear confirm` | Delete this binary's analysis memory |
| `/memory help` | Show the command syntax |

For example:

```text
/memory add The license check is separate from the network handshake; this is a hypothesis pending call-site evidence.
/memory add-local Inspect callers before assigning a structure type.
/new
/memory search license
/workflow protection Focus on anti-debugging and integrity checks.
```

`/new`, `/clear`, history deletion and conversation switching retain stored analysis memory. Run memory commands while the agent is idle; cancel an active request first. New/switch/clear conversations reset transient workflow and evidence state.

Records belong to the input SHA-256 stored in the IDB. When that digest is unavailable, an explicitly marked IDB-path identity is used. The IDB path and its database change counter identify the observation revision. Moving/copying an IDB or changing its analysis can mark evidence stale; stale records must be checked again. Address-scoped records and evidence use RVAs and resolve against the current image base after rebasing. Unresolvable addresses are reported as null.

The private SQLite store is outside the IDB:

- Windows: `%LOCALAPPDATA%\ida-agent\ai\analysis-memory.db`
- Linux: `${XDG_STATE_HOME:-$HOME/.local/state}/ida-agent/ai/analysis-memory.db`
- macOS: `~/Library/Application Support/ida-agent/ai/analysis-memory.db`

FTS5 is used when the linked SQLite supports it; otherwise parameterized literal search remains available, including Chinese text and quotes. Automatic retrieval prioritizes the current function/address, relevant terms and recent global notes. It injects at most six complete records within an 8 KiB memory budget. Each fact is at most 4 KiB with at most eight evidence references; storage is limited to 512 records per binary and 8192 overall. Remove obsolete notes when capacity is reached. A storage failure permits ordinary chat and read-only workflows to continue.

The built-in agent discovers these underscore-named tools through `ida_tool_search`:

| Tool | Behavior |
| --- | --- |
| `ida_analysis_memory_search` | Read records; include rejected records explicitly when investigating earlier conclusions |
| `ida_analysis_memory_save` | Create/update a record with bounded text, status, address and evidence |
| `ida_analysis_memory_forget` | Delete one record belonging to the active binary |
| `ida_analysis_workflow_get` | Read a workflow's required analysis steps |
| `ida_analysis_workflow_report` | Check a structured report against actual read-tool receipts |

The memory search and workflow lookup tools are in the initial core catalog. Saving/deleting uses the existing **Ask / Allow / Deny** conversation policy: under Ask, inspect the prepared operation and use `/y` or `/n`. Those commands allow or deny all side effects for the conversation, including ordinary IDB operations. Memory changes themselves do not modify the IDB.

Agent observations require evidence from successful read tools in the current request. Evidence retains the tool name, call ID, returned address, result SHA-256 and observation revision. The agent submits a report or save in a later tool round after the referenced reads have returned. Unknown call IDs, addresses absent from the referenced result, and stale evidence are rejected. Hypotheses remain labelled as hypotheses, and saving never promotes a claim to analyst verification. Chat prose is not automatically saved as a fact.

These five tools are private to the built-in agent. The external MCP gateway retains its 23 advertised direct/domain tools and existing RPC contracts.

## Evidence workflows

| Command | Required observations and report |
| --- | --- |
| `/workflow protection [question]` | Binary metadata, segments, imports, strings, code and references. Assess observed protection mechanisms against stated attacker goals; explain coverage, effort and uncertainty. API names or strings alone do not prove execution. |
| `/workflow function [question]` | Target function, code and references. Investigate inputs, outputs and data flow; use argument/guard tools when needed and state indirect-call, alias and truncation limits. |
| `/workflow types [question]` | Function/code, existing type definitions and inferred types/locals/stack layout. Proposed edits also require a successful ChangeSet preview, with conflicts surfaced. Applying changes remains a separate side effect. |
| `/workflow status` | Show current receipts, the last validated report and whether it became stale |
| `/workflow off` | Disable the workflow for this conversation |

Selecting a workflow sends its request immediately. It remains active for subsequent requests in that conversation. Normal messages can supply additional questions or scope. A new conversation, clear, or session switch disables the transient workflow.

The report validator checks successful current-turn tool provenance and returns `complete` or `partial`, missing steps, concrete evidence addresses, bounded-result warnings and ChangeSet preview conflicts. Failure, truncation or missing observations cannot be presented as complete coverage. This status describes the requested analysis steps; it does not prove an entire binary was analyzed, a conclusion is correct, or a candidate type is safe to apply. General xref traversal is not semantic taint analysis. Workflow reports apply no changes and do not automatically save memory. If the model finishes without a current validated report, the chat explicitly marks the workflow incomplete; partial coverage is also shown in the completion notice.

## IDA 9.5 beta acceptance on Windows

The stable supported UI ABI remains **IDA 9.4 / Qt 6.8.2 / namespace QT**. IDA 9.5 support requires actual runtime and licensed integration evidence. A beta with a different Qt ABI cannot be enabled by relaxing the version check.

Run the read-only ABI probe in an MSVC developer environment:

```powershell
python ida-agent-plugin/cmake/probe_ida_runtime.py `
  --ida-dir 'C:/IDA95' `
  --plugin 'build/ida-agent-plugin/ida-runtime/plugins/ida-agent-plugin.dll' `
  --output 'build/ida95-abi-preflight.json'
```

Pass `--dumpbin <absolute-path-to-dumpbin.exe>` when it is not in PATH. The probe checks executable/Qt file versions, Windows x64 machine types, QT namespace exports and every recognized IDA/Qt import of that exact plugin. Without `--plugin`, it only checks runtime metadata/namespace. It never loads the DLL, copies Qt, changes IDA settings or installs anything. `liveAcceptance: pending` remains explicit even when ABI preflight passes.

An explicit local beta build requires an actual 9.5 installation with the existing Qt ABI:

```powershell
$env:IDASDK = (Resolve-Path 'ida-sdk/src').Path
cmake -S ida-agent-plugin -B build/ida95-acceptance -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DIDA_AGENT_DEPLOY_DEBUG_USER_PLUGIN=OFF `
  -DIDA_AGENT_EXPERIMENTAL_IDA95=ON `
  '-DIDA_AGENT_IDA_QT_RUNTIME_DIR=C:/IDA95'
cmake --build build/ida95-acceptance
ctest --test-dir build/ida95-acceptance --output-on-failure
```

CMake performs runtime ABI preflight before regenerating import libraries. Run the probe again with the newly built DLL to check its exact imports. This is an experimental acceptance build, not a declaration of supported 9.5 runtime behavior.

Complete live acceptance using a separate `IDAUSR` and a harmless copied test database: load/unload the plugin, open and close AI Chat, make a read/decompile request, preview/cancel a ChangeSet, exercise Ask/Allow/Deny and cancellation, save/retrieve a note across new sessions and restart, and verify a clean IDA exit. Record the exact host build, plugin SHA-256, decompiler availability, logs and process exit code. Existing licensed integration runners remain opt-in; passing pure CTest or ABI preflight alone does not replace these live checks.

## Local regression tests

Build with the pinned SDK and automatic deployment disabled, then run:

```powershell
ctest --test-dir build/ida-agent-plugin --output-on-failure
ctest --test-dir build/ida-agent-plugin -R 'ida_ai_(analysis_memory|analysis_workflow|runtime_probe|chat_ui_model)$' --output-on-failure
```

The new pure tests cover persistence and binary isolation, rebasing/stale revisions, literal/optional FTS search, malformed and oversized records, quotas, context budgets, real receipt requirements, write approval, incomplete coverage, preview conflicts, user commands and unavailable storage. The probe's parser and version decisions run without an installed IDA.
