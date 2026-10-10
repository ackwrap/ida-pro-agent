package mcpserver

import "encoding/json"

func publicMethod(
	name, domain, summary string,
	schema string,
	parameters, output string,
	timeoutMs int,
) catalogMethod {
	source := "plugin_rpc"
	if domain == DomainInstances {
		source = "gateway"
	}
	return catalogMethod{
		Name: name, Domain: domain, Summary: summary, Status: MethodCallable, Source: source,
		SideEffect: "none", Parameters: parameters, Output: output,
		InputSchema: json.RawMessage(schema), TimeoutMs: timeoutMs,
	}
}

func publicMethodWithCapability(
	name, domain, summary, capability string,
	schema string,
	parameters, output string,
	timeoutMs int,
) catalogMethod {
	method := publicMethod(name, domain, summary, schema, parameters, output, timeoutMs)
	method.Capability = capability
	return method
}

func callablePluginMethod(
	name, domain, summary, sideEffect, capability, schema, parameters, output string,
	timeoutMs int,
) catalogMethod {
	method := publicMethod(name, domain, summary, schema, parameters, output, timeoutMs)
	method.Source = "plugin_rpc"
	method.SideEffect = sideEffect
	method.Capability = capability
	return method
}

func callableGatewayMethod(
	name, domain, summary, sideEffect, schema, parameters, output string,
	timeoutMs int,
) catalogMethod {
	method := publicMethod(name, domain, summary, schema, parameters, output, timeoutMs)
	method.Source = "gateway_composite"
	method.SideEffect = sideEffect
	return method
}

func pluginMethod(
	name, domain, summary, status, sideEffect, capability, parameters, output string,
	timeoutMs int,
) catalogMethod {
	return catalogMethod{
		Name: name, Domain: domain, Summary: summary, Status: status, Source: "plugin_rpc",
		SideEffect: sideEffect, Capability: capability, Parameters: parameters,
		Output: output, TimeoutMs: timeoutMs,
	}
}

func catalogMethods() []catalogMethod {
	methods := callableCatalogMethods()
	methods = append(methods, internalCatalogMethods()...)
	return methods
}

func callableCatalogMethods() []catalogMethod {
	return []catalogMethod{
		publicMethod(ToolInstancesList, DomainInstances, "Refresh and list verified IDA instances.",
			instancesListInputSchema, "No arguments.", "instances", 3000),
		publicMethod(ToolInstancesSelect, DomainInstances, "Select the active IDA instance.",
			instanceSelectInputSchema, "instanceId: UUID v4.", "activeInstance", 3000),
		publicMethod(ToolInstancesGetActive, DomainInstances, "Return the active IDA instance.",
			instancesGetActiveInputSchema, "No arguments.", "activeInstance", 3000),
		publicMethod(ToolDatabaseInfo, DomainDatabase, "Read fixed-size database metadata.",
			instanceInputSchema, "Optional instanceId.", "database metadata and segment counts", 12000),
		publicMethod(ToolDatabaseSegments, DomainDatabase, "List bounded database segments.",
			databaseSegmentsInputSchema, "Optional instanceId/name/limit/cursor.", "items/nextCursor/hasMore", 12000),
		publicMethod(ToolDatabaseEntryPoints, DomainDatabase, "List bounded entry-point records.",
			databaseEntryPointsInputSchema, "Optional instanceId/name/type/limit/cursor.", "items/nextCursor/hasMore", 12000),
		publicMethod(ToolFunctionGet, DomainFunctions, "Resolve and describe one function.",
			functionAddressInputSchema, "Optional instanceId; required address.", "function details", 12000),
		publicMethod(ToolFunctionSearch, DomainFunctions, "Search functions with cursor pagination.",
			functionSearchInputSchema, "Optional instanceId; exactly one name/address filter.", "items/nextCursor/hasMore", 12000),
		publicMethodWithCapability(ToolFunctionDecompile, DomainFunctions, "Read one bounded pseudocode page.", "decompiler",
			decompileInputSchema, "Optional instanceId; address/offset/maxBytes.", "pseudocode continuation", 35000),
		publicMethod(ToolFunctionDisassemble, DomainFunctions, "Read one bounded disassembly page.",
			functionAnalysisInputSchema, "Optional instanceId; address/offset/limit.", "items/nextOffset/hasMore", 12000),
		publicMethod(ToolFunctionBasicBlocks, DomainFunctions, "Read bounded function basic blocks.",
			functionAnalysisInputSchema, "Optional instanceId; address/offset/limit.", "items/nextOffset/hasMore", 12000),
		publicMethod(ToolFunctionCallees, DomainFunctions, "Read bounded direct callees.",
			functionAnalysisInputSchema, "Optional instanceId; address/offset/limit.", "items/nextOffset/hasMore", 12000),
		publicMethod(ToolXrefQuery, DomainSearch, "Query bounded incoming or outgoing xrefs.",
			xrefQueryInputSchema, "Optional instanceId; address/direction/category/includeFlow/limit/cursor.", "items/nextCursor/hasMore", 12000),
		publicMethod(ToolMemoryRead, DomainSearch, "Read bounded initialized IDB memory.",
			memoryReadInputSchema, "Optional instanceId; address/format and format-specific bounds.", "formatted memory value", 12000),
		publicMethod(ToolStringSearch, DomainSearch, "Search the existing IDA string list; refresh=true explicitly rebuilds it before the first page.",
			stringSearchInputSchema, "Optional instanceId/query/minLength/limit/cursor/refresh (default false; true cannot accompany cursor).", "items/nextCursor/hasMore", 12000),
		publicMethod(ToolSymbolImports, DomainSymbols, "List bounded imported symbols.",
			symbolImportsInputSchema, "Optional instanceId/module/name/limit/cursor.", "items/nextCursor/hasMore", 12000),
		publicMethod(ToolSymbolExports, DomainSymbols, "List bounded exported symbols.",
			symbolExportsInputSchema, "Optional instanceId/name/limit/cursor.", "items/nextCursor/hasMore", 12000),
		publicMethod(ToolSymbolSearch, DomainSymbols, "Search bounded non-function symbols.",
			symbolSearchInputSchema, "Optional instanceId/name/kind/limit/cursor.", "items/nextCursor/hasMore", 12000),
	}
}

func internalCatalogMethods() []catalogMethod {
	methods := append(append(append(
		internalSystemDatabaseMethods(), internalFunctionMethods()...),
		internalSearchTypeMethods()...), internalMutationDebuggerMethods()...)
	return append(methods, internalInspectionQueryMethods()...)
}

func internalInspectionQueryMethods() []catalogMethod {
	return []catalogMethod{
		callablePluginMethod(ToolSourceFiles, DomainSearch, "List IDB source-file mappings with basename-only filenames.", "none", "", indexListInputSchema, "Optional instanceId/limit/public cursor.", "items/public continuation", 35000),
		callablePluginMethod(ToolSourceLines, DomainSearch, "List IDB address-to-source-line mappings without reading source text.", "none", "", sourceLinesInputSchema, "instanceId/start/end/limit/public cursor.", "items/public continuation", 35000),
		callablePluginMethod(ToolNameDemangle, DomainSymbols, "Read an address name or demangle a supplied name using fixed short and long forms.", "none", "", nameDemangleInputSchema, "Exactly one of address/name; address returns the raw IDA name even when it is not mangled.", "raw/short/long", 35000),
		callablePluginMethod(ToolCommentGet, DomainAnalysis, "Read one existing ordinary item or function comment; an absent comment returns NOT_FOUND.", "none", "", commentGetInputSchema, "address/scope/repeatable.", "bounded plain comment text", 35000),
		callablePluginMethod(ToolBookmarkList, DomainDatabase, "List standard flat-view IDA bookmarks.", "none", "", indexListInputSchema, "Optional instanceId/limit/public cursor.", "items/public continuation", 35000),
		callablePluginMethod(ToolTypeXrefs, DomainTypes, "List direct program xrefs to an existing local type TID.", "none", "", typeXrefsInputSchema, "name/limit/public cursor.", "items/public continuation", 35000),
		callablePluginMethod(ToolDecompilerLocals, DomainFunctions, "Read bounded public local-variable metadata.", "none", "decompiler", decompilerLocalsInputSchema, "address/maxItems.", "entry/count/truncation/items", 35000),
		callablePluginMethod(ToolDecompilerCtree, DomainFunctions, "Traverse a bounded stable ctree projection.", "none", "decompiler", decompilerCtreeInputSchema, "address/maxDepth/maxNodes.", "entry/count/truncation/nodes", 35000),
		callablePluginMethod(ToolDecompilerLocalXrefs, DomainFunctions, "List bounded ctree references to one local variable.", "none", "decompiler", decompilerLocalXrefsInputSchema, "address/localIndex/maxDepth/maxNodes/maxItems.", "entry/local/visited/truncation/items", 35000),
		callablePluginMethod(ToolDebuggerThreads, DomainDebugger, "List suspended debugger threads.", "none", "debugger", indexListInputSchema, "Optional instanceId/limit/public cursor; requires suspended process.", "items/public continuation", 120000),
		callablePluginMethod(ToolDebuggerModules, DomainDebugger, "List suspended debugger modules with basename-only names.", "none", "debugger", indexListInputSchema, "Optional instanceId/limit/public cursor; requires suspended process.", "items/public continuation", 120000),
	}
}

func internalSystemDatabaseMethods() []catalogMethod {
	return []catalogMethod{
		callablePluginMethod(ToolSystemPing, DomainInstances, "Probe Plugin RPC liveness.", "none", "", catalogInstanceInputSchema, "Optional instanceId.", "status", 3000),
		callablePluginMethod(ToolSystemMethods, DomainInstances, "List Plugin RPC handler names.", "none", "", catalogInstanceInputSchema, "Optional instanceId.", "methods", 3000),
		callablePluginMethod(ToolInstanceInfo, DomainInstances, "Read sanitized Plugin instance identity.", "none", "", catalogInstanceInputSchema, "Optional instanceId.", "identity, safe basenames, and capabilities", 3000),
		callablePluginMethod(ToolDatabaseSurvey, DomainDatabase, "Build a bounded database survey.", "none", "", databaseSurveyInputSchema, "Optional instanceId; mode full|minimal; budget 3..100.", "metadata/statistics/samples", 30000),
		callablePluginMethod(ToolDatabaseSave, DomainDatabase, "Save the current IDA database without accepting a target path.", "filesystem_write", "", databaseSaveInputSchema, "Optional instanceId/compact/backup; target is forbidden.", "saved/explicitTarget=false", 120000),
	}
}

func internalFunctionMethods() []catalogMethod {
	return []catalogMethod{
		callablePluginMethod(ToolFunctionChunks, DomainFunctions, "List bounded entry and tail chunks for one function.", "none", "", readonlyPageInputSchema, "Optional instanceId; address; offset 0..1000000; limit 1..100.", "entryAddress/items/nextOffset/hasMore", 30000),
		callablePluginMethod(ToolExceptionTryBlocks, DomainFunctions, "Read bounded structured exception regions covering all function chunks.", "none", "", tryBlocksInputSchema, "Optional instanceId; address; limit 1..100.", "functionAddress/items/truncated", 30000),
		callablePluginMethod(ToolFunctionCallers, DomainFunctions, "Read direct callers and call sites.", "none", "", functionCallersInputSchema, "Optional instanceId; address; offset 0..1000000; limit 1..100.", "items/nextOffset/hasMore", 45000),
		callablePluginMethod(ToolFunctionCallGraph, DomainFunctions, "Build a bounded multi-root call graph.", "none", "", functionCallGraphInputSchema, "Optional instanceId; roots; direction; depth/node/edge bounds.", "nodes/edges/truncated", 60000),
		callablePluginMethod(ToolFunctionProfile, DomainFunctions, "Filter functions and collect bounded metrics.", "none", "", functionProfileInputSchema, "Optional instanceId and bounded name/size/flags/sample/cursor filters.", "items/metrics/public continuation", 60000),
		callablePluginMethod(ToolFunctionExport, DomainFunctions, "Render bounded function JSON or declarations.", "none", "", functionExportInputSchema, "Optional instanceId; addresses; format json|c_header|prototypes; maxBytes.", "format/content/truncation", 45000),
		callablePluginMethod(ToolFunctionAnalyze, DomainFunctions, "Run bounded composite function analysis.", "none", "optional decompiler", functionAnalyzeInputSchema, "Optional instanceId; addresses; sections; perSection; decompileBytes.", "explicit optional sections and items", 90000),
		callablePluginMethod(ToolFunctionAnalyzeBatch, DomainFunctions, "Alias of function.analyze with a distinct static RPC method.", "none", "optional decompiler", functionAnalyzeInputSchema, "Same typed contract as function.analyze.", "explicit optional sections and items", 90000),
		callablePluginMethod(ToolFunctionStackFrame, DomainFunctions, "Read bounded stack-frame variables.", "none", "", functionStackFrameInputSchema, "Optional instanceId; address.", "entryAddress/size/variables", 30000),
	}
}

func internalSearchTypeMethods() []catalogMethod {
	return []catalogMethod{
		callablePluginMethod(ToolInstructionGet, DomainSearch, "Read one normalized item and decode it only when it is code.", "none", "", readonlyAddressInputSchema, "Optional instanceId; address.", "item range/kind and optional decoded instruction", 12000),
		callablePluginMethod(ToolFixupGet, DomainSearch, "Read one exact fixup.", "none", "", readonlyAddressInputSchema, "Optional instanceId; exact source address.", "source/target/type/description/attributes", 12000),
		callablePluginMethod(ToolFixupList, DomainSearch, "List bounded fixups with authenticated continuation.", "none", "", addressListInputSchema, "Optional instanceId; optional paired start/end; limit; public cursor.", "items/nextCursor/hasMore", 30000),
		callablePluginMethod(ToolSwitchGet, DomainSearch, "Read existing switch metadata and calculated cases without creating a switch.", "none", "", readonlyAddressInputSchema, "Optional instanceId; address.", "cases/default/flags/metadata", 30000),
		callablePluginMethod(ToolMemorySearchBytes, DomainSearch, "Search an address range for a byte pattern.", "none", "", memorySearchBytesInputSchema, "Optional instanceId; pattern/start/end/limit.", "items/nextAddress/hasMore", 30000),
		callablePluginMethod(ToolInstructionSearch, DomainSearch, "Search instructions by mnemonic or operand.", "none", "", instructionSearchInputSchema, "Optional instanceId; start/end/mnemonic/operand/limit/public cursor.", "items/public continuation", 30000),
		callablePluginMethod(ToolInstructionQuery, DomainSearch, "Alias with a distinct static instruction.query RPC.", "none", "", instructionSearchInputSchema, "Same typed fields as instruction.search; cursor is method-bound.", "items/public continuation", 30000),
		callablePluginMethod(ToolListingSearch, DomainSearch, "Search one bounded disassembly-text page.", "none", "", listingSearchInputSchema, "Optional instanceId; start/end/query/limit; no cursor.", "items/truncated", 30000),
		callablePluginMethod(ToolListingSearchText, DomainSearch, "Search disassembly/comments with bounded text or safe regex.", "none", "", listingSearchTextInputSchema, "Optional instanceId; start/end; query xor regex; source flags/limit/public cursor.", "items/public continuation", 30000),
		callablePluginMethod(ToolStringSearchRegex, DomainSearch, "Search the existing IDA string list with a restricted safe regex; refresh=true explicitly rebuilds it.", "none", "", stringSearchRegexInputSchema, "Optional instanceId; pattern/minLength/limit/public cursor/refresh (default false; true cannot accompany cursor).", "items/public continuation", 20000),
		callablePluginMethod(ToolSignatureMake, DomainSearch, "Generate a bounded byte signature.", "none", "", signatureMakeInputSchema, "Optional instanceId; mode/address or range/format/wildcards/maxLength.", "signature metadata", 30000),
		callablePluginMethod(ToolSignatureXrefs, DomainSearch, "Generate signatures for code xrefs.", "none", "", signatureXrefsInputSchema, "Optional instanceId; address/format/wildcards/maxLength/top.", "items/totalXrefs/truncated", 30000),
		callablePluginMethod(ToolXrefStructField, DomainSearch, "Find references to a struct field.", "none", "", structFieldXrefsInputSchema, "Optional instanceId; type/field/limit.", "items/truncated", 12000),
		callablePluginMethod(ToolGlobalValue, DomainSymbols, "Read one typed global value.", "none", "", globalValueInputSchema, "Optional instanceId; exactly one address/name; maxBytes.", "typed bounded value", 12000),
		callablePluginMethod(ToolTypeSearch, DomainTypes, "Search local types with ordinal continuation.", "none", "", typeSearchInputSchema, "Optional instanceId; name/kind/ordinal/limit.", "items/nextOrdinal/hasMore", 12000),
		callablePluginMethod(ToolTypeQuery, DomainTypes, "Alias with a distinct static type.query RPC.", "none", "", typeSearchInputSchema, "Same ordinal contract as type.search.", "items/nextOrdinal/hasMore", 12000),
		callablePluginMethod(ToolTypeGet, DomainTypes, "Read one named type definition.", "none", "", typeGetInputSchema, "Optional instanceId; name.", "type details", 12000),
		callablePluginMethod(ToolTypeReadValue, DomainTypes, "Read memory using a named type.", "none", "", typeReadValueInputSchema, "Optional instanceId; address/name/maxBytes.", "typed value and fields", 12000),
		callablePluginMethod(ToolTypeReadStruct, DomainTypes, "Read or infer a UDT value.", "none", "", typeReadStructInputSchema, "Optional instanceId; address/optional name/maxBytes.", "typed value and fields", 12000),
		callablePluginMethod(ToolTypeInfer, DomainTypes, "Infer a declaration at an address.", "none", "", typeInferInputSchema, "Optional instanceId; address.", "address/declaration/source", 12000),
		callablePluginMethod(ToolAnalysisComponent, DomainAnalysis, "Analyze a bounded call component and shared evidence.", "none", "", analysisComponentInputSchema, "Optional instanceId; roots and graph/shared evidence bounds.", "graph/members/shared evidence", 60000),
		callablePluginMethod(ToolTraceArgumentCallers, DomainAnalysis, "Trace argument origins upward through known direct callers with separate contexts and ABI checks.", "none", "decompiler", argumentCallersInputSchema, "callAddress/argumentIndex; optional instanceId, maxDepth, maxContexts, maxCallers and shared budgets.", "contexts, parameter links, explicit boundaries and total work", 60000),
		callablePluginMethod(ToolTraceArgument, DomainAnalysis, "Trace one call argument through bounded function-local microcode definitions.", "none", "decompiler", argumentAnalysisInputSchema, "callAddress/zero-based argumentIndex; optional instanceId and budgets.", "value dependencies, boundaries, model and truncation", 60000),
		callablePluginMethod(ToolGuardEvidence, DomainAnalysis, "Extract argument-related comparisons and required CFG branch evidence; does not prove safety.", "none", "decompiler", argumentAnalysisInputSchema, "callAddress/zero-based argumentIndex; optional instanceId and budgets.", "argument dependencies, comparisons, required branches and value relations", 60000),
		callablePluginMethod(ToolAnalysisTraceDataFlow, DomainAnalysis, "Trace bounded xref-based data flow.", "none", "", traceDataFlowInputSchema, "Optional instanceId; address/direction/depth/node/edge bounds.", "model=xref_bfs/nodes/edges/truncated", 60000),
		callablePluginMethod(ToolAnalysisStatus, DomainAnalysis, "Observe auto-analysis state without waiting or changing queues.", "none", "", analysisStatusInputSchema, "Optional instanceId.", "queue/state/enabled/complete/currentAddress", 12000),
		callableGatewayMethod(ToolAnalysisWait, DomainAnalysis, "Poll analysis.status until complete or the bounded local timeout.", "none", analysisWaitInputSchema, "Optional instanceId/timeoutMs/pollIntervalMs.", "status/timedOut/pollCount/elapsedMs", 60000),
		callablePluginMethod(ToolAnalysisPlan, DomainAnalysis, "Queue a confirmed mapped range for reanalysis without waiting.", "idb_write", "", analysisPlanInputSchema, "start/end/confirm=true; maximum span 16 MiB.", "accepted/start/end/queue=used", 120000),
		callablePluginMethod(ToolAnalysisProblems, DomainAnalysis, "List one stable auto-analysis problem type with authenticated continuation.", "none", "", analysisProblemsInputSchema, "Optional instanceId; required type; optional start/limit/public cursor.", "items/nextCursor/hasMore", 30000),
		callablePluginMethod(ToolDiffBeforeAfter, DomainAnalysis, "Apply one reversible ChangeSet action and compare pseudocode.", "idb_write_then_rollback", "decompiler", diffBeforeAfterInputSchema, "one reversible action.", "before/after/change metadata", 120000),
	}
}

func internalMutationDebuggerMethods() []catalogMethod {
	return []catalogMethod{
		callablePluginMethod(ToolChangeSetPreview, DomainChanges, "Preview reversible IDB operations.", "none", "", changesetPreviewInputSchema, "operations 1..100.", "previewId/items/applicable", 30000),
		callablePluginMethod(ToolChangeSetApply, DomainChanges, "Apply a matching ChangeSet preview.", "idb_write", "", changesetApplyInputSchema, "previewId and identical operations.", "changeId/items/applied", 120000),
		callablePluginMethod(ToolChangeSetRollback, DomainChanges, "Rollback a retained reversible ChangeSet.", "idb_write", "", changesetRollbackInputSchema, "changeId.", "changeId/items/applied", 120000),
		callablePluginMethod(ToolChangeSetAudit, DomainChanges, "Read bounded redacted ChangeSet audit records.", "none", "", changesetAuditInputSchema, "offset/limit.", "items", 12000),
		callablePluginMethod(ToolPatchAssemble, DomainPatch, "Assemble instructions without modifying the IDB.", "none", "", patchAssembleInputSchema, "address/instruction.", "bytes/instruction ranges", 30000),
		callableGatewayMethod(ToolPatchWriteBytes, DomainPatch, "Write bytes through a reversible single-operation ChangeSet.", "idb_write", patchWriteBytesInputSchema, "address/hex bytes; optional expectedBytes conflict guard.", "address/before/after/changeId/applied", 120000),
		callableGatewayMethod(ToolPatchWriteInteger, DomainPatch, "Encode and write an integer through a reversible single-operation ChangeSet.", "idb_write", patchWriteIntegerInputSchema, "address/value/integerType; optional expectedBytes conflict guard.", "address/before/after/changeId/applied", 120000),
		callablePluginMethod(ToolDebuggerBackends, DomainDebugger, "List available debugger names and local/remote modes while idle. Works before a debugger is selected.", "none", "", debuggerEmptyInputSchema, "No parameters; requires no active process.", "items/current/remote", 120000),
		callablePluginMethod(ToolDebuggerConfiguration, DomainDebugger, "Read launch and remote options; password is never returned.", "none", "", debuggerEmptyInputSchema, "No parameters.", "path/arguments/directory/host/port/hasPassword", 120000),
		callablePluginMethod(ToolDebuggerProcesses, DomainDebugger, "List attach candidates using the selected debugger while idle. Remote enumeration may take time.", "none", "", debuggerProcessesInputSchema, "Optional limit 1..1000; no active process.", "items/total/truncated", 120000),
		callablePluginMethod(ToolDebuggerSelect, DomainDebugger, "Select an installed debugger while no process is active.", "debugger_state", "", debuggerSelectInputSchema, "name and remote from debugger.backends.", "accepted/state", 120000),
		callablePluginMethod(ToolDebuggerConfigure, DomainDebugger, "Update launch or remote options while idle; omitted fields are preserved, empty strings clear.", "debugger_state", "", debuggerConfigureInputSchema, "At least one of path/arguments/directory/host/port/password; port -1 selects default.", "accepted/state", 120000),
		callablePluginMethod(ToolDebuggerAttach, DomainDebugger, "Request attachment to an explicit PID while idle.", "process_control", "", debuggerAttachInputSchema, "pid from debugger.processes.", "accepted/state", 120000),
		callablePluginMethod(ToolDebuggerDetach, DomainDebugger, "Detach without terminating the target; requires a suspended process.", "process_control", "", debuggerEmptyInputSchema, "No parameters; suspend first if running.", "accepted/state", 120000),
		callablePluginMethod(ToolDebuggerSuspend, DomainDebugger, "Request pause of a running process.", "process_control", "", debuggerEmptyInputSchema, "No parameters; running process required.", "accepted/state", 120000),
		callablePluginMethod(ToolDebuggerInfo, DomainDebugger, "Read debugger process state.", "none", "debugger", debuggerEmptyInputSchema, "No parameters.", "debugger state", 120000),
		callablePluginMethod(ToolDebuggerStart, DomainDebugger, "Request debugger process start.", "process_control", "debugger", debuggerEmptyInputSchema, "No parameters.", "accepted/state", 120000),
		callablePluginMethod(ToolDebuggerExit, DomainDebugger, "Request debugger process exit.", "process_control", "debugger", debuggerEmptyInputSchema, "No parameters.", "accepted/state", 120000),
		callablePluginMethod(ToolDebuggerControl, DomainDebugger, "Continue, step, or run to an address.", "process_control", "debugger", debuggerControlInputSchema, "action and run_to address.", "accepted/state", 120000),
		callablePluginMethod(ToolDebuggerBreakpoints, DomainDebugger, "List or mutate debugger breakpoints.", "debugger_state", "debugger", debuggerBreakpointsInputSchema, "empty for list; otherwise bounded mutation action.", "items or accepted/state", 120000),
		callablePluginMethod(ToolDebuggerRegisters, DomainDebugger, "Read bounded debugger registers.", "none", "debugger", debuggerRegistersInputSchema, "thread/register selection.", "thread register items", 120000),
		callablePluginMethod(ToolDebuggerStackTrace, DomainDebugger, "Read a bounded debugger stack trace.", "none", "debugger", debuggerStackTraceInputSchema, "optional threadId/limit.", "items", 120000),
		callablePluginMethod(ToolDebuggerMemoryRead, DomainDebugger, "Read bounded debugger process memory.", "none", "debugger", debuggerMemoryReadInputSchema, "address/length.", "address/bytes", 120000),
		callablePluginMethod(ToolDebuggerMemoryWrite, DomainDebugger, "Write bounded debugger process memory.", "process_memory_write", "debugger", debuggerMemoryWriteInputSchema, "address/hex bytes.", "accepted/state", 120000),
		callablePluginMethod(ToolScriptExecute, DomainScripts, "Execute inline or file-backed IDAPython/IDC.", "arbitrary_code_execution", "", scriptInputSchema, "Optional instanceId; language python|idc; exactly one of code or Gateway-accessible path; source up to 32768 UTF-8 bytes.", "success/result/stdout/stderr/truncation", 120000),
	}
}
