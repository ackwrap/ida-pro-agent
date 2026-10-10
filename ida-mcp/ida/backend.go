package ida

import "context"

// Backend is the transport-neutral core IDA capability boundary used by MCP tools.
type Backend interface {
	ListInstances(context.Context) ([]Instance, error)
	DatabaseInfo(context.Context, string) (DatabaseInfo, error)
	DatabaseSegments(context.Context, string, SegmentListParams) (SegmentListResult, error)
	SearchStrings(context.Context, string, StringSearchParams) (StringSearchResult, error)
	SymbolImports(context.Context, string, ImportListParams) (ImportListResult, error)
	DatabaseEntryPoints(context.Context, string, EntryPointListParams) (EntryPointListResult, error)
	SymbolExports(context.Context, string, ExportListParams) (ExportListResult, error)
	SymbolSearch(context.Context, string, SymbolSearchParams) (SymbolSearchResult, error)
	GetFunction(context.Context, string, Address) (FunctionInfo, error)
	SearchFunctions(context.Context, string, FunctionSearchParams) (FunctionSearchResult, error)
	DisassembleFunction(context.Context, string, FunctionPageParams) (FunctionDisassemblyResult, error)
	FunctionBasicBlocks(context.Context, string, FunctionPageParams) (FunctionBasicBlocksResult, error)
	FunctionCallees(context.Context, string, FunctionPageParams) (FunctionCalleesResult, error)
	QueryXrefs(context.Context, string, XrefQueryParams) (XrefQueryResult, error)
	ReadMemory(context.Context, string, MemoryReadParams) (MemoryReadResult, error)
	DecompileFunction(context.Context, string, DecompileParams) (DecompileResult, error)
	SystemPing(context.Context, string) (SystemPingResult, error)
	SystemMethods(context.Context, string) (SystemMethodsResult, error)
	InstanceInfo(context.Context, string) (InstanceInfoResult, error)
	DatabaseSurvey(context.Context, string, DatabaseSurveyParams) (DatabaseSurveyResult, error)
	DatabaseSave(context.Context, string, DatabaseSaveParams) (DatabaseSaveResult, error)
	FunctionCallers(context.Context, string, FunctionCallersParams) (FunctionCallersResult, error)
	FunctionCallGraph(context.Context, string, FunctionCallGraphParams) (FunctionCallGraphResult, error)
	FunctionProfile(context.Context, string, FunctionProfileParams) (FunctionProfileResult, error)
	FunctionExport(context.Context, string, FunctionExportParams) (FunctionExportResult, error)
	FunctionAnalyze(context.Context, string, FunctionAnalyzeParams) (FunctionAnalyzeResult, error)
	FunctionAnalyzeBatch(context.Context, string, FunctionAnalyzeParams) (FunctionAnalyzeResult, error)
	FunctionStackFrame(context.Context, string, FunctionStackFrameParams) (FunctionStackFrameResult, error)
}

// MutationBackend exposes only the statically typed mutation and comparison
// operations implemented by a Backend. It intentionally has no generic RPC
// escape hatch.
type MutationBackend interface {
	PreviewChangeSet(context.Context, string, ChangeSetPreviewParams) (ChangeSetPreview, error)
	ApplyChangeSet(context.Context, string, ChangeSetApplyParams) (ChangeSetApplyResult, error)
	RollbackChangeSet(context.Context, string, ChangeSetRollbackParams) (ChangeSetApplyResult, error)
	ChangeSetAudit(context.Context, string, ChangeSetAuditParams) (ChangeSetAuditResult, error)
	AssemblePatch(context.Context, string, PatchAssembleParams) (PatchAssemblyResult, error)
	DiffBeforeAfter(context.Context, string, DiffBeforeAfterParams) (DiffBeforeAfterResult, error)
}

// DebuggerBackend is capability-gated by the concrete Backend. Cancellation
// only stops waiting for a result; it does not assert that an accepted process
// action or memory write was reverted.
type DebuggerBackend interface {
	DebuggerInfo(context.Context, string) (DebuggerInfo, error)
	DebuggerStart(context.Context, string) (DebuggerActionResult, error)
	DebuggerExit(context.Context, string) (DebuggerActionResult, error)
	DebuggerControl(context.Context, string, DebuggerControlParams) (DebuggerActionResult, error)
	DebuggerBreakpoints(context.Context, string, DebuggerBreakpointsParams) (DebuggerBreakpointsResult, error)
	DebuggerRegisters(context.Context, string, DebuggerRegistersParams) (DebuggerRegistersResult, error)
	DebuggerStackTrace(context.Context, string, DebuggerStackTraceParams) (DebuggerStackTraceResult, error)
	DebuggerReadMemory(context.Context, string, DebuggerMemoryReadParams) (DebuggerMemoryResult, error)
	DebuggerWriteMemory(context.Context, string, DebuggerMemoryWriteParams) (DebuggerActionResult, error)
}

// ScriptBackend executes inline source. It intentionally exposes no file path,
// generic RPC method, or permission flag.
type ScriptBackend interface {
	ExecuteScript(context.Context, string, ScriptExecuteParams) (ScriptExecutionResult, error)
}

// SearchBackend groups the bounded search/signature RPCs. Every method is
// statically named; implementations cannot forward a caller-supplied method.
type SearchBackend interface {
	SearchMemoryBytes(context.Context, string, MemorySearchBytesParams) (AddressSearchResult, error)
	SearchInstructions(context.Context, string, InstructionSearchParams) (InstructionSearchResult, error)
	QueryInstructions(context.Context, string, InstructionSearchParams) (InstructionSearchResult, error)
	SearchListing(context.Context, string, ListingSearchParams) (ListingSearchResult, error)
	SearchListingText(context.Context, string, ListingTextSearchParams) (ListingSearchResult, error)
	SearchStringsRegex(context.Context, string, StringRegexSearchParams) (StringSearchResult, error)
	MakeSignature(context.Context, string, SignatureMakeParams) (SignatureResult, error)
	SignatureXrefs(context.Context, string, SignatureXrefsParams) (XrefSignatureResult, error)
	StructFieldXrefs(context.Context, string, StructFieldXrefParams) (StructFieldXrefResult, error)
}

// TypeBackend exposes typed local-type and typed-value DTOs without a generic
// JSON or RPC escape hatch.
type TypeBackend interface {
	GlobalValue(context.Context, string, GlobalValueParams) (GlobalValueResult, error)
	SearchTypes(context.Context, string, TypeSearchParams) (TypeSearchResult, error)
	QueryTypes(context.Context, string, TypeSearchParams) (TypeSearchResult, error)
	GetType(context.Context, string, TypeGetParams) (TypeDetails, error)
	ReadTypeValue(context.Context, string, TypeReadValueParams) (TypedValueResult, error)
	ReadStruct(context.Context, string, TypeReadStructParams) (TypedValueResult, error)
	InferType(context.Context, string, TypeInferParams) (TypeInferenceResult, error)
}

// AnalysisBackend contains bounded composite analyses only.
type AnalysisBackend interface {
	AnalyzeComponent(context.Context, string, AnalysisComponentParams) (AnalysisComponentResult, error)
	TraceDataFlow(context.Context, string, TraceDataFlowParams) (TraceDataFlowResult, error)
}

// SemanticAnalysisBackend returns bounded function-local value and branch evidence.
type SemanticAnalysisBackend interface {
	TraceArgument(context.Context, string, ArgumentAnalysisParams) (ArgumentAnalysisResult, error)
	GuardEvidence(context.Context, string, ArgumentAnalysisParams) (ArgumentAnalysisResult, error)
}
