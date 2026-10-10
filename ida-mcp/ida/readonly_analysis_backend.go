package ida

import "context"

// ReadonlyAnalysisBackend exposes only fixed, bounded, side-effect-free analysis RPCs.
type ReadonlyAnalysisBackend interface {
	InstructionGet(context.Context, string, AddressParams) (InstructionResult, error)
	FunctionChunks(context.Context, string, ReadonlyPageParams) (FunctionChunksResult, error)
	FixupGet(context.Context, string, AddressParams) (FixupItem, error)
	FixupList(context.Context, string, AddressListParams) (FixupListResult, error)
	SwitchGet(context.Context, string, AddressParams) (SwitchResult, error)
	ExceptionTryBlocks(context.Context, string, ReadonlyPageParams) (TryBlocksResult, error)
	AnalysisStatus(context.Context, string) (AnalysisStatusResult, error)
	AnalysisProblems(context.Context, string, AnalysisProblemsParams) (AnalysisProblemsResult, error)
}
