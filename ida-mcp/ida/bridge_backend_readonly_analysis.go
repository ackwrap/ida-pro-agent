package ida

import (
	"context"
	"time"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

type BridgeReadonlyAnalysisClient interface {
	InstructionGet(context.Context, rpc.InstanceDescriptor, bridge.AddressParams) (bridge.InstructionResult, error)
	FunctionChunks(context.Context, rpc.InstanceDescriptor, bridge.ReadonlyPageParams) (bridge.FunctionChunksResult, error)
	FixupGet(context.Context, rpc.InstanceDescriptor, bridge.AddressParams) (bridge.FixupItem, error)
	FixupList(context.Context, rpc.InstanceDescriptor, bridge.AddressListParams) (bridge.FixupListResult, error)
	SwitchGet(context.Context, rpc.InstanceDescriptor, bridge.AddressParams) (bridge.SwitchResult, error)
	ExceptionTryBlocks(context.Context, rpc.InstanceDescriptor, bridge.ReadonlyPageParams) (bridge.TryBlocksResult, error)
	AnalysisStatus(context.Context, rpc.InstanceDescriptor) (bridge.AnalysisStatusResult, error)
	AnalysisProblems(context.Context, rpc.InstanceDescriptor, bridge.AnalysisProblemsParams) (bridge.AnalysisProblemsResult, error)
}

func (backend *BridgeBackend) prepareReadonlyAnalysis(ctx context.Context, instanceID string) (context.Context, context.CancelFunc, func(), rpc.InstanceDescriptor, BridgeReadonlyAnalysisClient, error) {
	ctx, cancel, release, instance, raw, err := backend.prepareReadRPC(ctx, instanceID, 30*time.Second)
	if err != nil {
		return ctx, cancel, release, instance, nil, err
	}
	client, ok := raw.(BridgeReadonlyAnalysisClient)
	if !ok {
		cancel()
		release()
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil, NewError(ErrorCapabilityUnavailable, "readonly analysis backend is unavailable", false)
	}
	return ctx, cancel, release, instance, client, nil
}

func readonlyConverted[T any, W any](ctx context.Context, backend *BridgeBackend, instanceID string, call func(BridgeReadonlyAnalysisClient, context.Context, rpc.InstanceDescriptor) (W, error)) (T, error) {
	var zero T
	ctx, cancel, release, instance, client, err := backend.prepareReadonlyAnalysis(ctx, instanceID)
	if err != nil {
		return zero, err
	}
	defer cancel()
	defer release()
	result, err := call(client, ctx, instance)
	return convertCatalogDTO[T](result, err)
}

func (backend *BridgeBackend) InstructionGet(ctx context.Context, id string, params AddressParams) (InstructionResult, error) {
	return readonlyConverted[InstructionResult](ctx, backend, id, func(c BridgeReadonlyAnalysisClient, x context.Context, i rpc.InstanceDescriptor) (bridge.InstructionResult, error) {
		return c.InstructionGet(x, i, bridge.AddressParams{Address: rpc.Address(params.Address)})
	})
}
func (backend *BridgeBackend) FunctionChunks(ctx context.Context, id string, params ReadonlyPageParams) (FunctionChunksResult, error) {
	return readonlyConverted[FunctionChunksResult](ctx, backend, id, func(c BridgeReadonlyAnalysisClient, x context.Context, i rpc.InstanceDescriptor) (bridge.FunctionChunksResult, error) {
		return c.FunctionChunks(x, i, bridge.ReadonlyPageParams{Address: rpc.Address(params.Address), Offset: params.Offset, Limit: params.Limit})
	})
}
func (backend *BridgeBackend) FixupGet(ctx context.Context, id string, params AddressParams) (FixupItem, error) {
	return readonlyConverted[FixupItem](ctx, backend, id, func(c BridgeReadonlyAnalysisClient, x context.Context, i rpc.InstanceDescriptor) (bridge.FixupItem, error) {
		return c.FixupGet(x, i, bridge.AddressParams{Address: rpc.Address(params.Address)})
	})
}
func (backend *BridgeBackend) FixupList(ctx context.Context, id string, params AddressListParams) (FixupListResult, error) {
	wire := bridge.AddressListParams{Limit: params.Limit}
	if params.Start != nil {
		v := rpc.Address(*params.Start)
		wire.Start = &v
	}
	if params.End != nil {
		v := rpc.Address(*params.End)
		wire.End = &v
	}
	if params.NextAddress != nil {
		v := rpc.Address(*params.NextAddress)
		wire.NextAddress = &v
	}
	return readonlyConverted[FixupListResult](ctx, backend, id, func(c BridgeReadonlyAnalysisClient, x context.Context, i rpc.InstanceDescriptor) (bridge.FixupListResult, error) {
		return c.FixupList(x, i, wire)
	})
}
func (backend *BridgeBackend) SwitchGet(ctx context.Context, id string, params AddressParams) (SwitchResult, error) {
	return readonlyConverted[SwitchResult](ctx, backend, id, func(c BridgeReadonlyAnalysisClient, x context.Context, i rpc.InstanceDescriptor) (bridge.SwitchResult, error) {
		return c.SwitchGet(x, i, bridge.AddressParams{Address: rpc.Address(params.Address)})
	})
}
func (backend *BridgeBackend) ExceptionTryBlocks(ctx context.Context, id string, params ReadonlyPageParams) (TryBlocksResult, error) {
	return readonlyConverted[TryBlocksResult](ctx, backend, id, func(c BridgeReadonlyAnalysisClient, x context.Context, i rpc.InstanceDescriptor) (bridge.TryBlocksResult, error) {
		return c.ExceptionTryBlocks(x, i, bridge.ReadonlyPageParams{Address: rpc.Address(params.Address), Limit: params.Limit})
	})
}
func (backend *BridgeBackend) AnalysisStatus(ctx context.Context, id string) (AnalysisStatusResult, error) {
	return readonlyConverted[AnalysisStatusResult](ctx, backend, id, func(c BridgeReadonlyAnalysisClient, x context.Context, i rpc.InstanceDescriptor) (bridge.AnalysisStatusResult, error) {
		return c.AnalysisStatus(x, i)
	})
}
func (backend *BridgeBackend) AnalysisPlan(ctx context.Context, id string, params AnalysisPlanParams) (AnalysisPlanResult, error) {
	requestContext, cancel, release, session, client, err := backend.prepareMutation(ctx, id, writeTimeout)
	if err != nil {
		return AnalysisPlanResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.AnalysisPlan(requestContext, session, bridge.AnalysisPlanParams{Start: rpc.Address(params.Start), End: rpc.Address(params.End), Confirm: true})
	return convertCatalogDTO[AnalysisPlanResult](result, err)
}
func (backend *BridgeBackend) AnalysisProblems(ctx context.Context, id string, params AnalysisProblemsParams) (AnalysisProblemsResult, error) {
	wire := bridge.AnalysisProblemsParams{Type: params.Type, Limit: params.Limit}
	if params.Start != nil {
		v := rpc.Address(*params.Start)
		wire.Start = &v
	}
	if params.NextAddress != nil {
		v := rpc.Address(*params.NextAddress)
		wire.NextAddress = &v
	}
	return readonlyConverted[AnalysisProblemsResult](ctx, backend, id, func(c BridgeReadonlyAnalysisClient, x context.Context, i rpc.InstanceDescriptor) (bridge.AnalysisProblemsResult, error) {
		return c.AnalysisProblems(x, i, wire)
	})
}
