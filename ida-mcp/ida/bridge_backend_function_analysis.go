package ida

import (
	"context"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

func (backend *BridgeBackend) DisassembleFunction(
	ctx context.Context, instanceID string, params FunctionPageParams,
) (FunctionDisassemblyResult, error) {
	wire, err := bridgeFunctionPageParams(params)
	if err != nil {
		return FunctionDisassemblyResult{}, err
	}
	release, err := backend.beginRequest(ctx, instanceID)
	if err != nil {
		return FunctionDisassemblyResult{}, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	instance, err := backend.resolve(ctx, instanceID)
	if err != nil {
		return FunctionDisassemblyResult{}, err
	}
	result, err := backend.client.DisassembleFunction(ctx, instance, wire)
	if err != nil {
		return FunctionDisassemblyResult{}, normalizeBridgeError(err)
	}
	converted := FunctionDisassemblyResult{
		EntryAddress: Address(result.EntryAddress), Items: make([]DisassemblyItem, 0, len(result.Items)),
		NextOffset: result.NextOffset, HasMore: result.HasMore,
	}
	for _, item := range result.Items {
		converted.Items = append(converted.Items, DisassemblyItem{Address: Address(item.Address), Text: item.Text})
	}
	if err := converted.Validate(params); err != nil {
		return FunctionDisassemblyResult{}, NewError(ErrorInternal, "IDA backend returned invalid function analysis", false)
	}
	return converted, nil
}

func (backend *BridgeBackend) FunctionBasicBlocks(
	ctx context.Context, instanceID string, params FunctionPageParams,
) (FunctionBasicBlocksResult, error) {
	wire, err := bridgeFunctionPageParams(params)
	if err != nil {
		return FunctionBasicBlocksResult{}, err
	}
	release, err := backend.beginRequest(ctx, instanceID)
	if err != nil {
		return FunctionBasicBlocksResult{}, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	instance, err := backend.resolve(ctx, instanceID)
	if err != nil {
		return FunctionBasicBlocksResult{}, err
	}
	result, err := backend.client.FunctionBasicBlocks(ctx, instance, wire)
	if err != nil {
		return FunctionBasicBlocksResult{}, normalizeBridgeError(err)
	}
	converted := FunctionBasicBlocksResult{
		EntryAddress: Address(result.EntryAddress), Items: make([]FunctionBasicBlock, 0, len(result.Items)),
		NextOffset: result.NextOffset, HasMore: result.HasMore,
	}
	for _, block := range result.Items {
		item := FunctionBasicBlock{
			Start: Address(block.Start), End: Address(block.End), Type: BasicBlockType(block.Type),
			Successors:   make([]Address, 0, len(block.Successors)),
			Predecessors: make([]Address, 0, len(block.Predecessors)),
		}
		for _, address := range block.Successors {
			item.Successors = append(item.Successors, Address(address))
		}
		for _, address := range block.Predecessors {
			item.Predecessors = append(item.Predecessors, Address(address))
		}
		converted.Items = append(converted.Items, item)
	}
	if err := converted.Validate(params); err != nil {
		return FunctionBasicBlocksResult{}, NewError(ErrorInternal, "IDA backend returned invalid function analysis", false)
	}
	return converted, nil
}

func (backend *BridgeBackend) FunctionCallees(
	ctx context.Context, instanceID string, params FunctionPageParams,
) (FunctionCalleesResult, error) {
	wire, err := bridgeFunctionPageParams(params)
	if err != nil {
		return FunctionCalleesResult{}, err
	}
	release, err := backend.beginRequest(ctx, instanceID)
	if err != nil {
		return FunctionCalleesResult{}, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	instance, err := backend.resolve(ctx, instanceID)
	if err != nil {
		return FunctionCalleesResult{}, err
	}
	result, err := backend.client.FunctionCallees(ctx, instance, wire)
	if err != nil {
		return FunctionCalleesResult{}, normalizeBridgeError(err)
	}
	converted := FunctionCalleesResult{
		EntryAddress: Address(result.EntryAddress), Items: make([]FunctionCallee, 0, len(result.Items)),
		NextOffset: result.NextOffset, HasMore: result.HasMore,
	}
	for _, callee := range result.Items {
		converted.Items = append(converted.Items, FunctionCallee{
			Address: Address(callee.Address), Name: callee.Name, Internal: callee.Internal,
		})
	}
	if err := converted.Validate(params); err != nil {
		return FunctionCalleesResult{}, NewError(ErrorInternal, "IDA backend returned invalid function analysis", false)
	}
	return converted, nil
}

func bridgeFunctionPageParams(params FunctionPageParams) (bridge.FunctionPageParams, error) {
	if err := params.Validate(); err != nil {
		return bridge.FunctionPageParams{}, NewError(ErrorInvalidArgument, "function analysis parameters are invalid", false)
	}
	return bridge.FunctionPageParams{
		Address: rpc.Address(params.Address), Offset: params.Offset, Limit: params.Limit,
	}, nil
}
