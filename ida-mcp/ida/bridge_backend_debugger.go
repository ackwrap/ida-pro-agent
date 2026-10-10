package ida

import (
	"context"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

var _ DebuggerBackend = (*BridgeBackend)(nil)

func (backend *BridgeBackend) DebuggerInfo(ctx context.Context, instanceID string) (DebuggerInfo, error) {
	requestContext, cancel, release, session, client, err := backend.prepareDebugger(ctx, instanceID, readTimeout)
	if err != nil {
		return DebuggerInfo{}, err
	}
	defer cancel()
	defer release()
	result, err := client.DebuggerInfo(requestContext, session)
	if err != nil {
		return DebuggerInfo{}, normalizeBridgeError(err)
	}
	if err := result.Validate(); err != nil {
		return DebuggerInfo{}, NewError(ErrorInternal, "IDA backend returned invalid debugger state", false)
	}
	return fromBridgeDebuggerInfo(result), nil
}

func (backend *BridgeBackend) DebuggerStart(ctx context.Context, instanceID string) (DebuggerActionResult, error) {
	return backend.debuggerAction(ctx, instanceID, func(ctx context.Context, client BridgeDebuggerClient, session rpc.InstanceDescriptor) (bridge.DebuggerActionResult, error) {
		return client.DebuggerStart(ctx, session)
	})
}

func (backend *BridgeBackend) DebuggerExit(ctx context.Context, instanceID string) (DebuggerActionResult, error) {
	return backend.debuggerAction(ctx, instanceID, func(ctx context.Context, client BridgeDebuggerClient, session rpc.InstanceDescriptor) (bridge.DebuggerActionResult, error) {
		return client.DebuggerExit(ctx, session)
	})
}

func (backend *BridgeBackend) DebuggerControl(ctx context.Context, instanceID string, params DebuggerControlParams) (DebuggerActionResult, error) {
	if err := params.Validate(); err != nil {
		return DebuggerActionResult{}, NewError(ErrorInvalidArgument, "debugger control parameters are invalid", false)
	}
	wire := bridge.DebuggerControlParams{Action: params.Action}
	if params.Address != nil {
		address := rpc.Address(*params.Address)
		wire.Address = &address
	}
	return backend.debuggerAction(ctx, instanceID, func(ctx context.Context, client BridgeDebuggerClient, session rpc.InstanceDescriptor) (bridge.DebuggerActionResult, error) {
		return client.DebuggerControl(ctx, session, wire)
	})
}

func (backend *BridgeBackend) DebuggerBreakpoints(ctx context.Context, instanceID string, params DebuggerBreakpointsParams) (DebuggerBreakpointsResult, error) {
	if err := params.Validate(); err != nil {
		return DebuggerBreakpointsResult{}, NewError(ErrorInvalidArgument, "debugger breakpoint parameters are invalid", false)
	}
	requestContext, cancel, release, session, client, err := backend.prepareDebugger(ctx, instanceID, writeTimeout)
	if err != nil {
		return DebuggerBreakpointsResult{}, err
	}
	defer cancel()
	defer release()
	wire := bridge.DebuggerBreakpointsParams{Action: params.Action, Enabled: params.Enabled, ConditionSet: params.Condition.Present, ConditionNull: params.Condition.Null, Condition: params.Condition.Value, Type: params.Type, Size: params.Size, Language: params.Language, LowLevel: params.LowLevel, PassCount: params.PassCount}
	if params.Address != nil {
		address := rpc.Address(*params.Address)
		wire.Address = &address
	}
	result, err := client.DebuggerBreakpoints(requestContext, session, wire)
	if err != nil {
		return DebuggerBreakpointsResult{}, normalizeBridgeError(err)
	}
	if err := result.Validate(); err != nil {
		return DebuggerBreakpointsResult{}, NewError(ErrorInternal, "IDA backend returned invalid breakpoints", false)
	}
	if result.Action != nil {
		action := fromBridgeDebuggerAction(*result.Action)
		return DebuggerBreakpointsResult{Action: &action}, nil
	}
	items := make([]BreakpointInfo, 0, len(*result.Items))
	for _, item := range *result.Items {
		items = append(items, BreakpointInfo{Address: Address(item.Address), Enabled: item.Enabled, Type: item.Type, Size: item.Size, PassCount: item.PassCount, LowLevel: item.LowLevel, Condition: item.Condition, ConditionLanguage: item.ConditionLanguage, Compiled: item.Compiled, Active: item.Active})
	}
	return DebuggerBreakpointsResult{Items: &items}, nil
}

func (backend *BridgeBackend) DebuggerRegisters(ctx context.Context, instanceID string, params DebuggerRegistersParams) (DebuggerRegistersResult, error) {
	if err := params.Validate(); err != nil {
		return DebuggerRegistersResult{}, NewError(ErrorInvalidArgument, "debugger register parameters are invalid", false)
	}
	requestContext, cancel, release, session, client, err := backend.prepareDebugger(ctx, instanceID, readTimeout)
	if err != nil {
		return DebuggerRegistersResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.DebuggerRegisters(requestContext, session, bridge.DebuggerRegistersParams{ThreadMode: params.ThreadMode, ThreadIDs: params.ThreadIDs, RegisterMode: params.RegisterMode, Names: params.Names})
	if err != nil {
		return DebuggerRegistersResult{}, normalizeBridgeError(err)
	}
	converted := DebuggerRegistersResult{Items: make([]ThreadRegisters, 0, len(result.Items))}
	for _, thread := range result.Items {
		item := ThreadRegisters{ThreadID: thread.ThreadID, Registers: make([]RegisterValue, 0, len(thread.Registers))}
		for _, value := range thread.Registers {
			item.Registers = append(item.Registers, RegisterValue(value))
		}
		converted.Items = append(converted.Items, item)
	}
	return converted, nil
}

func (backend *BridgeBackend) DebuggerStackTrace(ctx context.Context, instanceID string, params DebuggerStackTraceParams) (DebuggerStackTraceResult, error) {
	if err := params.Validate(); err != nil {
		return DebuggerStackTraceResult{}, NewError(ErrorInvalidArgument, "debugger stack parameters are invalid", false)
	}
	requestContext, cancel, release, session, client, err := backend.prepareDebugger(ctx, instanceID, readTimeout)
	if err != nil {
		return DebuggerStackTraceResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.DebuggerStackTrace(requestContext, session, bridge.DebuggerStackTraceParams{ThreadID: params.ThreadID, Limit: params.Limit})
	if err != nil {
		return DebuggerStackTraceResult{}, normalizeBridgeError(err)
	}
	converted := DebuggerStackTraceResult{Items: make([]StackTraceFrame, 0, len(result.Items))}
	for _, frame := range result.Items {
		converted.Items = append(converted.Items, StackTraceFrame{CallAddress: Address(frame.CallAddress), FunctionAddress: Address(frame.FunctionAddress), FramePointer: Address(frame.FramePointer), FunctionKnown: frame.FunctionKnown, Module: frame.Module, Symbol: frame.Symbol})
	}
	return converted, nil
}

func (backend *BridgeBackend) DebuggerReadMemory(ctx context.Context, instanceID string, params DebuggerMemoryReadParams) (DebuggerMemoryResult, error) {
	if err := params.Validate(); err != nil {
		return DebuggerMemoryResult{}, NewError(ErrorInvalidArgument, "debugger memory parameters are invalid", false)
	}
	requestContext, cancel, release, session, client, err := backend.prepareDebugger(ctx, instanceID, readTimeout)
	if err != nil {
		return DebuggerMemoryResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.DebuggerReadMemory(requestContext, session, bridge.DebuggerMemoryReadParams{Address: rpc.Address(params.Address), Length: params.Length})
	if err != nil {
		return DebuggerMemoryResult{}, normalizeBridgeError(err)
	}
	return DebuggerMemoryResult{Address: Address(result.Address), Bytes: result.Bytes}, nil
}

func (backend *BridgeBackend) DebuggerWriteMemory(ctx context.Context, instanceID string, params DebuggerMemoryWriteParams) (DebuggerActionResult, error) {
	if err := params.Validate(); err != nil {
		return DebuggerActionResult{}, NewError(ErrorInvalidArgument, "debugger memory parameters are invalid", false)
	}
	wire := bridge.DebuggerMemoryWriteParams{Address: rpc.Address(params.Address), Bytes: params.Bytes}
	return backend.debuggerAction(ctx, instanceID, func(ctx context.Context, client BridgeDebuggerClient, session rpc.InstanceDescriptor) (bridge.DebuggerActionResult, error) {
		return client.DebuggerWriteMemory(ctx, session, wire)
	})
}

func (backend *BridgeBackend) debuggerAction(ctx context.Context, instanceID string, call func(context.Context, BridgeDebuggerClient, rpc.InstanceDescriptor) (bridge.DebuggerActionResult, error)) (DebuggerActionResult, error) {
	requestContext, cancel, release, session, client, err := backend.prepareDebugger(ctx, instanceID, writeTimeout)
	if err != nil {
		return DebuggerActionResult{}, err
	}
	defer cancel()
	defer release()
	result, err := call(requestContext, client, session)
	if err != nil {
		return DebuggerActionResult{}, normalizeBridgeError(err)
	}
	if err := result.Validate(); err != nil {
		return DebuggerActionResult{}, NewError(ErrorInternal, "IDA backend returned invalid debugger action", false)
	}
	return fromBridgeDebuggerAction(result), nil
}

func fromBridgeDebuggerInfo(result bridge.DebuggerInfo) DebuggerInfo {
	converted := DebuggerInfo{State: result.State, Running: result.Running, Suspended: result.Suspended, ThreadID: result.ThreadID}
	if result.InstructionPointer != nil {
		address := Address(*result.InstructionPointer)
		converted.InstructionPointer = &address
	}
	return converted
}

func fromBridgeDebuggerAction(result bridge.DebuggerActionResult) DebuggerActionResult {
	converted := DebuggerActionResult{Accepted: result.Accepted, State: result.State, Running: result.Running, Suspended: result.Suspended, ThreadID: result.ThreadID}
	if result.InstructionPointer != nil {
		address := Address(*result.InstructionPointer)
		converted.InstructionPointer = &address
	}
	return converted
}
