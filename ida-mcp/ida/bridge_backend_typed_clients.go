package ida

import (
	"context"
	"time"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

const writeTimeout = 120 * time.Second

type BridgeMutationClient interface {
	AnalysisPlan(context.Context, rpc.InstanceDescriptor, bridge.AnalysisPlanParams) (bridge.AnalysisPlanResult, error)
	PreviewChangeSet(context.Context, rpc.InstanceDescriptor, bridge.ChangeSetPreviewParams) (bridge.ChangeSetPreview, error)
	ApplyChangeSet(context.Context, rpc.InstanceDescriptor, bridge.ChangeSetApplyParams) (bridge.ChangeSetApplyResult, error)
	RollbackChangeSet(context.Context, rpc.InstanceDescriptor, bridge.ChangeSetRollbackParams) (bridge.ChangeSetApplyResult, error)
	ChangeSetAudit(context.Context, rpc.InstanceDescriptor, bridge.ChangeSetAuditParams) (bridge.ChangeSetAuditResult, error)
	AssemblePatch(context.Context, rpc.InstanceDescriptor, bridge.PatchAssembleParams) (bridge.PatchAssemblyResult, error)
	DiffBeforeAfter(context.Context, rpc.InstanceDescriptor, bridge.DiffBeforeAfterParams) (bridge.DiffBeforeAfterResult, error)
}

type BridgeDebuggerClient interface {
	DebuggerInfo(context.Context, rpc.InstanceDescriptor) (bridge.DebuggerInfo, error)
	DebuggerStart(context.Context, rpc.InstanceDescriptor) (bridge.DebuggerActionResult, error)
	DebuggerExit(context.Context, rpc.InstanceDescriptor) (bridge.DebuggerActionResult, error)
	DebuggerControl(context.Context, rpc.InstanceDescriptor, bridge.DebuggerControlParams) (bridge.DebuggerActionResult, error)
	DebuggerBreakpoints(context.Context, rpc.InstanceDescriptor, bridge.DebuggerBreakpointsParams) (bridge.DebuggerBreakpointsResult, error)
	DebuggerRegisters(context.Context, rpc.InstanceDescriptor, bridge.DebuggerRegistersParams) (bridge.DebuggerRegistersResult, error)
	DebuggerStackTrace(context.Context, rpc.InstanceDescriptor, bridge.DebuggerStackTraceParams) (bridge.DebuggerStackTraceResult, error)
	DebuggerReadMemory(context.Context, rpc.InstanceDescriptor, bridge.DebuggerMemoryReadParams) (bridge.DebuggerMemoryResult, error)
	DebuggerWriteMemory(context.Context, rpc.InstanceDescriptor, bridge.DebuggerMemoryWriteParams) (bridge.DebuggerActionResult, error)
}

type BridgeScriptClient interface {
	ExecuteScript(context.Context, rpc.InstanceDescriptor, bridge.ScriptExecuteParams) (bridge.ScriptExecutionResult, error)
}

func (backend *BridgeBackend) prepareMutation(
	ctx context.Context, instanceID string, timeout time.Duration,
) (context.Context, context.CancelFunc, func(), rpc.InstanceDescriptor, BridgeMutationClient, error) {
	release, err := backend.beginRequest(ctx, instanceID)
	if err != nil {
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil, err
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	session, err := backend.resolve(requestContext, instanceID)
	if err != nil {
		cancel()
		release()
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil, err
	}
	client, ok := backend.client.(BridgeMutationClient)
	if !ok {
		cancel()
		release()
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil,
			NewError(ErrorCapabilityUnavailable, "mutation backend is unavailable", false)
	}
	return requestContext, cancel, release, session, client, nil
}

func (backend *BridgeBackend) prepareDebugger(
	ctx context.Context, instanceID string, timeout time.Duration,
) (context.Context, context.CancelFunc, func(), rpc.InstanceDescriptor, BridgeDebuggerClient, error) {
	// The first call may wait for the Pipe-wide consent dialog in IDA.
	timeout = writeTimeout
	release, err := backend.beginRequest(ctx, instanceID)
	if err != nil {
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil, err
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	session, err := backend.resolve(requestContext, instanceID)
	if err != nil {
		cancel()
		release()
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil, err
	}
	// IDA checks current debugger availability after its own consent gate.
	// A discovery snapshot must not prevent the dialog or mask a newly loaded debugger.
	client, ok := backend.client.(BridgeDebuggerClient)
	if !ok {
		cancel()
		release()
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil,
			NewError(ErrorCapabilityUnavailable, "debugger backend is unavailable", false)
	}
	return requestContext, cancel, release, session, client, nil
}

func (backend *BridgeBackend) prepareScript(
	ctx context.Context, instanceID string, timeout time.Duration,
) (context.Context, context.CancelFunc, func(), rpc.InstanceDescriptor, BridgeScriptClient, error) {
	release, err := backend.beginRequest(ctx, instanceID)
	if err != nil {
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil, err
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	session, err := backend.resolve(requestContext, instanceID)
	if err != nil {
		cancel()
		release()
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil, err
	}
	client, ok := backend.client.(BridgeScriptClient)
	if !ok {
		cancel()
		release()
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil,
			NewError(ErrorCapabilityUnavailable, "script backend is unavailable", false)
	}
	return requestContext, cancel, release, session, client, nil
}
