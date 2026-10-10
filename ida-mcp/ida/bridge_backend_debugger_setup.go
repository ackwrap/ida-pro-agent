package ida

import (
	"context"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

var _ DebuggerSetupBackend = (*BridgeBackend)(nil)

type BridgeDebuggerSetupClient interface {
	DebuggerBackends(context.Context, rpc.InstanceDescriptor) (bridge.DebuggerBackendsResult, error)
	DebuggerConfiguration(context.Context, rpc.InstanceDescriptor) (bridge.DebuggerConfiguration, error)
	DebuggerProcesses(context.Context, rpc.InstanceDescriptor, bridge.DebuggerProcessesParams) (bridge.DebuggerProcessesResult, error)
	DebuggerSelect(context.Context, rpc.InstanceDescriptor, bridge.DebuggerSelectParams) (bridge.DebuggerActionResult, error)
	DebuggerConfigure(context.Context, rpc.InstanceDescriptor, bridge.DebuggerConfigureParams) (bridge.DebuggerActionResult, error)
	DebuggerAttach(context.Context, rpc.InstanceDescriptor, bridge.DebuggerAttachParams) (bridge.DebuggerActionResult, error)
	DebuggerDetach(context.Context, rpc.InstanceDescriptor) (bridge.DebuggerActionResult, error)
	DebuggerSuspend(context.Context, rpc.InstanceDescriptor) (bridge.DebuggerActionResult, error)
}

func (backend *BridgeBackend) prepareDebuggerSetup(ctx context.Context, instanceID string) (context.Context, context.CancelFunc, func(), rpc.InstanceDescriptor, BridgeDebuggerSetupClient, error) {
	release, err := backend.beginRequest(ctx, instanceID)
	if err != nil {
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil, err
	}
	requestContext, cancel := context.WithTimeout(ctx, writeTimeout)
	session, err := backend.resolve(requestContext, instanceID)
	if err != nil {
		cancel()
		release()
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil, err
	}
	// Selection bootstraps a debugger; a stale capability snapshot cannot gate it.
	client, ok := backend.client.(BridgeDebuggerSetupClient)
	if !ok {
		cancel()
		release()
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil, NewError(ErrorCapabilityUnavailable, "debugger setup backend is unavailable", false)
	}
	return requestContext, cancel, release, session, client, nil
}

func (backend *BridgeBackend) DebuggerBackends(ctx context.Context, instanceID string) (DebuggerBackendsResult, error) {
	requestContext, cancel, release, session, client, err := backend.prepareDebuggerSetup(ctx, instanceID)
	if err != nil {
		return DebuggerBackendsResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.DebuggerBackends(requestContext, session)
	if err != nil {
		return DebuggerBackendsResult{}, normalizeBridgeError(err)
	}
	if err = result.Validate(); err != nil {
		return DebuggerBackendsResult{}, NewError(ErrorInternal, "IDA backend returned invalid debugger setup result", false)
	}
	return result, nil
}

func (backend *BridgeBackend) DebuggerConfiguration(ctx context.Context, instanceID string) (DebuggerConfiguration, error) {
	requestContext, cancel, release, session, client, err := backend.prepareDebuggerSetup(ctx, instanceID)
	if err != nil {
		return DebuggerConfiguration{}, err
	}
	defer cancel()
	defer release()
	result, err := client.DebuggerConfiguration(requestContext, session)
	if err != nil {
		return DebuggerConfiguration{}, normalizeBridgeError(err)
	}
	if err = result.Validate(); err != nil {
		return DebuggerConfiguration{}, NewError(ErrorInternal, "IDA backend returned invalid debugger setup result", false)
	}
	return result, nil
}

func (backend *BridgeBackend) DebuggerProcesses(ctx context.Context, instanceID string, p DebuggerProcessesParams) (DebuggerProcessesResult, error) {
	if err := p.Validate(); err != nil {
		return DebuggerProcessesResult{}, NewError(ErrorInvalidArgument, "invalid debugger setup parameters", false)
	}
	requestContext, cancel, release, session, client, err := backend.prepareDebuggerSetup(ctx, instanceID)
	if err != nil {
		return DebuggerProcessesResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.DebuggerProcesses(requestContext, session, p)
	if err != nil {
		return DebuggerProcessesResult{}, normalizeBridgeError(err)
	}
	if err = result.Validate(); err != nil {
		return DebuggerProcessesResult{}, NewError(ErrorInternal, "IDA backend returned invalid debugger setup result", false)
	}
	if len(result.Items) > int(p.EffectiveLimit()) {
		return DebuggerProcessesResult{}, NewError(ErrorInternal, "process result exceeds requested limit", false)
	}
	return result, nil
}

func (backend *BridgeBackend) DebuggerSelect(ctx context.Context, instanceID string, p DebuggerSelectParams) (DebuggerActionResult, error) {
	if err := p.Validate(); err != nil {
		return DebuggerActionResult{}, NewError(ErrorInvalidArgument, "invalid debugger setup parameters", false)
	}
	requestContext, cancel, release, session, client, err := backend.prepareDebuggerSetup(ctx, instanceID)
	if err != nil {
		return DebuggerActionResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.DebuggerSelect(requestContext, session, p)
	if err != nil {
		return DebuggerActionResult{}, normalizeBridgeError(err)
	}
	if err = result.Validate(); err != nil {
		return DebuggerActionResult{}, NewError(ErrorInternal, "IDA backend returned invalid debugger setup result", false)
	}
	return fromBridgeDebuggerAction(result), nil
}

func (backend *BridgeBackend) DebuggerConfigure(ctx context.Context, instanceID string, p DebuggerConfigureParams) (DebuggerActionResult, error) {
	if err := p.Validate(); err != nil {
		return DebuggerActionResult{}, NewError(ErrorInvalidArgument, "invalid debugger setup parameters", false)
	}
	requestContext, cancel, release, session, client, err := backend.prepareDebuggerSetup(ctx, instanceID)
	if err != nil {
		return DebuggerActionResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.DebuggerConfigure(requestContext, session, p)
	if err != nil {
		return DebuggerActionResult{}, normalizeBridgeError(err)
	}
	if err = result.Validate(); err != nil {
		return DebuggerActionResult{}, NewError(ErrorInternal, "IDA backend returned invalid debugger setup result", false)
	}
	return fromBridgeDebuggerAction(result), nil
}

func (backend *BridgeBackend) DebuggerAttach(ctx context.Context, instanceID string, p DebuggerAttachParams) (DebuggerActionResult, error) {
	if err := p.Validate(); err != nil {
		return DebuggerActionResult{}, NewError(ErrorInvalidArgument, "invalid debugger setup parameters", false)
	}
	requestContext, cancel, release, session, client, err := backend.prepareDebuggerSetup(ctx, instanceID)
	if err != nil {
		return DebuggerActionResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.DebuggerAttach(requestContext, session, p)
	if err != nil {
		return DebuggerActionResult{}, normalizeBridgeError(err)
	}
	if err = result.Validate(); err != nil {
		return DebuggerActionResult{}, NewError(ErrorInternal, "IDA backend returned invalid debugger setup result", false)
	}
	return fromBridgeDebuggerAction(result), nil
}

func (backend *BridgeBackend) DebuggerDetach(ctx context.Context, instanceID string) (DebuggerActionResult, error) {
	requestContext, cancel, release, session, client, err := backend.prepareDebuggerSetup(ctx, instanceID)
	if err != nil {
		return DebuggerActionResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.DebuggerDetach(requestContext, session)
	if err != nil {
		return DebuggerActionResult{}, normalizeBridgeError(err)
	}
	if err = result.Validate(); err != nil {
		return DebuggerActionResult{}, NewError(ErrorInternal, "IDA backend returned invalid debugger setup result", false)
	}
	return fromBridgeDebuggerAction(result), nil
}

func (backend *BridgeBackend) DebuggerSuspend(ctx context.Context, instanceID string) (DebuggerActionResult, error) {
	requestContext, cancel, release, session, client, err := backend.prepareDebuggerSetup(ctx, instanceID)
	if err != nil {
		return DebuggerActionResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.DebuggerSuspend(requestContext, session)
	if err != nil {
		return DebuggerActionResult{}, normalizeBridgeError(err)
	}
	if err = result.Validate(); err != nil {
		return DebuggerActionResult{}, NewError(ErrorInternal, "IDA backend returned invalid debugger setup result", false)
	}
	return fromBridgeDebuggerAction(result), nil
}
