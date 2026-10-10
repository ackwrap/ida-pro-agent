package mcpserver

import (
	"context"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ToolDebuggerBackends      = "debugger.backends"
	ToolDebuggerConfiguration = "debugger.configuration"
	ToolDebuggerProcesses     = "debugger.processes"
	ToolDebuggerSelect        = "debugger.select"
	ToolDebuggerConfigure     = "debugger.configure"
	ToolDebuggerAttach        = "debugger.attach"
	ToolDebuggerDetach        = "debugger.detach"
	ToolDebuggerSuspend       = "debugger.suspend"
)

type debuggerProcessesInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	ida.DebuggerProcessesParams
}
type debuggerSelectInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	ida.DebuggerSelectParams
}
type debuggerConfigureInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	ida.DebuggerConfigureParams
}
type debuggerAttachInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	ida.DebuggerAttachParams
}

func (registry *toolRegistry) prepareDebuggerSetup(ctx context.Context, instance *string) (ida.DebuggerSetupBackend, string, context.Context, context.CancelFunc, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, "", ctx, func() {}, err
	}
	backend, ok := registry.backend.(ida.DebuggerSetupBackend)
	if !ok {
		return nil, "", ctx, func() {}, ida.NewError(ida.ErrorCapabilityUnavailable, "debugger setup backend is unavailable", false)
	}
	instanceID, err := registry.instances.resolve(instance)
	if err != nil {
		return nil, "", ctx, func() {}, err
	}
	requestContext, cancel := context.WithTimeout(ctx, debuggerWriteToolTimeout)
	return backend, instanceID, requestContext, cancel, nil
}

func (registry *toolRegistry) debuggerBackends(ctx context.Context, _ *mcp.CallToolRequest, input debuggerEmptyInput) (*mcp.CallToolResult, ida.DebuggerBackendsResult, error) {
	backend, instanceID, requestContext, cancel, err := registry.prepareDebuggerSetup(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.DebuggerBackendsResult{}, err
	}
	defer cancel()
	result, err := backend.DebuggerBackends(requestContext, instanceID)
	if err != nil {
		return nil, ida.DebuggerBackendsResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) debuggerConfiguration(ctx context.Context, _ *mcp.CallToolRequest, input debuggerEmptyInput) (*mcp.CallToolResult, ida.DebuggerConfiguration, error) {
	backend, instanceID, requestContext, cancel, err := registry.prepareDebuggerSetup(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.DebuggerConfiguration{}, err
	}
	defer cancel()
	result, err := backend.DebuggerConfiguration(requestContext, instanceID)
	if err != nil {
		return nil, ida.DebuggerConfiguration{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) debuggerProcesses(ctx context.Context, _ *mcp.CallToolRequest, input debuggerProcessesInput) (*mcp.CallToolResult, ida.DebuggerProcessesResult, error) {
	if err := input.DebuggerProcessesParams.Validate(); err != nil {
		return nil, ida.DebuggerProcessesResult{}, ida.NewError(ida.ErrorInvalidArgument, "invalid debugger setup parameters", false)
	}
	backend, instanceID, requestContext, cancel, err := registry.prepareDebuggerSetup(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.DebuggerProcessesResult{}, err
	}
	defer cancel()
	result, err := backend.DebuggerProcesses(requestContext, instanceID, input.DebuggerProcessesParams)
	if err != nil {
		return nil, ida.DebuggerProcessesResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) debuggerSelect(ctx context.Context, _ *mcp.CallToolRequest, input debuggerSelectInput) (*mcp.CallToolResult, ida.DebuggerActionResult, error) {
	if err := input.DebuggerSelectParams.Validate(); err != nil {
		return nil, ida.DebuggerActionResult{}, ida.NewError(ida.ErrorInvalidArgument, "invalid debugger setup parameters", false)
	}
	backend, instanceID, requestContext, cancel, err := registry.prepareDebuggerSetup(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.DebuggerActionResult{}, err
	}
	defer cancel()
	result, err := backend.DebuggerSelect(requestContext, instanceID, input.DebuggerSelectParams)
	if err != nil {
		return nil, ida.DebuggerActionResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) debuggerConfigure(ctx context.Context, _ *mcp.CallToolRequest, input debuggerConfigureInput) (*mcp.CallToolResult, ida.DebuggerActionResult, error) {
	if err := input.DebuggerConfigureParams.Validate(); err != nil {
		return nil, ida.DebuggerActionResult{}, ida.NewError(ida.ErrorInvalidArgument, "invalid debugger setup parameters", false)
	}
	backend, instanceID, requestContext, cancel, err := registry.prepareDebuggerSetup(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.DebuggerActionResult{}, err
	}
	defer cancel()
	result, err := backend.DebuggerConfigure(requestContext, instanceID, input.DebuggerConfigureParams)
	if err != nil {
		return nil, ida.DebuggerActionResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) debuggerAttach(ctx context.Context, _ *mcp.CallToolRequest, input debuggerAttachInput) (*mcp.CallToolResult, ida.DebuggerActionResult, error) {
	if err := input.DebuggerAttachParams.Validate(); err != nil {
		return nil, ida.DebuggerActionResult{}, ida.NewError(ida.ErrorInvalidArgument, "invalid debugger setup parameters", false)
	}
	backend, instanceID, requestContext, cancel, err := registry.prepareDebuggerSetup(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.DebuggerActionResult{}, err
	}
	defer cancel()
	result, err := backend.DebuggerAttach(requestContext, instanceID, input.DebuggerAttachParams)
	if err != nil {
		return nil, ida.DebuggerActionResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) debuggerDetach(ctx context.Context, _ *mcp.CallToolRequest, input debuggerEmptyInput) (*mcp.CallToolResult, ida.DebuggerActionResult, error) {
	backend, instanceID, requestContext, cancel, err := registry.prepareDebuggerSetup(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.DebuggerActionResult{}, err
	}
	defer cancel()
	result, err := backend.DebuggerDetach(requestContext, instanceID)
	if err != nil {
		return nil, ida.DebuggerActionResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) debuggerSuspend(ctx context.Context, _ *mcp.CallToolRequest, input debuggerEmptyInput) (*mcp.CallToolResult, ida.DebuggerActionResult, error) {
	backend, instanceID, requestContext, cancel, err := registry.prepareDebuggerSetup(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.DebuggerActionResult{}, err
	}
	defer cancel()
	result, err := backend.DebuggerSuspend(requestContext, instanceID)
	if err != nil {
		return nil, ida.DebuggerActionResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) invokeDebuggerSetupMethod(ctx context.Context, request *mcp.CallToolRequest, method string, arguments []byte) ([]byte, bool, error) {
	switch method {
	case ToolDebuggerBackends:
		return invokeHandled(ctx, request, arguments, registry.debuggerBackends)
	case ToolDebuggerConfiguration:
		return invokeHandled(ctx, request, arguments, registry.debuggerConfiguration)
	case ToolDebuggerProcesses:
		return invokeHandled(ctx, request, arguments, registry.debuggerProcesses)
	case ToolDebuggerSelect:
		return invokeHandled(ctx, request, arguments, registry.debuggerSelect)
	case ToolDebuggerConfigure:
		return invokeHandled(ctx, request, arguments, registry.debuggerConfigure)
	case ToolDebuggerAttach:
		return invokeHandled(ctx, request, arguments, registry.debuggerAttach)
	case ToolDebuggerDetach:
		return invokeHandled(ctx, request, arguments, registry.debuggerDetach)
	case ToolDebuggerSuspend:
		return invokeHandled(ctx, request, arguments, registry.debuggerSuspend)
	default:
		return nil, false, nil
	}
}
