package mcpserver

import (
	"context"
	"time"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ToolDebuggerInfo        = "debugger.info"
	ToolDebuggerStart       = "debugger.start"
	ToolDebuggerExit        = "debugger.exit"
	ToolDebuggerControl     = "debugger.control"
	ToolDebuggerBreakpoints = "debugger.breakpoints"
	ToolDebuggerRegisters   = "debugger.registers"
	ToolDebuggerStackTrace  = "debugger.stacktrace"
	ToolDebuggerMemoryRead  = "debugger.memory_read"
	ToolDebuggerMemoryWrite = "debugger.memory_write"

	debuggerReadToolTimeout  = 120 * time.Second
	debuggerWriteToolTimeout = 120 * time.Second
)

type debuggerEmptyInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
}
type debuggerControlInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Action     string  `json:"action"`
	Address    *string `json:"address,omitempty"`
}
type debuggerBreakpointsInput struct {
	InstanceID *string            `json:"instanceId,omitempty"`
	Action     *string            `json:"action,omitempty"`
	Address    *string            `json:"address,omitempty"`
	Enabled    *bool              `json:"enabled,omitempty"`
	Condition  ida.NullableString `json:"condition,omitempty"`
	Type       *string            `json:"type,omitempty"`
	Size       *uint32            `json:"size,omitempty"`
	Language   *string            `json:"language,omitempty"`
	LowLevel   *bool              `json:"lowLevel,omitempty"`
	PassCount  *uint32            `json:"passCount,omitempty"`
}
type debuggerRegistersInput struct {
	InstanceID   *string  `json:"instanceId,omitempty"`
	ThreadMode   *string  `json:"threadMode,omitempty"`
	ThreadIDs    []int64  `json:"threadIds,omitempty"`
	RegisterMode *string  `json:"registerMode,omitempty"`
	Names        []string `json:"names,omitempty"`
}
type debuggerStackTraceInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	ThreadID   *int64  `json:"threadId,omitempty"`
	Limit      *uint32 `json:"limit,omitempty"`
}
type debuggerMemoryReadInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
	Length     uint32  `json:"length"`
}
type debuggerMemoryWriteInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
	Bytes      string  `json:"bytes"`
}

func (registry *toolRegistry) debuggerInfo(ctx context.Context, _ *mcp.CallToolRequest, input debuggerEmptyInput) (*mcp.CallToolResult, ida.DebuggerInfo, error) {
	backend, instanceID, requestContext, cancel, err := registry.prepareDebugger(ctx, input.InstanceID, debuggerReadToolTimeout)
	if err != nil {
		return nil, ida.DebuggerInfo{}, err
	}
	defer cancel()
	result, err := backend.DebuggerInfo(requestContext, instanceID)
	if err != nil {
		return nil, ida.DebuggerInfo{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) debuggerStart(ctx context.Context, _ *mcp.CallToolRequest, input debuggerEmptyInput) (*mcp.CallToolResult, ida.DebuggerActionResult, error) {
	return registry.runDebuggerAction(ctx, input.InstanceID, func(ctx context.Context, backend ida.DebuggerBackend, instanceID string) (ida.DebuggerActionResult, error) {
		return backend.DebuggerStart(ctx, instanceID)
	})
}
func (registry *toolRegistry) debuggerExit(ctx context.Context, _ *mcp.CallToolRequest, input debuggerEmptyInput) (*mcp.CallToolResult, ida.DebuggerActionResult, error) {
	return registry.runDebuggerAction(ctx, input.InstanceID, func(ctx context.Context, backend ida.DebuggerBackend, instanceID string) (ida.DebuggerActionResult, error) {
		return backend.DebuggerExit(ctx, instanceID)
	})
}
func (registry *toolRegistry) debuggerControl(ctx context.Context, _ *mcp.CallToolRequest, input debuggerControlInput) (*mcp.CallToolResult, ida.DebuggerActionResult, error) {
	params := ida.DebuggerControlParams{Action: input.Action}
	if input.Address != nil {
		address, err := parseToolAddress(*input.Address)
		if err != nil {
			return nil, ida.DebuggerActionResult{}, err
		}
		params.Address = &address
	}
	return registry.runDebuggerAction(ctx, input.InstanceID, func(ctx context.Context, backend ida.DebuggerBackend, instanceID string) (ida.DebuggerActionResult, error) {
		return backend.DebuggerControl(ctx, instanceID, params)
	})
}

func (registry *toolRegistry) debuggerBreakpoints(ctx context.Context, _ *mcp.CallToolRequest, input debuggerBreakpointsInput) (*mcp.CallToolResult, ida.DebuggerBreakpointsResult, error) {
	backend, instanceID, requestContext, cancel, err := registry.prepareDebugger(ctx, input.InstanceID, debuggerWriteToolTimeout)
	if err != nil {
		return nil, ida.DebuggerBreakpointsResult{}, err
	}
	defer cancel()
	params := ida.DebuggerBreakpointsParams{Action: input.Action, Enabled: input.Enabled, Condition: input.Condition, Type: input.Type, Size: input.Size, Language: input.Language, LowLevel: input.LowLevel, PassCount: input.PassCount}
	if input.Address != nil {
		address, err := parseToolAddress(*input.Address)
		if err != nil {
			return nil, ida.DebuggerBreakpointsResult{}, err
		}
		params.Address = &address
	}
	result, err := backend.DebuggerBreakpoints(requestContext, instanceID, params)
	if err != nil {
		return nil, ida.DebuggerBreakpointsResult{}, sanitizeToolError(err)
	}
	if result.Items != nil {
		return checkedCollectionOutput(*result.Items, result)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) debuggerRegisters(ctx context.Context, _ *mcp.CallToolRequest, input debuggerRegistersInput) (*mcp.CallToolResult, ida.DebuggerRegistersResult, error) {
	backend, instanceID, requestContext, cancel, err := registry.prepareDebugger(ctx, input.InstanceID, debuggerReadToolTimeout)
	if err != nil {
		return nil, ida.DebuggerRegistersResult{}, err
	}
	defer cancel()
	result, err := backend.DebuggerRegisters(requestContext, instanceID, ida.DebuggerRegistersParams{ThreadMode: input.ThreadMode, ThreadIDs: input.ThreadIDs, RegisterMode: input.RegisterMode, Names: input.Names})
	if err != nil {
		return nil, ida.DebuggerRegistersResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(result.Items, result)
}

func (registry *toolRegistry) debuggerStackTrace(ctx context.Context, _ *mcp.CallToolRequest, input debuggerStackTraceInput) (*mcp.CallToolResult, ida.DebuggerStackTraceResult, error) {
	backend, instanceID, requestContext, cancel, err := registry.prepareDebugger(ctx, input.InstanceID, debuggerReadToolTimeout)
	if err != nil {
		return nil, ida.DebuggerStackTraceResult{}, err
	}
	defer cancel()
	result, err := backend.DebuggerStackTrace(requestContext, instanceID, ida.DebuggerStackTraceParams{ThreadID: input.ThreadID, Limit: input.Limit})
	if err != nil {
		return nil, ida.DebuggerStackTraceResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(result.Items, result)
}

func (registry *toolRegistry) debuggerMemoryRead(ctx context.Context, _ *mcp.CallToolRequest, input debuggerMemoryReadInput) (*mcp.CallToolResult, ida.DebuggerMemoryResult, error) {
	backend, instanceID, requestContext, cancel, err := registry.prepareDebugger(ctx, input.InstanceID, debuggerReadToolTimeout)
	if err != nil {
		return nil, ida.DebuggerMemoryResult{}, err
	}
	defer cancel()
	address, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, ida.DebuggerMemoryResult{}, err
	}
	result, err := backend.DebuggerReadMemory(requestContext, instanceID, ida.DebuggerMemoryReadParams{Address: address, Length: input.Length})
	if err != nil {
		return nil, ida.DebuggerMemoryResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) debuggerMemoryWrite(ctx context.Context, _ *mcp.CallToolRequest, input debuggerMemoryWriteInput) (*mcp.CallToolResult, ida.DebuggerActionResult, error) {
	address, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, ida.DebuggerActionResult{}, err
	}
	params := ida.DebuggerMemoryWriteParams{Address: address, Bytes: input.Bytes}
	return registry.runDebuggerAction(ctx, input.InstanceID, func(ctx context.Context, backend ida.DebuggerBackend, instanceID string) (ida.DebuggerActionResult, error) {
		return backend.DebuggerWriteMemory(ctx, instanceID, params)
	})
}

func (registry *toolRegistry) prepareDebugger(ctx context.Context, instance *string, timeout time.Duration) (ida.DebuggerBackend, string, context.Context, context.CancelFunc, error) {
	if err := registry.ensureBackend(); err != nil {
		return nil, "", ctx, func() {}, err
	}
	backend, ok := registry.backend.(ida.DebuggerBackend)
	if !ok {
		return nil, "", ctx, func() {}, ida.NewError(ida.ErrorCapabilityUnavailable, "debugger backend is unavailable", false)
	}
	instanceID, err := registry.instances.resolve(instance)
	if err != nil {
		return nil, "", ctx, func() {}, err
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	return backend, instanceID, requestContext, cancel, nil
}

func (registry *toolRegistry) runDebuggerAction(ctx context.Context, instance *string, call func(context.Context, ida.DebuggerBackend, string) (ida.DebuggerActionResult, error)) (*mcp.CallToolResult, ida.DebuggerActionResult, error) {
	backend, instanceID, requestContext, cancel, err := registry.prepareDebugger(ctx, instance, debuggerWriteToolTimeout)
	if err != nil {
		return nil, ida.DebuggerActionResult{}, err
	}
	defer cancel()
	result, err := call(requestContext, backend, instanceID)
	if err != nil {
		return nil, ida.DebuggerActionResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}

func (registry *toolRegistry) invokeDebuggerDomainMethod(ctx context.Context, request *mcp.CallToolRequest, method string, arguments []byte) ([]byte, bool, error) {
	switch method {
	case ToolDebuggerInfo:
		return invokeHandled(ctx, request, arguments, registry.debuggerInfo)
	case ToolDebuggerStart:
		return invokeHandled(ctx, request, arguments, registry.debuggerStart)
	case ToolDebuggerExit:
		return invokeHandled(ctx, request, arguments, registry.debuggerExit)
	case ToolDebuggerControl:
		return invokeHandled(ctx, request, arguments, registry.debuggerControl)
	case ToolDebuggerBreakpoints:
		return invokeHandled(ctx, request, arguments, registry.debuggerBreakpoints)
	case ToolDebuggerRegisters:
		return invokeHandled(ctx, request, arguments, registry.debuggerRegisters)
	case ToolDebuggerStackTrace:
		return invokeHandled(ctx, request, arguments, registry.debuggerStackTrace)
	case ToolDebuggerMemoryRead:
		return invokeHandled(ctx, request, arguments, registry.debuggerMemoryRead)
	case ToolDebuggerMemoryWrite:
		return invokeHandled(ctx, request, arguments, registry.debuggerMemoryWrite)
	default:
		return registry.invokeDebuggerSetupMethod(ctx, request, method, arguments)
	}
}
