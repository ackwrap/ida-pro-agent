package ida

import (
	"context"
	"testing"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

type fakeDebuggerBridgeClient struct {
	*fakeBridgeClient
	infoCalls int
}

func (client *fakeDebuggerBridgeClient) DebuggerInfo(context.Context, rpc.InstanceDescriptor) (bridge.DebuggerInfo, error) {
	client.infoCalls++
	return bridge.DebuggerInfo{State: "not_running"}, nil
}
func (*fakeDebuggerBridgeClient) DebuggerStart(context.Context, rpc.InstanceDescriptor) (bridge.DebuggerActionResult, error) {
	return bridge.DebuggerActionResult{State: "running", Running: true}, nil
}
func (*fakeDebuggerBridgeClient) DebuggerExit(context.Context, rpc.InstanceDescriptor) (bridge.DebuggerActionResult, error) {
	return bridge.DebuggerActionResult{State: "not_running"}, nil
}
func (*fakeDebuggerBridgeClient) DebuggerControl(context.Context, rpc.InstanceDescriptor, bridge.DebuggerControlParams) (bridge.DebuggerActionResult, error) {
	return bridge.DebuggerActionResult{State: "running", Running: true}, nil
}
func (*fakeDebuggerBridgeClient) DebuggerBreakpoints(context.Context, rpc.InstanceDescriptor, bridge.DebuggerBreakpointsParams) (bridge.DebuggerBreakpointsResult, error) {
	items := []bridge.BreakpointInfo{}
	return bridge.DebuggerBreakpointsResult{Items: &items}, nil
}
func (*fakeDebuggerBridgeClient) DebuggerRegisters(context.Context, rpc.InstanceDescriptor, bridge.DebuggerRegistersParams) (bridge.DebuggerRegistersResult, error) {
	return bridge.DebuggerRegistersResult{Items: []bridge.ThreadRegisters{}}, nil
}
func (*fakeDebuggerBridgeClient) DebuggerStackTrace(context.Context, rpc.InstanceDescriptor, bridge.DebuggerStackTraceParams) (bridge.DebuggerStackTraceResult, error) {
	return bridge.DebuggerStackTraceResult{Items: []bridge.StackTraceFrame{}}, nil
}
func (*fakeDebuggerBridgeClient) DebuggerReadMemory(context.Context, rpc.InstanceDescriptor, bridge.DebuggerMemoryReadParams) (bridge.DebuggerMemoryResult, error) {
	return bridge.DebuggerMemoryResult{}, nil
}
func (*fakeDebuggerBridgeClient) DebuggerWriteMemory(context.Context, rpc.InstanceDescriptor, bridge.DebuggerMemoryWriteParams) (bridge.DebuggerActionResult, error) {
	return bridge.DebuggerActionResult{State: "running", Running: true}, nil
}

func TestBridgeBackendRefreshesDebuggerInPluginDespiteDiscoverySnapshot(t *testing.T) {
	client := &fakeDebuggerBridgeClient{fakeBridgeClient: &fakeBridgeClient{}}
	backend := NewBridgeBackend(&fakeInstanceSource{instances: []rpc.InstanceDescriptor{testBackendInstance(testInstanceA, false)}}, client)
	_, err := backend.DebuggerInfo(context.Background(), testInstanceA)
	if err != nil {
		t.Fatalf("DebuggerInfo error = %v", err)
	}
	if client.infoCalls != 1 {
		t.Fatalf("debugger RPC calls = %d", client.infoCalls)
	}
}
