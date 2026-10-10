package ida

import (
	"context"
	"testing"
	"time"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

type setupBridgeClient struct {
	*fakeBridgeClient
	calls int
	bad   bool
}

func (c *setupBridgeClient) DebuggerBackends(ctx context.Context, _ rpc.InstanceDescriptor) (bridge.DebuggerBackendsResult, error) {
	c.calls++
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) < 110*time.Second {
		panic("missing consent timeout")
	}
	if c.bad {
		return bridge.DebuggerBackendsResult{}, nil
	}
	return bridge.DebuggerBackendsResult{Items: []bridge.DebuggerBackendInfo{{Name: "win32"}}}, nil
}
func (c *setupBridgeClient) DebuggerConfiguration(ctx context.Context, _ rpc.InstanceDescriptor) (bridge.DebuggerConfiguration, error) {
	c.calls++
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) < 110*time.Second {
		panic("missing consent timeout")
	}
	return bridge.DebuggerConfiguration{Port: -1, HasPassword: true}, nil
}
func (c *setupBridgeClient) DebuggerProcesses(ctx context.Context, _ rpc.InstanceDescriptor, p bridge.DebuggerProcessesParams) (bridge.DebuggerProcessesResult, error) {
	c.calls++
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) < 110*time.Second {
		panic("missing consent timeout")
	}
	return bridge.DebuggerProcessesResult{Items: []bridge.DebuggerProcessInfo{}, Total: 0}, nil
}
func (c *setupBridgeClient) DebuggerSelect(ctx context.Context, _ rpc.InstanceDescriptor, p bridge.DebuggerSelectParams) (bridge.DebuggerActionResult, error) {
	c.calls++
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) < 110*time.Second {
		panic("missing consent timeout")
	}
	return bridge.DebuggerActionResult{Accepted: true, State: "not_running"}, nil
}
func (c *setupBridgeClient) DebuggerConfigure(ctx context.Context, _ rpc.InstanceDescriptor, p bridge.DebuggerConfigureParams) (bridge.DebuggerActionResult, error) {
	c.calls++
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) < 110*time.Second {
		panic("missing consent timeout")
	}
	return bridge.DebuggerActionResult{Accepted: true, State: "not_running"}, nil
}
func (c *setupBridgeClient) DebuggerAttach(ctx context.Context, _ rpc.InstanceDescriptor, p bridge.DebuggerAttachParams) (bridge.DebuggerActionResult, error) {
	c.calls++
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) < 110*time.Second {
		panic("missing consent timeout")
	}
	return bridge.DebuggerActionResult{Accepted: true, State: "not_running"}, nil
}
func (c *setupBridgeClient) DebuggerDetach(ctx context.Context, _ rpc.InstanceDescriptor) (bridge.DebuggerActionResult, error) {
	c.calls++
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) < 110*time.Second {
		panic("missing consent timeout")
	}
	return bridge.DebuggerActionResult{Accepted: true, State: "not_running"}, nil
}
func (c *setupBridgeClient) DebuggerSuspend(ctx context.Context, _ rpc.InstanceDescriptor) (bridge.DebuggerActionResult, error) {
	c.calls++
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) < 110*time.Second {
		panic("missing consent timeout")
	}
	return bridge.DebuggerActionResult{Accepted: true, State: "not_running"}, nil
}
func TestDebuggerSetupBackendBootstrapsAndValidates(t *testing.T) {
	c := &setupBridgeClient{fakeBridgeClient: &fakeBridgeClient{}}
	b := NewBridgeBackend(&fakeInstanceSource{instances: []rpc.InstanceDescriptor{testBackendInstance(testInstanceA, false)}}, c)
	ctx := context.Background()
	host := "localhost"
	if _, err := b.DebuggerBackends(ctx, testInstanceA); err != nil {
		t.Fatal(err)
	}
	if _, err := b.DebuggerConfiguration(ctx, testInstanceA); err != nil {
		t.Fatal(err)
	}
	if _, err := b.DebuggerProcesses(ctx, testInstanceA, DebuggerProcessesParams{}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.DebuggerSelect(ctx, testInstanceA, DebuggerSelectParams{Name: "win32"}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.DebuggerConfigure(ctx, testInstanceA, DebuggerConfigureParams{Host: &host}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.DebuggerAttach(ctx, testInstanceA, DebuggerAttachParams{PID: 1234}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.DebuggerDetach(ctx, testInstanceA); err != nil {
		t.Fatal(err)
	}
	if _, err := b.DebuggerSuspend(ctx, testInstanceA); err != nil {
		t.Fatal(err)
	}
	if c.calls != 8 {
		t.Fatalf("calls=%d", c.calls)
	}
	if _, err := b.DebuggerAttach(ctx, testInstanceA, DebuggerAttachParams{PID: 0}); err == nil {
		t.Fatal("invalid PID accepted")
	}
	if c.calls != 8 {
		t.Fatal("invalid request reached Pipe")
	}
	c.bad = true
	if _, err := b.DebuggerBackends(ctx, testInstanceA); err == nil {
		t.Fatal("malformed result accepted")
	}
}
