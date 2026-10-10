package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"ida-mcp/ida"
)

type debuggerSetupBackend struct {
	*typedDomainBackend
	selected   ida.DebuggerSelectParams
	configured ida.DebuggerConfigureParams
	attached   ida.DebuggerAttachParams
}

func (b *debuggerSetupBackend) DebuggerBackends(_ context.Context, _ string) (ida.DebuggerBackendsResult, error) {
	b.record(ToolDebuggerBackends)
	return ida.DebuggerBackendsResult{Items: []ida.DebuggerBackendInfo{{Name: "win32", Remote: true}}}, nil
}
func (b *debuggerSetupBackend) DebuggerConfiguration(_ context.Context, _ string) (ida.DebuggerConfiguration, error) {
	b.record(ToolDebuggerConfiguration)
	return ida.DebuggerConfiguration{Port: -1, HasPassword: true}, nil
}
func (b *debuggerSetupBackend) DebuggerProcesses(_ context.Context, _ string, p ida.DebuggerProcessesParams) (ida.DebuggerProcessesResult, error) {
	b.record(ToolDebuggerProcesses)
	return ida.DebuggerProcessesResult{Items: []ida.DebuggerProcessInfo{{PID: 1234, Name: "demo.exe"}}, Total: 1}, nil
}
func (b *debuggerSetupBackend) DebuggerSelect(_ context.Context, _ string, p ida.DebuggerSelectParams) (ida.DebuggerActionResult, error) {
	b.record(ToolDebuggerSelect)
	b.selected = p
	return testDebuggerAction(), nil
}
func (b *debuggerSetupBackend) DebuggerConfigure(_ context.Context, _ string, p ida.DebuggerConfigureParams) (ida.DebuggerActionResult, error) {
	b.record(ToolDebuggerConfigure)
	b.configured = p
	return testDebuggerAction(), nil
}
func (b *debuggerSetupBackend) DebuggerAttach(_ context.Context, _ string, p ida.DebuggerAttachParams) (ida.DebuggerActionResult, error) {
	b.record(ToolDebuggerAttach)
	b.attached = p
	return testDebuggerAction(), nil
}
func (b *debuggerSetupBackend) DebuggerDetach(_ context.Context, _ string) (ida.DebuggerActionResult, error) {
	b.record(ToolDebuggerDetach)
	return testDebuggerAction(), nil
}
func (b *debuggerSetupBackend) DebuggerSuspend(_ context.Context, _ string) (ida.DebuggerActionResult, error) {
	b.record(ToolDebuggerSuspend)
	return testDebuggerAction(), nil
}

func TestDebuggerSetupMCPDispatchAndBounds(t *testing.T) {
	b := &debuggerSetupBackend{typedDomainBackend: newTypedDomainBackend()}
	session := connectTestClient(t, b)
	tests := []struct {
		method string
		args   map[string]any
	}{
		{ToolDebuggerBackends, map[string]any{}}, {ToolDebuggerConfiguration, map[string]any{}},
		{ToolDebuggerProcesses, map[string]any{"limit": 1}},
		{ToolDebuggerSelect, map[string]any{"name": "win32", "remote": true}},
		{ToolDebuggerConfigure, map[string]any{"path": "C:\\sample.exe", "password": "", "port": -1}},
		{ToolDebuggerAttach, map[string]any{"pid": 1234}},
		{ToolDebuggerDetach, map[string]any{}}, {ToolDebuggerSuspend, map[string]any{}},
	}
	for _, test := range tests {
		t.Run(test.method, func(t *testing.T) {
			test.args["instanceId"] = testInstanceA
			var out domainCallOutput
			callDomainAction(t, session, ToolDomainDebugger, map[string]any{"action": "call", "method": test.method, "arguments": test.args}, &out)
			if out.Method != test.method || !json.Valid(out.Result) {
				t.Fatalf("invalid output: %+v", out)
			}
			test.args["unknown"] = true
			if !callDomainResult(t, session, ToolDomainDebugger, map[string]any{"action": "call", "method": test.method, "arguments": test.args}).IsError {
				t.Fatal("unknown field reached backend")
			}
		})
	}
	if len(b.calls) != len(tests) {
		t.Fatalf("calls=%v", b.calls)
	}
	if b.selected.Name != "win32" || !b.selected.Remote || b.attached.PID != 1234 || b.configured.Password == nil || *b.configured.Password != "" || b.configured.Host != nil || b.configured.Port == nil || *b.configured.Port != -1 {
		t.Fatal("typed parameter presence or value lost")
	}
	for _, test := range []struct {
		method string
		args   map[string]any
	}{
		{ToolDebuggerConfigure, map[string]any{}}, {ToolDebuggerConfigure, map[string]any{"password": nil}},
		{ToolDebuggerConfigure, map[string]any{"port": 0}}, {ToolDebuggerConfigure, map[string]any{"host": strings.Repeat("界", 400)}},
		{ToolDebuggerAttach, map[string]any{"pid": 0}}, {ToolDebuggerAttach, map[string]any{"pid": 2147483648}},
		{ToolDebuggerSelect, map[string]any{"name": "win32", "remote": nil}},
		{ToolDebuggerProcesses, map[string]any{"limit": 1001}},
	} {
		test.args["instanceId"] = testInstanceA
		if !callDomainResult(t, session, ToolDomainDebugger, map[string]any{"action": "call", "method": test.method, "arguments": test.args}).IsError {
			t.Errorf("invalid %s reached backend", test.method)
		}
	}
	if len(b.calls) != len(tests) {
		t.Fatal("invalid input invoked debugger")
	}
}
