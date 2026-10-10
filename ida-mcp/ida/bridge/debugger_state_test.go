package bridge

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func debuggerStateFixture(t *testing.T, directory, name string) json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "protocol", "testdata", directory, name))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Result
}

// The paused IDA process returns running=false. Exercise the typed Pipe clients,
// including all action-result routes, so the actual wire flags stay intact.
func TestDebuggerClientsAcceptSuspendedPipeResponses(t *testing.T) {
	instance := testInstanceDescriptor()
	info := debuggerStateFixture(t, "valid", "response-debugger-info-suspended.json")
	action := debuggerStateFixture(t, "valid", "response-debugger-memory-write.json")
	ctx := context.Background()
	tests := []struct {
		method string
		result json.RawMessage
		call   func(*Client) error
	}{
		{methodDebuggerInfo, info, func(c *Client) error { _, e := c.DebuggerInfo(ctx, instance); return e }},
		{methodDebuggerStart, action, func(c *Client) error { _, e := c.DebuggerStart(ctx, instance); return e }},
		{methodDebuggerExit, action, func(c *Client) error { _, e := c.DebuggerExit(ctx, instance); return e }},
		{methodDebuggerControl, action, func(c *Client) error {
			_, e := c.DebuggerControl(ctx, instance, DebuggerControlParams{Action: "pause"})
			return e
		}},
		{methodDebuggerMemoryWrite, action, func(c *Client) error {
			_, e := c.DebuggerWriteMemory(ctx, instance, DebuggerMemoryWriteParams{Bytes: "90"})
			return e
		}},
		{methodDebuggerBreakpoints, action, func(c *Client) error {
			a := "add"
			_, e := c.DebuggerBreakpoints(ctx, instance, DebuggerBreakpointsParams{Action: &a})
			return e
		}},
	}
	for _, test := range tests {
		t.Run(test.method, func(t *testing.T) {
			if err := test.call(functionAnalysisTestClient(t, instance, test.method, test.result)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDebuggerClientsRejectInconsistentSuspendedState(t *testing.T) {
	instance := testInstanceDescriptor()
	result := debuggerStateFixture(t, "invalid", "response-debugger-info-inconsistent-state.json")
	c := functionAnalysisTestClient(t, instance, methodDebuggerInfo, result)
	if _, err := c.DebuggerInfo(context.Background(), instance); err == nil {
		t.Fatal("running and suspended were both accepted")
	}
	var action DebuggerActionResult
	if err := json.Unmarshal(result, &action); err == nil {
		t.Fatal("missing accepted field was accepted")
	}
	action = DebuggerActionResult{Accepted: true, State: "suspended", Running: true, Suspended: true}
	if err := action.Validate(); err == nil {
		t.Fatal("inconsistent action flags were accepted")
	}
}
