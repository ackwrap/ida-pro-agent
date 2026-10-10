package mcpserver

import (
	"context"
	"ida-mcp/ida"
	"ida-mcp/ida/bridge"
	"testing"
)

type callersBackend struct {
	*semanticBackend
	request ida.ArgumentCallersParams
}

func (b *callersBackend) TraceArgumentCallers(ctx context.Context, id string, p ida.ArgumentCallersParams) (ida.ArgumentCallersResult, error) {
	b.request = p
	local, err := b.TraceArgument(ctx, id, ida.ArgumentAnalysisParams{CallAddress: p.CallAddress, ArgumentIndex: p.ArgumentIndex})
	r := ida.ArgumentCallersResult{CallAddress: local.CallAddress, ArgumentIndex: p.ArgumentIndex, Model: "microcode_caller_contexts", Scope: "known_direct_callers", Status: "complete", Contexts: []bridge.ArgumentContext{{ID: 0, Depth: 0, Trace: local}}, Links: []bridge.ArgumentContextLink{}, Boundaries: []bridge.ArgumentBoundary{}, Limitations: []string{}, VisitedWork: 2, TotalNodes: 1}
	if b.broken {
		r.TotalNodes = 100
	}
	return r, err
}
func TestCallerTraceTypedDispatchAndBounds(t *testing.T) {
	b := &callersBackend{semanticBackend: &semanticBackend{fakeBackend: &fakeBackend{}}}
	session := connectTestClient(t, b)
	input := map[string]any{"instanceId": testInstanceA, "callAddress": "0x1020", "argumentIndex": 2}
	var r ida.ArgumentCallersResult
	callTool(t, session, ToolTraceArgumentCallers, input, &r)
	if b.request.MaxDepth != 2 || b.request.MaxContexts != 16 || b.request.MaxCallers != 8 || b.request.MaxWork != 100000 {
		t.Fatal("caller defaults")
	}
	input["maxDepth"] = 0
	callTool(t, session, ToolTraceArgumentCallers, input, &r)
	if b.request.MaxDepth != 0 {
		t.Fatal("explicit zero depth lost")
	}
	for field, value := range map[string]any{"maxDepth": 6, "maxContexts": 0, "maxCallers": 33, "maxNodes": 4001, "maxWork": 1000001, "extra": true} {
		invalid := map[string]any{"instanceId": testInstanceA, "callAddress": "0x1020", "argumentIndex": 0, field: value}
		if !callToolRejected(t, session, ToolTraceArgumentCallers, invalid) {
			t.Fatalf("accepted %s", field)
		}
	}
	if b.calls != 2 {
		t.Fatal("invalid caller request reached backend")
	}
	b.broken = true
	if !callToolResult(t, session, ToolTraceArgumentCallers, input).IsError {
		t.Fatal("invalid caller result escaped validation")
	}
}
