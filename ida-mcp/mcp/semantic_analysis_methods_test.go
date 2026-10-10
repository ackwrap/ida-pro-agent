package mcpserver

import (
	"context"
	"ida-mcp/ida"
	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
	"testing"
)

type semanticBackend struct {
	*fakeBackend
	calls  int
	broken bool
}

func (b *semanticBackend) TraceArgument(_ context.Context, _ string, p ida.ArgumentAnalysisParams) (ida.ArgumentAnalysisResult, error) {
	b.calls++
	root := uint32(0)
	model := "microcode_reaching_definitions"
	if b.broken {
		model = "xref_bfs"
	}
	return ida.ArgumentAnalysisResult{EntryAddress: rpc.Address(0x1000), CallAddress: rpc.Address(p.CallAddress), ArgumentIndex: p.ArgumentIndex, ArgumentCount: 3,
		Model: model, Maturity: "MMAT_CALLS", Scope: "function", Status: "complete", CFGComplete: true, Root: &root,
		Nodes: []bridge.ArgumentNode{{ID: 0, Kind: "constant", Bits: 64, Value: "0xffffffffffffffff"}}, Edges: []bridge.ArgumentEdge{}, Guards: []bridge.GuardEvidence{}, Limitations: []string{}, VisitedStates: 1}, nil
}
func (b *semanticBackend) GuardEvidence(ctx context.Context, id string, p ida.ArgumentAnalysisParams) (ida.ArgumentAnalysisResult, error) {
	return b.TraceArgument(ctx, id, p)
}
func TestSemanticMethodsUseTypedDispatch(t *testing.T) {
	backend := &semanticBackend{fakeBackend: &fakeBackend{}}
	session := connectTestClient(t, backend)
	for _, method := range []string{ToolTraceArgument, ToolGuardEvidence} {
		params := map[string]any{"instanceId": testInstanceA, "callAddress": "0x1020", "argumentIndex": 2}
		var result ida.ArgumentAnalysisResult
		callTool(t, session, method, params, &result)
		if result.ArgumentIndex != 2 || result.CallAddress != 0x1020 || result.Nodes[0].Value != "0xffffffffffffffff" {
			t.Fatal("semantic arguments or evidence corrupted")
		}
		for _, bad := range []map[string]any{
			{"callAddress": "0x1020"},
			{"callAddress": "0x1020", "argumentIndex": -1},
			{"callAddress": "0x1020", "argumentIndex": 0, "maxWork": 0},
			{"callAddress": "0x1020", "argumentIndex": 0, "maxNodes": 1001},
			{"callAddress": "0x1020", "argumentIndex": 0, "extra": true},
		} {
			bad["instanceId"] = testInstanceA
			if !callToolRejected(t, session, method, bad) {
				t.Fatal("invalid semantic request accepted")
			}
		}
	}
	if backend.calls != 2 {
		t.Fatal("rejected request reached backend")
	}
	backend.broken = true
	if !callToolResult(t, session, ToolTraceArgument, map[string]any{"instanceId": testInstanceA, "callAddress": "0x1020", "argumentIndex": 0}).IsError {
		t.Fatal("wrong semantic model escaped validation")
	}
}
