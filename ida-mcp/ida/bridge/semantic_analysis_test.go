package bridge

import (
	"context"
	"encoding/json"
	"ida-mcp/ida/rpc"
	"os"
	"path/filepath"
	"testing"
)

func semanticFixture(t *testing.T, name string) ArgumentAnalysisResult {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "protocol", "testdata", "valid", "response-analysis-"+name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Result ArgumentAnalysisResult `json:"result"`
	}
	if err = json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	return wire.Result
}
func TestSemanticStaticClientsAndResultValidation(t *testing.T) {
	p := ArgumentAnalysisParams{CallAddress: rpc.Address(0x1020), MaxNodes: 200, MaxWork: 20000, MaxGuards: 32}
	instance := testInstanceDescriptor()
	for _, name := range []string{"trace_argument", "guard_evidence"} {
		stem := "trace-argument"
		if name == "guard_evidence" {
			stem = "guard-evidence"
		}
		result := semanticFixture(t, stem)
		client := functionAnalysisTestClient(t, instance, "analysis."+name, result)
		var err error
		if name == "trace_argument" {
			_, err = client.TraceArgument(context.Background(), instance, p)
		} else {
			_, err = client.GuardEvidence(context.Background(), instance, p)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	mutations := []func(*ArgumentAnalysisResult){
		func(r *ArgumentAnalysisResult) { r.Model = "xref_bfs" },
		func(r *ArgumentAnalysisResult) { id := uint32(999); r.Root = &id },
		func(r *ArgumentAnalysisResult) { r.Nodes[0].ID = 99 },
		func(r *ArgumentAnalysisResult) { r.Guards[0].Operands = []uint32{999} },
		func(r *ArgumentAnalysisResult) { r.CFGComplete = false },
		func(r *ArgumentAnalysisResult) { r.Truncated = true },
		func(r *ArgumentAnalysisResult) { r.VisitedStates = 100001 },
	}
	for _, mutate := range mutations {
		result := semanticFixture(t, "guard-evidence")
		mutate(&result)
		if ValidateArgumentAnalysis(result, p, true) == nil {
			t.Fatal("malformed semantic evidence was accepted")
		}
	}
	result := semanticFixture(t, "guard-evidence")
	if result.Nodes[1].Value != "0xffffffffffffffff" {
		t.Fatal("64-bit constant precision was lost")
	}
	result.Status = "partial"
	result.Truncated = true
	result.Root = nil
	result.Guards = []GuardEvidence{}
	result.Limitations = []string{"work_budget"}
	if err := ValidateArgumentAnalysis(result, p, false); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	data, _ := json.Marshal(result)
	json.Unmarshal(data, &raw)
	raw["unexpected"] = true
	client := functionAnalysisTestClient(t, instance, "analysis.trace_argument", raw)
	if _, err := client.TraceArgument(context.Background(), instance, p); err == nil {
		t.Fatal("unknown response field accepted")
	}
}
