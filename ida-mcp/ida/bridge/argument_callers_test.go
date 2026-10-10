package bridge

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func callerFixture(t *testing.T) ArgumentCallersResult {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "protocol", "testdata", "valid", "response-analysis-trace-argument-callers.json"))
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Result ArgumentCallersResult `json:"result"`
	}
	if err = json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	return response.Result
}
func TestCallerTraceClientAndGraphValidation(t *testing.T) {
	p := ArgumentCallersParams{CallAddress: 0x1020, MaxDepth: 2, MaxContexts: 16, MaxCallers: 8, MaxNodes: 1000, MaxWork: 100000}
	instance := testInstanceDescriptor()
	c := functionAnalysisTestClient(t, instance, "analysis.trace_argument_callers", callerFixture(t))
	r, err := c.TraceArgumentCallers(context.Background(), instance, p)
	if err != nil || r.Contexts[1].Trace.Nodes[0].Value != "0xffffffffffffffff" {
		t.Fatalf("caller trace failed: %v", err)
	}
	for _, mutate := range []func(*ArgumentCallersResult){
		func(r *ArgumentCallersResult) { r.Links[0].ToContext = 9 },
		func(r *ArgumentCallersResult) { r.Links[0].FromContext = 1 },
		func(r *ArgumentCallersResult) { r.Links[0].ParameterNode = 99 },
		func(r *ArgumentCallersResult) { r.Contexts[1].Depth = 2 },
		func(r *ArgumentCallersResult) { r.Contexts[1].Trace.ArgumentIndex = 1 },
		func(r *ArgumentCallersResult) { r.TotalNodes = 9 },
		func(r *ArgumentCallersResult) { r.Status = "complete" },
		func(r *ArgumentCallersResult) { r.Links = nil },
		func(r *ArgumentCallersResult) { r.VisitedWork = 1 },
		func(r *ArgumentCallersResult) { r.Limitations = []string{} },
		func(r *ArgumentCallersResult) { r.Contexts[0].Trace.Root = nil; r.Contexts[0].Trace.Status = "partial" },
		func(r *ArgumentCallersResult) {
			r.Boundaries = []ArgumentBoundary{{Context: 9, Reason: "recursive_call"}}
		},
	} {
		r := callerFixture(t)
		mutate(&r)
		if ValidateArgumentCallers(r, p) == nil {
			t.Fatal("invalid context graph accepted")
		}
	}
	var raw map[string]any
	data, _ := json.Marshal(callerFixture(t))
	json.Unmarshal(data, &raw)
	raw["unexpected"] = true
	c = functionAnalysisTestClient(t, instance, "analysis.trace_argument_callers", raw)
	if _, err = c.TraceArgumentCallers(context.Background(), instance, p); err == nil {
		t.Fatal("unknown response field accepted")
	}
	p.MaxDepth = 6
	if _, err = c.TraceArgumentCallers(context.Background(), instance, p); err == nil {
		t.Fatal("invalid request accepted")
	}
}
