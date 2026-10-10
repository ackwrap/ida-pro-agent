package mcpserver

import (
	"context"
	"testing"

	"ida-mcp/ida"
)

func TestFunctionAnalysisToolsSuccessDefaultsAndPagination(t *testing.T) {
	backend := &fakeBackend{}
	session := connectTestClient(t, backend)
	var disassembly functionDisassemblyOutput
	callTool(t, session, ToolFunctionDisassemble, map[string]any{
		"instanceId": testInstanceA, "address": "0x401000",
	}, &disassembly)
	if len(disassembly.Items) != 1 || disassembly.NextOffset == nil || *disassembly.NextOffset != 1 {
		t.Fatalf("disassembly = %+v", disassembly)
	}
	var blocks functionBasicBlocksOutput
	callTool(t, session, ToolFunctionBasicBlocks, map[string]any{
		"instanceId": testInstanceA, "address": "0x401000", "offset": 4, "limit": 7,
	}, &blocks)
	if len(blocks.Items) != 1 || blocks.Items[0].Type != "return" {
		t.Fatalf("basic blocks = %+v", blocks)
	}
	var callees functionCalleesOutput
	callTool(t, session, ToolFunctionCallees, map[string]any{
		"instanceId": testInstanceA, "address": "0x401000",
	}, &callees)
	if len(callees.Items) != 1 || callees.Items[0].Name != "callee" {
		t.Fatalf("callees = %+v", callees)
	}
	backend.mutex.Lock()
	seen := append([]ida.FunctionPageParams(nil), backend.analysisParams...)
	backend.mutex.Unlock()
	if len(seen) != 3 || seen[0].Offset != 0 || seen[0].Limit != 20 ||
		seen[1].Offset != 4 || seen[1].Limit != 7 {
		t.Fatalf("analysis params = %+v", seen)
	}
}

func TestFunctionAnalysisSchemasRejectUnknownAndBoundaries(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})
	for _, test := range []struct {
		name      string
		arguments map[string]any
	}{
		{ToolFunctionDisassemble, map[string]any{"instanceId": testInstanceA, "address": "0x401000", "extra": true}},
		{ToolFunctionBasicBlocks, map[string]any{"instanceId": testInstanceA, "address": "401000"}},
		{ToolFunctionCallees, map[string]any{"instanceId": testInstanceA, "address": "0x401000", "offset": 1_000_001}},
		{ToolFunctionDisassemble, map[string]any{"instanceId": testInstanceA, "address": "0x401000", "limit": 0}},
		{ToolFunctionBasicBlocks, map[string]any{"instanceId": testInstanceA, "address": "0x401000", "limit": 101}},
	} {
		if !callToolRejected(t, session, test.name, test.arguments) {
			t.Fatalf("invalid call accepted: %s %+v", test.name, test.arguments)
		}
	}
}

type maliciousAnalysisBackend struct{ *fakeBackend }

func (*maliciousAnalysisBackend) FunctionCallees(
	context.Context, string, ida.FunctionPageParams,
) (ida.FunctionCalleesResult, error) {
	return ida.FunctionCalleesResult{
		EntryAddress: 0x401000,
		Items:        []ida.FunctionCallee{{Address: 0x402000, Name: "", Internal: true}},
	}, nil
}

func TestFunctionAnalysisToolRejectsMaliciousBackendResponse(t *testing.T) {
	session := connectTestClient(t, &maliciousAnalysisBackend{fakeBackend: &fakeBackend{}})
	result := callToolResult(t, session, ToolFunctionCallees, map[string]any{
		"instanceId": testInstanceA, "address": "0x401000",
	})
	if !result.IsError {
		t.Fatal("malicious backend response was accepted")
	}
}

type budgetAnalysisBackend struct{ *fakeBackend }

func (*budgetAnalysisBackend) FunctionBasicBlocks(
	_ context.Context, _ string, params ida.FunctionPageParams,
) (ida.FunctionBasicBlocksResult, error) {
	edges := make([]ida.Address, 64)
	for index := range edges {
		edges[index] = ida.Address(uint64(0xffff_ffff_ffff_0000) + uint64(index))
	}
	items := make([]ida.FunctionBasicBlock, 100)
	for index := range items {
		start := ida.Address(0x1000 + index*2)
		items[index] = ida.FunctionBasicBlock{
			Start: start, End: start + 1, Type: ida.BasicBlockNormal,
			Successors:   append([]ida.Address(nil), edges...),
			Predecessors: append([]ida.Address(nil), edges...),
		}
	}
	return ida.FunctionBasicBlocksResult{EntryAddress: params.Address, Items: items}, nil
}

func TestFunctionAnalysisToolEnforcesTotalOutputBudget(t *testing.T) {
	session := connectTestClient(t, &budgetAnalysisBackend{fakeBackend: &fakeBackend{}})
	result := callToolResult(t, session, ToolFunctionBasicBlocks, map[string]any{
		"instanceId": testInstanceA, "address": "0x401000", "limit": 100,
	})
	if !result.IsError {
		t.Fatal("oversized function analysis output was accepted")
	}
}

func TestFunctionAnalysisDomainMapping(t *testing.T) {
	for _, method := range []string{
		ToolFunctionDisassemble, ToolFunctionBasicBlocks, ToolFunctionCallees,
	} {
		if domain, ok := DomainToolForMethod(method); !ok || domain != ToolDomainFunctions {
			t.Fatalf("mapping %s = %q, %t", method, domain, ok)
		}
	}
}
