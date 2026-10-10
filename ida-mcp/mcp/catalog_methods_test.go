package mcpserver

import (
	"context"
	"strings"
	"testing"

	"ida-mcp/ida"
)

func TestCatalogMethodsAreCallableWithTypedSuccessResults(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})
	tests := []struct {
		method string
		input  map[string]any
	}{
		{ToolSystemPing, map[string]any{"instanceId": testInstanceA}},
		{ToolSystemMethods, map[string]any{"instanceId": testInstanceA}},
		{ToolInstanceInfo, map[string]any{"instanceId": testInstanceA}},
		{ToolDatabaseSurvey, map[string]any{"instanceId": testInstanceA}},
		{ToolDatabaseSave, map[string]any{"instanceId": testInstanceA, "compact": true, "backup": true}},
		{ToolFunctionCallers, map[string]any{"instanceId": testInstanceA, "address": "0x401000"}},
		{ToolFunctionCallGraph, map[string]any{"instanceId": testInstanceA, "roots": []any{"0x401000"}, "maxDepth": 0}},
		{ToolFunctionProfile, map[string]any{"instanceId": testInstanceA, "name": "main"}},
		{ToolFunctionExport, map[string]any{"instanceId": testInstanceA, "addresses": []any{"0x401000"}, "format": "prototypes"}},
		{ToolFunctionAnalyze, map[string]any{"instanceId": testInstanceA, "addresses": []any{"0x401000"}, "sections": []any{"overview"}}},
		{ToolFunctionAnalyzeBatch, map[string]any{"instanceId": testInstanceA, "addresses": []any{"0x401000"}, "sections": []any{"metrics"}}},
		{ToolFunctionStackFrame, map[string]any{"instanceId": testInstanceA, "address": "0x401000"}},
	}
	for _, test := range tests {
		t.Run(test.method, func(t *testing.T) {
			result := callToolResult(t, session, test.method, test.input)
			if result.IsError {
				t.Fatalf("%s returned error: %+v", test.method, result.Content)
			}
		})
	}
}

func TestCatalogMethodSchemasAreStrictAndMatchPluginBounds(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})
	invalid := []struct {
		method string
		input  map[string]any
	}{
		{ToolSystemPing, map[string]any{"instanceId": testInstanceA, "method": "arbitrary.rpc"}},
		{ToolDatabaseSurvey, map[string]any{"instanceId": testInstanceA, "budget": 2}},
		{ToolDatabaseSave, map[string]any{"instanceId": testInstanceA, "target": "D:\\forbidden.i64"}},
		{ToolFunctionCallers, map[string]any{"instanceId": testInstanceA, "address": "0x401000", "offset": 1_000_001}},
		{ToolFunctionCallGraph, map[string]any{"instanceId": testInstanceA, "roots": []any{}, "maxNodes": 501}},
		{ToolFunctionProfile, map[string]any{"instanceId": testInstanceA, "minSize": 100, "maxSize": 10}},
		{ToolFunctionProfile, map[string]any{"instanceId": testInstanceA, "sampleLimit": 8, "limit": 50}},
		{ToolFunctionExport, map[string]any{"instanceId": testInstanceA, "addresses": []any{"0x401000"}, "format": "raw"}},
		{ToolFunctionAnalyze, map[string]any{"instanceId": testInstanceA, "addresses": []any{"0x401000"}, "sections": []any{"overview", "overview"}}},
		{ToolFunctionAnalyzeBatch, map[string]any{"instanceId": testInstanceA, "addresses": []any{"0x401000"}, "decompileBytes": 65537}},
		{ToolFunctionStackFrame, map[string]any{"instanceId": testInstanceA, "address": "401000"}},
	}
	for _, test := range invalid {
		if !callToolRejected(t, session, test.method, test.input) {
			t.Fatalf("invalid %s call accepted: %+v", test.method, test.input)
		}
	}
}

func TestFunctionProfileCursorAuthenticationAndBinding(t *testing.T) {
	backend := &fakeBackend{}
	session := connectTestClient(t, backend)
	input := map[string]any{"instanceId": testInstanceA, "name": "Main", "limit": 1, "includePrototype": true}
	var first ida.FunctionProfileResult
	callTool(t, session, ToolFunctionProfile, input, &first)
	if first.NextCursor == nil || !strings.HasPrefix(*first.NextCursor, "fp2.") {
		t.Fatalf("profile cursor = %+v", first.NextCursor)
	}
	continuation := cloneArguments(input)
	continuation["cursor"] = *first.NextCursor
	var second ida.FunctionProfileResult
	callTool(t, session, ToolFunctionProfile, continuation, &second)
	backend.mutex.Lock()
	seen := append([]ida.FunctionProfileParams(nil), backend.profileParams...)
	backend.mutex.Unlock()
	if len(seen) != 2 || !strings.HasPrefix(seen[1].Cursor, "fp1.") {
		t.Fatalf("internal profile cursors = %+v", seen)
	}
	for _, rejected := range []map[string]any{
		{"instanceId": testInstanceA, "name": "Main", "limit": 1, "includePrototype": true, "cursor": tamper(*first.NextCursor)},
		{"instanceId": testInstanceB, "name": "Main", "limit": 1, "includePrototype": true, "cursor": *first.NextCursor},
		{"instanceId": testInstanceA, "name": "Other", "limit": 1, "includePrototype": true, "cursor": *first.NextCursor},
	} {
		if !callToolRejected(t, session, ToolFunctionProfile, rejected) {
			t.Fatalf("invalid profile cursor accepted: %+v", rejected)
		}
	}
	if !callToolRejected(t, session, ToolFunctionSearch, map[string]any{
		"instanceId": testInstanceA, "name": "Main", "limit": 1, "cursor": *first.NextCursor,
	}) {
		t.Fatal("profile cursor was accepted by function.search")
	}
	restarted := connectTestClient(t, backend)
	if !callToolRejected(t, restarted, ToolFunctionProfile, continuation) {
		t.Fatal("profile cursor survived Gateway restart")
	}
}

type catalogPathBackend struct{ *fakeBackend }

func (*catalogPathBackend) InstanceInfo(_ context.Context, instanceID string) (ida.InstanceInfoResult, error) {
	return ida.InstanceInfoResult{InstanceID: instanceID, Database: `D:\private\sample.i64`, InputFile: `/tmp/input.exe`}, nil
}

func TestInstanceInfoReturnsOnlySafeBasenames(t *testing.T) {
	session := connectTestClient(t, &catalogPathBackend{fakeBackend: &fakeBackend{}})
	var result ida.InstanceInfoResult
	callTool(t, session, ToolInstanceInfo, map[string]any{"instanceId": testInstanceA}, &result)
	if result.Database != "sample.i64" || result.InputFile != "input.exe" || strings.ContainsAny(result.Database+result.InputFile, `/\`) {
		t.Fatalf("instance.info leaked a path: %+v", result)
	}
}

type catalogBudgetBackend struct{ *fakeBackend }

func (*catalogBudgetBackend) FunctionExport(_ context.Context, _ string, params ida.FunctionExportParams) (ida.FunctionExportResult, error) {
	return ida.FunctionExportResult{Format: params.Format, Content: strings.Repeat("x", maxToolItemOutputBytes+1), OriginalSize: maxToolItemOutputBytes + 1}, nil
}

func TestCatalogMethodOutputBudgetIsEnforced(t *testing.T) {
	session := connectTestClient(t, &catalogBudgetBackend{fakeBackend: &fakeBackend{}})
	if result := callToolResult(t, session, ToolFunctionExport, map[string]any{
		"instanceId": testInstanceA, "addresses": []any{"0x401000"}, "format": "json", "maxBytes": 65536,
	}); !result.IsError {
		t.Fatal("oversized catalog output was accepted")
	}
}

func cloneArguments(input map[string]any) map[string]any {
	result := make(map[string]any, len(input)+1)
	for key, value := range input {
		result[key] = value
	}
	return result
}
