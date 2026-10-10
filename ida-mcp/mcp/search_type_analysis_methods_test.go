package mcpserver

import (
	"context"
	"strings"
	"testing"

	"ida-mcp/ida"
)

func TestRemainingPluginMethodsAreCallable(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})
	tests := []struct {
		method string
		input  map[string]any
	}{
		{ToolMemorySearchBytes, map[string]any{"pattern": "90", "start": "0x401000", "end": "0x402000"}},
		{ToolInstructionSearch, map[string]any{"start": "0x401000", "end": "0x402000", "mnemonic": "nop"}},
		{ToolInstructionQuery, map[string]any{"start": "0x401000", "end": "0x402000", "operand": "eax"}},
		{ToolListingSearch, map[string]any{"start": "0x401000", "end": "0x402000", "query": "nop"}},
		{ToolListingSearchText, map[string]any{"start": "0x401000", "end": "0x402000", "query": "sample"}},
		{ToolStringSearchRegex, map[string]any{"pattern": "sample"}},
		{ToolSignatureMake, map[string]any{"address": "0x401000"}},
		{ToolSignatureXrefs, map[string]any{"address": "0x401000"}},
		{ToolXrefStructField, map[string]any{"type": "sample_t", "field": "value"}},
		{ToolGlobalValue, map[string]any{"name": "global_value"}},
		{ToolTypeSearch, map[string]any{"name": "sample"}}, {ToolTypeQuery, map[string]any{"kind": "struct"}},
		{ToolTypeGet, map[string]any{"name": "sample_t"}},
		{ToolTypeReadValue, map[string]any{"address": "0x403000", "name": "sample_t"}},
		{ToolTypeReadStruct, map[string]any{"address": "0x403000"}},
		{ToolTypeInfer, map[string]any{"address": "0x403000"}},
		{ToolAnalysisComponent, map[string]any{"roots": []any{"0x401000"}}},
		{ToolAnalysisTraceDataFlow, map[string]any{"address": "0x401000"}},
	}
	for _, test := range tests {
		t.Run(test.method, func(t *testing.T) {
			test.input["instanceId"] = testInstanceA
			result := callToolResult(t, session, test.method, test.input)
			if result.IsError {
				t.Fatalf("%s returned error: %+v", test.method, result.Content)
			}
		})
	}
}

func TestRemainingMethodSchemasRejectUnknownAndBoundaryValues(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})
	invalid := []struct {
		method string
		input  map[string]any
	}{
		{ToolMemorySearchBytes, map[string]any{"pattern": "90", "start": "0x401000", "end": "0x402000", "unknown": true}},
		{ToolInstructionSearch, map[string]any{"start": "0x401000", "end": "0x402000", "limit": 101}},
		{ToolListingSearchText, map[string]any{"start": "0x401000", "end": "0x402000", "query": "a", "regex": "a"}},
		{ToolStringSearchRegex, map[string]any{"pattern": "a", "minLength": 4097}},
		{ToolSignatureXrefs, map[string]any{"address": "0x401000", "top": 33}},
		{ToolGlobalValue, map[string]any{"address": "0x401000", "name": "both"}},
		{ToolTypeSearch, map[string]any{"ordinal": 1000001}},
		{ToolTypeReadValue, map[string]any{"address": "0x401000", "name": "sample_t", "maxBytes": 65537}},
		{ToolAnalysisComponent, map[string]any{"roots": []any{"0x401000"}, "maxNodes": 201}},
		{ToolAnalysisTraceDataFlow, map[string]any{"address": "0x401000", "direction": "magic"}},
	}
	for _, test := range invalid {
		test.input["instanceId"] = testInstanceA
		if !callToolRejected(t, session, test.method, test.input) {
			t.Fatalf("invalid %s accepted: %+v", test.method, test.input)
		}
	}
}

func TestSearchCursorsAuthenticateRestartAndPublicMethod(t *testing.T) {
	backend := &fakeBackend{}
	session := connectTestClient(t, backend)
	base := map[string]any{"instanceId": testInstanceA, "start": "0x401000", "end": "0x402000", "mnemonic": "NOP", "limit": 1}
	var first ida.InstructionSearchResult
	callTool(t, session, ToolInstructionSearch, base, &first)
	if first.NextCursor == nil || !strings.HasPrefix(*first.NextCursor, "in2.") {
		t.Fatalf("cursor = %+v", first.NextCursor)
	}
	continuation := cloneArguments(base)
	continuation["cursor"] = *first.NextCursor
	var second ida.InstructionSearchResult
	callTool(t, session, ToolInstructionSearch, continuation, &second)
	backend.mutex.Lock()
	seen := append([]ida.InstructionSearchParams(nil), backend.instructionParams...)
	backend.mutex.Unlock()
	if len(seen) != 2 || !strings.HasPrefix(seen[1].Cursor, "iq1.") {
		t.Fatalf("internal cursors = %+v", seen)
	}
	for _, rejected := range []struct {
		method string
		input  map[string]any
	}{
		{ToolInstructionSearch, map[string]any{"instanceId": testInstanceA, "start": "0x401000", "end": "0x402000", "mnemonic": "NOP", "limit": 1, "cursor": tamper(*first.NextCursor)}},
		{ToolInstructionQuery, continuation},
		{ToolInstructionSearch, map[string]any{"instanceId": testInstanceB, "start": "0x401000", "end": "0x402000", "mnemonic": "NOP", "limit": 1, "cursor": *first.NextCursor}},
		{ToolInstructionSearch, map[string]any{"instanceId": testInstanceA, "start": "0x401000", "end": "0x402000", "mnemonic": "mov", "limit": 1, "cursor": *first.NextCursor}},
	} {
		if !callToolRejected(t, session, rejected.method, rejected.input) {
			t.Fatalf("cursor accepted by %s", rejected.method)
		}
	}
	restarted := connectTestClient(t, backend)
	if !callToolRejected(t, restarted, ToolInstructionSearch, continuation) {
		t.Fatal("cursor survived restart")
	}
}

func TestListingAndRegexCursorsAreAuthenticatedAndBound(t *testing.T) {
	backend := &fakeBackend{}
	session := connectTestClient(t, backend)
	tests := []struct {
		method string
		base   map[string]any
	}{
		{ToolListingSearchText, map[string]any{"instanceId": testInstanceA, "start": "0x401000", "end": "0x402000", "query": "Sample", "limit": 1}},
		{ToolStringSearchRegex, map[string]any{"instanceId": testInstanceA, "pattern": "Sample", "minLength": 1, "limit": 1}},
	}
	var cursors []string
	for _, test := range tests {
		var first struct {
			NextCursor *string `json:"nextCursor"`
		}
		callTool(t, session, test.method, test.base, &first)
		if first.NextCursor == nil {
			t.Fatalf("%s returned no cursor", test.method)
		}
		cursors = append(cursors, *first.NextCursor)
		continuation := cloneArguments(test.base)
		continuation["cursor"] = *first.NextCursor
		var second struct {
			NextCursor *string `json:"nextCursor"`
		}
		callTool(t, session, test.method, continuation, &second)
		tampered := cloneArguments(test.base)
		tampered["cursor"] = tamper(*first.NextCursor)
		if !callToolRejected(t, session, test.method, tampered) {
			t.Fatalf("%s accepted tampering", test.method)
		}
		changed := cloneArguments(test.base)
		changed["cursor"] = *first.NextCursor
		if test.method == ToolListingSearchText {
			changed["query"] = "Other"
		} else {
			changed["pattern"] = "Other"
		}
		if !callToolRejected(t, session, test.method, changed) {
			t.Fatalf("%s accepted changed filters", test.method)
		}
		restarted := connectTestClient(t, backend)
		if !callToolRejected(t, restarted, test.method, continuation) {
			t.Fatalf("%s cursor survived restart", test.method)
		}
	}
	cross := cloneArguments(tests[1].base)
	cross["cursor"] = cursors[0]
	if !callToolRejected(t, session, ToolStringSearchRegex, cross) {
		t.Fatal("listing cursor was accepted by string.search_regex")
	}
}

type remainingBudgetBackend struct{ *fakeBackend }

func (*remainingBudgetBackend) GetType(context.Context, string, ida.TypeGetParams) (ida.TypeDetails, error) {
	result := fakeTypeDetails()
	result.Declaration = strings.Repeat("x", maxToolOutputBytes+1)
	return result, nil
}
func TestRemainingMethodOutputBudget(t *testing.T) {
	session := connectTestClient(t, &remainingBudgetBackend{fakeBackend: &fakeBackend{}})
	if result := callToolResult(t, session, ToolTypeGet, map[string]any{"instanceId": testInstanceA, "name": "sample_t"}); !result.IsError {
		t.Fatal("oversized type output accepted")
	}
}
