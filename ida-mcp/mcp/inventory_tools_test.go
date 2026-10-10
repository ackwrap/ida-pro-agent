package mcpserver

import (
	"context"
	"strings"
	"testing"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type emptyInventoryPageBackend struct{ *fakeBackend }

func (*emptyInventoryPageBackend) DatabaseSegments(
	context.Context, string, ida.SegmentListParams,
) (ida.SegmentListResult, error) {
	cursor := "ds1.0000000000000001.0000000000001000.0000000000000003"
	return ida.SegmentListResult{Items: []ida.SegmentInfo{}, NextCursor: &cursor, HasMore: true}, nil
}

func (*emptyInventoryPageBackend) SearchStrings(
	context.Context, string, ida.StringSearchParams,
) (ida.StringSearchResult, error) {
	cursor := "ss1.0000000000000001.0000000000001000.0000000000000003"
	return ida.StringSearchResult{Items: []ida.StringInfo{}, NextCursor: &cursor, HasMore: true}, nil
}

func (*emptyInventoryPageBackend) SymbolImports(
	context.Context, string, ida.ImportListParams,
) (ida.ImportListResult, error) {
	cursor := "si1.0000000000000001.0000000000001000.0000000000000003"
	return ida.ImportListResult{Items: []ida.ImportInfo{}, NextCursor: &cursor, HasMore: true}, nil
}

type inventoryBudgetBackend struct{ *fakeBackend }

func (*inventoryBudgetBackend) SearchStrings(
	context.Context, string, ida.StringSearchParams,
) (ida.StringSearchResult, error) {
	items := make([]ida.StringInfo, 100)
	for index := range items {
		items[index] = ida.StringInfo{
			Address: ida.Address(0x1000 + index), Length: 4096, Encoding: "UTF-8",
			Value: strings.Repeat("x", 4096), OriginalSize: 4096,
		}
	}
	return ida.StringSearchResult{Items: items}, nil
}

func TestInventoryToolsForwardNormalizedFiltersAndDefaults(t *testing.T) {
	backend := &fakeBackend{}
	session := connectTestClient(t, backend)
	var segments databaseSegmentsOutput
	callTool(t, session, ToolDatabaseSegments, map[string]any{
		"instanceId": testInstanceA, "name": "TeXt",
	}, &segments)
	var stringsOutput stringSearchOutput
	callTool(t, session, ToolStringSearch, map[string]any{
		"instanceId": testInstanceA, "query": "HeLLo",
	}, &stringsOutput)
	var imports symbolImportsOutput
	callTool(t, session, ToolSymbolImports, map[string]any{
		"instanceId": testInstanceA, "module": "KERNEL32", "name": "File",
	}, &imports)

	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if len(backend.segmentParams) != 1 || backend.segmentParams[0].Name != "TeXt" || backend.segmentParams[0].Limit != 20 {
		t.Fatalf("segment params = %+v", backend.segmentParams)
	}
	if len(backend.stringParams) != 1 || backend.stringParams[0].Query != "HeLLo" ||
		backend.stringParams[0].MinLength != 4 || backend.stringParams[0].Limit != 20 {
		t.Fatalf("string params = %+v", backend.stringParams)
	}
	if len(backend.importParams) != 1 || backend.importParams[0].Module != "KERNEL32" ||
		backend.importParams[0].Name != "File" || backend.importParams[0].Limit != 20 {
		t.Fatalf("import params = %+v", backend.importParams)
	}
}

func TestInventoryToolsPreserveSelectiveEmptyContinuationPages(t *testing.T) {
	session := connectTestClient(t, &emptyInventoryPageBackend{fakeBackend: &fakeBackend{}})
	var segments databaseSegmentsOutput
	callTool(t, session, ToolDatabaseSegments, map[string]any{"instanceId": testInstanceA}, &segments)
	if len(segments.Items) != 0 || !segments.HasMore || segments.NextCursor == nil {
		t.Fatalf("segments = %+v", segments)
	}
	var stringsOutput stringSearchOutput
	callTool(t, session, ToolStringSearch, map[string]any{"instanceId": testInstanceA}, &stringsOutput)
	if len(stringsOutput.Items) != 0 || !stringsOutput.HasMore || stringsOutput.NextCursor == nil {
		t.Fatalf("strings = %+v", stringsOutput)
	}
	var imports symbolImportsOutput
	callTool(t, session, ToolSymbolImports, map[string]any{"instanceId": testInstanceA}, &imports)
	if len(imports.Items) != 0 || !imports.HasMore || imports.NextCursor == nil {
		t.Fatalf("imports = %+v", imports)
	}
}

func TestInventoryPublicCursorsBindAllNormalizedFilters(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})

	var segments databaseSegmentsOutput
	callTool(t, session, ToolDatabaseSegments, map[string]any{
		"instanceId": testInstanceA, "name": "TeXt", "limit": 1,
	}, &segments)
	assertCursorCases(t, session, ToolDatabaseSegments, *segments.NextCursor,
		map[string]any{"instanceId": testInstanceA, "name": "text", "limit": 1},
		[]map[string]any{
			{"instanceId": testInstanceB, "name": "text", "limit": 1},
			{"instanceId": testInstanceA, "name": "data", "limit": 1},
		})

	var stringsOutput stringSearchOutput
	callTool(t, session, ToolStringSearch, map[string]any{
		"instanceId": testInstanceA, "query": "HeLLo", "minLength": 4, "limit": 1,
	}, &stringsOutput)
	assertCursorCases(t, session, ToolStringSearch, *stringsOutput.NextCursor,
		map[string]any{"instanceId": testInstanceA, "query": "hello", "minLength": 4, "limit": 1},
		[]map[string]any{
			{"instanceId": testInstanceB, "query": "hello", "minLength": 4, "limit": 1},
			{"instanceId": testInstanceA, "query": "other", "minLength": 4, "limit": 1},
			{"instanceId": testInstanceA, "query": "hello", "minLength": 5, "limit": 1},
		})

	var imports symbolImportsOutput
	callTool(t, session, ToolSymbolImports, map[string]any{
		"instanceId": testInstanceA, "module": "KERNEL32", "name": "File", "limit": 1,
	}, &imports)
	assertCursorCases(t, session, ToolSymbolImports, *imports.NextCursor,
		map[string]any{"instanceId": testInstanceA, "module": "kernel32", "name": "file", "limit": 1},
		[]map[string]any{
			{"instanceId": testInstanceB, "module": "kernel32", "name": "file", "limit": 1},
			{"instanceId": testInstanceA, "module": "user32", "name": "file", "limit": 1},
			{"instanceId": testInstanceA, "module": "kernel32", "name": "close", "limit": 1},
		})
}

func TestInventoryPublicCursorsExpireAfterRestart(t *testing.T) {
	firstSession := connectTestClient(t, &fakeBackend{})
	var first stringSearchOutput
	callTool(t, firstSession, ToolStringSearch, map[string]any{
		"instanceId": testInstanceA, "query": "hello", "minLength": 4, "limit": 1,
	}, &first)
	secondSession := connectTestClient(t, &fakeBackend{})
	if result := callToolResult(t, secondSession, ToolStringSearch, map[string]any{
		"instanceId": testInstanceA, "query": "hello", "minLength": 4, "limit": 1,
		"cursor": *first.NextCursor,
	}); !result.IsError {
		t.Fatal("cursor from a previous Gateway process key was accepted")
	}
}

func TestInventoryToolSchemasRejectUnknownAndBounds(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})
	for _, test := range []struct {
		tool string
		args map[string]any
	}{
		{ToolDatabaseSegments, map[string]any{"instanceId": testInstanceA, "unknown": true}},
		{ToolDatabaseSegments, map[string]any{"instanceId": testInstanceA, "limit": 101}},
		{ToolStringSearch, map[string]any{"instanceId": testInstanceA, "minLength": 4097}},
		{ToolStringSearch, map[string]any{"instanceId": testInstanceA, "query": strings.Repeat("x", 257)}},
		{ToolSymbolImports, map[string]any{"instanceId": testInstanceA, "module": 42}},
	} {
		if !callToolRejected(t, session, test.tool, test.args) {
			t.Fatalf("invalid call accepted: %s %+v", test.tool, test.args)
		}
	}
}

func TestInventoryToolTotalOutputBudget(t *testing.T) {
	session := connectTestClient(t, &inventoryBudgetBackend{fakeBackend: &fakeBackend{}})
	result := callToolResult(t, session, ToolStringSearch, map[string]any{
		"instanceId": testInstanceA, "limit": 100,
	})
	if !result.IsError {
		t.Fatal("inventory output above the total budget was accepted")
	}
}

func assertCursorCases(
	t *testing.T,
	session *mcp.ClientSession,
	tool string,
	cursor string,
	valid map[string]any,
	invalid []map[string]any,
) {
	t.Helper()
	valid["cursor"] = cursor
	if result := callToolResult(t, session, tool, valid); result.IsError {
		t.Fatalf("normalized cursor binding rejected for %s", tool)
	}
	for _, arguments := range invalid {
		arguments["cursor"] = cursor
		if result := callToolResult(t, session, tool, arguments); !result.IsError {
			t.Fatalf("mismatched cursor accepted for %s: %+v", tool, arguments)
		}
	}
	tampered := make(map[string]any, len(valid))
	for key, value := range valid {
		tampered[key] = value
	}
	tampered["cursor"] = tamper(cursor)
	if result := callToolResult(t, session, tool, tampered); !result.IsError {
		t.Fatalf("tampered cursor accepted for %s", tool)
	}
}
