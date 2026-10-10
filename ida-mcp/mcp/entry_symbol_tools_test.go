package mcpserver

import (
	"context"
	"strings"
	"testing"

	"ida-mcp/ida"
)

type emptyEntrySymbolPageBackend struct{ *fakeBackend }

func (*emptyEntrySymbolPageBackend) DatabaseEntryPoints(
	context.Context, string, ida.EntryPointListParams,
) (ida.EntryPointListResult, error) {
	cursor := "ep1.0000000000000001.0000000000001000.0000000000000003"
	return ida.EntryPointListResult{Items: []ida.EntryPointInfo{}, NextCursor: &cursor, HasMore: true}, nil
}

func (*emptyEntrySymbolPageBackend) SymbolExports(
	context.Context, string, ida.ExportListParams,
) (ida.ExportListResult, error) {
	cursor := "se1.0000000000000001.0000000000001000.0000000000000003"
	return ida.ExportListResult{Items: []ida.ExportInfo{}, NextCursor: &cursor, HasMore: true}, nil
}

func (*emptyEntrySymbolPageBackend) SymbolSearch(
	context.Context, string, ida.SymbolSearchParams,
) (ida.SymbolSearchResult, error) {
	cursor := "sy1.0000000000000001.0000000000001000.0000000000000003"
	return ida.SymbolSearchResult{Items: []ida.SymbolInfo{}, NextCursor: &cursor, HasMore: true}, nil
}

func TestEntrySymbolToolsForwardFiltersAndDefaults(t *testing.T) {
	backend := &fakeBackend{}
	session := connectTestClient(t, backend)
	var entries databaseEntryPointsOutput
	callTool(t, session, ToolDatabaseEntryPoints, map[string]any{
		"instanceId": testInstanceA, "name": "StArT", "type": "entry",
	}, &entries)
	var exports symbolExportsOutput
	callTool(t, session, ToolSymbolExports, map[string]any{
		"instanceId": testInstanceA, "name": "ApI",
	}, &exports)
	var symbols symbolSearchOutput
	callTool(t, session, ToolSymbolSearch, map[string]any{
		"instanceId": testInstanceA, "name": "StAtE", "kind": "data",
	}, &symbols)

	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if len(backend.entryParams) != 1 || backend.entryParams[0].Name != "StArT" || backend.entryParams[0].Limit != 20 {
		t.Fatalf("entry params = %+v", backend.entryParams)
	}
	if len(backend.exportParams) != 1 || backend.exportParams[0].Name != "ApI" || backend.exportParams[0].Limit != 20 {
		t.Fatalf("export params = %+v", backend.exportParams)
	}
	if len(backend.symbolParams) != 1 || backend.symbolParams[0].Kind != "data" || backend.symbolParams[0].Limit != 20 {
		t.Fatalf("symbol params = %+v", backend.symbolParams)
	}
}

func TestEntrySymbolToolsPreserveSelectiveEmptyPages(t *testing.T) {
	session := connectTestClient(t, &emptyEntrySymbolPageBackend{fakeBackend: &fakeBackend{}})
	var entries databaseEntryPointsOutput
	callTool(t, session, ToolDatabaseEntryPoints, map[string]any{"instanceId": testInstanceA}, &entries)
	if len(entries.Items) != 0 || !entries.HasMore || entries.NextCursor == nil {
		t.Fatalf("entries = %+v", entries)
	}
	var exports symbolExportsOutput
	callTool(t, session, ToolSymbolExports, map[string]any{"instanceId": testInstanceA}, &exports)
	if len(exports.Items) != 0 || !exports.HasMore || exports.NextCursor == nil {
		t.Fatalf("exports = %+v", exports)
	}
	var symbols symbolSearchOutput
	callTool(t, session, ToolSymbolSearch, map[string]any{"instanceId": testInstanceA}, &symbols)
	if len(symbols.Items) != 0 || !symbols.HasMore || symbols.NextCursor == nil {
		t.Fatalf("symbols = %+v", symbols)
	}
}

func TestEntrySymbolPublicCursorsBindNormalizedFilters(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})
	var entries databaseEntryPointsOutput
	callTool(t, session, ToolDatabaseEntryPoints, map[string]any{
		"instanceId": testInstanceA, "name": "StArT", "type": "entry", "limit": 1,
	}, &entries)
	assertCursorCases(t, session, ToolDatabaseEntryPoints, *entries.NextCursor,
		map[string]any{"instanceId": testInstanceA, "name": "start", "type": "entry", "limit": 100},
		[]map[string]any{
			{"instanceId": testInstanceB, "name": "start", "type": "entry"},
			{"instanceId": testInstanceA, "name": "other", "type": "entry"},
			{"instanceId": testInstanceA, "name": "start", "type": "export"},
		})

	var exports symbolExportsOutput
	callTool(t, session, ToolSymbolExports, map[string]any{
		"instanceId": testInstanceA, "name": "ApI", "limit": 1,
	}, &exports)
	assertCursorCases(t, session, ToolSymbolExports, *exports.NextCursor,
		map[string]any{"instanceId": testInstanceA, "name": "api", "limit": 20},
		[]map[string]any{
			{"instanceId": testInstanceB, "name": "api"},
			{"instanceId": testInstanceA, "name": "other"},
		})

	var symbols symbolSearchOutput
	callTool(t, session, ToolSymbolSearch, map[string]any{
		"instanceId": testInstanceA, "name": "StAtE", "kind": "data", "limit": 1,
	}, &symbols)
	assertCursorCases(t, session, ToolSymbolSearch, *symbols.NextCursor,
		map[string]any{"instanceId": testInstanceA, "name": "state", "kind": "data", "limit": 20},
		[]map[string]any{
			{"instanceId": testInstanceB, "name": "state", "kind": "data"},
			{"instanceId": testInstanceA, "name": "other", "kind": "data"},
			{"instanceId": testInstanceA, "name": "state", "kind": "label"},
		})
	if !callToolRejected(t, session, ToolSymbolExports, map[string]any{
		"instanceId": testInstanceA, "cursor": *symbols.NextCursor,
	}) {
		t.Fatal("cross-Tool public cursor was accepted")
	}
}

func TestEntrySymbolPublicCursorsExpireAfterRestart(t *testing.T) {
	firstSession := connectTestClient(t, &fakeBackend{})
	var first symbolExportsOutput
	callTool(t, firstSession, ToolSymbolExports, map[string]any{
		"instanceId": testInstanceA, "name": "api", "limit": 1,
	}, &first)
	secondSession := connectTestClient(t, &fakeBackend{})
	if result := callToolResult(t, secondSession, ToolSymbolExports, map[string]any{
		"instanceId": testInstanceA, "name": "api", "cursor": *first.NextCursor,
	}); !result.IsError {
		t.Fatal("cursor from a previous Gateway process key was accepted")
	}
}

func TestEntrySymbolSchemasRejectUnknownFieldsAndBounds(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})
	for _, test := range []struct {
		tool string
		args map[string]any
	}{
		{ToolDatabaseEntryPoints, map[string]any{"instanceId": testInstanceA, "type": "main"}},
		{ToolDatabaseEntryPoints, map[string]any{"instanceId": testInstanceA, "path": "out.json"}},
		{ToolSymbolExports, map[string]any{"instanceId": testInstanceA, "limit": 101}},
		{ToolSymbolSearch, map[string]any{"instanceId": testInstanceA, "kind": "function"}},
		{ToolSymbolSearch, map[string]any{"instanceId": testInstanceA, "name": strings.Repeat("x", 257)}},
	} {
		if !callToolRejected(t, session, test.tool, test.args) {
			t.Fatalf("invalid call accepted: %s %+v", test.tool, test.args)
		}
	}
}
