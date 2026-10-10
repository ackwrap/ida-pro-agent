package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	testInstanceA = "11111111-0000-4000-8000-000000000001"
	testInstanceB = "22222222-0000-4000-8000-000000000002"
)

type fakeBackend struct {
	mutex             sync.Mutex
	listCalls         int
	empty             bool
	analysisParams    []ida.FunctionPageParams
	segmentParams     []ida.SegmentListParams
	stringParams      []ida.StringSearchParams
	importParams      []ida.ImportListParams
	entryParams       []ida.EntryPointListParams
	exportParams      []ida.ExportListParams
	symbolParams      []ida.SymbolSearchParams
	profileParams     []ida.FunctionProfileParams
	instructionParams []ida.InstructionSearchParams
	listingTextParams []ida.ListingTextSearchParams
	regexParams       []ida.StringRegexSearchParams
}

type oversizedBackend struct{ *fakeBackend }

func (*oversizedBackend) SearchFunctions(
	context.Context, string, ida.FunctionSearchParams,
) (ida.FunctionSearchResult, error) {
	return ida.FunctionSearchResult{
		Items: []ida.FunctionSummary{{EntryAddress: 0x401000, Name: strings.Repeat("x", maxToolItemOutputBytes)}},
	}, nil
}

type failingBackend struct{ *fakeBackend }

func (*failingBackend) DatabaseInfo(context.Context, string) (ida.DatabaseInfo, error) {
	return ida.DatabaseInfo{}, errors.New(`sensitive D:\private\sample.i64 \\.\pipe\ida-agent-secret`)
}

func (backend *fakeBackend) ListInstances(context.Context) ([]ida.Instance, error) {
	backend.mutex.Lock()
	backend.listCalls++
	backend.mutex.Unlock()
	if backend.empty {
		return []ida.Instance{}, nil
	}
	return []ida.Instance{
		testInstance(testInstanceA, "a.i64"), testInstance(testInstanceB, "b.i64"),
	}, nil
}

func (*fakeBackend) DatabaseInfo(context.Context, string) (ida.DatabaseInfo, error) {
	return ida.DatabaseInfo{
		Database: "sample.i64", Processor: "metapc", Architecture: "x86_64", AddressBits: 64,
		Segments: ida.SegmentSummary{Total: 2, Code: 1, Data: 1},
	}, nil
}

func (backend *fakeBackend) DatabaseSegments(
	_ context.Context, _ string, params ida.SegmentListParams,
) (ida.SegmentListResult, error) {
	backend.mutex.Lock()
	backend.segmentParams = append(backend.segmentParams, params)
	backend.mutex.Unlock()
	if params.Cursor == "" {
		cursor := "ds1.0000000000000001.0000000000000002.0000000000000003"
		return ida.SegmentListResult{
			Items:      []ida.SegmentInfo{{Start: 0x401000, End: 0x402000, Name: ".text", Class: "CODE", Bitness: 64, Permissions: "r-x", Type: "code"}},
			NextCursor: &cursor, HasMore: true,
		}, nil
	}
	return ida.SegmentListResult{Items: []ida.SegmentInfo{}}, nil
}

func (backend *fakeBackend) SearchStrings(
	_ context.Context, _ string, params ida.StringSearchParams,
) (ida.StringSearchResult, error) {
	backend.mutex.Lock()
	backend.stringParams = append(backend.stringParams, params)
	backend.mutex.Unlock()
	if params.Cursor == "" {
		cursor := "ss1.0000000000000001.0000000000000002.0000000000000003"
		return ida.StringSearchResult{
			Items:      []ida.StringInfo{{Address: 0x403000, Length: 5, Encoding: "UTF-8", Value: "hello", OriginalSize: 5}},
			NextCursor: &cursor, HasMore: true,
		}, nil
	}
	return ida.StringSearchResult{Items: []ida.StringInfo{}}, nil
}

func (backend *fakeBackend) SymbolImports(
	_ context.Context, _ string, params ida.ImportListParams,
) (ida.ImportListResult, error) {
	backend.mutex.Lock()
	backend.importParams = append(backend.importParams, params)
	backend.mutex.Unlock()
	if params.Cursor == "" {
		cursor := "si1.0000000000000001.0000000000000002.0000000000000003"
		ordinal := uint64(42)
		return ida.ImportListResult{
			Items:      []ida.ImportInfo{{Address: 0x404000, Name: "CreateFileW", Module: "KERNEL32", Ordinal: &ordinal}},
			NextCursor: &cursor, HasMore: true,
		}, nil
	}
	return ida.ImportListResult{Items: []ida.ImportInfo{}}, nil
}

func (backend *fakeBackend) DatabaseEntryPoints(
	_ context.Context, _ string, params ida.EntryPointListParams,
) (ida.EntryPointListResult, error) {
	backend.mutex.Lock()
	backend.entryParams = append(backend.entryParams, params)
	backend.mutex.Unlock()
	if params.Cursor == "" {
		cursor := "ep1.0000000000000001.0000000000000002.0000000000000003"
		return ida.EntryPointListResult{
			Items:      []ida.EntryPointInfo{{Address: 0x401000, Name: "start", Type: "entry"}},
			NextCursor: &cursor, HasMore: true,
		}, nil
	}
	return ida.EntryPointListResult{Items: []ida.EntryPointInfo{}}, nil
}

func (backend *fakeBackend) SymbolExports(
	_ context.Context, _ string, params ida.ExportListParams,
) (ida.ExportListResult, error) {
	backend.mutex.Lock()
	backend.exportParams = append(backend.exportParams, params)
	backend.mutex.Unlock()
	if params.Cursor == "" {
		cursor := "se1.0000000000000001.0000000000000002.0000000000000003"
		return ida.ExportListResult{
			Items:      []ida.ExportInfo{{Address: 0x402000, Name: "ExportedApi", Ordinal: 1}},
			NextCursor: &cursor, HasMore: true,
		}, nil
	}
	return ida.ExportListResult{Items: []ida.ExportInfo{}}, nil
}

func (backend *fakeBackend) SymbolSearch(
	_ context.Context, _ string, params ida.SymbolSearchParams,
) (ida.SymbolSearchResult, error) {
	backend.mutex.Lock()
	backend.symbolParams = append(backend.symbolParams, params)
	backend.mutex.Unlock()
	if params.Cursor == "" {
		cursor := "sy1.0000000000000001.0000000000000002.0000000000000003"
		return ida.SymbolSearchResult{
			Items:      []ida.SymbolInfo{{Address: 0x403000, Name: "global_state", Kind: "data"}},
			NextCursor: &cursor, HasMore: true,
		}, nil
	}
	return ida.SymbolSearchResult{Items: []ida.SymbolInfo{}}, nil
}

func (*fakeBackend) GetFunction(
	_ context.Context, instanceID string, address ida.Address,
) (ida.FunctionInfo, error) {
	return ida.FunctionInfo{
		EntryAddress: address, AddressRange: ida.AddressRange{Start: address, End: address + 16},
		Name: instanceID + "_function",
	}, nil
}

func (*fakeBackend) SearchFunctions(
	_ context.Context, instanceID string, params ida.FunctionSearchParams,
) (ida.FunctionSearchResult, error) {
	if params.Cursor == "" {
		cursor := "fs1.0000000000000001.0000000000000002.0000000000000003"
		return ida.FunctionSearchResult{
			Items:      []ida.FunctionSummary{{EntryAddress: 0x401000, Name: instanceID}},
			NextCursor: &cursor, HasMore: true,
		}, nil
	}
	return ida.FunctionSearchResult{
		Items: []ida.FunctionSummary{{EntryAddress: 0x402000, Name: instanceID + "_next"}},
	}, nil
}

func (backend *fakeBackend) DisassembleFunction(
	_ context.Context, _ string, params ida.FunctionPageParams,
) (ida.FunctionDisassemblyResult, error) {
	backend.recordAnalysisParams(params)
	next := params.Offset + 1
	return ida.FunctionDisassemblyResult{
		EntryAddress: params.Address,
		Items:        []ida.DisassemblyItem{{Address: params.Address, Text: "push rbp"}},
		NextOffset:   &next, HasMore: true,
	}, nil
}

func (backend *fakeBackend) FunctionBasicBlocks(
	_ context.Context, _ string, params ida.FunctionPageParams,
) (ida.FunctionBasicBlocksResult, error) {
	backend.recordAnalysisParams(params)
	return ida.FunctionBasicBlocksResult{
		EntryAddress: params.Address,
		Items: []ida.FunctionBasicBlock{{
			Start: params.Address, End: params.Address + 16, Type: ida.BasicBlockReturn,
			Successors: []ida.Address{}, Predecessors: []ida.Address{},
		}},
	}, nil
}

func (backend *fakeBackend) FunctionCallees(
	_ context.Context, _ string, params ida.FunctionPageParams,
) (ida.FunctionCalleesResult, error) {
	backend.recordAnalysisParams(params)
	return ida.FunctionCalleesResult{
		EntryAddress: params.Address,
		Items:        []ida.FunctionCallee{{Address: params.Address + 0x1000, Name: "callee", Internal: true}},
	}, nil
}

func (backend *fakeBackend) recordAnalysisParams(params ida.FunctionPageParams) {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	backend.analysisParams = append(backend.analysisParams, params)
}

func (*fakeBackend) QueryXrefs(
	_ context.Context, _ string, params ida.XrefQueryParams,
) (ida.XrefQueryResult, error) {
	return ida.XrefQueryResult{Items: []ida.XrefInfo{{
		From: params.Address, To: params.Address + 4, Type: "code.call", Code: true,
	}}}, nil
}

func (*fakeBackend) ReadMemory(
	_ context.Context, _ string, params ida.MemoryReadParams,
) (ida.MemoryReadResult, error) {
	return ida.MemoryReadResult{
		Address: params.Address, Format: params.Format, BytesRead: 4, Value: "90909090",
	}, nil
}

func (*fakeBackend) DecompileFunction(
	_ context.Context, _ string, params ida.DecompileParams,
) (ida.DecompileResult, error) {
	return ida.DecompileResult{
		EntryAddress: params.Address, Pseudocode: "int main() {}", ReturnedSize: 13, OriginalSize: 13,
	}, nil
}

func (*fakeBackend) SystemPing(context.Context, string) (ida.SystemPingResult, error) {
	return ida.SystemPingResult{Status: "ok"}, nil
}

func (*fakeBackend) SystemMethods(context.Context, string) (ida.SystemMethodsResult, error) {
	return ida.SystemMethodsResult{Methods: []string{"database.info", "system.ping"}}, nil
}

func (*fakeBackend) InstanceInfo(_ context.Context, instanceID string) (ida.InstanceInfoResult, error) {
	return ida.InstanceInfoResult{
		InstanceID: instanceID, PID: 4242, IDAVersion: "9.4", Database: "sample.i64",
		InputFile: "sample.exe", Processor: "metapc", Bitness: 64, Architecture: "x86_64",
		Capabilities: ida.Capabilities{Decompiler: true, AddressBits: 64},
	}, nil
}

func (*fakeBackend) DatabaseSurvey(_ context.Context, _ string, params ida.DatabaseSurveyParams) (ida.DatabaseSurveyResult, error) {
	return ida.DatabaseSurveyResult{
		Mode: params.Mode, Metadata: ida.DatabaseInfo{Database: "sample.i64", Processor: "metapc", Architecture: "x86_64", AddressBits: 64, Segments: ida.SegmentSummary{Total: 2}},
		Statistics: ida.SurveyStatistics{SampledFunctions: 1}, ImportCategories: []ida.SurveyImportCategory{},
		Metrics: ida.SurveyMetrics{Segments: 2}, Budget: ida.SurveyBudget{RequestedItems: params.Budget, PerSection: params.Budget / 3},
		Functions: ida.SurveyFunctions{Items: []ida.FunctionSummary{{EntryAddress: 0x401000, Name: "main"}}},
		Strings:   ida.SurveyStrings{Items: []ida.StringInfo{}},
	}, nil
}

func (*fakeBackend) DatabaseSave(context.Context, string, ida.DatabaseSaveParams) (ida.DatabaseSaveResult, error) {
	return ida.DatabaseSaveResult{Saved: true}, nil
}

func (*fakeBackend) FunctionCallers(_ context.Context, _ string, params ida.FunctionCallersParams) (ida.FunctionCallersResult, error) {
	return ida.FunctionCallersResult{EntryAddress: params.Address, Items: []ida.FunctionCaller{{Address: params.Address + 0x100, Name: "caller", CallSites: []ida.Address{params.Address + 0x110}}}}, nil
}

func (*fakeBackend) FunctionCallGraph(_ context.Context, _ string, params ida.FunctionCallGraphParams) (ida.FunctionCallGraphResult, error) {
	return ida.FunctionCallGraphResult{Nodes: []ida.FunctionCallGraphNode{{Address: params.Roots[0], Name: "root"}}, Edges: []ida.FunctionCallGraphEdge{}}, nil
}

func (backend *fakeBackend) FunctionProfile(_ context.Context, _ string, params ida.FunctionProfileParams) (ida.FunctionProfileResult, error) {
	backend.mutex.Lock()
	backend.profileParams = append(backend.profileParams, params)
	backend.mutex.Unlock()
	result := ida.FunctionProfileResult{Items: []ida.FunctionProfileItem{{Address: 0x401000, Name: "main"}}, Metrics: ida.FunctionProfileSummary{Candidates: 1, Matched: 1}}
	if params.Cursor == "" {
		cursor := "fp1.0000000000000001.0000000000000002.0000000000000003"
		result.NextCursor = &cursor
		result.HasMore = true
	}
	return result, nil
}

func (*fakeBackend) FunctionExport(_ context.Context, _ string, params ida.FunctionExportParams) (ida.FunctionExportResult, error) {
	return ida.FunctionExportResult{Format: params.Format, Content: "int main(void);", OriginalSize: 15}, nil
}

func (*fakeBackend) FunctionAnalyze(_ context.Context, _ string, params ida.FunctionAnalyzeParams) (ida.FunctionAnalyzeResult, error) {
	return fakeFunctionAnalyze(params), nil
}

func (*fakeBackend) FunctionAnalyzeBatch(_ context.Context, _ string, params ida.FunctionAnalyzeParams) (ida.FunctionAnalyzeResult, error) {
	return fakeFunctionAnalyze(params), nil
}

func fakeFunctionAnalyze(params ida.FunctionAnalyzeParams) ida.FunctionAnalyzeResult {
	sections := append([]string(nil), params.Sections...)
	if sections == nil {
		sections = []string{"overview"}
	}
	items := make([]ida.FunctionAnalyzeItem, 0, len(params.Addresses))
	for _, address := range params.Addresses {
		items = append(items, ida.FunctionAnalyzeItem{Address: address, Name: "main"})
	}
	return ida.FunctionAnalyzeResult{Sections: sections, Items: items}
}

func (*fakeBackend) FunctionStackFrame(_ context.Context, _ string, params ida.FunctionStackFrameParams) (ida.FunctionStackFrameResult, error) {
	return ida.FunctionStackFrameResult{EntryAddress: params.Address, Size: 32, Variables: []ida.StackVariable{{Name: "local", Declaration: "int local", BitSize: 32, Role: "local"}}}, nil
}

func TestInitializeAndToolsListDoNotRequireIDA(t *testing.T) {
	backend := &fakeBackend{empty: true}
	session := connectTestClient(t, backend)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(listed.Tools) != 23 {
		t.Fatalf("tools = %d", len(listed.Tools))
	}
	backend.mutex.Lock()
	listCalls := backend.listCalls
	backend.mutex.Unlock()
	if listCalls != 0 {
		t.Fatalf("initialize/tools.list performed %d discovery calls", listCalls)
	}
	var output instancesListOutput
	callTool(t, session, ToolInstancesList, map[string]any{}, &output)
	if output.Instances == nil || len(output.Instances) != 0 {
		t.Fatalf("instances = %+v", output.Instances)
	}
}

func TestInstanceSelectionAndActiveRouting(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})
	var listed instancesListOutput
	callTool(t, session, ToolInstancesList, map[string]any{}, &listed)
	if len(listed.Instances) != 2 {
		t.Fatalf("instances = %+v", listed.Instances)
	}
	var selected instanceSelectionOutput
	callTool(t, session, ToolInstancesSelect, map[string]any{"instanceId": testInstanceB}, &selected)
	if selected.ActiveInstance.InstanceID != testInstanceB {
		t.Fatalf("selected = %+v", selected)
	}
	var active instancesGetActiveOutput
	callTool(t, session, ToolInstancesGetActive, map[string]any{}, &active)
	if active.ActiveInstance == nil || active.ActiveInstance.InstanceID != testInstanceB {
		t.Fatalf("active = %+v", active)
	}
	var function functionInfoOutput
	callTool(t, session, ToolFunctionGet, map[string]any{"address": "0x401000"}, &function)
	if !strings.Contains(function.Name, testInstanceB) {
		t.Fatalf("function = %+v", function)
	}
	callTool(t, session, ToolFunctionGet, map[string]any{
		"instanceId": testInstanceA, "address": "0x401000",
	}, &function)
	if !strings.Contains(function.Name, testInstanceA) {
		t.Fatalf("explicit function = %+v", function)
	}
}

func TestBusinessToolRequiresExplicitOrActiveInstance(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})
	result := callToolResult(t, session, ToolDatabaseInfo, map[string]any{})
	if !result.IsError {
		t.Fatal("database.info succeeded without an active instance")
	}
}

func TestSignedCursorIsBoundToInstanceAndQuery(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})
	var first functionSearchOutput
	callTool(t, session, ToolFunctionSearch, map[string]any{
		"instanceId": testInstanceA, "name": "main", "limit": 1,
	}, &first)
	if first.NextCursor == nil {
		t.Fatal("continuation cursor missing")
	}
	var second functionSearchOutput
	callTool(t, session, ToolFunctionSearch, map[string]any{
		"instanceId": testInstanceA, "name": "main", "limit": 1, "cursor": *first.NextCursor,
	}, &second)
	if len(second.Items) != 1 {
		t.Fatalf("second page = %+v", second)
	}
	for _, arguments := range []map[string]any{
		{"instanceId": testInstanceB, "name": "main", "limit": 1, "cursor": *first.NextCursor},
		{"instanceId": testInstanceA, "name": "other", "limit": 1, "cursor": *first.NextCursor},
		{"instanceId": testInstanceA, "name": "main", "limit": 1, "cursor": tamper(*first.NextCursor)},
	} {
		if result := callToolResult(t, session, ToolFunctionSearch, arguments); !result.IsError {
			t.Fatalf("invalid cursor accepted: %+v", arguments)
		}
	}
}

func TestToolSchemasRejectUnknownAndInvalidInstance(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})
	for _, test := range []struct {
		name      string
		arguments map[string]any
	}{
		{ToolInstancesSelect, map[string]any{"instanceId": "not-a-uuid"}},
		{ToolFunctionGet, map[string]any{"instanceId": testInstanceA, "address": "401000"}},
		{ToolFunctionGet, map[string]any{"instanceId": testInstanceA, "address": "0x401000", "write": true}},
		{ToolMemoryRead, map[string]any{"instanceId": testInstanceA, "address": "0x401000", "format": "bytes", "length": 4097}},
	} {
		if !callToolRejected(t, session, test.name, test.arguments) {
			t.Fatalf("invalid call accepted: %s %+v", test.name, test.arguments)
		}
	}
}

func TestToolOutputBudgetRejectsOversizedItem(t *testing.T) {
	session := connectTestClient(t, &oversizedBackend{fakeBackend: &fakeBackend{}})
	result := callToolResult(t, session, ToolFunctionSearch, map[string]any{
		"instanceId": testInstanceA, "name": "", "limit": 1,
	})
	if !result.IsError {
		t.Fatal("oversized tool item was accepted")
	}
}

func TestToolErrorDoesNotExposeBackendDetails(t *testing.T) {
	session := connectTestClient(t, &failingBackend{fakeBackend: &fakeBackend{}})
	result := callToolResult(t, session, ToolDatabaseInfo, map[string]any{"instanceId": testInstanceA})
	if !result.IsError {
		t.Fatal("backend failure was not returned as a tool error")
	}
	encoded, err := json.Marshal(result.Content)
	if err != nil {
		t.Fatalf("marshal error content: %v", err)
	}
	text := string(encoded)
	if strings.Contains(text, "private") || strings.Contains(text, "ida-agent-secret") {
		t.Fatalf("tool error leaked backend details: %s", text)
	}
}

func testInstance(instanceID, database string) ida.Instance {
	return ida.Instance{
		InstanceID: instanceID, PID: 4242, IDAVersion: "9.4", Database: database,
		InputFile: "sample.exe", Processor: "metapc", Bitness: 64, Architecture: "x86_64",
		Capabilities: ida.Capabilities{Decompiler: true, AddressBits: 64},
	}
}

func connectTestClient(t *testing.T, backend ida.Backend) *mcp.ClientSession {
	t.Helper()
	server, err := NewServer("test-version", backend)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatalf("server Connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0.0"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	cancel()
	if err != nil {
		_ = serverSession.Close()
		t.Fatalf("client Connect: %v", err)
	}
	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	})
	return clientSession
}

func callToolResult(
	t *testing.T, session *mcp.ClientSession, name string, arguments map[string]any,
) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := callCatalogMethod(ctx, session, name, arguments)
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	return result
}

func callToolRejected(
	t *testing.T, session *mcp.ClientSession, name string, arguments map[string]any,
) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := callCatalogMethod(ctx, session, name, arguments)
	return err != nil || (result != nil && result.IsError)
}

func callTool(
	t *testing.T, session *mcp.ClientSession, name string, arguments map[string]any, output any,
) {
	t.Helper()
	result := callToolResult(t, session, name, arguments)
	if result.IsError {
		t.Fatalf("CallTool %s returned error: %+v", name, result.Content)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal %s output: %v", name, err)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatalf("decode %s domain output: %v", name, err)
	}
	if err := json.Unmarshal(envelope.Result, output); err != nil {
		t.Fatalf("decode %s output: %v", name, err)
	}
}

func callCatalogMethod(
	ctx context.Context,
	session *mcp.ClientSession,
	name string,
	arguments map[string]any,
) (*mcp.CallToolResult, error) {
	domain, ok := DomainToolForMethod(name)
	if !ok {
		return nil, fmt.Errorf("no domain tool for %s", name)
	}
	return session.CallTool(ctx, &mcp.CallToolParams{Name: domain, Arguments: map[string]any{
		"action": "call", "method": name, "arguments": arguments,
	}})
}

func tamper(cursor string) string {
	replacement := byte('A')
	if cursor[len(cursor)-1] == replacement {
		replacement = 'B'
	}
	return cursor[:len(cursor)-1] + string(replacement)
}
