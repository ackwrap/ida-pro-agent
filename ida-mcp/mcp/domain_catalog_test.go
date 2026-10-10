package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestDomainCatalogCoversGatewayAndPluginMethods(t *testing.T) {
	catalog, err := newDomainCatalog()
	if err != nil {
		t.Fatalf("newDomainCatalog: %v", err)
	}
	if len(catalog.byName) != 98 {
		t.Fatalf("catalog methods = %d, want 98", len(catalog.byName))
	}
	pluginMethods := 0
	pluginReadOnlyMethods := 0
	gatewayMethods := 0
	callableMethods := 0
	for _, method := range catalog.byName {
		if method.Source == "plugin_rpc" {
			pluginMethods++
			if method.SideEffect == "none" {
				pluginReadOnlyMethods++
			}
		}
		if method.Source == "gateway" || method.Source == "gateway_composite" {
			gatewayMethods++
		}
		if method.Status == MethodCallable {
			callableMethods++
			if method.compiledInput == nil {
				t.Errorf("callable method %s has no validator", method.Name)
			}
		}
		if method.Summary == "" || method.Parameters == "" || method.Output == "" {
			t.Errorf("method %s has incomplete documentation", method.Name)
		}
	}
	if pluginMethods != 92 || gatewayMethods != 6 || callableMethods != 98 {
		t.Fatalf("catalog plugin/gateway/callable = %d/%d/%d, want 92/6/98", pluginMethods, gatewayMethods, callableMethods)
	}
	if pluginReadOnlyMethods != 76 {
		t.Fatalf("read-only plugin methods = %d, want 76", pluginReadOnlyMethods)
	}
	for _, name := range []string{
		ToolSourceFiles, ToolSourceLines, ToolNameDemangle, ToolCommentGet, ToolBookmarkList, ToolTypeXrefs,
		ToolDecompilerLocals, ToolDecompilerCtree, ToolDecompilerLocalXrefs,
	} {
		if method := catalog.byName[name]; method == nil || method.TimeoutMs != 35000 {
			t.Errorf("inspection timeout for %s = %+v, want 35000ms", name, method)
		}
	}
	for _, method := range catalog.byName {
		if method.Domain == DomainDebugger && method.TimeoutMs != 120000 {
			t.Errorf("debugger timeout for %s = %d, want 120000ms for IDA consent", method.Name, method.TimeoutMs)
		}
	}
	for _, name := range []string{ToolChangeSetPreview, ToolPatchAssemble} {
		if method := catalog.byName[name]; method == nil || method.TimeoutMs != 30000 {
			t.Errorf("mutation read timeout for %s = %+v, want 30000ms", name, method)
		}
	}
	if method := catalog.byName[ToolFunctionDecompile]; method == nil || method.TimeoutMs != 35000 {
		t.Errorf("decompile timeout = %+v, want 35000ms", method)
	}
}

func TestToolsListContainsFixedCompatibilityCatalog(t *testing.T) {
	backend := &fakeBackend{empty: true}
	session := connectTestClient(t, backend)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	expected := map[string]bool{
		"ida_instances": true, "ida_database": true, "ida_functions": true,
		"ida_search": true, "ida_symbols": true, "ida_types": true,
		"ida_analysis": true, "ida_changes": true, "ida_patch": true,
		"ida_debugger": true, "ida_scripts": true,
	}
	for _, spec := range directToolSpecs {
		expected[spec.name] = true
	}
	if len(listed.Tools) != len(expected) {
		t.Fatalf("tools/list count = %d, want %d", len(listed.Tools), len(expected))
	}
	encoded, err := json.Marshal(listed.Tools)
	if err != nil {
		t.Fatalf("marshal tools/list: %v", err)
	}
	if len(encoded) > 48*1024 {
		t.Fatalf("tools/list uses %d bytes", len(encoded))
	}
	for _, tool := range listed.Tools {
		if !expected[tool.Name] {
			t.Errorf("tools/list exposed non-domain tool %s", tool.Name)
		}
		if tool.OutputSchema != nil {
			t.Errorf("domain tool %s exposed an eager output schema", tool.Name)
		}
		if tool.Name == ToolDomainPatch {
			annotations := tool.Annotations
			if annotations == nil || annotations.ReadOnlyHint || annotations.IdempotentHint || annotations.DestructiveHint == nil || !*annotations.DestructiveHint {
				t.Errorf("patch domain annotations do not disclose writes: %+v", annotations)
			}
		}
		isDomain := false
		for _, domainName := range domainToolNames {
			if domainName == tool.Name {
				isDomain = true
				break
			}
		}
		if !isDomain {
			continue
		}
		for _, guidance := range []string{"action=list", "action=describe", "action=call", "Do not guess"} {
			if !strings.Contains(tool.Description, guidance) {
				t.Errorf("domain tool %s description omitted %q guidance", tool.Name, guidance)
			}
		}
		schema, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("marshal %s input schema: %v", tool.Name, err)
		}
		for _, guidance := range []string{"Start with action=list", "Do not guess method names", "Do not guess argument fields"} {
			if !strings.Contains(string(schema), guidance) {
				t.Errorf("domain tool %s schema omitted %q guidance", tool.Name, guidance)
			}
		}
	}
	backend.mutex.Lock()
	listCalls := backend.listCalls
	backend.mutex.Unlock()
	if listCalls != 0 {
		t.Fatalf("initialize/tools.list performed %d discovery calls", listCalls)
	}
}

func TestDomainToolInputSchemaIsSimple(t *testing.T) {
	var schema map[string]json.RawMessage
	if err := json.Unmarshal([]byte(domainToolInputSchema), &schema); err != nil {
		t.Fatal(err)
	}
	for _, keyword := range []string{"oneOf", "anyOf", "not", "allOf"} {
		if _, exists := schema[keyword]; exists {
			t.Fatalf("complex public schema: %s", keyword)
		}
	}
	compiled, err := compileCatalogSchema("domain-tool", json.RawMessage(domainToolInputSchema))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiled.Validate(map[string]any{"action": "call", "method": "function.get"}); err != nil {
		t.Fatalf("workflow validation must be handled as a tool execution error: %v", err)
	}
}

func TestDomainListDescribeAndUnavailableCall(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})
	var listed domainListOutput
	callDomainAction(t, session, ToolDomainFunctions, map[string]any{"action": "list"}, &listed)
	if listed.Category != DomainFunctions || len(listed.Methods) != 18 {
		t.Fatalf("function catalog = %+v", listed)
	}
	foundDecompileCapability := false
	for _, method := range listed.Methods {
		if method.Method == ToolFunctionDecompile {
			foundDecompileCapability = method.Capability == "decompiler"
		}
	}
	if !foundDecompileCapability {
		t.Fatal("function catalog list omitted the decompiler capability")
	}
	var described domainDescribeOutput
	callDomainAction(t, session, ToolDomainFunctions, map[string]any{
		"action": "describe", "method": "function.callgraph",
	}, &described)
	if described.Description.Status != MethodCallable || described.Description.SideEffect != "none" {
		t.Fatalf("description = %+v", described.Description)
	}
	if !json.Valid(described.Description.InputSchema) {
		t.Fatal("callable method omitted its input schema")
	}
	callDomainAction(t, session, ToolDomainFunctions, map[string]any{
		"action": "describe", "method": ToolFunctionGet,
	}, &described)
	if described.Description.Status != MethodCallable || !json.Valid(described.Description.InputSchema) {
		t.Fatalf("callable description = %+v", described.Description)
	}
	callDomainAction(t, session, ToolDomainFunctions, map[string]any{
		"action": "describe", "method": ToolFunctionDecompile,
	}, &described)
	if described.Description.Capability != "decompiler" {
		t.Fatalf("decompiler capability = %q", described.Description.Capability)
	}
	described = domainDescribeOutput{}
	callDomainAction(t, session, ToolDomainScripts, map[string]any{
		"action": "describe", "method": ToolScriptExecute,
	}, &described)
	if described.Description.Capability != "" || described.Description.SideEffect != "arbitrary_code_execution" {
		t.Fatalf("script description = %+v", described.Description)
	}
	for method, capability := range map[string]string{
		ToolDecompilerLocals: "decompiler", ToolDecompilerCtree: "decompiler", ToolDecompilerLocalXrefs: "decompiler",
		ToolDebuggerThreads: "debugger", ToolDebuggerModules: "debugger",
	} {
		entry := catalogMethods()
		found := false
		for _, candidate := range entry {
			if candidate.Name == method {
				found = true
				if candidate.Capability != capability {
					t.Errorf("%s capability = %q", method, candidate.Capability)
				}
				break
			}
		}
		if !found {
			t.Errorf("catalog omitted %s", method)
		}
	}
}

func TestDomainRejectsCrossDomainAndInvalidActions(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})
	if result := callDomainResult(t, session, ToolDomainFunctions, map[string]any{
		"action": "describe", "method": "type.get",
	}); !result.IsError {
		t.Fatal("cross-domain type description was accepted by functions domain")
	}
	for _, input := range []map[string]any{
		{"action": "list", "method": "function.get"},
		{"action": "describe"},
		{"action": "call", "method": "function.get"},
	} {
		result := callDomainResult(t, session, ToolDomainFunctions, input)
		if !result.IsError {
			t.Fatalf("invalid domain action accepted: %+v", input)
		}
	}
	if result := callDomainResult(t, session, ToolDomainChanges, map[string]any{
		"action": "call", "method": ToolDebuggerInfo, "arguments": map[string]any{},
	}); !result.IsError {
		t.Fatal("cross-domain debugger call was accepted by changes domain")
	}
}

func TestCatalogReadsAndBlockedCallsDoNotDiscoverIDA(t *testing.T) {
	backend := &fakeBackend{empty: true}
	session := connectTestClient(t, backend)
	var listed domainListOutput
	callDomainAction(t, session, ToolDomainTypes, map[string]any{"action": "list"}, &listed)
	var described domainDescribeOutput
	callDomainAction(t, session, ToolDomainInstances, map[string]any{
		"action": "describe", "method": "system.ping",
	}, &described)
	result := callDomainResult(t, session, ToolDomainDatabase, map[string]any{
		"action": "call", "method": ToolDatabaseSave, "arguments": map[string]any{"target": "forbidden.i64"},
	})
	if !result.IsError {
		t.Fatal("database.save accepted target")
	}
	backend.mutex.Lock()
	listCalls := backend.listCalls
	backend.mutex.Unlock()
	if listCalls != 0 {
		t.Fatalf("catalog-only actions performed %d discovery calls", listCalls)
	}
}

func callDomainResult(
	t *testing.T, session *mcp.ClientSession, tool string, arguments map[string]any,
) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: arguments})
	if err != nil {
		t.Fatalf("CallTool %s: %v", tool, err)
	}
	return result
}

func callDomainAction(
	t *testing.T, session *mcp.ClientSession, tool string, arguments map[string]any, output any,
) {
	t.Helper()
	result := callDomainResult(t, session, tool, arguments)
	if result.IsError {
		t.Fatalf("CallTool %s returned error: %+v", tool, result.Content)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal %s output: %v", tool, err)
	}
	if err := json.Unmarshal(encoded, output); err != nil {
		t.Fatalf("decode %s output: %v", tool, err)
	}
}
