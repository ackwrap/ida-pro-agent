package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"ida-mcp/ida"
)

func decodeToolFailure(t *testing.T, result *mcp.CallToolResult) toolFailure {
	t.Helper()
	if !result.IsError {
		t.Fatal("expected correctable tool execution error")
	}
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var failure toolFailure
	if err := json.Unmarshal(data, &failure); err != nil {
		t.Fatal(err)
	}
	assertTextMatchesStructured(t, result)
	if failure.Code == "" || failure.Hint == "" {
		t.Fatalf("incomplete error: %+v", failure)
	}
	return failure
}
func assertTextMatchesStructured(t *testing.T, result *mcp.CallToolResult) {
	t.Helper()
	if len(result.Content) != 1 {
		t.Fatalf("content: %+v", result.Content)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("missing text fallback")
	}
	var decoded any
	if err := json.Unmarshal([]byte(text.Text), &decoded); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(result.StructuredContent)
	var structured any
	if err := json.Unmarshal(data, &structured); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, structured) {
		t.Fatal("text and structured results differ")
	}
}
func TestArgumentErrorsAreActionableAndSessionRecovers(t *testing.T) {
	backend := &fakeBackend{empty: true}
	session := connectTestClient(t, backend)
	cases := []struct {
		tool        string
		arguments   map[string]any
		field, rule string
	}{
		{"ida_get_function", map[string]any{}, "arguments.address", "required"},
		{"ida_functions", map[string]any{"action": "call", "method": ToolFunctionSearch, "arguments": map[string]any{"name": "main", "limit": "SECRET-value"}}, "arguments.limit", "type"},
		{"ida_get_function", map[string]any{"address": 123}, "arguments.address", "type"},
		{"ida_functions", map[string]any{"action": "call", "method": ToolFunctionGet, "arguments": "SECRET-value"}, "arguments.arguments", "type"},
		{"ida_get_function", map[string]any{"address": "0x401000", "instanceId": nil}, "arguments.instanceId", "type"},
		{"ida_get_function", map[string]any{"address": "0x401000", "secret": "SECRET-value"}, "arguments.secret", "additionalProperties"},
		{"ida_functions", map[string]any{"action": "invalid"}, "arguments.action", "enum"},
	}
	for _, test := range cases {
		failure := decodeToolFailure(t, callDomainResult(t, session, test.tool, test.arguments))
		if failure.Code != ida.ErrorInvalidArgument {
			t.Fatalf("error: %+v", failure)
		}
		found := false
		for _, issue := range failure.Issues {
			if issue.Field == test.field && issue.Rule == test.rule {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %s/%s: %+v", test.field, test.rule, failure)
		}
		data, _ := json.Marshal(failure)
		if strings.Contains(string(data), "SECRET-value") {
			t.Fatal("error echoed an input value")
		}
	}
	// Workflow errors also stay within tools/call and must not discover IDA.
	decodeToolFailure(t, callDomainResult(t, session, "ida_functions", map[string]any{"action": "call", "method": ToolFunctionGet}))
	backend.mutex.Lock()
	calls := backend.listCalls
	backend.mutex.Unlock()
	if calls != 0 {
		t.Fatalf("invalid calls performed discovery %d times", calls)
	}
	failure := decodeToolFailure(t, callDomainResult(t, session, "ida_search", map[string]any{"action": "describe", "method": ToolFunctionGet}))
	if !strings.Contains(failure.Hint, "ida_functions") {
		t.Fatalf("missing correct domain: %+v", failure)
	}
	result := callDomainResult(t, session, "ida_list_instances", map[string]any{})
	if result.IsError {
		t.Fatal(result.Content)
	}
	assertTextMatchesStructured(t, result)
}

type oneInstanceBackend struct{ *fakeBackend }

func (backend *oneInstanceBackend) ListInstances(ctx context.Context) ([]ida.Instance, error) {
	instances, err := backend.fakeBackend.ListInstances(ctx)
	if err != nil || len(instances) == 0 {
		return instances, err
	}
	return instances[:1], nil
}
func TestDirectRoutingAndFixedAliases(t *testing.T) {
	session := connectTestClient(t, &oneInstanceBackend{&fakeBackend{}})
	cases := []struct {
		tool      string
		arguments map[string]any
	}{
		{"ida_list_instances", map[string]any{}}, {"ida_select_instance", map[string]any{"instanceId": testInstanceA}},
		{"ida_database_info", map[string]any{}}, {"ida_get_function", map[string]any{"address": "0x401000"}},
		{"ida_search_functions", map[string]any{"name": "main"}}, {"ida_decompile_function", map[string]any{"address": "0x401000"}},
		{"ida_disassemble_function", map[string]any{"address": "0x401000"}}, {"ida_function_callers", map[string]any{"address": "0x401000"}},
		{"ida_function_callees", map[string]any{"address": "0x401000"}}, {"ida_query_xrefs", map[string]any{"address": "0x401000", "direction": "incoming"}},
		{"ida_search_strings", map[string]any{"query": "hello"}}, {"ida_read_memory", map[string]any{"address": "0x401000", "format": "bytes", "length": 4}},
	}
	for _, test := range cases {
		result := callDomainResult(t, session, test.tool, test.arguments)
		if result.IsError {
			t.Fatalf("%s: %v", test.tool, result.Content)
		}
		assertTextMatchesStructured(t, result)
	}
	// A fresh connection with one database works without selecting it first.
	session = connectTestClient(t, &oneInstanceBackend{&fakeBackend{}})
	result := callDomainResult(t, session, "ida_get_function", map[string]any{"address": "0x401000"})
	if result.IsError {
		t.Fatal(result.Content)
	}
	domain := callDomainResult(t, session, "ida_functions", map[string]any{"action": "call", "method": ToolFunctionGet, "arguments": map[string]any{"instanceId": testInstanceA, "address": "0x401000"}})
	data, _ := json.Marshal(domain.StructuredContent)
	var envelope domainCallOutput
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	direct, _ := json.Marshal(result.StructuredContent)
	var a, b any
	_ = json.Unmarshal(direct, &a)
	_ = json.Unmarshal(envelope.Result, &b)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("alias differs from typed domain result")
	}
	session = connectTestClient(t, &fakeBackend{})
	failure := decodeToolFailure(t, callDomainResult(t, session, "ida_get_function", map[string]any{"address": "0x401000"}))
	if failure.Code != ida.ErrorNotFound || !strings.Contains(failure.Message, "Multiple") {
		t.Fatal(failure)
	}
	result = callDomainResult(t, session, "ida_get_function", map[string]any{"instanceId": testInstanceB, "address": "0x401000"})
	if result.IsError {
		t.Fatal(result.Content)
	}
	callDomainResult(t, session, "ida_select_instance", map[string]any{"instanceId": testInstanceB})
	result = callDomainResult(t, session, "ida_get_function", map[string]any{"address": "0x401000"})
	data, _ = json.Marshal(result.StructuredContent)
	if !strings.Contains(string(data), testInstanceB) {
		t.Fatal("selected instance was ignored")
	}
}

type retryBackend struct {
	*typedDomainBackend
	mutex        sync.Mutex
	calls        int
	err          error
	busyAttempts int
	deadlines    []time.Time
}

func (backend *retryBackend) attempt(ctx context.Context) error {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	backend.calls++
	deadline, _ := ctx.Deadline()
	backend.deadlines = append(backend.deadlines, deadline)
	if backend.busyAttempts > 0 {
		backend.busyAttempts--
		return ida.NewError(ida.ErrorIDABusy, "busy", true)
	}
	return backend.err
}
func (backend *retryBackend) GetFunction(ctx context.Context, instance string, address ida.Address) (ida.FunctionInfo, error) {
	if err := backend.attempt(ctx); err != nil {
		return ida.FunctionInfo{}, err
	}
	return backend.fakeBackend.GetFunction(ctx, instance, address)
}
func (backend *retryBackend) DatabaseSave(ctx context.Context, _ string, _ ida.DatabaseSaveParams) (ida.DatabaseSaveResult, error) {
	return ida.DatabaseSaveResult{}, backend.attempt(ctx)
}
func (backend *retryBackend) ExecuteScript(ctx context.Context, _ string, _ ida.ScriptExecuteParams) (ida.ScriptExecutionResult, error) {
	return ida.ScriptExecutionResult{}, backend.attempt(ctx)
}
func (backend *retryBackend) DebuggerStart(ctx context.Context, _ string) (ida.DebuggerActionResult, error) {
	return ida.DebuggerActionResult{}, backend.attempt(ctx)
}
func TestBusyRetriesRespectDeadlineAndSideEffects(t *testing.T) {
	backend := &retryBackend{typedDomainBackend: newTypedDomainBackend(), busyAttempts: 2}
	session := connectTestClient(t, backend)
	result := callDomainResult(t, session, "ida_get_function", map[string]any{"instanceId": testInstanceA, "address": "0x401000"})
	if result.IsError || backend.calls != 3 {
		t.Fatalf("read retry: %d %v", backend.calls, result.Content)
	}
	for _, deadline := range backend.deadlines {
		if !deadline.Equal(backend.deadlines[0]) {
			t.Fatal("retry restarted the overall deadline")
		}
	}
	for _, test := range []struct {
		method string
		args   map[string]any
	}{
		{ToolDatabaseSave, map[string]any{}}, {ToolScriptExecute, map[string]any{"language": "python", "code": "print('SECRET-value')"}}, {ToolDebuggerStart, map[string]any{}},
	} {
		for _, code := range []ida.ErrorCode{ida.ErrorIDABusy, ida.ErrorTimeout} {
			backend := &retryBackend{typedDomainBackend: newTypedDomainBackend(), err: ida.NewError(code, "failed", true)}
			session := connectTestClient(t, backend)
			test.args["instanceId"] = testInstanceA
			result := callToolResult(t, session, test.method, test.args)
			failure := decodeToolFailure(t, result)
			if backend.calls != 1 {
				t.Fatalf("%s executed %d times", test.method, backend.calls)
			}
			if code == ida.ErrorTimeout && (failure.Retryable || failure.ExecutionState != "unknown") {
				t.Fatalf("unsafe timeout hint: %+v", failure)
			}
		}
	}
	// Cancellation during backoff must stop before a second attempt.
	backend = &retryBackend{typedDomainBackend: newTypedDomainBackend(), busyAttempts: 3}
	catalog, _ := newDomainCatalog()
	registry := &toolRegistry{backend: backend, instances: newInstanceManager(backend)}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := registry.executeMethod(ctx, nil, catalog.byName[ToolFunctionGet], json.RawMessage(`{"instanceId":"`+testInstanceA+`","address":"0x401000"}`))
	var failure *toolFailure
	if !errors.As(err, &failure) || failure.Code != ida.ErrorTimeout || backend.calls != 1 {
		t.Fatalf("cancelled backoff: %d %v", backend.calls, err)
	}
}

func TestDirectPaginationSharesMethodBoundCursors(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})
	var first functionSearchOutput
	callDomainAction(t, session, "ida_search_functions", map[string]any{"instanceId": testInstanceA, "name": "main", "limit": 1}, &first)
	if first.NextCursor == nil {
		t.Fatal("direct search omitted continuation")
	}
	var second functionSearchOutput
	callTool(t, session, ToolFunctionSearch, map[string]any{"instanceId": testInstanceA, "name": "main", "limit": 1, "cursor": *first.NextCursor}, &second)
	if len(second.Items) != 1 {
		t.Fatalf("domain continuation: %+v", second)
	}
	result := callDomainResult(t, session, "ida_search_functions", map[string]any{"instanceId": testInstanceB, "name": "main", "limit": 1, "cursor": *first.NextCursor})
	failure := decodeToolFailure(t, result)
	if failure.Code != ida.ErrorInvalidArgument {
		t.Fatal("direct alias accepted another instance's cursor")
	}
	result = callDomainResult(t, session, "ida_search_functions", map[string]any{"instanceId": testInstanceA, "name": "other", "limit": 1, "cursor": *first.NextCursor})
	if !result.IsError {
		t.Fatal("direct alias accepted a cursor for different filters")
	}
}

func TestDirectContractCombinationsRemainStrict(t *testing.T) {
	backend := &fakeBackend{empty: true}
	session := connectTestClient(t, backend)
	for _, test := range []struct {
		tool string
		args map[string]any
	}{
		{"ida_search_functions", map[string]any{"address": "0x401000"}},
		{"ida_read_memory", map[string]any{"address": "0x401000", "format": "bytes"}},
		{"ida_read_memory", map[string]any{"address": "0x401000", "format": "integer", "length": 4}},
		{"ida_read_memory", map[string]any{"address": "0x401000", "format": "pointer", "length": 4}},
		{"ida_search_strings", map[string]any{"refresh": true, "cursor": "ss2." + strings.Repeat("a", 72) + "." + strings.Repeat("a", 43)}},
	} {
		failure := decodeToolFailure(t, callDomainResult(t, session, test.tool, test.args))
		if failure.Code != ida.ErrorInvalidArgument {
			t.Fatal(failure)
		}
	}
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if backend.listCalls != 0 {
		t.Fatal("invalid combinations discovered IDA")
	}
}
