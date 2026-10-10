package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"ida-mcp/ida"
)

type typedDomainBackend struct {
	*fakeBackend
	mutex            sync.Mutex
	calls            []string
	previewParams    ida.ChangeSetPreviewParams
	applyParams      ida.ChangeSetApplyParams
	auditParams      ida.ChangeSetAuditParams
	breakpointParams ida.DebuggerBreakpointsParams
	oversizedAudit   bool
	previewConflict  bool
	returnConflict   bool
}

type oversizedDebuggerBackend struct{ *typedDomainBackend }

func (*oversizedDebuggerBackend) DebuggerRegisters(context.Context, string, ida.DebuggerRegistersParams) (ida.DebuggerRegistersResult, error) {
	return ida.DebuggerRegistersResult{Items: []ida.ThreadRegisters{{
		ThreadID: 1, Registers: []ida.RegisterValue{{Name: "rax", Value: strings.Repeat("x", maxToolItemOutputBytes)}},
	}}}, nil
}

func newTypedDomainBackend() *typedDomainBackend {
	return &typedDomainBackend{fakeBackend: &fakeBackend{}}
}
func (backend *typedDomainBackend) record(name string) {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	backend.calls = append(backend.calls, name)
}

func (backend *typedDomainBackend) PreviewChangeSet(_ context.Context, _ string, params ida.ChangeSetPreviewParams) (ida.ChangeSetPreview, error) {
	backend.record(ToolChangeSetPreview)
	backend.previewParams = params
	return ida.ChangeSetPreview{PreviewID: "preview-1", Items: []ida.ChangePreviewItem{{Index: 0, Before: "90", After: "cc", Conflict: backend.previewConflict}}, Applicable: !backend.previewConflict}, nil
}
func (backend *typedDomainBackend) ApplyChangeSet(_ context.Context, _ string, params ida.ChangeSetApplyParams) (ida.ChangeSetApplyResult, error) {
	backend.record(ToolChangeSetApply)
	backend.applyParams = params
	if backend.returnConflict {
		return ida.ChangeSetApplyResult{}, ida.NewError(ida.ErrorConflict, "conflict", false)
	}
	return testChangeApply(), nil
}
func (backend *typedDomainBackend) RollbackChangeSet(context.Context, string, ida.ChangeSetRollbackParams) (ida.ChangeSetApplyResult, error) {
	backend.record(ToolChangeSetRollback)
	return testChangeApply(), nil
}
func (backend *typedDomainBackend) ChangeSetAudit(_ context.Context, _ string, params ida.ChangeSetAuditParams) (ida.ChangeSetAuditResult, error) {
	backend.record(ToolChangeSetAudit)
	backend.auditParams = params
	before := "len=3,fnv64=0000000000000000"
	if backend.oversizedAudit {
		before = strings.Repeat("x", maxToolItemOutputBytes)
	}
	return ida.ChangeSetAuditResult{Items: []ida.ChangeAuditEntry{{ChangeID: "change-1", SessionID: "len=36,fnv64=0000000000000000", Operation: "comment.set", Address: 0, Before: before, After: "len=3,fnv64=0000000000000000", Success: true, TimestampM: 1}}}, nil
}
func (backend *typedDomainBackend) AssemblePatch(context.Context, string, ida.PatchAssembleParams) (ida.PatchAssemblyResult, error) {
	backend.record(ToolPatchAssemble)
	return ida.PatchAssemblyResult{Address: 0, Bytes: "90", Size: 1, Instructions: []ida.AssemblyInstruction{{StartAddress: 0, EndAddress: 1, Size: 1}}}, nil
}
func (backend *typedDomainBackend) DiffBeforeAfter(_ context.Context, _ string, params ida.DiffBeforeAfterParams) (ida.DiffBeforeAfterResult, error) {
	backend.record(ToolDiffBeforeAfter)
	return ida.DiffBeforeAfterResult{Before: "old", After: "new", Action: params.Action, Changed: true}, nil
}
func (backend *typedDomainBackend) DebuggerInfo(context.Context, string) (ida.DebuggerInfo, error) {
	backend.record(ToolDebuggerInfo)
	return ida.DebuggerInfo{State: "not_running"}, nil
}
func (backend *typedDomainBackend) DebuggerStart(context.Context, string) (ida.DebuggerActionResult, error) {
	backend.record(ToolDebuggerStart)
	return testDebuggerAction(), nil
}
func (backend *typedDomainBackend) DebuggerExit(context.Context, string) (ida.DebuggerActionResult, error) {
	backend.record(ToolDebuggerExit)
	return testDebuggerAction(), nil
}
func (backend *typedDomainBackend) DebuggerControl(context.Context, string, ida.DebuggerControlParams) (ida.DebuggerActionResult, error) {
	backend.record(ToolDebuggerControl)
	return testDebuggerAction(), nil
}
func (backend *typedDomainBackend) DebuggerBreakpoints(_ context.Context, _ string, params ida.DebuggerBreakpointsParams) (ida.DebuggerBreakpointsResult, error) {
	backend.record(ToolDebuggerBreakpoints)
	backend.breakpointParams = params
	if params.Action != nil {
		action := testDebuggerAction()
		return ida.DebuggerBreakpointsResult{Action: &action}, nil
	}
	items := []ida.BreakpointInfo{}
	return ida.DebuggerBreakpointsResult{Items: &items}, nil
}
func (backend *typedDomainBackend) DebuggerRegisters(context.Context, string, ida.DebuggerRegistersParams) (ida.DebuggerRegistersResult, error) {
	backend.record(ToolDebuggerRegisters)
	return ida.DebuggerRegistersResult{Items: []ida.ThreadRegisters{}}, nil
}
func (backend *typedDomainBackend) DebuggerStackTrace(context.Context, string, ida.DebuggerStackTraceParams) (ida.DebuggerStackTraceResult, error) {
	backend.record(ToolDebuggerStackTrace)
	return ida.DebuggerStackTraceResult{Items: []ida.StackTraceFrame{}}, nil
}
func (backend *typedDomainBackend) DebuggerReadMemory(context.Context, string, ida.DebuggerMemoryReadParams) (ida.DebuggerMemoryResult, error) {
	backend.record(ToolDebuggerMemoryRead)
	return ida.DebuggerMemoryResult{Address: 0, Bytes: "90"}, nil
}
func (backend *typedDomainBackend) DebuggerWriteMemory(context.Context, string, ida.DebuggerMemoryWriteParams) (ida.DebuggerActionResult, error) {
	backend.record(ToolDebuggerMemoryWrite)
	return testDebuggerAction(), nil
}

func testChangeApply() ida.ChangeSetApplyResult {
	return ida.ChangeSetApplyResult{ChangeID: "change-1", Items: []ida.ChangeApplyItem{{Index: 0, Applied: true}}, Applied: true}
}
func testDebuggerAction() ida.DebuggerActionResult {
	return ida.DebuggerActionResult{Accepted: true, State: "running", Running: true}
}

func TestMutationAndDebuggerMethodsDispatchTypedSuccess(t *testing.T) {
	backend := newTypedDomainBackend()
	session := connectTestClient(t, backend)
	operation := map[string]any{"kind": "comment.set", "address": "0x0", "value": "new", "repeatable": false}
	tests := []struct {
		method, domain string
		arguments      map[string]any
	}{
		{ToolChangeSetPreview, ToolDomainChanges, map[string]any{"operations": []any{operation}}},
		{ToolChangeSetApply, ToolDomainChanges, map[string]any{"previewId": "preview-1", "operations": []any{operation}}},
		{ToolChangeSetRollback, ToolDomainChanges, map[string]any{"changeId": "change-1"}},
		{ToolChangeSetAudit, ToolDomainChanges, map[string]any{"offset": 0, "limit": 1}},
		{ToolPatchAssemble, ToolDomainPatch, map[string]any{"address": "0x0", "instruction": "nop"}},
		{ToolDiffBeforeAfter, ToolDomainAnalysis, map[string]any{"action": operation}},
		{ToolDebuggerInfo, ToolDomainDebugger, map[string]any{}},
		{ToolDebuggerStart, ToolDomainDebugger, map[string]any{}},
		{ToolDebuggerExit, ToolDomainDebugger, map[string]any{}},
		{ToolDebuggerControl, ToolDomainDebugger, map[string]any{"action": "run_to", "address": "0x0"}},
		{ToolDebuggerBreakpoints, ToolDomainDebugger, map[string]any{}},
		{ToolDebuggerRegisters, ToolDomainDebugger, map[string]any{}},
		{ToolDebuggerStackTrace, ToolDomainDebugger, map[string]any{}},
		{ToolDebuggerMemoryRead, ToolDomainDebugger, map[string]any{"address": "0x0", "length": 1}},
		{ToolDebuggerMemoryWrite, ToolDomainDebugger, map[string]any{"address": "0x0", "bytes": "90"}},
	}
	for _, test := range tests {
		t.Run(test.method, func(t *testing.T) {
			test.arguments["instanceId"] = testInstanceA
			var output domainCallOutput
			callDomainAction(t, session, test.domain, map[string]any{"action": "call", "method": test.method, "arguments": test.arguments}, &output)
			if output.Method != test.method || !json.Valid(output.Result) {
				t.Fatalf("output = %+v", output)
			}
		})
	}
	backend.mutex.Lock()
	calls := append([]string(nil), backend.calls...)
	backend.mutex.Unlock()
	if len(calls) != len(tests) {
		t.Fatalf("typed calls = %v", calls)
	}
	operationResult := backend.previewParams.Operations[0]
	if operationResult.Address == nil || *operationResult.Address != 0 || operationResult.Repeatable == nil || *operationResult.Repeatable {
		t.Fatalf("optional zero values were lost: %+v", operationResult)
	}
	var offsetOutput domainCallOutput
	callDomainAction(t, session, ToolDomainChanges, map[string]any{
		"action": "call", "method": ToolChangeSetPreview, "arguments": map[string]any{
			"instanceId": testInstanceA,
			"operations": []any{map[string]any{
				"kind": "operand.struct_offset", "address": "0x0", "value": "0", "subject": "S", "offset": 0,
			}},
		},
	}, &offsetOutput)
	operationResult = backend.previewParams.Operations[0]
	if operationResult.Offset == nil || *operationResult.Offset != 0 {
		t.Fatalf("optional offset zero was lost: %+v", operationResult)
	}
	if backend.auditParams.Offset == nil || *backend.auditParams.Offset != 0 {
		t.Fatalf("audit offset presence was lost: %+v", backend.auditParams)
	}
}

func TestPatchWriteMethodsUseSingleOperationChangeSets(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		arguments map[string]any
		kind      string
		value     string
		subject   string
	}{
		{
			name: "bytes", method: ToolPatchWriteBytes,
			arguments: map[string]any{"address": "0x401000", "bytes": "90CC", "expectedBytes": "558b"},
			kind:      "patch.bytes", value: "90CC",
		},
		{
			name: "integer", method: ToolPatchWriteInteger,
			arguments: map[string]any{"address": "0x401000", "value": "0x1234", "integerType": "u16be", "expectedBytes": "558b"},
			kind:      "patch.integer", value: "0x1234", subject: "u16be",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newTypedDomainBackend()
			session := connectTestClient(t, backend)
			arguments := cloneMap(test.arguments)
			arguments["instanceId"] = testInstanceA
			var output domainCallOutput
			callDomainAction(t, session, ToolDomainPatch, map[string]any{
				"action": "call", "method": test.method, "arguments": arguments,
			}, &output)
			var result patchWriteResult
			if err := json.Unmarshal(output.Result, &result); err != nil {
				t.Fatalf("decode result: %v", err)
			}
			if result.Address != "0x401000" || result.Before != "90" || result.After != "cc" || result.ChangeID != "change-1" || !result.Applied {
				t.Fatalf("result = %+v", result)
			}
			if len(backend.calls) != 2 || backend.calls[0] != ToolChangeSetPreview || backend.calls[1] != ToolChangeSetApply {
				t.Fatalf("calls = %v", backend.calls)
			}
			if len(backend.previewParams.Operations) != 1 || len(backend.applyParams.Operations) != 1 || backend.applyParams.PreviewID != "preview-1" {
				t.Fatalf("preview/apply params = %+v / %+v", backend.previewParams, backend.applyParams)
			}
			operation := backend.previewParams.Operations[0]
			if operation.Kind != test.kind || operation.Address == nil || *operation.Address != 0x401000 || operation.Value != test.value || operation.Expected == nil || *operation.Expected != "558B" {
				t.Fatalf("operation = %+v", operation)
			}
			if (test.subject == "" && operation.Subject != nil) || (test.subject != "" && (operation.Subject == nil || *operation.Subject != test.subject)) {
				t.Fatalf("operation subject = %+v", operation.Subject)
			}
			if backend.applyParams.Operations[0].Kind != operation.Kind || backend.applyParams.Operations[0].Value != operation.Value {
				t.Fatalf("apply operation differs: %+v", backend.applyParams.Operations[0])
			}
		})
	}
}

func TestPatchWriteDoesNotApplyConflictingPreview(t *testing.T) {
	backend := newTypedDomainBackend()
	backend.previewConflict = true
	session := connectTestClient(t, backend)
	result := callDomainResult(t, session, ToolDomainPatch, map[string]any{
		"action": "call", "method": ToolPatchWriteBytes,
		"arguments": map[string]any{"instanceId": testInstanceA, "address": "0x401000", "bytes": "90", "expectedBytes": "CC"},
	})
	if !result.IsError {
		t.Fatal("conflicting patch preview was applied")
	}
	if len(backend.calls) != 1 || backend.calls[0] != ToolChangeSetPreview {
		t.Fatalf("calls = %v", backend.calls)
	}
}

func TestPatchWritePropagatesApplyConflict(t *testing.T) {
	backend := newTypedDomainBackend()
	backend.returnConflict = true
	session := connectTestClient(t, backend)
	result := callDomainResult(t, session, ToolDomainPatch, map[string]any{
		"action": "call", "method": ToolPatchWriteInteger,
		"arguments": map[string]any{"instanceId": testInstanceA, "address": "0x401000", "value": "1", "integerType": "u8"},
	})
	if !result.IsError {
		t.Fatal("apply conflict was not returned")
	}
	if len(backend.calls) != 2 || backend.calls[0] != ToolChangeSetPreview || backend.calls[1] != ToolChangeSetApply {
		t.Fatalf("calls = %v", backend.calls)
	}
}

func TestNewDomainSchemasRejectUnknownAndConditionalInputs(t *testing.T) {
	backend := newTypedDomainBackend()
	session := connectTestClient(t, backend)
	operation := map[string]any{"kind": "comment.set", "address": "0x401000", "value": "x"}
	valid := map[string]struct {
		domain string
		args   map[string]any
	}{
		ToolChangeSetPreview: {ToolDomainChanges, map[string]any{"operations": []any{operation}}}, ToolChangeSetApply: {ToolDomainChanges, map[string]any{"previewId": "p", "operations": []any{operation}}}, ToolChangeSetRollback: {ToolDomainChanges, map[string]any{"changeId": "c"}}, ToolChangeSetAudit: {ToolDomainChanges, map[string]any{}}, ToolPatchAssemble: {ToolDomainPatch, map[string]any{"address": "0x0", "instruction": "nop"}}, ToolPatchWriteBytes: {ToolDomainPatch, map[string]any{"address": "0x0", "bytes": "90"}}, ToolPatchWriteInteger: {ToolDomainPatch, map[string]any{"address": "0x0", "value": "1", "integerType": "u8"}}, ToolDiffBeforeAfter: {ToolDomainAnalysis, map[string]any{"action": operation}}, ToolDebuggerInfo: {ToolDomainDebugger, map[string]any{}}, ToolDebuggerStart: {ToolDomainDebugger, map[string]any{}}, ToolDebuggerExit: {ToolDomainDebugger, map[string]any{}}, ToolDebuggerControl: {ToolDomainDebugger, map[string]any{"action": "continue"}}, ToolDebuggerBreakpoints: {ToolDomainDebugger, map[string]any{}}, ToolDebuggerRegisters: {ToolDomainDebugger, map[string]any{}}, ToolDebuggerStackTrace: {ToolDomainDebugger, map[string]any{}}, ToolDebuggerMemoryRead: {ToolDomainDebugger, map[string]any{"address": "0x0", "length": 1}}, ToolDebuggerMemoryWrite: {ToolDomainDebugger, map[string]any{"address": "0x0", "bytes": "90"}},
	}
	for method, test := range valid {
		args := cloneMap(test.args)
		args["unknown"] = true
		if result := callDomainResult(t, session, test.domain, map[string]any{"action": "call", "method": method, "arguments": args}); !result.IsError {
			t.Errorf("%s accepted unknown field", method)
		}
	}
	for _, test := range []struct {
		method string
		args   map[string]any
	}{
		{ToolDebuggerControl, map[string]any{"action": "run_to"}},
		{ToolDebuggerControl, map[string]any{"action": "continue", "address": "0x1"}},
		{ToolDebuggerBreakpoints, map[string]any{"action": "add"}},
		{ToolDebuggerBreakpoints, map[string]any{"action": "delete", "address": "0x1", "condition": "x"}},
		{ToolDebuggerBreakpoints, map[string]any{"action": "toggle", "address": "0x1"}},
		{ToolDebuggerRegisters, map[string]any{"threadMode": "specified"}},
		{ToolDebuggerRegisters, map[string]any{"threadMode": "current", "threadIds": []any{1}}},
		{ToolChangeSetPreview, map[string]any{"operations": []any{map[string]any{
			"kind": "comment.set", "address": "0x1", "value": "x", "offset": 0,
		}}}},
		{ToolPatchWriteBytes, map[string]any{"address": "0x1", "bytes": "9"}},
		{ToolPatchWriteInteger, map[string]any{"address": "0x1", "value": "1", "integerType": "u16"}},
	} {
		domain := ToolDomainDebugger
		if test.method == ToolChangeSetPreview {
			domain = ToolDomainChanges
		} else if test.method == ToolPatchWriteBytes || test.method == ToolPatchWriteInteger {
			domain = ToolDomainPatch
		}
		if result := callDomainResult(t, session, domain, map[string]any{"action": "call", "method": test.method, "arguments": test.args}); !result.IsError {
			t.Errorf("%s accepted inconsistent input %+v", test.method, test.args)
		}
	}
	for _, arguments := range []map[string]any{
		{"instanceId": testInstanceA, "action": "step_until_return"},
		{"instanceId": testInstanceA, "threadIds": []any{1}},
		{"instanceId": testInstanceA, "names": []any{"rax"}},
	} {
		method := ToolDebuggerControl
		if _, ok := arguments["threadIds"]; ok {
			method = ToolDebuggerRegisters
		}
		if _, ok := arguments["names"]; ok {
			method = ToolDebuggerRegisters
		}
		var output domainCallOutput
		callDomainAction(t, session, ToolDomainDebugger, map[string]any{
			"action": "call", "method": method, "arguments": arguments,
		}, &output)
	}
}

func TestDatabaseMutationSchemasAndTypedDispatch(t *testing.T) {
	backend := newTypedDomainBackend()
	session := connectTestClient(t, backend)
	valid := []map[string]any{
		{"kind": "segment.rename", "address": "0x401000", "value": "TEXT_NEW"},
		{"kind": "segment.permissions", "address": "0x402000", "value": "r-x"},
		{"kind": "function.flags", "address": "0x403000", "value": "noreturn,library"},
		{"kind": "xref.code.add", "address": "0x404000", "value": "0x405000", "subject": "jump_near"},
		{"kind": "xref.data.delete", "address": "0x406000", "value": "0x407000", "subject": "read"},
		{"kind": "function.end", "address": "0x408000", "value": "0x408100"},
		{"kind": "function.chunk.add", "address": "0x409000", "value": "0x40a000", "subject": "0x40a100"},
	}
	for _, operation := range valid {
		var output domainCallOutput
		callDomainAction(t, session, ToolDomainChanges, map[string]any{
			"action": "call", "method": ToolChangeSetPreview,
			"arguments": map[string]any{"instanceId": testInstanceA, "operations": []any{operation}},
		}, &output)
		if backend.previewParams.Operations[0].Kind != operation["kind"] {
			t.Fatalf("typed operation = %+v", backend.previewParams.Operations[0])
		}
	}
	invalid := []map[string]any{
		{"kind": "segment.permissions", "address": "0x1", "value": "rwx!"},
		{"kind": "function.flags", "address": "0x1", "value": "library,library"},
		{"kind": "xref.code.add", "address": "0x1", "value": "0x2", "subject": "read"},
		{"kind": "xref.data.add", "address": "0x1", "value": "bad", "subject": "read"},
		{"kind": "function.end", "address": "0x1", "value": "bad"},
		{"kind": "function.chunk.add", "address": "0x1", "value": "0x3", "subject": "0x2"},
	}
	for _, operation := range invalid {
		result := callDomainResult(t, session, ToolDomainChanges, map[string]any{
			"action": "call", "method": ToolChangeSetPreview,
			"arguments": map[string]any{"instanceId": testInstanceA, "operations": []any{operation}},
		})
		if !result.IsError {
			t.Errorf("accepted invalid database mutation %+v", operation)
		}
	}
}

func TestDebuggerBreakpointMutationPreservesOptionalZeroAndNull(t *testing.T) {
	backend := newTypedDomainBackend()
	session := connectTestClient(t, backend)
	var output domainCallOutput
	callDomainAction(t, session, ToolDomainDebugger, map[string]any{
		"action": "call", "method": ToolDebuggerBreakpoints, "arguments": map[string]any{
			"instanceId": testInstanceA, "action": "add", "address": "0x0",
			"enabled": false, "size": 0, "condition": nil,
		},
	}, &output)
	params := backend.breakpointParams
	if params.Address == nil || *params.Address != 0 || params.Enabled == nil || *params.Enabled ||
		params.Size == nil || *params.Size != 0 || !params.Condition.Present || !params.Condition.Null {
		t.Fatalf("optional breakpoint values were lost: %+v", params)
	}
	var action ida.DebuggerActionResult
	if err := json.Unmarshal(output.Result, &action); err != nil || !action.Accepted {
		t.Fatalf("breakpoint action output = %s, err=%v", output.Result, err)
	}
}

func TestTypedDomainCapabilityErrorsAndOutputBudget(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})
	if result := callDomainResult(t, session, ToolDomainDebugger, map[string]any{"action": "call", "method": ToolDebuggerInfo, "arguments": map[string]any{}}); !result.IsError {
		t.Fatal("backend without DebuggerBackend was accepted")
	}
	backend := newTypedDomainBackend()
	backend.returnConflict = true
	session = connectTestClient(t, backend)
	operation := map[string]any{"kind": "comment.set", "address": "0x1", "value": "x"}
	if result := callDomainResult(t, session, ToolDomainChanges, map[string]any{"action": "call", "method": ToolChangeSetApply, "arguments": map[string]any{"instanceId": testInstanceA, "previewId": "p", "operations": []any{operation}}}); !result.IsError {
		t.Fatal("typed backend error was not returned")
	}
	backend = newTypedDomainBackend()
	backend.oversizedAudit = true
	session = connectTestClient(t, backend)
	if result := callDomainResult(t, session, ToolDomainChanges, map[string]any{"action": "call", "method": ToolChangeSetAudit, "arguments": map[string]any{"instanceId": testInstanceA}}); !result.IsError {
		t.Fatal("oversized audit item was accepted")
	}
	debuggerBackend := &oversizedDebuggerBackend{typedDomainBackend: newTypedDomainBackend()}
	session = connectTestClient(t, debuggerBackend)
	if result := callDomainResult(t, session, ToolDomainDebugger, map[string]any{"action": "call", "method": ToolDebuggerRegisters, "arguments": map[string]any{"instanceId": testInstanceA}}); !result.IsError {
		t.Fatal("oversized debugger register was accepted")
	}
}

func cloneMap(input map[string]any) map[string]any {
	result := make(map[string]any, len(input)+1)
	for key, value := range input {
		result[key] = value
	}
	return result
}
