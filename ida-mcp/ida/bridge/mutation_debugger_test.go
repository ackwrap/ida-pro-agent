package bridge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"ida-mcp/ida/rpc"
)

func TestMutationAndDebuggerClientsUseStaticTypedMethods(t *testing.T) {
	instance := testInstanceDescriptor()
	action := map[string]any{"accepted": true, "state": "running", "running": true, "suspended": false, "instructionPointer": nil, "threadId": nil}
	tests := []struct {
		method string
		result any
		call   func(*Client) error
	}{
		{methodChangeSetPreview, map[string]any{"previewId": "p", "items": []any{map[string]any{"index": 0, "before": "a", "after": "b", "conflict": false}}, "applicable": true}, func(client *Client) error {
			_, err := client.PreviewChangeSet(context.Background(), instance, ChangeSetPreviewParams{Operations: []ChangeOperation{{Kind: "comment.set", Value: "b"}}})
			return err
		}},
		{methodChangeSetApply, map[string]any{"changeId": "c", "items": []any{map[string]any{"index": 0, "applied": true, "error": nil}}, "applied": true}, func(client *Client) error {
			_, err := client.ApplyChangeSet(context.Background(), instance, ChangeSetApplyParams{PreviewID: "p", Operations: []ChangeOperation{{Kind: "comment.set", Value: "b"}}})
			return err
		}},
		{methodChangeSetRollback, map[string]any{"changeId": "c", "items": []any{map[string]any{"index": 0, "applied": true, "error": nil}}, "applied": true}, func(client *Client) error {
			_, err := client.RollbackChangeSet(context.Background(), instance, ChangeSetRollbackParams{ChangeID: "c"})
			return err
		}},
		{methodChangeSetAudit, map[string]any{"items": []any{}}, func(client *Client) error {
			_, err := client.ChangeSetAudit(context.Background(), instance, ChangeSetAuditParams{})
			return err
		}},
		{methodPatchAssemble, map[string]any{"address": "0x0", "bytes": "90", "size": 1, "instructions": []any{map[string]any{"startAddress": "0x0", "endAddress": "0x1", "offset": 0, "size": 1}}}, func(client *Client) error {
			_, err := client.AssemblePatch(context.Background(), instance, PatchAssembleParams{Instruction: "nop"})
			return err
		}},
		{methodDiffBeforeAfter, map[string]any{"before": "a", "after": "b", "action": map[string]any{"kind": "comment.set", "address": "0x0", "value": "b", "repeatable": false}, "changed": true}, func(client *Client) error {
			address := rpc.Address(0)
			repeatable := false
			_, err := client.DiffBeforeAfter(context.Background(), instance, DiffBeforeAfterParams{Action: ChangeOperation{Kind: "comment.set", Address: &address, Value: "b", Repeatable: &repeatable}})
			return err
		}},
		{methodDebuggerInfo, map[string]any{"state": "not_running", "running": false, "suspended": false, "instructionPointer": nil, "threadId": nil}, func(client *Client) error { _, err := client.DebuggerInfo(context.Background(), instance); return err }},
		{methodDebuggerStart, action, func(client *Client) error { _, err := client.DebuggerStart(context.Background(), instance); return err }},
		{methodDebuggerExit, action, func(client *Client) error { _, err := client.DebuggerExit(context.Background(), instance); return err }},
		{methodDebuggerControl, action, func(client *Client) error {
			_, err := client.DebuggerControl(context.Background(), instance, DebuggerControlParams{Action: "continue"})
			return err
		}},
		{methodDebuggerBreakpoints, map[string]any{"items": []any{}}, func(client *Client) error {
			_, err := client.DebuggerBreakpoints(context.Background(), instance, DebuggerBreakpointsParams{})
			return err
		}},
		{methodDebuggerRegisters, map[string]any{"items": []any{}}, func(client *Client) error {
			_, err := client.DebuggerRegisters(context.Background(), instance, DebuggerRegistersParams{})
			return err
		}},
		{methodDebuggerStackTrace, map[string]any{"items": []any{}}, func(client *Client) error {
			_, err := client.DebuggerStackTrace(context.Background(), instance, DebuggerStackTraceParams{})
			return err
		}},
		{methodDebuggerMemoryRead, map[string]any{"address": "0x0", "bytes": "90"}, func(client *Client) error {
			_, err := client.DebuggerReadMemory(context.Background(), instance, DebuggerMemoryReadParams{Length: 1})
			return err
		}},
		{methodDebuggerMemoryWrite, action, func(client *Client) error {
			_, err := client.DebuggerWriteMemory(context.Background(), instance, DebuggerMemoryWriteParams{Bytes: "90"})
			return err
		}},
		{string(methodScriptExecute), map[string]any{"language": "python", "success": true, "result": nil, "stdout": "ok\n", "stderr": "", "truncated": false, "originalSize": 3}, func(client *Client) error {
			_, err := client.ExecuteScript(context.Background(), instance, ScriptExecuteParams{Language: "python", Code: "print('ok')"})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.method, func(t *testing.T) {
			client := functionAnalysisTestClient(t, instance, test.method, test.result)
			if err := test.call(client); err != nil {
				t.Fatalf("call: %v", err)
			}
		})
	}
}

func TestTypedBridgeDecodersRejectUnknownAndOversizedResults(t *testing.T) {
	instance := testInstanceDescriptor()
	tests := []struct {
		name, method, result string
		call                 func(*Client) error
	}{
		{"mutation unknown", methodChangeSetPreview, `{"previewId":"p","items":[],"applicable":true,"extra":true}`, func(client *Client) error {
			_, err := client.PreviewChangeSet(context.Background(), instance, ChangeSetPreviewParams{})
			return err
		}},
		{"debugger unknown", methodDebuggerInfo, `{"state":"not_running","running":false,"suspended":false,"instructionPointer":null,"threadId":null,"extra":true}`, func(client *Client) error { _, err := client.DebuggerInfo(context.Background(), instance); return err }},
		{"debugger missing", methodDebuggerInfo, `{"state":"not_running","running":false,"suspended":false,"instructionPointer":null}`, func(client *Client) error { _, err := client.DebuggerInfo(context.Background(), instance); return err }},
		{"debugger contradictory", methodDebuggerInfo, `{"state":"not_running","running":true,"suspended":false,"instructionPointer":null,"threadId":null}`, func(client *Client) error { _, err := client.DebuggerInfo(context.Background(), instance); return err }},
		{"breakpoint union unknown", methodDebuggerBreakpoints, `{"items":[],"accepted":true}`, func(client *Client) error {
			_, err := client.DebuggerBreakpoints(context.Background(), instance, DebuggerBreakpointsParams{})
			return err
		}},
		{"invalid address", methodDebuggerMemoryRead, `{"address":"0xfffffffffffffffff","bytes":"90"}`, func(client *Client) error {
			_, err := client.DebuggerReadMemory(context.Background(), instance, DebuggerMemoryReadParams{Length: 1})
			return err
		}},
		{"memory length mismatch", methodDebuggerMemoryRead, `{"address":"0x0","bytes":"9000"}`, func(client *Client) error {
			_, err := client.DebuggerReadMemory(context.Background(), instance, DebuggerMemoryReadParams{Length: 1})
			return err
		}},
		{"script unknown", string(methodScriptExecute), `{"language":"python","success":true,"result":null,"stdout":"ok\\n","stderr":"","truncated":false,"originalSize":3,"path":"x.py"}`, func(client *Client) error {
			_, err := client.ExecuteScript(context.Background(), instance, ScriptExecuteParams{Language: "python", Code: "print('ok')"})
			return err
		}},
		{"oversized preview", methodChangeSetPreview, `{"previewId":"p","items":[{"index":0,"before":"` + strings.Repeat("x", 65537) + `","after":"b","conflict":false}],"applicable":true}`, func(client *Client) error {
			result, err := client.PreviewChangeSet(context.Background(), instance, ChangeSetPreviewParams{})
			if err == nil {
				err = result.Validate(1)
			}
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := functionAnalysisTestClient(t, instance, test.method, json.RawMessage(test.result))
			if err := test.call(client); err == nil {
				t.Fatal("invalid result was accepted")
			}
		})
	}
}
