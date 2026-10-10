package bridge

import (
	"context"
	"encoding/json"
	"testing"

	"ida-mcp/ida/rpc"
)

func TestCatalogClientsUseDistinctStaticTypedMethods(t *testing.T) {
	instance := testInstanceDescriptor()
	address := rpc.Address(0x401000)
	metadata := map[string]any{
		"database": "sample.i64", "processor": "metapc", "architecture": "x86_64",
		"addressBits": 64, "addressRange": nil,
		"segments": map[string]any{"total": 0, "code": 0, "data": 0, "bss": 0, "other": 0, "readable": 0, "writable": 0, "executable": 0},
	}
	survey := map[string]any{
		"mode": "full", "metadata": metadata,
		"statistics":       map[string]any{"sampledFunctions": 0, "sampledStrings": 0, "sampledImports": 0, "functionsTruncated": false, "stringsTruncated": false, "importsTruncated": false},
		"importCategories": []any{}, "callGraph": map[string]any{"roots": 0, "nodes": 0, "edges": 0, "truncated": false},
		"metrics":   map[string]any{"segments": 0, "functions": map[string]any{"sampled": 0, "hasMore": false}, "strings": map[string]any{"sampled": 0, "hasMore": false}, "imports": map[string]any{"sampled": 0, "hasMore": false}},
		"truncated": false, "budget": map[string]any{"requestedItems": 60, "perSection": 20},
		"functions": map[string]any{"items": []any{}, "nextCursor": nil, "hasMore": false},
		"strings":   map[string]any{"items": []any{}, "nextCursor": nil, "hasMore": false},
	}
	tests := []struct {
		method string
		result any
		call   func(*Client) error
	}{
		{methodSystemPing, map[string]any{"status": "ok"}, func(client *Client) error { _, err := client.SystemPing(context.Background(), instance); return err }},
		{methodSystemMethods, map[string]any{"methods": []any{"system.methods", "system.ping"}}, func(client *Client) error { _, err := client.SystemMethods(context.Background(), instance); return err }},
		{methodInstanceInfo, map[string]any{"instance_id": instance.InstanceID, "pid": instance.PID, "ida_version": "9.4", "database": "sample.i64", "input_file": "sample.exe", "processor": "metapc", "bitness": 64, "architecture": "x86_64", "capabilities": map[string]any{"decompiler": false, "debugger": false, "ui": false, "address_bits": 64}}, func(client *Client) error { _, err := client.InstanceInfo(context.Background(), instance); return err }},
		{methodDatabaseSurvey, survey, func(client *Client) error {
			_, err := client.DatabaseSurvey(context.Background(), instance, DatabaseSurveyParams{Mode: "full", Budget: 60})
			return err
		}},
		{methodDatabaseSave, map[string]any{"saved": true, "explicitTarget": false}, func(client *Client) error {
			_, err := client.DatabaseSave(context.Background(), instance, DatabaseSaveParams{})
			return err
		}},
		{methodFunctionCallers, map[string]any{"entryAddress": "0x401000", "items": []any{}, "nextOffset": nil, "hasMore": false}, func(client *Client) error {
			_, err := client.FunctionCallers(context.Background(), instance, FunctionCallersParams{Address: address, Limit: 20})
			return err
		}},
		{methodFunctionCallGraph, map[string]any{"nodes": []any{map[string]any{"address": "0x401000", "name": "main", "depth": 0}}, "edges": []any{}, "truncated": false}, func(client *Client) error {
			_, err := client.FunctionCallGraph(context.Background(), instance, FunctionCallGraphParams{Roots: []rpc.Address{address}, MaxNodes: 100, MaxEdges: 200})
			return err
		}},
		{methodFunctionProfile, map[string]any{"items": []any{}, "nextCursor": nil, "hasMore": false, "metrics": map[string]any{"candidates": 0, "matched": 0, "sampledInstructions": 0}}, func(client *Client) error {
			_, err := client.FunctionProfile(context.Background(), instance, FunctionProfileParams{MaxSize: 1048576, Limit: 20})
			return err
		}},
		{methodFunctionExport, map[string]any{"format": "prototypes", "content": "int main(void);\n", "truncated": false, "originalSize": 16}, func(client *Client) error {
			_, err := client.FunctionExport(context.Background(), instance, FunctionExportParams{Addresses: []rpc.Address{address}, Format: "prototypes", MaxBytes: 1024})
			return err
		}},
		{methodFunctionAnalyze, map[string]any{"sections": []any{"overview"}, "items": []any{map[string]any{"address": "0x401000", "name": "main"}}}, func(client *Client) error {
			_, err := client.FunctionAnalyze(context.Background(), instance, FunctionAnalyzeParams{Addresses: []rpc.Address{address}, Sections: []string{"overview"}})
			return err
		}},
		{methodFunctionAnalyzeBatch, map[string]any{"sections": []any{"metrics"}, "items": []any{map[string]any{"address": "0x401000", "name": "main"}}}, func(client *Client) error {
			_, err := client.FunctionAnalyzeBatch(context.Background(), instance, FunctionAnalyzeParams{Addresses: []rpc.Address{address}, Sections: []string{"metrics"}})
			return err
		}},
		{methodFunctionStackFrame, map[string]any{"entryAddress": "0x401000", "size": 0, "variables": []any{}}, func(client *Client) error {
			_, err := client.FunctionStackFrame(context.Background(), instance, FunctionStackFrameParams{Address: address})
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

func TestCatalogClientStrictlyRejectsUnknownAnalyzeOutput(t *testing.T) {
	instance := testInstanceDescriptor()
	client := functionAnalysisTestClient(t, instance, methodFunctionAnalyze, json.RawMessage(`{"sections":["overview"],"items":[{"address":"0x401000","extra":true}]}`))
	_, err := client.FunctionAnalyze(context.Background(), instance, FunctionAnalyzeParams{Addresses: []rpc.Address{0x401000}, Sections: []string{"overview"}})
	if err == nil {
		t.Fatal("unknown analyze output field was accepted")
	}
}
