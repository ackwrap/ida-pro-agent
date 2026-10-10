package bridge

import (
	"context"
	"encoding/json"
	"testing"

	"ida-mcp/ida/rpc"
)

func TestReadonlyAnalysisClientsUseStaticTypedMethods(t *testing.T) {
	instance := testInstanceDescriptor()
	address := rpc.Address(0x401000)
	tests := []struct {
		method string
		result any
		call   func(*Client) error
	}{
		{string(methodInstructionGet), map[string]any{"requestedAddress": "0x401001", "address": "0x401000", "end": "0x401002", "size": 2, "kind": "code", "bytes": "9090", "mnemonic": "nop", "text": "nop", "operands": []any{}}, func(c *Client) error {
			_, e := c.InstructionGet(context.Background(), instance, AddressParams{Address: address + 1})
			return e
		}},
		{string(methodFunctionChunks), map[string]any{"entryAddress": "0x401000", "items": []any{map[string]any{"start": "0x401000", "end": "0x401010", "kind": "entry"}}, "nextOffset": 1, "hasMore": true}, func(c *Client) error {
			_, e := c.FunctionChunks(context.Background(), instance, ReadonlyPageParams{Address: address, Limit: 1})
			return e
		}},
		{string(methodFixupGet), fixupResult(), func(c *Client) error {
			_, e := c.FixupGet(context.Background(), instance, AddressParams{Address: address})
			return e
		}},
		{string(methodFixupList), map[string]any{"items": []any{fixupResult()}, "nextAddress": "0x401004", "hasMore": true}, func(c *Client) error {
			_, e := c.FixupList(context.Background(), instance, AddressListParams{Limit: 1})
			return e
		}},
		{string(methodSwitchGet), map[string]any{"address": "0x401000", "cases": []any{}, "defaultTarget": nil, "flags": map[string]any{"sparse": false, "custom": false, "indirect": false, "subtract": false, "userDefined": false}, "jumpTable": nil, "caseCount": 0, "lowCase": "0", "truncated": false}, func(c *Client) error {
			_, e := c.SwitchGet(context.Background(), instance, AddressParams{Address: address})
			return e
		}},
		{string(methodExceptionTryBlocks), map[string]any{"functionAddress": "0x401000", "items": []any{}, "truncated": false}, func(c *Client) error {
			_, e := c.ExceptionTryBlocks(context.Background(), instance, ReadonlyPageParams{Address: address, Limit: 20})
			return e
		}},
		{string(methodAnalysisStatus), map[string]any{"queue": "none", "state": "ready", "enabled": true, "complete": true, "currentAddress": nil}, func(c *Client) error { _, e := c.AnalysisStatus(context.Background(), instance); return e }},
		{string(methodAnalysisPlan), map[string]any{"accepted": true, "start": "0x401000", "end": "0x401001", "queue": "used"}, func(c *Client) error {
			_, e := c.AnalysisPlan(context.Background(), instance, AnalysisPlanParams{Start: 0x401000, End: 0x401001, Confirm: true})
			return e
		}},
		{string(methodAnalysisProblems), map[string]any{"items": []any{}, "nextAddress": nil, "hasMore": false}, func(c *Client) error {
			_, e := c.AnalysisProblems(context.Background(), instance, AnalysisProblemsParams{Type: "disassembly", Limit: 20})
			return e
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

func TestReadonlyAnalysisStrictOutputAndPagination(t *testing.T) {
	instance := testInstanceDescriptor()
	t.Run("unknown output", func(t *testing.T) {
		client := functionAnalysisTestClient(t, instance, string(methodAnalysisStatus), json.RawMessage(`{"queue":"none","state":"ready","enabled":true,"complete":true,"currentAddress":null,"extra":true}`))
		if _, err := client.AnalysisStatus(context.Background(), instance); err == nil {
			t.Fatal("unknown output field was accepted")
		}
	})
	t.Run("inconsistent continuation", func(t *testing.T) {
		client := functionAnalysisTestClient(t, instance, string(methodFixupList), json.RawMessage(`{"items":[],"nextAddress":"0x401000","hasMore":true}`))
		if _, err := client.FixupList(context.Background(), instance, AddressListParams{Limit: 20}); err == nil {
			t.Fatal("empty continuation page was accepted")
		}
	})
}

func fixupResult() map[string]any {
	return map[string]any{"source": "0x401000", "target": "0x402000", "type": "offset32", "description": "relocation", "relative": false, "external": false, "unused": false, "created": false}
}
