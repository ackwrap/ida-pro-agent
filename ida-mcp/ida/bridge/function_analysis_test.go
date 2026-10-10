package bridge

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"ida-mcp/ida/rpc"
)

func TestFunctionAnalysisClientsDecodeStrictResults(t *testing.T) {
	t.Parallel()
	instance := testInstanceDescriptor()
	next := uint32(3)
	tests := []struct {
		name   string
		method string
		result map[string]any
		call   func(*Client) error
	}{
		{
			name: "disassembly", method: "function.disassemble",
			result: map[string]any{
				"entryAddress": "0x401000", "items": []any{map[string]any{"address": "0x401002", "text": "ret"}},
				"nextOffset": next, "hasMore": true,
			},
			call: func(client *Client) error {
				_, err := client.DisassembleFunction(context.Background(), instance, FunctionPageParams{Address: 0x401000, Offset: 2, Limit: 1})
				return err
			},
		},
		{
			name: "basic blocks", method: "function.basic_blocks",
			result: map[string]any{
				"entryAddress": "0x401000", "items": []any{map[string]any{
					"start": "0x401000", "end": "0x401010", "type": "return",
					"successors": []any{}, "predecessors": []any{},
				}}, "nextOffset": nil, "hasMore": false,
			},
			call: func(client *Client) error {
				_, err := client.FunctionBasicBlocks(context.Background(), instance, FunctionPageParams{Address: 0x401000})
				return err
			},
		},
		{
			name: "callees", method: "function.callees",
			result: map[string]any{
				"entryAddress": "0x401000", "items": []any{map[string]any{
					"address": "0x402000", "name": "callee", "internal": true,
				}}, "nextOffset": nil, "hasMore": false,
			},
			call: func(client *Client) error {
				_, err := client.FunctionCallees(context.Background(), instance, FunctionPageParams{Address: 0x401000})
				return err
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := functionAnalysisTestClient(t, instance, test.method, test.result)
			if err := test.call(client); err != nil {
				t.Fatalf("call: %v", err)
			}
		})
	}
}

func TestFunctionAnalysisDecoderRejectsUnknownAndMaliciousResults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		method string
		result string
	}{
		{"unknown field", "function.disassemble", `{"entryAddress":"0x401000","items":[],"nextOffset":null,"hasMore":false,"extra":true}`},
		{"unknown item field", "function.disassemble", `{"entryAddress":"0x401000","items":[{"address":"0x401000","text":"ret","extra":true}],"nextOffset":null,"hasMore":false}`},
		{"invalid address", "function.disassemble", `{"entryAddress":"401000","items":[],"nextOffset":null,"hasMore":false}`},
		{"line too long", "function.disassemble", `{"entryAddress":"0x401000","items":[{"address":"0x401000","text":"` + strings.Repeat("x", 4097) + `"}],"nextOffset":null,"hasMore":false}`},
		{"reversed block", "function.basic_blocks", `{"entryAddress":"0x401000","items":[{"start":"0x401010","end":"0x401000","type":"normal","successors":[],"predecessors":[]}],"nextOffset":null,"hasMore":false}`},
		{"missing edge list", "function.basic_blocks", `{"entryAddress":"0x401000","items":[{"start":"0x401000","end":"0x401010","type":"normal","predecessors":[]}],"nextOffset":null,"hasMore":false}`},
		{"unsorted callees", "function.callees", `{"entryAddress":"0x401000","items":[{"address":"0x402000","name":"a","internal":true},{"address":"0x401000","name":"b","internal":true}],"nextOffset":null,"hasMore":false}`},
		{"empty callee name", "function.callees", `{"entryAddress":"0x401000","items":[{"address":"0x402000","name":"","internal":true}],"nextOffset":null,"hasMore":false}`},
		{"inconsistent page", "function.disassemble", `{"entryAddress":"0x401000","items":[],"nextOffset":1,"hasMore":true}`},
		{"missing required field", "function.disassemble", `{"entryAddress":"0x401000","items":[],"hasMore":false}`},
	}
	instance := testInstanceDescriptor()
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var call func(*Client) error
			switch test.method {
			case "function.basic_blocks":
				call = func(client *Client) error {
					_, err := client.FunctionBasicBlocks(context.Background(), instance, FunctionPageParams{Address: 0x401000, Limit: 2})
					return err
				}
			case "function.callees":
				call = func(client *Client) error {
					_, err := client.FunctionCallees(context.Background(), instance, FunctionPageParams{Address: 0x401000, Limit: 2})
					return err
				}
			default:
				call = func(client *Client) error {
					_, err := client.DisassembleFunction(context.Background(), instance, FunctionPageParams{Address: 0x401000, Limit: 2})
					return err
				}
			}
			client := functionAnalysisTestClient(t, instance, test.method, json.RawMessage(test.result))
			if err := call(client); err == nil {
				t.Fatal("malicious result was accepted")
			}
		})
	}
}

func TestFunctionAnalysisParamsRejectBoundaries(t *testing.T) {
	t.Parallel()
	for _, params := range []FunctionPageParams{
		{Address: 0x401000, Offset: 1_000_001},
		{Address: 0x401000, Limit: -1},
		{Address: 0x401000, Limit: 101},
	} {
		if err := params.Validate(); err == nil {
			t.Fatalf("invalid params accepted: %+v", params)
		}
	}
}

func functionAnalysisTestClient(
	t *testing.T, instance rpc.InstanceDescriptor, method string, result any,
) *Client {
	t.Helper()
	client := NewClient()
	client.Dialer = testPipeDialer{handle: func(connection net.Conn) {
		readTestFrame(t, connection)
		writeTestFrame(t, connection, map[string]any{
			"product": "ida-agent-plugin", "protocol": 1,
			"instance_id": instance.InstanceID, "pid": instance.PID,
		})
		request, err := rpc.DecodeRequest(readTestFrame(t, connection))
		if err != nil {
			t.Errorf("DecodeRequest: %v", err)
			return
		}
		if request.Method != method {
			t.Errorf("method = %q", request.Method)
			return
		}
		encoded, err := json.Marshal(result)
		if raw, ok := result.(json.RawMessage); ok {
			encoded = raw
		}
		if err != nil {
			t.Errorf("Marshal result: %v", err)
			return
		}
		writeTestFrame(t, connection, rpc.Response{
			ProtocolVersion: rpc.ProtocolVersion, RequestID: request.RequestID,
			SessionID: request.SessionID, Result: encoded,
		})
	}}
	return client
}
