package bridge

import (
	"context"
	"encoding/json"
	"testing"

	"ida-mcp/ida/rpc"
)

func TestRemainingClientsUseDistinctStaticTypedMethods(t *testing.T) {
	instance := testInstanceDescriptor()
	address := rpc.Address(0x401000)
	typeDetails := map[string]any{
		"ordinal": 1, "name": "sample_t", "kind": "struct", "size": 4,
		"declaration": "struct sample_t { int value; };", "declarationOriginalSize": 31,
		"declarationTruncated": false, "members": []any{}, "memberCount": 0,
		"membersTruncated": false, "enumMembers": []any{}, "enumMemberCount": 0,
		"enumMembersTruncated": false, "relatedTypes": []any{}, "relatedTypeCount": 0,
		"relatedTypesTruncated": false,
	}
	typedValue := map[string]any{
		"address": "0x401000", "type": typeDetails, "bytes": "01000000", "bytesRead": 4,
		"originalSize": 4, "truncated": false, "fields": []any{}, "fieldsTruncated": false,
	}
	tests := []struct {
		method rpcMethod
		result any
		call   func(*Client) error
	}{
		{methodMemorySearchBytes, map[string]any{"items": []any{"0x401000"}, "nextAddress": nil, "hasMore": false}, func(client *Client) error {
			_, err := client.SearchMemoryBytes(context.Background(), instance, MemorySearchBytesParams{Pattern: "90", Start: address, End: address + 0x100, Limit: 20})
			return err
		}},
		{methodInstructionSearch, instructionTestResult(), func(client *Client) error {
			_, err := client.SearchInstructions(context.Background(), instance, InstructionSearchParams{Start: address, End: address + 0x100, Limit: 20})
			return err
		}},
		{methodInstructionQuery, instructionTestResult(), func(client *Client) error {
			_, err := client.QueryInstructions(context.Background(), instance, InstructionSearchParams{Start: address, End: address + 0x100, Limit: 20})
			return err
		}},
		{methodListingSearch, listingTestResult(), func(client *Client) error {
			_, err := client.SearchListing(context.Background(), instance, ListingSearchParams{Start: address, End: address + 0x100, Query: "nop", Limit: 20})
			return err
		}},
		{methodListingSearchText, listingTestResult(), func(client *Client) error {
			query := "nop"
			_, err := client.SearchListingText(context.Background(), instance, ListingTextSearchParams{Start: address, End: address + 0x100, Query: &query, IncludeDisassembly: true, Limit: 20})
			return err
		}},
		{methodStringSearchRegex, map[string]any{"items": []any{}, "nextCursor": nil, "hasMore": false}, func(client *Client) error {
			_, err := client.SearchStringsRegex(context.Background(), instance, StringRegexSearchParams{Pattern: ".", MinLength: 1, Limit: 20})
			return err
		}},
		{methodSignatureMake, map[string]any{"mode": "address", "address": "0x401000", "endAddress": nil, "signature": "90", "format": "ida", "length": 1, "unique": true}, func(client *Client) error {
			_, err := client.MakeSignature(context.Background(), instance, SignatureMakeParams{Mode: "address", Address: &address, Format: "ida", WildcardOperands: true, MaxLength: 1000})
			return err
		}},
		{methodSignatureXrefs, map[string]any{"address": "0x401000", "items": []any{}, "totalXrefs": 0, "truncated": false}, func(client *Client) error {
			_, err := client.SignatureXrefs(context.Background(), instance, SignatureXrefsParams{Address: address, Format: "ida", Top: 5})
			return err
		}},
		{methodXrefStructField, map[string]any{"items": []any{}, "truncated": false}, func(client *Client) error {
			_, err := client.StructFieldXrefs(context.Background(), instance, StructFieldXrefParams{Type: "sample_t", Field: "value", Limit: 100})
			return err
		}},
		{methodGlobalValue, map[string]any{"address": "0x401000", "symbol": nil, "declaration": nil, "size": 4, "bytesRead": 4, "format": "integer", "value": "0x1", "truncated": false}, func(client *Client) error {
			_, err := client.GlobalValue(context.Background(), instance, GlobalValueParams{Address: &address, MaxBytes: 4096})
			return err
		}},
		{methodTypeSearch, map[string]any{"items": []any{}, "nextOrdinal": nil, "hasMore": false}, func(client *Client) error {
			_, err := client.SearchTypes(context.Background(), instance, TypeSearchParams{Ordinal: 1, Limit: 20})
			return err
		}},
		{methodTypeQuery, map[string]any{"items": []any{}, "nextOrdinal": nil, "hasMore": false}, func(client *Client) error {
			_, err := client.QueryTypes(context.Background(), instance, TypeSearchParams{Ordinal: 1, Limit: 20})
			return err
		}},
		{methodTypeGet, typeDetails, func(client *Client) error {
			_, err := client.GetType(context.Background(), instance, TypeGetParams{Name: "sample_t"})
			return err
		}},
		{methodTypeReadValue, typedValue, func(client *Client) error {
			_, err := client.ReadTypeValue(context.Background(), instance, TypeReadValueParams{Address: address, Name: "sample_t", MaxBytes: 4096})
			return err
		}},
		{methodTypeReadStruct, typedValue, func(client *Client) error {
			_, err := client.ReadStruct(context.Background(), instance, TypeReadStructParams{Address: address, MaxBytes: 4096})
			return err
		}},
		{methodTypeInfer, map[string]any{"address": "0x401000", "declaration": "int value", "source": "tinfo"}, func(client *Client) error {
			_, err := client.InferType(context.Background(), instance, TypeInferParams{Address: address})
			return err
		}},
		{methodAnalysisComponent, map[string]any{"graph": map[string]any{"nodes": []any{}, "edges": []any{}, "truncated": false}, "members": []any{}, "sharedGlobals": []any{}, "sharedStrings": []any{}, "statistics": map[string]any{"internal": map[string]any{"functions": 0, "calls": 0}, "interface": map[string]any{"incomingCalls": 0, "outgoingCalls": 0}}, "truncated": false}, func(client *Client) error {
			_, err := client.AnalyzeComponent(context.Background(), instance, AnalysisComponentParams{Roots: []rpc.Address{address}, MaxNodes: 100, MaxEdges: 200})
			return err
		}},
		{methodTraceDataFlow, map[string]any{"model": "xref_bfs", "nodes": []any{}, "edges": []any{}, "truncated": false}, func(client *Client) error {
			_, err := client.TraceDataFlow(context.Background(), instance, TraceDataFlowParams{Address: address, Direction: "both", MaxNodes: 200, MaxEdges: 500})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(string(test.method), func(t *testing.T) {
			client := functionAnalysisTestClient(t, instance, string(test.method), test.result)
			if err := test.call(client); err != nil {
				t.Fatalf("call: %v", err)
			}
		})
	}
}

func TestRemainingClientStrictlyRejectsUnknownOutput(t *testing.T) {
	instance := testInstanceDescriptor()
	client := functionAnalysisTestClient(t, instance, string(methodInstructionSearch), json.RawMessage(`{"items":[],"nextCursor":null,"hasMore":false,"unknown":true}`))
	_, err := client.SearchInstructions(context.Background(), instance, InstructionSearchParams{Start: 0x401000, End: 0x402000, Limit: 20})
	if err == nil {
		t.Fatal("unknown instruction output field was accepted")
	}
}

func TestListingSearchAcceptsInternalTruncationCursor(t *testing.T) {
	instance := testInstanceDescriptor()
	cursor := "lt1.0000000000401001.0000000000000001.0000000000000001"
	result := map[string]any{
		"items": []any{map[string]any{
			"address": "0x401000", "source": "disassembly", "text": "nop",
		}},
		"nextCursor": cursor,
		"hasMore":    true,
	}
	client := functionAnalysisTestClient(t, instance, string(methodListingSearch), result)
	page, err := client.SearchListing(context.Background(), instance, ListingSearchParams{
		Start: 0x401000, End: 0x402000, Query: "nop", Limit: 1,
	})
	if err != nil || page.NextCursor == nil || !page.HasMore {
		t.Fatalf("listing truncation metadata = %+v, err=%v", page, err)
	}
}

func instructionTestResult() map[string]any {
	return map[string]any{"items": []any{map[string]any{"address": "0x401000", "bytes": "90", "size": 1, "text": "nop", "mnemonic": "nop", "operands": []any{}}}, "nextCursor": nil, "hasMore": false}
}
func listingTestResult() map[string]any {
	return map[string]any{"items": []any{map[string]any{"address": "0x401000", "source": "disassembly", "text": "nop"}}, "nextCursor": nil, "hasMore": false}
}
