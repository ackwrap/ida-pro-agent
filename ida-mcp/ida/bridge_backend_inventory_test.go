package ida

import (
	"context"
	"errors"
	"strings"
	"testing"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

type inventoryBridgeClient struct {
	*fakeBridgeClient
	stringParams bridge.StringSearchParams
}

func (client *inventoryBridgeClient) SearchStrings(
	_ context.Context,
	_ rpc.InstanceDescriptor,
	params bridge.StringSearchParams,
) (bridge.StringSearchResult, error) {
	client.stringParams = params
	return bridge.StringSearchResult{Items: []bridge.StringInfo{{
		Address: 0x401000, Length: 5, Encoding: "UTF-8", Value: "hello", OriginalSize: 5,
	}}}, nil
}

func TestBridgeBackendConvertsInventoryDTOs(t *testing.T) {
	t.Parallel()
	client := &inventoryBridgeClient{fakeBridgeClient: &fakeBridgeClient{}}
	backend := NewBridgeBackend(
		&fakeInstanceSource{instances: []rpc.InstanceDescriptor{testBackendInstance(testInstanceA, true)}},
		client,
	)
	result, err := backend.SearchStrings(context.Background(), testInstanceA, StringSearchParams{
		Query: "hello", MinLength: 4, Limit: 20, Refresh: true,
	})
	if err != nil {
		t.Fatalf("SearchStrings: %v", err)
	}
	if len(result.Items) != 1 || result.Items[0].Address != 0x401000 || client.stringParams.Query != "hello" || !client.stringParams.Refresh {
		t.Fatalf("result = %+v, params = %+v", result, client.stringParams)
	}
}

func TestBridgeBackendRejectsInventoryInputBeforeRPC(t *testing.T) {
	t.Parallel()
	backend := NewBridgeBackend(
		&fakeInstanceSource{instances: []rpc.InstanceDescriptor{testBackendInstance(testInstanceA, true)}},
		&fakeBridgeClient{},
	)
	_, err := backend.SymbolImports(context.Background(), testInstanceA, ImportListParams{
		Name: strings.Repeat("x", 257),
	})
	var backendError *Error
	if !errors.As(err, &backendError) || backendError.Code != ErrorInvalidArgument {
		t.Fatalf("error = %v", err)
	}
}

type maliciousInventoryBridgeClient struct{ *fakeBridgeClient }

func (*maliciousInventoryBridgeClient) DatabaseSegments(
	context.Context, rpc.InstanceDescriptor, bridge.SegmentListParams,
) (bridge.SegmentListResult, error) {
	return bridge.SegmentListResult{Items: []bridge.SegmentInfo{
		{Start: 0x2000, End: 0x3000, Name: ".b", Bitness: 64, Permissions: "r--", Type: "data"},
		{Start: 0x1000, End: 0x1800, Name: ".a", Bitness: 64, Permissions: "r-x", Type: "code"},
	}}, nil
}

func TestBridgeBackendRejectsInvalidInventoryResponse(t *testing.T) {
	t.Parallel()
	backend := NewBridgeBackend(
		&fakeInstanceSource{instances: []rpc.InstanceDescriptor{testBackendInstance(testInstanceA, true)}},
		&maliciousInventoryBridgeClient{fakeBridgeClient: &fakeBridgeClient{}},
	)
	_, err := backend.DatabaseSegments(context.Background(), testInstanceA, SegmentListParams{})
	var backendError *Error
	if !errors.As(err, &backendError) || backendError.Code != ErrorInternal {
		t.Fatalf("error = %v", err)
	}
}

type outputLimitInventoryBridgeClient struct{ *fakeBridgeClient }

func (*outputLimitInventoryBridgeClient) SymbolImports(
	context.Context, rpc.InstanceDescriptor, bridge.ImportListParams,
) (bridge.ImportListResult, error) {
	return bridge.ImportListResult{}, &rpc.ResponseError{
		Code: rpc.ErrorOutputLimit, Message: "continuation exceeds limit", Retryable: false,
	}
}

func TestBridgeBackendPreservesInventoryOutputLimit(t *testing.T) {
	t.Parallel()
	backend := NewBridgeBackend(
		&fakeInstanceSource{instances: []rpc.InstanceDescriptor{testBackendInstance(testInstanceA, true)}},
		&outputLimitInventoryBridgeClient{fakeBridgeClient: &fakeBridgeClient{}},
	)
	_, err := backend.SymbolImports(context.Background(), testInstanceA, ImportListParams{})
	var backendError *Error
	if !errors.As(err, &backendError) || backendError.Code != ErrorOutputLimit {
		t.Fatalf("error = %v", err)
	}
}
