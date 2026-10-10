package ida

import (
	"context"
	"errors"
	"testing"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

type entrySymbolBridgeClient struct {
	*fakeBridgeClient
	symbolParams bridge.SymbolSearchParams
}

func (client *entrySymbolBridgeClient) SymbolSearch(
	_ context.Context,
	_ rpc.InstanceDescriptor,
	params bridge.SymbolSearchParams,
) (bridge.SymbolSearchResult, error) {
	client.symbolParams = params
	return bridge.SymbolSearchResult{Items: []bridge.SymbolInfo{{
		Address: 0x401000, Name: "global_state", Kind: "data",
	}}}, nil
}

func TestBridgeBackendConvertsEntrySymbolDTOs(t *testing.T) {
	t.Parallel()
	client := &entrySymbolBridgeClient{fakeBridgeClient: &fakeBridgeClient{}}
	backend := NewBridgeBackend(
		&fakeInstanceSource{instances: []rpc.InstanceDescriptor{testBackendInstance(testInstanceA, true)}},
		client,
	)
	result, err := backend.SymbolSearch(context.Background(), testInstanceA, SymbolSearchParams{
		Name: "state", Kind: "data", Limit: 20,
	})
	if err != nil {
		t.Fatalf("SymbolSearch: %v", err)
	}
	if len(result.Items) != 1 || result.Items[0].Address != 0x401000 || client.symbolParams.Kind != "data" {
		t.Fatalf("result = %+v, params = %+v", result, client.symbolParams)
	}
}

func TestBridgeBackendRejectsInvalidEntrySymbolInput(t *testing.T) {
	t.Parallel()
	backend := NewBridgeBackend(
		&fakeInstanceSource{instances: []rpc.InstanceDescriptor{testBackendInstance(testInstanceA, true)}},
		&fakeBridgeClient{},
	)
	_, err := backend.DatabaseEntryPoints(context.Background(), testInstanceA, EntryPointListParams{Type: "main"})
	var backendError *Error
	if !errors.As(err, &backendError) || backendError.Code != ErrorInvalidArgument {
		t.Fatalf("error = %v", err)
	}
}

type maliciousEntrySymbolBridgeClient struct{ *fakeBridgeClient }

func (*maliciousEntrySymbolBridgeClient) SymbolExports(
	context.Context, rpc.InstanceDescriptor, bridge.ExportListParams,
) (bridge.ExportListResult, error) {
	return bridge.ExportListResult{Items: []bridge.ExportInfo{{
		Address: 0x401000, Name: "bad", Ordinal: 0,
	}}}, nil
}

func TestBridgeBackendRejectsInvalidEntrySymbolResponse(t *testing.T) {
	t.Parallel()
	backend := NewBridgeBackend(
		&fakeInstanceSource{instances: []rpc.InstanceDescriptor{testBackendInstance(testInstanceA, true)}},
		&maliciousEntrySymbolBridgeClient{fakeBridgeClient: &fakeBridgeClient{}},
	)
	_, err := backend.SymbolExports(context.Background(), testInstanceA, ExportListParams{})
	var backendError *Error
	if !errors.As(err, &backendError) || backendError.Code != ErrorInternal {
		t.Fatalf("error = %v", err)
	}
}
