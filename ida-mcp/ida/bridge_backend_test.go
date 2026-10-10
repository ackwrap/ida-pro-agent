package ida

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

const (
	testInstanceA = "11111111-0000-4000-8000-000000000001"
	testInstanceB = "22222222-0000-4000-8000-000000000002"
)

type fakeInstanceSource struct {
	instances []rpc.InstanceDescriptor
	err       error
}

func (source *fakeInstanceSource) List(context.Context) ([]rpc.InstanceDescriptor, error) {
	return source.instances, source.err
}

type fakeBridgeClient struct {
	functionStart chan struct{}
	functionWait  chan struct{}
	mutex         sync.Mutex
	seen          []string
}

func (client *fakeBridgeClient) DatabaseInfo(
	context.Context, rpc.InstanceDescriptor,
) (bridge.DatabaseInfo, error) {
	return bridge.DatabaseInfo{
		Database: "sample.i64", Processor: "metapc", Architecture: "x86_64", AddressBits: 64,
	}, nil
}

func (*fakeBridgeClient) DatabaseSegments(
	context.Context, rpc.InstanceDescriptor, bridge.SegmentListParams,
) (bridge.SegmentListResult, error) {
	return bridge.SegmentListResult{Items: []bridge.SegmentInfo{}}, nil
}

func (*fakeBridgeClient) SearchStrings(
	context.Context, rpc.InstanceDescriptor, bridge.StringSearchParams,
) (bridge.StringSearchResult, error) {
	return bridge.StringSearchResult{Items: []bridge.StringInfo{}}, nil
}

func (*fakeBridgeClient) SymbolImports(
	context.Context, rpc.InstanceDescriptor, bridge.ImportListParams,
) (bridge.ImportListResult, error) {
	return bridge.ImportListResult{Items: []bridge.ImportInfo{}}, nil
}

func (*fakeBridgeClient) DatabaseEntryPoints(
	context.Context, rpc.InstanceDescriptor, bridge.EntryPointListParams,
) (bridge.EntryPointListResult, error) {
	return bridge.EntryPointListResult{Items: []bridge.EntryPointInfo{}}, nil
}

func (*fakeBridgeClient) SymbolExports(
	context.Context, rpc.InstanceDescriptor, bridge.ExportListParams,
) (bridge.ExportListResult, error) {
	return bridge.ExportListResult{Items: []bridge.ExportInfo{}}, nil
}

func (*fakeBridgeClient) SymbolSearch(
	context.Context, rpc.InstanceDescriptor, bridge.SymbolSearchParams,
) (bridge.SymbolSearchResult, error) {
	return bridge.SymbolSearchResult{Items: []bridge.SymbolInfo{}}, nil
}

func (client *fakeBridgeClient) GetFunction(
	ctx context.Context,
	instance rpc.InstanceDescriptor,
	address rpc.Address,
) (bridge.FunctionInfo, error) {
	client.mutex.Lock()
	client.seen = append(client.seen, instance.InstanceID)
	client.mutex.Unlock()
	if client.functionStart != nil {
		client.functionStart <- struct{}{}
	}
	if client.functionWait != nil {
		select {
		case <-client.functionWait:
		case <-ctx.Done():
			return bridge.FunctionInfo{}, ctx.Err()
		}
	}
	return bridge.FunctionInfo{
		EntryAddress: address, AddressRange: bridge.AddressRange{Start: address, End: address + 16},
		Name: instance.InstanceID,
	}, nil
}

func (*fakeBridgeClient) SearchFunctions(
	context.Context, rpc.InstanceDescriptor, bridge.FunctionSearchParams,
) (bridge.FunctionSearchResult, error) {
	return bridge.FunctionSearchResult{Items: []bridge.FunctionSummary{}}, nil
}

func (*fakeBridgeClient) DisassembleFunction(
	_ context.Context, _ rpc.InstanceDescriptor, params bridge.FunctionPageParams,
) (bridge.FunctionDisassemblyResult, error) {
	return bridge.FunctionDisassemblyResult{
		EntryAddress: params.Address,
		Items:        []bridge.DisassemblyItem{{Address: params.Address, Text: "ret"}},
	}, nil
}

func (*fakeBridgeClient) FunctionBasicBlocks(
	_ context.Context, _ rpc.InstanceDescriptor, params bridge.FunctionPageParams,
) (bridge.FunctionBasicBlocksResult, error) {
	return bridge.FunctionBasicBlocksResult{
		EntryAddress: params.Address,
		Items: []bridge.FunctionBasicBlock{{
			Start: params.Address, End: params.Address + 1, Type: "return",
			Successors: []rpc.Address{}, Predecessors: []rpc.Address{},
		}},
	}, nil
}

func (*fakeBridgeClient) FunctionCallees(
	_ context.Context, _ rpc.InstanceDescriptor, params bridge.FunctionPageParams,
) (bridge.FunctionCalleesResult, error) {
	return bridge.FunctionCalleesResult{
		EntryAddress: params.Address,
		Items:        []bridge.FunctionCallee{{Address: params.Address + 1, Name: "callee", Internal: true}},
	}, nil
}

func (*fakeBridgeClient) QueryXrefs(
	context.Context, rpc.InstanceDescriptor, bridge.XrefQueryParams,
) (bridge.XrefQueryResult, error) {
	return bridge.XrefQueryResult{Items: []bridge.XrefInfo{}}, nil
}

func (*fakeBridgeClient) ReadMemory(
	context.Context, rpc.InstanceDescriptor, bridge.MemoryReadParams,
) (bridge.MemoryReadResult, error) {
	return bridge.MemoryReadResult{}, nil
}

func (*fakeBridgeClient) DecompileFunction(
	context.Context, rpc.InstanceDescriptor, bridge.DecompileParams,
) (bridge.DecompileResult, error) {
	return bridge.DecompileResult{}, nil
}

func TestBridgeBackendListsSanitizedInstances(t *testing.T) {
	t.Parallel()
	backend := NewBridgeBackend(
		&fakeInstanceSource{instances: []rpc.InstanceDescriptor{testBackendInstance(testInstanceA, true)}},
		&fakeBridgeClient{},
	)
	instances, err := backend.ListInstances(context.Background())
	if err != nil {
		t.Fatalf("ListInstances: %v", err)
	}
	if len(instances) != 1 || instances[0].InstanceID != testInstanceA ||
		instances[0].Database != "sample.i64" || !instances[0].Capabilities.Decompiler {
		t.Fatalf("instances = %+v", instances)
	}
}

func TestBridgeBackendRoutesExplicitInstance(t *testing.T) {
	t.Parallel()
	client := &fakeBridgeClient{}
	backend := NewBridgeBackend(&fakeInstanceSource{instances: []rpc.InstanceDescriptor{
		testBackendInstance(testInstanceA, true), testBackendInstance(testInstanceB, true),
	}}, client)
	result, err := backend.GetFunction(context.Background(), testInstanceB, 0x401000)
	if err != nil {
		t.Fatalf("GetFunction: %v", err)
	}
	if result.Name != testInstanceB {
		t.Fatalf("result = %+v", result)
	}
}

func TestBridgeBackendRejectsDuplicateInstanceID(t *testing.T) {
	t.Parallel()
	backend := NewBridgeBackend(&fakeInstanceSource{instances: []rpc.InstanceDescriptor{
		testBackendInstance(testInstanceA, true), testBackendInstance(testInstanceA, true),
	}}, &fakeBridgeClient{})
	_, err := backend.GetFunction(context.Background(), testInstanceA, 0x401000)
	var backendError *Error
	if !errors.As(err, &backendError) || backendError.Code != ErrorConflict {
		t.Fatalf("error = %v", err)
	}
}

func TestBridgeBackendRejectsUnavailableDecompiler(t *testing.T) {
	t.Parallel()
	backend := NewBridgeBackend(
		&fakeInstanceSource{instances: []rpc.InstanceDescriptor{testBackendInstance(testInstanceA, false)}},
		&fakeBridgeClient{},
	)
	_, err := backend.DecompileFunction(context.Background(), testInstanceA, DecompileParams{
		Address: 0x401000, MaxBytes: 64,
	})
	var backendError *Error
	if !errors.As(err, &backendError) || backendError.Code != ErrorCapabilityUnavailable {
		t.Fatalf("error = %v", err)
	}
}

type maliciousAnalysisBridgeClient struct{ *fakeBridgeClient }

func (*maliciousAnalysisBridgeClient) DisassembleFunction(
	context.Context, rpc.InstanceDescriptor, bridge.FunctionPageParams,
) (bridge.FunctionDisassemblyResult, error) {
	return bridge.FunctionDisassemblyResult{
		EntryAddress: 0x401000,
		Items: []bridge.DisassemblyItem{
			{Address: 0x401010, Text: "first"},
			{Address: 0x401000, Text: "unsorted"},
		},
	}, nil
}

func TestBridgeBackendRejectsMaliciousFunctionAnalysisResponse(t *testing.T) {
	t.Parallel()
	backend := NewBridgeBackend(
		&fakeInstanceSource{instances: []rpc.InstanceDescriptor{testBackendInstance(testInstanceA, true)}},
		&maliciousAnalysisBridgeClient{fakeBridgeClient: &fakeBridgeClient{}},
	)
	_, err := backend.DisassembleFunction(context.Background(), testInstanceA, FunctionPageParams{
		Address: 0x401000, Limit: 2,
	})
	var backendError *Error
	if !errors.As(err, &backendError) || backendError.Code != ErrorInternal {
		t.Fatalf("error = %v", err)
	}
}

func TestBridgeBackendAppliesPerInstanceBackpressureAndRecovers(t *testing.T) {
	client := &fakeBridgeClient{
		functionStart: make(chan struct{}, 2), functionWait: make(chan struct{}),
	}
	backend := NewBridgeBackend(
		&fakeInstanceSource{instances: []rpc.InstanceDescriptor{testBackendInstance(testInstanceA, true)}},
		client,
	)
	errorsChannel := make(chan error, 2)
	for index := 0; index < 2; index++ {
		go func() {
			_, err := backend.GetFunction(context.Background(), testInstanceA, 0x401000)
			errorsChannel <- err
		}()
	}
	<-client.functionStart
	<-client.functionStart
	_, err := backend.GetFunction(context.Background(), testInstanceA, 0x401000)
	var backendError *Error
	if !errors.As(err, &backendError) || backendError.Code != ErrorIDABusy || !backendError.Retryable {
		t.Fatalf("third request error = %v", err)
	}
	close(client.functionWait)
	for index := 0; index < 2; index++ {
		if err := <-errorsChannel; err != nil {
			t.Fatalf("admitted request: %v", err)
		}
	}
	if _, err := backend.GetFunction(context.Background(), testInstanceA, 0x401000); err != nil {
		t.Fatalf("request after release: %v", err)
	}
}

func TestBridgeBackendHonorsCallerDeadline(t *testing.T) {
	t.Parallel()
	client := &fakeBridgeClient{functionWait: make(chan struct{})}
	backend := NewBridgeBackend(
		&fakeInstanceSource{instances: []rpc.InstanceDescriptor{testBackendInstance(testInstanceA, true)}},
		client,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := backend.GetFunction(ctx, testInstanceA, 0x401000)
	var backendError *Error
	if !errors.As(err, &backendError) || backendError.Code != ErrorTimeout || !backendError.Retryable {
		t.Fatalf("error = %v", err)
	}
}

func TestNormalizeBridgeErrorPreservesRecoveryChangeID(t *testing.T) {
	recoveryChangeID := "change-0123456789abcdef-1"
	err := normalizeBridgeError(&rpc.ResponseError{
		Code: rpc.ErrorInternal, Message: "rollback failed", RecoveryChangeID: &recoveryChangeID,
	})
	var backendError *Error
	if !errors.As(err, &backendError) || backendError.Code != ErrorInternal ||
		backendError.RecoveryChangeID != recoveryChangeID {
		t.Fatalf("error = %#v", err)
	}
}

func testBackendInstance(instanceID string, decompiler bool) rpc.InstanceDescriptor {
	prefix := instanceID[:8]
	return rpc.InstanceDescriptor{
		Version: 1, ProtocolVersion: rpc.ProtocolVersion, InstanceID: instanceID, PID: 4242,
		Pipe: `\\.\pipe\ida-agent-4242-` + prefix, IDAVersion: "9.4",
		Database: `D:\samples\sample.i64`, InputFile: "sample.exe", Processor: "metapc",
		Bitness: 64, StartedAt: 1788063000, Arch: "x86_64",
		Capabilities: rpc.InstanceCapabilities{Decompiler: decompiler, AddressBits: 64},
	}
}
