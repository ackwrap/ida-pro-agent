package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"ida-mcp/ida"
)

type readonlyFakeBackend struct {
	*fakeBackend
	instructionCalls  int
	fixupListParams   []ida.AddressListParams
	problemListParams []ida.AnalysisProblemsParams
	statuses          []ida.AnalysisStatusResult
	statusCalls       int
	planParams        []ida.AnalysisPlanParams
}

func (backend *readonlyFakeBackend) InstructionGet(_ context.Context, _ string, params ida.AddressParams) (ida.InstructionResult, error) {
	backend.instructionCalls++
	bytes, mnemonic, text := "90", "nop", "nop"
	operands := []ida.InstructionOperand{}
	return ida.InstructionResult{RequestedAddress: params.Address, Address: params.Address, End: params.Address + 1, Size: 1, Kind: "code", Bytes: &bytes, Mnemonic: &mnemonic, Text: &text, Operands: &operands}, nil
}
func (*readonlyFakeBackend) FunctionChunks(context.Context, string, ida.ReadonlyPageParams) (ida.FunctionChunksResult, error) {
	return ida.FunctionChunksResult{}, nil
}
func (*readonlyFakeBackend) FixupGet(context.Context, string, ida.AddressParams) (ida.FixupItem, error) {
	return ida.FixupItem{}, nil
}
func (backend *readonlyFakeBackend) FixupList(_ context.Context, _ string, params ida.AddressListParams) (ida.FixupListResult, error) {
	backend.fixupListParams = append(backend.fixupListParams, params)
	if params.NextAddress != nil {
		return ida.FixupListResult{Items: []ida.FixupItem{}}, nil
	}
	next := ida.Address(0x401004)
	return ida.FixupListResult{Items: []ida.FixupItem{{Source: 0x401000, Target: 0x402000, Type: "offset32"}}, NextAddress: &next, HasMore: true}, nil
}
func (*readonlyFakeBackend) SwitchGet(context.Context, string, ida.AddressParams) (ida.SwitchResult, error) {
	return ida.SwitchResult{}, nil
}
func (*readonlyFakeBackend) ExceptionTryBlocks(context.Context, string, ida.ReadonlyPageParams) (ida.TryBlocksResult, error) {
	return ida.TryBlocksResult{}, nil
}
func (backend *readonlyFakeBackend) AnalysisStatus(context.Context, string) (ida.AnalysisStatusResult, error) {
	backend.statusCalls++
	if len(backend.statuses) == 0 {
		return ida.AnalysisStatusResult{Queue: "none", State: "ready"}, nil
	}
	index := backend.statusCalls - 1
	if index >= len(backend.statuses) {
		index = len(backend.statuses) - 1
	}
	return backend.statuses[index], nil
}
func (backend *readonlyFakeBackend) AnalysisPlan(_ context.Context, _ string, params ida.AnalysisPlanParams) (ida.AnalysisPlanResult, error) {
	backend.planParams = append(backend.planParams, params)
	return ida.AnalysisPlanResult{Accepted: true, Start: params.Start, End: params.End, Queue: "used"}, nil
}
func (backend *readonlyFakeBackend) AnalysisProblems(_ context.Context, _ string, params ida.AnalysisProblemsParams) (ida.AnalysisProblemsResult, error) {
	backend.problemListParams = append(backend.problemListParams, params)
	if params.NextAddress != nil {
		return ida.AnalysisProblemsResult{Items: []ida.AnalysisProblem{}}, nil
	}
	next := ida.Address(0x401008)
	return ida.AnalysisProblemsResult{Items: []ida.AnalysisProblem{{Address: 0x401000, Type: params.Type, Name: "problem"}}, NextAddress: &next, HasMore: true}, nil
}

func TestReadonlyAnalysisPublicCursorsAreAuthenticatedAndBound(t *testing.T) {
	backend := &readonlyFakeBackend{fakeBackend: &fakeBackend{}}
	session := connectTestClient(t, backend)
	var fixups fixupListOutput
	var envelope domainCallOutput
	callDomainAction(t, session, ToolDomainSearch, map[string]any{
		"action": "call", "method": ToolFixupList,
		"arguments": map[string]any{"instanceId": testInstanceA, "start": "0x401000", "end": "0x402000", "limit": 1},
	}, &envelope)
	if err := json.Unmarshal(envelope.Result, &fixups); err != nil {
		t.Fatalf("decode first fixup page: %v", err)
	}
	if fixups.NextCursor == nil || len(backend.fixupListParams) != 1 || backend.fixupListParams[0].NextAddress != nil {
		t.Fatalf("first fixup page = %+v, params = %+v", fixups, backend.fixupListParams)
	}
	fixupCursor := *fixups.NextCursor
	callDomainAction(t, session, ToolDomainSearch, map[string]any{
		"action": "call", "method": ToolFixupList,
		"arguments": map[string]any{"instanceId": testInstanceA, "start": "0x401000", "end": "0x402000", "limit": 1, "cursor": fixupCursor},
	}, &envelope)
	if err := json.Unmarshal(envelope.Result, &fixups); err != nil {
		t.Fatalf("decode second fixup page: %v", err)
	}
	if len(backend.fixupListParams) != 2 || backend.fixupListParams[1].NextAddress == nil || *backend.fixupListParams[1].NextAddress != 0x401004 {
		t.Fatalf("decoded fixup continuation = %+v", backend.fixupListParams)
	}
	rejected := callDomainResult(t, session, ToolDomainSearch, map[string]any{
		"action": "call", "method": ToolFixupList,
		"arguments": map[string]any{"instanceId": testInstanceA, "start": "0x401000", "end": "0x402000", "limit": 2, "cursor": fixupCursor},
	})
	if !rejected.IsError || len(backend.fixupListParams) != 2 {
		t.Fatal("fixup cursor was not bound to the effective limit")
	}

	var problems analysisProblemsOutput
	callDomainAction(t, session, ToolDomainAnalysis, map[string]any{
		"action": "call", "method": ToolAnalysisProblems,
		"arguments": map[string]any{"instanceId": testInstanceA, "type": "disassembly", "limit": 1},
	}, &envelope)
	if err := json.Unmarshal(envelope.Result, &problems); err != nil {
		t.Fatalf("decode analysis problems: %v", err)
	}
	if problems.NextCursor == nil {
		t.Fatal("analysis.problems did not wrap its internal continuation")
	}
	rejected = callDomainResult(t, session, ToolDomainAnalysis, map[string]any{
		"action": "call", "method": ToolAnalysisProblems,
		"arguments": map[string]any{"instanceId": testInstanceA, "type": "bad_stack", "limit": 1, "cursor": *problems.NextCursor},
	})
	if !rejected.IsError || len(backend.problemListParams) != 1 {
		t.Fatal("analysis problem cursor was not bound to problem type")
	}
}

func TestReadonlyAnalysisTypedDispatchAndStrictSchema(t *testing.T) {
	backend := &readonlyFakeBackend{fakeBackend: &fakeBackend{}}
	session := connectTestClient(t, backend)
	first := callDomainResult(t, session, ToolDomainSearch, map[string]any{
		"action": "call", "method": ToolInstructionGet,
		"arguments": map[string]any{"instanceId": testInstanceA, "address": "0x401000"},
	})
	if first.IsError || backend.instructionCalls != 1 {
		t.Fatalf("typed dispatch failed: calls=%d content=%+v", backend.instructionCalls, first.Content)
	}
	result := callDomainResult(t, session, ToolDomainSearch, map[string]any{
		"action": "call", "method": ToolInstructionGet,
		"arguments": map[string]any{"instanceId": testInstanceA, "address": "0x401000", "unknown": true},
	})
	if !result.IsError || backend.instructionCalls != 1 {
		t.Fatal("unknown input field reached readonly backend")
	}
}

func TestAnalysisWaitCompleteTimeoutCancelAndDefaults(t *testing.T) {
	t.Run("complete", func(t *testing.T) {
		backend := &readonlyFakeBackend{fakeBackend: &fakeBackend{}, statuses: []ida.AnalysisStatusResult{{Queue: "used", State: "thinking"}, {Queue: "none", State: "ready", Complete: true}}}
		registry := &toolRegistry{backend: backend, instances: newInstanceManager(backend)}
		_, result, err := registry.analysisWait(context.Background(), nil, analysisWaitInput{InstanceID: stringPtr(testInstanceA), TimeoutMs: 500, PollIntervalMs: 50})
		if err != nil || !result.Complete || result.TimedOut || result.PollCount != 2 {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		backend := &readonlyFakeBackend{fakeBackend: &fakeBackend{}, statuses: []ida.AnalysisStatusResult{{Queue: "used", State: "thinking"}}}
		registry := &toolRegistry{backend: backend, instances: newInstanceManager(backend)}
		_, result, err := registry.analysisWait(context.Background(), nil, analysisWaitInput{InstanceID: stringPtr(testInstanceA), TimeoutMs: 100, PollIntervalMs: 50})
		if err != nil || !result.TimedOut || result.PollCount == 0 || result.PollCount > 3 || result.ElapsedMs < 90 {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		backend := &readonlyFakeBackend{fakeBackend: &fakeBackend{}, statuses: []ida.AnalysisStatusResult{{Queue: "used", State: "thinking"}}}
		registry := &toolRegistry{backend: backend, instances: newInstanceManager(backend)}
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(20*time.Millisecond, cancel)
		_, _, err := registry.analysisWait(ctx, nil, analysisWaitInput{InstanceID: stringPtr(testInstanceA), TimeoutMs: 500, PollIntervalMs: 50})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("defaults", func(t *testing.T) {
		input := analysisWaitInput{}
		defaultAnalysisWait(&input)
		if input.TimeoutMs != 10000 || input.PollIntervalMs != 200 {
			t.Fatalf("defaults=%+v", input)
		}
	})
}

func TestAnalysisPlanTypedDispatch(t *testing.T) {
	backend := &readonlyFakeBackend{fakeBackend: &fakeBackend{}}
	session := connectTestClient(t, backend)
	result := callDomainResult(t, session, ToolDomainAnalysis, map[string]any{"action": "call", "method": ToolAnalysisPlan, "arguments": map[string]any{"instanceId": testInstanceA, "start": "0x401000", "end": "0x401001", "confirm": true}})
	if result.IsError || len(backend.planParams) != 1 {
		t.Fatalf("result=%+v params=%+v", result, backend.planParams)
	}
}
