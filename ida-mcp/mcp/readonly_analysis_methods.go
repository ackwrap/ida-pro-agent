package mcpserver

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ToolInstructionGet     = "instruction.get"
	ToolFunctionChunks     = "function.chunks"
	ToolFixupGet           = "fixup.get"
	ToolFixupList          = "fixup.list"
	ToolSwitchGet          = "switch.get"
	ToolExceptionTryBlocks = "exception.try_blocks"
	ToolAnalysisStatus     = "analysis.status"
	ToolAnalysisWait       = "analysis.wait"
	ToolAnalysisPlan       = "analysis.plan"
	ToolAnalysisProblems   = "analysis.problems"
)

func (registry *toolRegistry) invokeReadonlyAnalysisMethod(ctx context.Context, request *mcp.CallToolRequest, method string, arguments json.RawMessage) (json.RawMessage, bool, error) {
	switch method {
	case ToolInstructionGet, ToolFixupGet, ToolSwitchGet:
		if method == ToolInstructionGet {
			result, err := invokeTyped(ctx, request, arguments, registry.instructionGet)
			return result, true, err
		}
		if method == ToolFixupGet {
			result, err := invokeTyped(ctx, request, arguments, registry.fixupGet)
			return result, true, err
		}
		result, err := invokeTyped(ctx, request, arguments, registry.switchGet)
		return result, true, err
	case ToolFunctionChunks:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultReadonlyPage, registry.functionChunks)
		return result, true, err
	case ToolExceptionTryBlocks:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultReadonlyPage, registry.exceptionTryBlocks)
		return result, true, err
	case ToolFixupList:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultAddressList, registry.fixupList)
		return result, true, err
	case ToolAnalysisStatus:
		result, err := invokeTyped(ctx, request, arguments, registry.analysisStatus)
		return result, true, err
	case ToolAnalysisWait:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultAnalysisWait, registry.analysisWait)
		return result, true, err
	case ToolAnalysisPlan:
		result, err := invokeTyped(ctx, request, arguments, registry.analysisPlan)
		return result, true, err
	case ToolAnalysisProblems:
		result, err := invokeTypedWithDefaults(ctx, request, arguments, defaultAnalysisProblems, registry.analysisProblems)
		return result, true, err
	default:
		return nil, false, nil
	}
}

func (registry *toolRegistry) readonlyAnalysisBackend() (ida.ReadonlyAnalysisBackend, error) {
	backend, ok := registry.backend.(ida.ReadonlyAnalysisBackend)
	if !ok {
		return nil, ida.NewError(ida.ErrorCapabilityUnavailable, "readonly analysis backend is unavailable", false)
	}
	return backend, nil
}

func (registry *toolRegistry) readonlyAnalysisCall(ctx context.Context, requested *string) (ida.ReadonlyAnalysisBackend, string, context.Context, context.CancelFunc, error) {
	backend, err := registry.readonlyAnalysisBackend()
	if err != nil {
		return nil, "", ctx, func() {}, err
	}
	requestContext, instanceID, cancel, err := registry.catalogInstance(ctx, requested, 30*time.Second)
	return backend, instanceID, requestContext, cancel, err
}

func parseReadonlyAddress(input readonlyAddressInput) (ida.AddressParams, error) {
	address, err := parseToolAddress(input.Address)
	return ida.AddressParams{Address: address}, err
}

func (registry *toolRegistry) instructionGet(ctx context.Context, _ *mcp.CallToolRequest, input readonlyAddressInput) (*mcp.CallToolResult, ida.InstructionResult, error) {
	backend, id, ctx, cancel, err := registry.readonlyAnalysisCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.InstructionResult{}, err
	}
	defer cancel()
	params, err := parseReadonlyAddress(input)
	if err != nil {
		return nil, ida.InstructionResult{}, err
	}
	result, err := backend.InstructionGet(ctx, id, params)
	if err != nil {
		return nil, ida.InstructionResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}
func (registry *toolRegistry) fixupGet(ctx context.Context, _ *mcp.CallToolRequest, input readonlyAddressInput) (*mcp.CallToolResult, ida.FixupItem, error) {
	backend, id, ctx, cancel, err := registry.readonlyAnalysisCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.FixupItem{}, err
	}
	defer cancel()
	params, err := parseReadonlyAddress(input)
	if err != nil {
		return nil, ida.FixupItem{}, err
	}
	result, err := backend.FixupGet(ctx, id, params)
	if err != nil {
		return nil, ida.FixupItem{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}
func (registry *toolRegistry) switchGet(ctx context.Context, _ *mcp.CallToolRequest, input readonlyAddressInput) (*mcp.CallToolResult, ida.SwitchResult, error) {
	backend, id, ctx, cancel, err := registry.readonlyAnalysisCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.SwitchResult{}, err
	}
	defer cancel()
	params, err := parseReadonlyAddress(input)
	if err != nil {
		return nil, ida.SwitchResult{}, err
	}
	result, err := backend.SwitchGet(ctx, id, params)
	if err != nil {
		return nil, ida.SwitchResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(result.Cases, result)
}
func (registry *toolRegistry) functionChunks(ctx context.Context, _ *mcp.CallToolRequest, input readonlyPageInput) (*mcp.CallToolResult, ida.FunctionChunksResult, error) {
	backend, id, ctx, cancel, err := registry.readonlyAnalysisCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.FunctionChunksResult{}, err
	}
	defer cancel()
	address, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, ida.FunctionChunksResult{}, err
	}
	result, err := backend.FunctionChunks(ctx, id, ida.ReadonlyPageParams{Address: address, Offset: input.Offset, Limit: input.Limit})
	if err != nil {
		return nil, ida.FunctionChunksResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(result.Items, result)
}
func (registry *toolRegistry) exceptionTryBlocks(ctx context.Context, _ *mcp.CallToolRequest, input readonlyPageInput) (*mcp.CallToolResult, ida.TryBlocksResult, error) {
	backend, id, ctx, cancel, err := registry.readonlyAnalysisCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.TryBlocksResult{}, err
	}
	defer cancel()
	address, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, ida.TryBlocksResult{}, err
	}
	result, err := backend.ExceptionTryBlocks(ctx, id, ida.ReadonlyPageParams{Address: address, Limit: input.Limit})
	if err != nil {
		return nil, ida.TryBlocksResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(result.Items, result)
}
func addressListParams(input addressListInput) (ida.AddressListParams, error) {
	result := ida.AddressListParams{Limit: input.Limit}
	if input.Start != nil {
		v, e := parseToolAddress(*input.Start)
		if e != nil {
			return result, e
		}
		result.Start = &v
	}
	if input.End != nil {
		v, e := parseToolAddress(*input.End)
		if e != nil {
			return result, e
		}
		result.End = &v
	}
	if result.Start != nil && *result.Start >= *result.End {
		return result, ida.NewError(ida.ErrorInvalidArgument, "address range is invalid", false)
	}
	return result, nil
}
func (registry *toolRegistry) fixupList(ctx context.Context, _ *mcp.CallToolRequest, input addressListInput) (*mcp.CallToolResult, fixupListOutput, error) {
	backend, id, ctx, cancel, err := registry.readonlyAnalysisCall(ctx, input.InstanceID)
	if err != nil {
		return nil, fixupListOutput{}, err
	}
	defer cancel()
	params, err := addressListParams(input)
	if err != nil {
		return nil, fixupListOutput{}, err
	}
	binding := readonlyCursorBinding(ToolFixupList, id, params.Start, params.End, "", input.Limit)
	if input.Cursor != "" {
		internal, decodeErr := registry.cursors.decode("fx1", binding, input.Cursor)
		if decodeErr != nil {
			return nil, fixupListOutput{}, invalidCursorError()
		}
		address, parseErr := parseToolAddress(internal)
		if parseErr != nil || params.Start != nil && (address < *params.Start || address >= *params.End) {
			return nil, fixupListOutput{}, invalidCursorError()
		}
		params.NextAddress = &address
	}
	result, err := backend.FixupList(ctx, id, params)
	if err != nil {
		return nil, fixupListOutput{}, sanitizeToolError(err)
	}
	output := fixupListOutput{Items: result.Items, HasMore: result.HasMore}
	if result.NextAddress != nil {
		encoded, encodeErr := registry.cursors.encode("fx1", binding, result.NextAddress.String())
		if encodeErr != nil {
			return nil, fixupListOutput{}, ida.NewError(ida.ErrorInternal, "fixup cursor encoding failed", false)
		}
		output.NextCursor = &encoded
	}
	return checkedCollectionOutput(output.Items, output)
}
func (registry *toolRegistry) analysisStatus(ctx context.Context, _ *mcp.CallToolRequest, input analysisStatusInput) (*mcp.CallToolResult, ida.AnalysisStatusResult, error) {
	backend, id, ctx, cancel, err := registry.readonlyAnalysisCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.AnalysisStatusResult{}, err
	}
	defer cancel()
	result, err := backend.AnalysisStatus(ctx, id)
	if err != nil {
		return nil, ida.AnalysisStatusResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}
func defaultAnalysisWait(input *analysisWaitInput) {
	if input.TimeoutMs == 0 {
		input.TimeoutMs = 10000
	}
	if input.PollIntervalMs == 0 {
		input.PollIntervalMs = 200
	}
}
func (registry *toolRegistry) analysisWait(ctx context.Context, _ *mcp.CallToolRequest, input analysisWaitInput) (*mcp.CallToolResult, ida.AnalysisWaitResult, error) {
	if input.PollIntervalMs > input.TimeoutMs {
		return nil, ida.AnalysisWaitResult{}, ida.NewError(ida.ErrorInvalidArgument, "poll interval exceeds timeout", false)
	}
	backend, err := registry.readonlyAnalysisBackend()
	if err != nil {
		return nil, ida.AnalysisWaitResult{}, err
	}
	instanceID, err := registry.instances.resolve(input.InstanceID)
	if err != nil {
		return nil, ida.AnalysisWaitResult{}, err
	}
	started := time.Now()
	deadline := time.NewTimer(time.Duration(input.TimeoutMs) * time.Millisecond)
	defer deadline.Stop()
	waitContext, cancel := context.WithTimeout(ctx, time.Duration(input.TimeoutMs)*time.Millisecond)
	defer cancel()
	var last ida.AnalysisStatusResult
	var polls uint32
	for {
		status, callErr := backend.AnalysisStatus(waitContext, instanceID)
		if callErr != nil {
			if ctx.Err() != nil {
				return nil, ida.AnalysisWaitResult{}, ctx.Err()
			}
			if waitContext.Err() != nil && polls > 0 {
				return checkedOutput(ida.AnalysisWaitResult{AnalysisStatusResult: last, TimedOut: true, PollCount: polls, ElapsedMs: uint64(time.Since(started).Milliseconds())})
			}
			return nil, ida.AnalysisWaitResult{}, sanitizeToolError(callErr)
		}
		last = status
		polls++
		if status.Complete {
			return checkedOutput(ida.AnalysisWaitResult{AnalysisStatusResult: status, PollCount: polls, ElapsedMs: uint64(time.Since(started).Milliseconds())})
		}
		interval := time.NewTimer(time.Duration(input.PollIntervalMs) * time.Millisecond)
		select {
		case <-ctx.Done():
			if !interval.Stop() {
				select {
				case <-interval.C:
				default:
				}
			}
			return nil, ida.AnalysisWaitResult{}, ctx.Err()
		case <-deadline.C:
			if !interval.Stop() {
				select {
				case <-interval.C:
				default:
				}
			}
			return checkedOutput(ida.AnalysisWaitResult{AnalysisStatusResult: last, TimedOut: true, PollCount: polls, ElapsedMs: uint64(time.Since(started).Milliseconds())})
		case <-interval.C:
		}
	}
}
func (registry *toolRegistry) analysisPlan(ctx context.Context, _ *mcp.CallToolRequest, input analysisPlanInput) (*mcp.CallToolResult, ida.AnalysisPlanResult, error) {
	if !input.Confirm {
		return nil, ida.AnalysisPlanResult{}, ida.NewError(ida.ErrorInvalidArgument, "analysis.plan requires confirmation", false)
	}
	start, err := parseToolAddress(input.Start)
	if err != nil {
		return nil, ida.AnalysisPlanResult{}, err
	}
	end, err := parseToolAddress(input.End)
	if err != nil || start >= end || uint64(end-start) > 16*1024*1024 {
		return nil, ida.AnalysisPlanResult{}, ida.NewError(ida.ErrorInvalidArgument, "analysis.plan range is invalid", false)
	}
	if err := registry.ensureBackend(); err != nil {
		return nil, ida.AnalysisPlanResult{}, err
	}
	backend, ok := registry.backend.(ida.AnalysisControlBackend)
	if !ok {
		return nil, ida.AnalysisPlanResult{}, ida.NewError(ida.ErrorCapabilityUnavailable, "analysis control backend is unavailable", false)
	}
	requestContext, instanceID, cancel, err := registry.catalogInstance(ctx, input.InstanceID, mutationWriteToolTimeout)
	if err != nil {
		return nil, ida.AnalysisPlanResult{}, err
	}
	defer cancel()
	result, err := backend.AnalysisPlan(requestContext, instanceID, ida.AnalysisPlanParams{Start: start, End: end})
	if err != nil {
		return nil, ida.AnalysisPlanResult{}, sanitizeToolError(err)
	}
	return checkedOutput(result)
}
func (registry *toolRegistry) analysisProblems(ctx context.Context, _ *mcp.CallToolRequest, input analysisProblemsInput) (*mcp.CallToolResult, analysisProblemsOutput, error) {
	backend, id, ctx, cancel, err := registry.readonlyAnalysisCall(ctx, input.InstanceID)
	if err != nil {
		return nil, analysisProblemsOutput{}, err
	}
	defer cancel()
	params := ida.AnalysisProblemsParams{Type: input.Type, Limit: input.Limit}
	if input.Start != nil {
		v, e := parseToolAddress(*input.Start)
		if e != nil {
			return nil, analysisProblemsOutput{}, e
		}
		params.Start = &v
	}
	binding := readonlyCursorBinding(ToolAnalysisProblems, id, params.Start, nil, input.Type, input.Limit)
	if input.Cursor != "" {
		internal, decodeErr := registry.cursors.decode("pr1", binding, input.Cursor)
		if decodeErr != nil {
			return nil, analysisProblemsOutput{}, invalidCursorError()
		}
		address, parseErr := parseToolAddress(internal)
		if parseErr != nil || params.Start != nil && address < *params.Start {
			return nil, analysisProblemsOutput{}, invalidCursorError()
		}
		params.NextAddress = &address
	}
	result, err := backend.AnalysisProblems(ctx, id, params)
	if err != nil {
		return nil, analysisProblemsOutput{}, sanitizeToolError(err)
	}
	output := analysisProblemsOutput{Items: result.Items, HasMore: result.HasMore}
	if result.NextAddress != nil {
		encoded, encodeErr := registry.cursors.encode("pr1", binding, result.NextAddress.String())
		if encodeErr != nil {
			return nil, analysisProblemsOutput{}, ida.NewError(ida.ErrorInternal, "analysis problem cursor encoding failed", false)
		}
		output.NextCursor = &encoded
	}
	return checkedCollectionOutput(output.Items, output)
}

func readonlyCursorBinding(method, instanceID string, start, end *ida.Address, problemType string, limit uint32) string {
	startText, endText := "", ""
	if start != nil {
		startText = start.String()
	}
	if end != nil {
		endText = end.String()
	}
	return method + "\x00" + instanceID + "\x00" + startText + "\x00" + endText + "\x00" + problemType + "\x00" + strconv.FormatUint(uint64(limit), 10)
}
func defaultReadonlyPage(input *readonlyPageInput) {
	if input.Limit == 0 {
		input.Limit = 20
	}
}
func defaultAddressList(input *addressListInput) {
	if input.Limit == 0 {
		input.Limit = 20
	}
}
func defaultAnalysisProblems(input *analysisProblemsInput) {
	if input.Limit == 0 {
		input.Limit = 20
	}
}
