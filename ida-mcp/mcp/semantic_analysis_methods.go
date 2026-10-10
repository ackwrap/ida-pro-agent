package mcpserver

import (
	"context"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"ida-mcp/ida"
	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
	"time"
)

const ToolTraceArgument = "analysis.trace_argument"
const ToolGuardEvidence = "analysis.guard_evidence"
const argumentAnalysisInputSchema = `{
 "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["callAddress","argumentIndex"],"properties":{
 "instanceId":` + instanceIDSchema + `,"callAddress":` + addressSchema + `,
 "argumentIndex":{"type":"integer","minimum":0,"maximum":255},
 "maxNodes":{"type":"integer","minimum":1,"maximum":1000,"default":200},
 "maxWork":{"type":"integer","minimum":1,"maximum":100000,"default":20000},
 "maxGuards":{"type":"integer","minimum":1,"maximum":128,"default":32}}}`

type argumentAnalysisInput struct {
	InstanceID    *string `json:"instanceId,omitempty"`
	CallAddress   string  `json:"callAddress"`
	ArgumentIndex uint32  `json:"argumentIndex"`
	MaxNodes      uint32  `json:"maxNodes,omitempty"`
	MaxWork       uint32  `json:"maxWork,omitempty"`
	MaxGuards     uint32  `json:"maxGuards,omitempty"`
}

func defaultArgumentAnalysis(i *argumentAnalysisInput) {
	if i.MaxNodes == 0 {
		i.MaxNodes = 200
	}
	if i.MaxWork == 0 {
		i.MaxWork = 20000
	}
	if i.MaxGuards == 0 {
		i.MaxGuards = 32
	}
}
func (r *toolRegistry) runArgumentAnalysis(ctx context.Context, input argumentAnalysisInput, guards bool) (*mcp.CallToolResult, ida.ArgumentAnalysisResult, error) {
	backend, ok := r.backend.(ida.SemanticAnalysisBackend)
	if !ok {
		return nil, ida.ArgumentAnalysisResult{}, ida.NewError(ida.ErrorCapabilityUnavailable, "semantic analysis backend is unavailable", false)
	}
	ctx, instance, cancel, err := r.catalogInstance(ctx, input.InstanceID, 60*time.Second)
	if err != nil {
		return nil, ida.ArgumentAnalysisResult{}, err
	}
	defer cancel()
	address, err := parseToolAddress(input.CallAddress)
	if err != nil {
		return nil, ida.ArgumentAnalysisResult{}, err
	}
	params := ida.ArgumentAnalysisParams{CallAddress: address, ArgumentIndex: input.ArgumentIndex, MaxNodes: input.MaxNodes, MaxWork: input.MaxWork, MaxGuards: input.MaxGuards}
	var result ida.ArgumentAnalysisResult
	if guards {
		result, err = backend.GuardEvidence(ctx, instance, params)
	} else {
		result, err = backend.TraceArgument(ctx, instance, params)
	}
	if err != nil {
		return nil, ida.ArgumentAnalysisResult{}, sanitizeToolError(err)
	}
	if err = bridge.ValidateArgumentAnalysis(result, bridge.ArgumentAnalysisParams{CallAddress: rpc.Address(address), ArgumentIndex: params.ArgumentIndex, MaxNodes: params.MaxNodes, MaxWork: params.MaxWork, MaxGuards: params.MaxGuards}, guards); err != nil {
		return nil, ida.ArgumentAnalysisResult{}, ida.NewError(ida.ErrorInternal, "argument analysis result is invalid", false)
	}
	return checkedOutput(result)
}
func (r *toolRegistry) traceArgument(ctx context.Context, _ *mcp.CallToolRequest, input argumentAnalysisInput) (*mcp.CallToolResult, ida.ArgumentAnalysisResult, error) {
	return r.runArgumentAnalysis(ctx, input, false)
}
func (r *toolRegistry) guardEvidence(ctx context.Context, _ *mcp.CallToolRequest, input argumentAnalysisInput) (*mcp.CallToolResult, ida.ArgumentAnalysisResult, error) {
	return r.runArgumentAnalysis(ctx, input, true)
}
