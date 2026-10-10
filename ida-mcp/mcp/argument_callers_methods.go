package mcpserver

import (
	"context"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"ida-mcp/ida"
	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
	"time"
)

const ToolTraceArgumentCallers = "analysis.trace_argument_callers"
const argumentCallersInputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["callAddress","argumentIndex"],"properties":{
 "instanceId":` + instanceIDSchema + `,"callAddress":` + addressSchema + `,
 "argumentIndex":{"type":"integer","minimum":0,"maximum":255},
 "maxDepth":{"type":"integer","minimum":0,"maximum":5,"default":2},
 "maxContexts":{"type":"integer","minimum":1,"maximum":64,"default":16},
 "maxCallers":{"type":"integer","minimum":1,"maximum":32,"default":8},
 "maxNodes":{"type":"integer","minimum":1,"maximum":4000,"default":1000},
 "maxWork":{"type":"integer","minimum":1,"maximum":1000000,"default":100000}}}`

type argumentCallersInput struct {
	InstanceID    *string `json:"instanceId,omitempty"`
	CallAddress   string  `json:"callAddress"`
	ArgumentIndex uint32  `json:"argumentIndex"`
	MaxDepth      *uint32 `json:"maxDepth,omitempty"`
	MaxContexts   uint32  `json:"maxContexts,omitempty"`
	MaxCallers    uint32  `json:"maxCallers,omitempty"`
	MaxNodes      uint32  `json:"maxNodes,omitempty"`
	MaxWork       uint32  `json:"maxWork,omitempty"`
}

func defaultArgumentCallers(p *argumentCallersInput) {
	if p.MaxDepth == nil {
		depth := uint32(2)
		p.MaxDepth = &depth
	}
	if p.MaxContexts == 0 {
		p.MaxContexts = 16
	}
	if p.MaxCallers == 0 {
		p.MaxCallers = 8
	}
	if p.MaxNodes == 0 {
		p.MaxNodes = 1000
	}
	if p.MaxWork == 0 {
		p.MaxWork = 100000
	}
}
func (r *toolRegistry) traceArgumentCallers(ctx context.Context, _ *mcp.CallToolRequest, input argumentCallersInput) (*mcp.CallToolResult, ida.ArgumentCallersResult, error) {
	b, ok := r.backend.(ida.ArgumentCallersBackend)
	if !ok {
		return nil, ida.ArgumentCallersResult{}, ida.NewError(ida.ErrorCapabilityUnavailable, "caller tracing is unavailable", false)
	}
	ctx, id, cancel, err := r.catalogInstance(ctx, input.InstanceID, 60*time.Second)
	if err != nil {
		return nil, ida.ArgumentCallersResult{}, err
	}
	defer cancel()
	address, err := parseToolAddress(input.CallAddress)
	if err != nil {
		return nil, ida.ArgumentCallersResult{}, err
	}
	p := ida.ArgumentCallersParams{CallAddress: address, ArgumentIndex: input.ArgumentIndex, MaxDepth: *input.MaxDepth, MaxContexts: input.MaxContexts, MaxCallers: input.MaxCallers, MaxNodes: input.MaxNodes, MaxWork: input.MaxWork}
	result, err := b.TraceArgumentCallers(ctx, id, p)
	if err != nil {
		return nil, ida.ArgumentCallersResult{}, sanitizeToolError(err)
	}
	wire := bridge.ArgumentCallersParams{CallAddress: rpc.Address(address), ArgumentIndex: p.ArgumentIndex, MaxDepth: p.MaxDepth, MaxContexts: p.MaxContexts, MaxCallers: p.MaxCallers, MaxNodes: p.MaxNodes, MaxWork: p.MaxWork}
	if bridge.ValidateArgumentCallers(result, wire) != nil {
		return nil, ida.ArgumentCallersResult{}, ida.NewError(ida.ErrorInternal, "invalid caller trace result", false)
	}
	return checkedOutput(result)
}
