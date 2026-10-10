package bridge

import (
	"context"
	"errors"

	"ida-mcp/ida/rpc"
)

const (
	methodAnalysisComponent rpcMethod = "analysis.component"
	methodTraceDataFlow     rpcMethod = "analysis.trace_data_flow"
)

type AnalysisComponentParams struct {
	Roots       []rpc.Address `json:"roots"`
	MaxDepth    uint32        `json:"maxDepth"`
	MaxNodes    uint32        `json:"maxNodes,omitempty"`
	MaxEdges    uint32        `json:"maxEdges,omitempty"`
	PerFunction uint32        `json:"perFunction,omitempty"`
	SharedLimit uint32        `json:"sharedLimit,omitempty"`
}
type ComponentGlobal struct {
	Address      rpc.Address   `json:"address"`
	Name         string        `json:"name"`
	Kind         string        `json:"kind"`
	ReferencedBy []rpc.Address `json:"referencedBy"`
}
type ComponentString struct {
	Address      rpc.Address   `json:"address"`
	Length       uint64        `json:"length"`
	Encoding     string        `json:"encoding"`
	Value        string        `json:"value"`
	Truncated    bool          `json:"truncated"`
	OriginalSize uint64        `json:"originalSize"`
	ReferencedBy []rpc.Address `json:"referencedBy"`
}
type ComponentStatistics struct {
	Internal struct {
		Functions uint64 `json:"functions"`
		Calls     uint64 `json:"calls"`
	} `json:"internal"`
	Interface struct {
		IncomingCalls uint64 `json:"incomingCalls"`
		OutgoingCalls uint64 `json:"outgoingCalls"`
	} `json:"interface"`
}
type AnalysisComponentResult struct {
	Graph         FunctionCallGraphResult `json:"graph"`
	Members       []FunctionInfo          `json:"members"`
	SharedGlobals []ComponentGlobal       `json:"sharedGlobals"`
	SharedStrings []ComponentString       `json:"sharedStrings"`
	Statistics    ComponentStatistics     `json:"statistics"`
	Truncated     bool                    `json:"truncated"`
}
type TraceDataFlowParams struct {
	Address   rpc.Address `json:"address"`
	Direction string      `json:"direction,omitempty"`
	MaxDepth  uint32      `json:"maxDepth"`
	MaxNodes  uint32      `json:"maxNodes,omitempty"`
	MaxEdges  uint32      `json:"maxEdges,omitempty"`
}
type TraceFunction struct {
	EntryAddress rpc.Address `json:"entryAddress"`
	Name         string      `json:"name"`
	Prototype    *string     `json:"prototype"`
}
type TraceString struct {
	Address      rpc.Address `json:"address"`
	Length       uint64      `json:"length"`
	Encoding     string      `json:"encoding"`
	Value        string      `json:"value"`
	Truncated    bool        `json:"truncated"`
	OriginalSize uint64      `json:"originalSize"`
}
type TraceNode struct {
	Address    rpc.Address    `json:"address"`
	Kind       string         `json:"kind"`
	Function   *TraceFunction `json:"function,omitempty"`
	String     *TraceString   `json:"string,omitempty"`
	Name       string         `json:"name,omitempty"`
	SymbolKind string         `json:"symbolKind,omitempty"`
}
type TraceDataFlowResult struct {
	Model     string      `json:"model"`
	Nodes     []TraceNode `json:"nodes"`
	Edges     []XrefInfo  `json:"edges"`
	Truncated bool        `json:"truncated"`
}

func (client *Client) AnalyzeComponent(ctx context.Context, instance rpc.InstanceDescriptor, params AnalysisComponentParams) (AnalysisComponentResult, error) {
	result, err := callTyped[AnalysisComponentParams, AnalysisComponentResult](client, ctx, instance, methodAnalysisComponent, params)
	if err == nil && (result.Graph.Nodes == nil || result.Graph.Edges == nil || result.Members == nil || result.SharedGlobals == nil || result.SharedStrings == nil || len(result.Graph.Nodes) > int(params.MaxNodes) || len(result.Graph.Edges) > int(params.MaxEdges)) {
		err = errors.New("analysis.component result is invalid")
	}
	return result, err
}
func (client *Client) TraceDataFlow(ctx context.Context, instance rpc.InstanceDescriptor, params TraceDataFlowParams) (TraceDataFlowResult, error) {
	result, err := callTyped[TraceDataFlowParams, TraceDataFlowResult](client, ctx, instance, methodTraceDataFlow, params)
	if err == nil && (result.Model != "xref_bfs" || result.Nodes == nil || result.Edges == nil || len(result.Nodes) > int(params.MaxNodes) || len(result.Edges) > int(params.MaxEdges)) {
		err = errors.New("analysis.trace_data_flow result is invalid")
	}
	return result, err
}
