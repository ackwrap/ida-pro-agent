package bridge

import (
	"context"
	"errors"
	"unicode/utf8"

	"ida-mcp/ida/rpc"
)

const (
	methodFunctionCallers    = "function.callers"
	methodFunctionCallGraph  = "function.callgraph"
	methodFunctionProfile    = "function.profile"
	methodFunctionExport     = "function.export"
	methodFunctionStackFrame = "function.stack_frame"
)

type FunctionCallersParams struct {
	Address rpc.Address `json:"address"`
	Offset  uint32      `json:"offset,omitempty"`
	Limit   int         `json:"limit,omitempty"`
}

type FunctionCaller struct {
	Address   rpc.Address   `json:"address"`
	Name      string        `json:"name"`
	CallSites []rpc.Address `json:"callSites"`
}

type FunctionCallersResult struct {
	EntryAddress rpc.Address      `json:"entryAddress"`
	Items        []FunctionCaller `json:"items"`
	NextOffset   *uint32          `json:"nextOffset"`
	HasMore      bool             `json:"hasMore"`
}

type FunctionCallGraphParams struct {
	Roots       []rpc.Address `json:"roots"`
	Direction   string        `json:"direction,omitempty"`
	MaxDepth    uint32        `json:"maxDepth"`
	MaxNodes    uint32        `json:"maxNodes,omitempty"`
	MaxEdges    uint32        `json:"maxEdges,omitempty"`
	PerFunction uint32        `json:"perFunction,omitempty"`
}

type FunctionCallGraphNode struct {
	Address rpc.Address `json:"address"`
	Name    string      `json:"name"`
	Depth   uint32      `json:"depth"`
}

type FunctionCallGraphEdge struct {
	From rpc.Address `json:"from"`
	To   rpc.Address `json:"to"`
}

type FunctionCallGraphResult struct {
	Nodes     []FunctionCallGraphNode `json:"nodes"`
	Edges     []FunctionCallGraphEdge `json:"edges"`
	Truncated bool                    `json:"truncated"`
}

type FunctionProfileParams struct {
	Name             string `json:"name,omitempty"`
	MinSize          uint32 `json:"minSize,omitempty"`
	MaxSize          uint32 `json:"maxSize,omitempty"`
	Library          *bool  `json:"library,omitempty"`
	Thunk            *bool  `json:"thunk,omitempty"`
	IncludePrototype bool   `json:"includePrototype,omitempty"`
	SampleLimit      uint32 `json:"sampleLimit,omitempty"`
	Limit            uint32 `json:"limit,omitempty"`
	Cursor           string `json:"cursor,omitempty"`
}

type FunctionProfileMetrics struct {
	SizeBytes    uint64 `json:"sizeBytes"`
	Instructions uint64 `json:"instructions"`
	BasicBlocks  uint64 `json:"basicBlocks"`
	Chunks       uint64 `json:"chunks"`
}

type FunctionProfileFlags struct {
	Library bool `json:"library"`
	Thunk   bool `json:"thunk"`
}

type FunctionProfileItem struct {
	Address          rpc.Address            `json:"address"`
	Name             string                 `json:"name"`
	Metrics          FunctionProfileMetrics `json:"metrics"`
	Flags            FunctionProfileFlags   `json:"flags"`
	Prototype        *string                `json:"prototype,omitempty"`
	Samples          *[]DisassemblyItem     `json:"samples,omitempty"`
	SamplesTruncated *bool                  `json:"samplesTruncated,omitempty"`
}

type FunctionProfileSummary struct {
	Candidates          uint32 `json:"candidates"`
	Matched             uint32 `json:"matched"`
	SampledInstructions uint32 `json:"sampledInstructions"`
}

type FunctionProfileResult struct {
	Items      []FunctionProfileItem  `json:"items"`
	NextCursor *string                `json:"nextCursor"`
	HasMore    bool                   `json:"hasMore"`
	Metrics    FunctionProfileSummary `json:"metrics"`
}

type FunctionExportParams struct {
	Addresses []rpc.Address `json:"addresses"`
	Format    string        `json:"format"`
	MaxBytes  uint32        `json:"maxBytes,omitempty"`
}

type FunctionExportResult struct {
	Format       string `json:"format"`
	Content      string `json:"content"`
	Truncated    bool   `json:"truncated"`
	OriginalSize uint64 `json:"originalSize"`
}

type StackVariable struct {
	Name        string `json:"name"`
	Declaration string `json:"declaration"`
	BitOffset   int64  `json:"bitOffset"`
	BitSize     uint64 `json:"bitSize"`
	Role        string `json:"role"`
}

type FunctionStackFrameParams struct {
	Address rpc.Address `json:"address"`
}

type FunctionStackFrameResult struct {
	EntryAddress rpc.Address     `json:"entryAddress"`
	Size         uint64          `json:"size"`
	Variables    []StackVariable `json:"variables"`
}

func (client *Client) FunctionCallers(ctx context.Context, instance rpc.InstanceDescriptor, params FunctionCallersParams) (FunctionCallersResult, error) {
	result, err := callTyped[FunctionCallersParams, FunctionCallersResult](client, ctx, instance, methodFunctionCallers, params)
	if err == nil {
		err = result.Validate(params)
	}
	return result, err
}

func (client *Client) FunctionCallGraph(ctx context.Context, instance rpc.InstanceDescriptor, params FunctionCallGraphParams) (FunctionCallGraphResult, error) {
	result, err := callTyped[FunctionCallGraphParams, FunctionCallGraphResult](client, ctx, instance, methodFunctionCallGraph, params)
	if err == nil {
		err = result.Validate(params)
	}
	return result, err
}

func (client *Client) FunctionProfile(ctx context.Context, instance rpc.InstanceDescriptor, params FunctionProfileParams) (FunctionProfileResult, error) {
	result, err := callTyped[FunctionProfileParams, FunctionProfileResult](client, ctx, instance, methodFunctionProfile, params)
	if err == nil {
		err = result.Validate(params)
	}
	return result, err
}

func (client *Client) FunctionExport(ctx context.Context, instance rpc.InstanceDescriptor, params FunctionExportParams) (FunctionExportResult, error) {
	result, err := callTyped[FunctionExportParams, FunctionExportResult](client, ctx, instance, methodFunctionExport, params)
	if err == nil && (result.Format != params.Format || result.Content == "" || result.OriginalSize < uint64(len(result.Content)) || result.Truncated != (result.OriginalSize > uint64(len(result.Content)))) {
		err = errors.New("function.export result is invalid")
	}
	return result, err
}

func (client *Client) FunctionStackFrame(ctx context.Context, instance rpc.InstanceDescriptor, params FunctionStackFrameParams) (FunctionStackFrameResult, error) {
	result, err := callTyped[FunctionStackFrameParams, FunctionStackFrameResult](client, ctx, instance, methodFunctionStackFrame, params)
	if err == nil && result.Variables == nil {
		err = errors.New("function.stack_frame result is invalid")
	}
	return result, err
}

func (result FunctionCallersResult) Validate(params FunctionCallersParams) error {
	limit := params.Limit
	if limit == 0 {
		limit = 20
	}
	if result.Items == nil || len(result.Items) > limit || result.HasMore != (result.NextOffset != nil) {
		return errors.New("function.callers pagination is invalid")
	}
	if result.NextOffset != nil && (len(result.Items) == 0 || *result.NextOffset != params.Offset+uint32(len(result.Items))) {
		return errors.New("function.callers continuation is invalid")
	}
	var previous rpc.Address
	for index, item := range result.Items {
		if item.Name == "" || !utf8.ValidString(item.Name) || len(item.Name) > 4096 || len(item.CallSites) > 4096 || (index > 0 && item.Address <= previous) {
			return errors.New("function.callers item is invalid")
		}
		previous = item.Address
	}
	return nil
}

func (result FunctionCallGraphResult) Validate(params FunctionCallGraphParams) error {
	maxNodes := params.MaxNodes
	if maxNodes == 0 {
		maxNodes = 100
	}
	maxEdges := params.MaxEdges
	if maxEdges == 0 {
		maxEdges = 200
	}
	if result.Nodes == nil || len(result.Nodes) == 0 || result.Edges == nil || len(result.Nodes) > int(maxNodes) || len(result.Edges) > int(maxEdges) {
		return errors.New("function.callgraph result is invalid")
	}
	for _, node := range result.Nodes {
		if node.Name == "" || !utf8.ValidString(node.Name) || len(node.Name) > 4096 {
			return errors.New("function.callgraph node is invalid")
		}
	}
	return nil
}

func (result FunctionProfileResult) Validate(params FunctionProfileParams) error {
	limit := params.Limit
	if limit == 0 {
		limit = 20
	}
	if result.Items == nil || len(result.Items) > int(limit) || result.HasMore != (result.NextCursor != nil) {
		return errors.New("function.profile pagination is invalid")
	}
	if result.Metrics.Matched != uint32(len(result.Items)) || result.Metrics.Candidates > limit {
		return errors.New("function.profile metrics are invalid")
	}
	for _, item := range result.Items {
		if item.Name == "" || !utf8.ValidString(item.Name) || len(item.Name) > 4096 {
			return errors.New("function.profile item is invalid")
		}
		if (!params.IncludePrototype && item.Prototype != nil) ||
			(params.SampleLimit == 0 && (item.Samples != nil || item.SamplesTruncated != nil)) ||
			(params.SampleLimit != 0 && (item.Samples == nil || item.SamplesTruncated == nil || len(*item.Samples) > int(params.SampleLimit))) {
			return errors.New("function.profile optional fields are invalid")
		}
	}
	return nil
}
