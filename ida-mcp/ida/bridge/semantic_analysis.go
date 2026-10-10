package bridge

import (
	"context"
	"errors"
	"ida-mcp/ida/rpc"
	"slices"
	"unicode/utf8"
)

type ArgumentAnalysisParams struct {
	CallAddress   rpc.Address `json:"callAddress"`
	ArgumentIndex uint32      `json:"argumentIndex"`
	MaxNodes      uint32      `json:"maxNodes"`
	MaxWork       uint32      `json:"maxWork"`
	MaxGuards     uint32      `json:"maxGuards"`
}
type ArgumentNode struct {
	ID        uint32       `json:"id"`
	Kind      string       `json:"kind"`
	Operation string       `json:"operation"`
	Bits      uint32       `json:"bits"`
	Address   *rpc.Address `json:"address"`
	Value     string       `json:"value"`
}
type ArgumentEdge struct {
	From uint32 `json:"from"`
	To   uint32 `json:"to"`
}
type GuardEvidence struct {
	Address        *rpc.Address `json:"address"`
	Operation      string       `json:"operation"`
	Bits           uint32       `json:"bits"`
	Operands       []uint32     `json:"operands"`
	RequiredBranch string       `json:"requiredBranch"`
	ValueRelation  string       `json:"valueRelation"`
}
type ArgumentAnalysisResult struct {
	EntryAddress  rpc.Address     `json:"entryAddress"`
	CallAddress   rpc.Address     `json:"callAddress"`
	ArgumentIndex uint32          `json:"argumentIndex"`
	ArgumentCount uint32          `json:"argumentCount"`
	ArgumentType  string          `json:"argumentType"`
	Model         string          `json:"model"`
	Maturity      string          `json:"maturity"`
	Scope         string          `json:"scope"`
	Status        string          `json:"status"`
	CFGComplete   bool            `json:"cfgComplete"`
	Root          *uint32         `json:"root"`
	Nodes         []ArgumentNode  `json:"nodes"`
	Edges         []ArgumentEdge  `json:"edges"`
	Guards        []GuardEvidence `json:"guards"`
	Limitations   []string        `json:"limitations"`
	Truncated     bool            `json:"truncated"`
	VisitedStates uint32          `json:"visitedStates"`
}

func ValidArgumentAnalysisParams(p ArgumentAnalysisParams) bool {
	return p.ArgumentIndex <= 255 && p.MaxNodes >= 1 && p.MaxNodes <= 1000 && p.MaxWork >= 1 && p.MaxWork <= 100000 && p.MaxGuards >= 1 && p.MaxGuards <= 128
}
func ValidateArgumentAnalysis(result ArgumentAnalysisResult, p ArgumentAnalysisParams, guards bool) error {
	invalid := errors.New("argument analysis result is invalid")
	if !ValidArgumentAnalysisParams(p) || result.Model != "microcode_reaching_definitions" || result.Maturity != "MMAT_CALLS" || result.Scope != "function" ||
		!slices.Contains([]string{"complete", "partial"}, result.Status) || result.CallAddress != p.CallAddress || result.ArgumentIndex != p.ArgumentIndex ||
		result.ArgumentCount == 0 || result.ArgumentCount > 256 || result.ArgumentIndex >= result.ArgumentCount ||
		result.Nodes == nil || result.Edges == nil || result.Guards == nil || result.Limitations == nil ||
		len(result.Nodes) > int(p.MaxNodes) || len(result.Edges) > 2000 || len(result.Guards) > int(p.MaxGuards) || result.VisitedStates > p.MaxWork ||
		len(result.ArgumentType) > 4096 || !utf8.ValidString(result.ArgumentType) || len(result.Limitations) > 64 || (!guards && len(result.Guards) > 0) {
		return invalid
	}
	if result.Root != nil && *result.Root >= uint32(len(result.Nodes)) {
		return invalid
	}
	if result.Status == "complete" && (result.Root == nil || result.Truncated || !result.CFGComplete || len(result.Limitations) > 0) {
		return invalid
	}
	for i, n := range result.Nodes {
		if n.ID != uint32(i) || n.Bits > 128 || len(n.Operation) > 128 || len(n.Value) > 4096 || !utf8.ValidString(n.Operation+n.Value) ||
			!slices.Contains([]string{"constant", "operation", "parameter", "entry_value", "call_return", "memory_read", "address", "unknown", "merge"}, n.Kind) {
			return invalid
		}
	}
	for _, e := range result.Edges {
		if e.From >= uint32(len(result.Nodes)) || e.To >= uint32(len(result.Nodes)) || e.From == e.To {
			return invalid
		}
	}
	for _, g := range result.Guards {
		if g.Operands == nil || len(g.Operands) > 2 || g.Bits > 128 || len(g.Operation) > 128 || !utf8.ValidString(g.Operation) ||
			!slices.Contains([]string{"true", "false", "neither", "unknown"}, g.RequiredBranch) ||
			!slices.Contains([]string{"same_value", "derived_value", "unrelated", "unknown"}, g.ValueRelation) || (!result.CFGComplete && g.RequiredBranch != "unknown") {
			return invalid
		}
		for _, id := range g.Operands {
			if id >= uint32(len(result.Nodes)) {
				return invalid
			}
		}
	}
	for _, reason := range result.Limitations {
		if len(reason) == 0 || len(reason) > 128 || !utf8.ValidString(reason) {
			return invalid
		}
	}
	return nil
}
func (c *Client) TraceArgument(ctx context.Context, instance rpc.InstanceDescriptor, p ArgumentAnalysisParams) (ArgumentAnalysisResult, error) {
	if !ValidArgumentAnalysisParams(p) {
		return ArgumentAnalysisResult{}, errors.New("invalid argument analysis parameters")
	}
	result, err := callTyped[ArgumentAnalysisParams, ArgumentAnalysisResult](c, ctx, instance, rpcMethod("analysis.trace_argument"), p)
	if err == nil {
		err = ValidateArgumentAnalysis(result, p, false)
	}
	return result, err
}
func (c *Client) GuardEvidence(ctx context.Context, instance rpc.InstanceDescriptor, p ArgumentAnalysisParams) (ArgumentAnalysisResult, error) {
	if !ValidArgumentAnalysisParams(p) {
		return ArgumentAnalysisResult{}, errors.New("invalid argument analysis parameters")
	}
	result, err := callTyped[ArgumentAnalysisParams, ArgumentAnalysisResult](c, ctx, instance, rpcMethod("analysis.guard_evidence"), p)
	if err == nil {
		err = ValidateArgumentAnalysis(result, p, true)
	}
	return result, err
}
