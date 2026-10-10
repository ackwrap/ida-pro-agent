package bridge

import (
	"context"
	"errors"
	"ida-mcp/ida/rpc"
	"slices"
	"strconv"
	"strings"
)

type ArgumentCallersParams struct {
	CallAddress   rpc.Address `json:"callAddress"`
	ArgumentIndex uint32      `json:"argumentIndex"`
	MaxDepth      uint32      `json:"maxDepth"`
	MaxContexts   uint32      `json:"maxContexts"`
	MaxCallers    uint32      `json:"maxCallers"`
	MaxNodes      uint32      `json:"maxNodes"`
	MaxWork       uint32      `json:"maxWork"`
}
type ArgumentContext struct {
	ID    uint32                 `json:"id"`
	Depth uint32                 `json:"depth"`
	Trace ArgumentAnalysisResult `json:"trace"`
}
type ArgumentContextLink struct {
	FromContext   uint32 `json:"fromContext"`
	ParameterNode uint32 `json:"parameterNode"`
	ToContext     uint32 `json:"toContext"`
}
type ArgumentBoundary struct {
	Context       uint32       `json:"context"`
	ParameterNode *uint32      `json:"parameterNode"`
	CallAddress   *rpc.Address `json:"callAddress"`
	Reason        string       `json:"reason"`
}
type ArgumentCallersResult struct {
	CallAddress   rpc.Address           `json:"callAddress"`
	ArgumentIndex uint32                `json:"argumentIndex"`
	Model         string                `json:"model"`
	Scope         string                `json:"scope"`
	Status        string                `json:"status"`
	Contexts      []ArgumentContext     `json:"contexts"`
	Links         []ArgumentContextLink `json:"links"`
	Boundaries    []ArgumentBoundary    `json:"boundaries"`
	Limitations   []string              `json:"limitations"`
	Truncated     bool                  `json:"truncated"`
	VisitedWork   uint32                `json:"visitedWork"`
	TotalNodes    uint32                `json:"totalNodes"`
}

func ValidArgumentCallersParams(p ArgumentCallersParams) bool {
	return p.ArgumentIndex <= 255 && p.MaxDepth <= 5 && p.MaxContexts >= 1 && p.MaxContexts <= 64 &&
		p.MaxCallers >= 1 && p.MaxCallers <= 32 && p.MaxNodes >= 1 && p.MaxNodes <= 4000 && p.MaxWork >= 1 && p.MaxWork <= 1000000
}
func ValidateArgumentCallers(r ArgumentCallersResult, p ArgumentCallersParams) error {
	invalid := errors.New("caller argument trace is invalid")
	if !ValidArgumentCallersParams(p) || r.CallAddress != p.CallAddress || r.ArgumentIndex != p.ArgumentIndex ||
		r.Model != "microcode_caller_contexts" || r.Scope != "known_direct_callers" || !slices.Contains([]string{"complete", "partial"}, r.Status) ||
		r.Contexts == nil || r.Links == nil || r.Boundaries == nil || r.Limitations == nil || len(r.Contexts) > int(p.MaxContexts) ||
		len(r.Boundaries) > 512 || len(r.Limitations) > 64 || r.VisitedWork > p.MaxWork || r.TotalNodes > p.MaxNodes {
		return invalid
	}
	partial := r.Truncated || len(r.Boundaries) > 0 || len(r.Limitations) > 0
	reachable := make([]map[uint32]bool, len(r.Contexts))
	parameterOrigin := false
	var nodes, work uint32
	for i, c := range r.Contexts {
		if c.ID != uint32(i) || c.Depth > p.MaxDepth || (i == 0 && (c.Depth != 0 || c.Trace.CallAddress != p.CallAddress || c.Trace.ArgumentIndex != p.ArgumentIndex)) {
			return invalid
		}
		local := ArgumentAnalysisParams{CallAddress: c.Trace.CallAddress, ArgumentIndex: c.Trace.ArgumentIndex, MaxNodes: min(p.MaxNodes, 1000), MaxWork: min(p.MaxWork, 100000), MaxGuards: 32}
		if ValidateArgumentAnalysis(c.Trace, local, false) != nil {
			return invalid
		}
		nodes += uint32(len(c.Trace.Nodes))
		work += c.Trace.VisitedStates
		partial = partial || c.Trace.Status == "partial"
		if c.Trace.Truncated && !r.Truncated {
			return invalid
		}
		reachable[i] = argumentDependencies(c.Trace)
		for node := range reachable[i] {
			parameterOrigin = parameterOrigin || c.Trace.Nodes[node].Kind == "parameter"
		}
	}
	if nodes != r.TotalNodes || work > r.VisitedWork || (len(r.Contexts) == 0 && !r.Truncated) {
		return invalid
	}
	parents := map[uint32]bool{}
	fanout := map[[2]uint32]uint32{}
	calls := map[[3]uint64]bool{}
	for _, l := range r.Links {
		if l.ToContext >= uint32(len(r.Contexts)) || l.FromContext >= l.ToContext || parents[l.ToContext] {
			return invalid
		}
		from, to := r.Contexts[l.FromContext], r.Contexts[l.ToContext]
		if !reachable[l.FromContext][l.ParameterNode] || from.Trace.Nodes[l.ParameterNode].Kind != "parameter" || to.Depth != from.Depth+1 {
			return invalid
		}
		index, err := strconv.ParseUint(from.Trace.Nodes[l.ParameterNode].Value, 10, 32)
		if err != nil || uint32(index) != to.Trace.ArgumentIndex {
			return invalid
		}
		parents[l.ToContext] = true
		key := [2]uint32{l.FromContext, l.ParameterNode}
		fanout[key]++
		call := [3]uint64{uint64(l.FromContext), uint64(l.ParameterNode), uint64(to.Trace.CallAddress)}
		if fanout[key] > p.MaxCallers || calls[call] {
			return invalid
		}
		calls[call] = true
	}
	if len(r.Contexts) > 0 && len(parents) != len(r.Contexts)-1 {
		return invalid
	}
	reasons := []string{"context_budget", "node_budget", "depth_budget", "caller_budget", "boundary_budget", "extraction_budget", "caller_analysis_unavailable", "recursive_call", "ambiguous_call", "prototype_mismatch", "argument_mapping_unavailable", "call_not_recovered", "parameter_abi_unavailable", "non_call_reference", "no_known_callers"}
	for _, b := range r.Boundaries {
		if b.Context >= uint32(len(r.Contexts)) || !slices.Contains(reasons, b.Reason) {
			return invalid
		}
		if b.ParameterNode != nil && (*b.ParameterNode >= uint32(len(r.Contexts[b.Context].Trace.Nodes)) || r.Contexts[b.Context].Trace.Nodes[*b.ParameterNode].Kind != "parameter") {
			return invalid
		}
		if strings.HasSuffix(b.Reason, "_budget") && !r.Truncated {
			return invalid
		}
	}
	for _, reason := range r.Limitations {
		if !slices.Contains([]string{"caller_set_not_proven_complete", "work_budget", "boundary_budget"}, reason) {
			return invalid
		}
		if strings.HasSuffix(reason, "_budget") && !r.Truncated {
			return invalid
		}
	}
	if parameterOrigin && !slices.Contains(r.Limitations, "caller_set_not_proven_complete") {
		return invalid
	}
	if r.Status == "complete" && partial {
		return invalid
	}
	return nil
}
func argumentDependencies(trace ArgumentAnalysisResult) map[uint32]bool {
	seen := map[uint32]bool{}
	if trace.Root == nil {
		return seen
	}
	edges := map[uint32][]uint32{}
	for _, e := range trace.Edges {
		edges[e.From] = append(edges[e.From], e.To)
	}
	pending := []uint32{*trace.Root}
	for len(pending) != 0 {
		node := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen[node] {
			continue
		}
		seen[node] = true
		pending = append(pending, edges[node]...)
	}
	return seen
}
func (c *Client) TraceArgumentCallers(ctx context.Context, instance rpc.InstanceDescriptor, p ArgumentCallersParams) (ArgumentCallersResult, error) {
	if !ValidArgumentCallersParams(p) {
		return ArgumentCallersResult{}, errors.New("invalid caller trace parameters")
	}
	result, err := callTyped[ArgumentCallersParams, ArgumentCallersResult](c, ctx, instance, rpcMethod("analysis.trace_argument_callers"), p)
	if err == nil {
		err = ValidateArgumentCallers(result, p)
	}
	return result, err
}
