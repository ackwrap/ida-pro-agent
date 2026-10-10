package ida

import (
	"context"
	"time"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

type BridgeAnalysisClient interface {
	AnalyzeComponent(context.Context, rpc.InstanceDescriptor, bridge.AnalysisComponentParams) (bridge.AnalysisComponentResult, error)
	TraceDataFlow(context.Context, rpc.InstanceDescriptor, bridge.TraceDataFlowParams) (bridge.TraceDataFlowResult, error)
}

func (backend *BridgeBackend) prepareAnalysis(ctx context.Context, instanceID string) (context.Context, context.CancelFunc, func(), rpc.InstanceDescriptor, BridgeAnalysisClient, error) {
	ctx, cancel, release, instance, raw, err := backend.prepareReadRPC(ctx, instanceID, 60*time.Second)
	if err != nil {
		return ctx, cancel, release, instance, nil, err
	}
	client, ok := raw.(BridgeAnalysisClient)
	if !ok {
		cancel()
		release()
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil, NewError(ErrorCapabilityUnavailable, "analysis backend is unavailable", false)
	}
	return ctx, cancel, release, instance, client, nil
}
func (backend *BridgeBackend) AnalyzeComponent(ctx context.Context, instanceID string, params AnalysisComponentParams) (AnalysisComponentResult, error) {
	if len(params.Roots) < 1 || len(params.Roots) > 16 || params.MaxDepth > 5 || params.MaxNodes > 200 || params.MaxEdges > 1000 || params.PerFunction > 100 || params.SharedLimit > 100 {
		return AnalysisComponentResult{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, client, err := backend.prepareAnalysis(ctx, instanceID)
	if err != nil {
		return AnalysisComponentResult{}, err
	}
	defer cancel()
	defer release()
	wire := bridge.AnalysisComponentParams{MaxDepth: params.MaxDepth, MaxNodes: params.MaxNodes, MaxEdges: params.MaxEdges, PerFunction: params.PerFunction, SharedLimit: params.SharedLimit}
	for _, root := range params.Roots {
		wire.Roots = append(wire.Roots, rpc.Address(root))
	}
	result, err := client.AnalyzeComponent(ctx, instance, wire)
	return convertCatalogDTO[AnalysisComponentResult](result, err)
}
func (backend *BridgeBackend) TraceDataFlow(ctx context.Context, instanceID string, params TraceDataFlowParams) (TraceDataFlowResult, error) {
	if params.Direction != "" && params.Direction != "incoming" && params.Direction != "outgoing" && params.Direction != "both" || params.MaxDepth > 8 || params.MaxNodes > 1000 || params.MaxEdges > 2000 {
		return TraceDataFlowResult{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, client, err := backend.prepareAnalysis(ctx, instanceID)
	if err != nil {
		return TraceDataFlowResult{}, err
	}
	defer cancel()
	defer release()
	result, err := client.TraceDataFlow(ctx, instance, bridge.TraceDataFlowParams{Address: rpc.Address(params.Address), Direction: params.Direction, MaxDepth: params.MaxDepth, MaxNodes: params.MaxNodes, MaxEdges: params.MaxEdges})
	return convertCatalogDTO[TraceDataFlowResult](result, err)
}
