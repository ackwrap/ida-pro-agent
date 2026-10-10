package ida

import (
	"context"
	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
	"time"
)

type BridgeSemanticAnalysisClient interface {
	TraceArgument(context.Context, rpc.InstanceDescriptor, bridge.ArgumentAnalysisParams) (bridge.ArgumentAnalysisResult, error)
	GuardEvidence(context.Context, rpc.InstanceDescriptor, bridge.ArgumentAnalysisParams) (bridge.ArgumentAnalysisResult, error)
}

func (b *BridgeBackend) argumentAnalysis(ctx context.Context, instanceID string, p ArgumentAnalysisParams, guards bool) (ArgumentAnalysisResult, error) {
	wire := bridge.ArgumentAnalysisParams{CallAddress: rpc.Address(p.CallAddress), ArgumentIndex: p.ArgumentIndex, MaxNodes: p.MaxNodes, MaxWork: p.MaxWork, MaxGuards: p.MaxGuards}
	if !bridge.ValidArgumentAnalysisParams(wire) {
		return ArgumentAnalysisResult{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, raw, err := b.prepareReadRPC(ctx, instanceID, 60*time.Second)
	if err != nil {
		return ArgumentAnalysisResult{}, err
	}
	defer cancel()
	defer release()
	client, ok := raw.(BridgeSemanticAnalysisClient)
	if !ok {
		return ArgumentAnalysisResult{}, NewError(ErrorCapabilityUnavailable, "semantic analysis backend is unavailable", false)
	}
	var result bridge.ArgumentAnalysisResult
	if guards {
		result, err = client.GuardEvidence(ctx, instance, wire)
	} else {
		result, err = client.TraceArgument(ctx, instance, wire)
	}
	return convertCatalogDTO[ArgumentAnalysisResult](result, err)
}
func (b *BridgeBackend) TraceArgument(ctx context.Context, instanceID string, p ArgumentAnalysisParams) (ArgumentAnalysisResult, error) {
	return b.argumentAnalysis(ctx, instanceID, p, false)
}
func (b *BridgeBackend) GuardEvidence(ctx context.Context, instanceID string, p ArgumentAnalysisParams) (ArgumentAnalysisResult, error) {
	return b.argumentAnalysis(ctx, instanceID, p, true)
}
