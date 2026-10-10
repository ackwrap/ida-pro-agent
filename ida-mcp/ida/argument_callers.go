package ida

import (
	"context"
	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
	"time"
)

type ArgumentCallersResult = bridge.ArgumentCallersResult
type ArgumentCallersParams struct {
	CallAddress   Address
	ArgumentIndex uint32
	MaxDepth      uint32
	MaxContexts   uint32
	MaxCallers    uint32
	MaxNodes      uint32
	MaxWork       uint32
}
type ArgumentCallersBackend interface {
	TraceArgumentCallers(context.Context, string, ArgumentCallersParams) (ArgumentCallersResult, error)
}
type BridgeArgumentCallersClient interface {
	TraceArgumentCallers(context.Context, rpc.InstanceDescriptor, bridge.ArgumentCallersParams) (bridge.ArgumentCallersResult, error)
}

func (b *BridgeBackend) TraceArgumentCallers(ctx context.Context, id string, p ArgumentCallersParams) (ArgumentCallersResult, error) {
	wire := bridge.ArgumentCallersParams{CallAddress: rpc.Address(p.CallAddress), ArgumentIndex: p.ArgumentIndex, MaxDepth: p.MaxDepth, MaxContexts: p.MaxContexts, MaxCallers: p.MaxCallers, MaxNodes: p.MaxNodes, MaxWork: p.MaxWork}
	if !bridge.ValidArgumentCallersParams(wire) {
		return ArgumentCallersResult{}, invalidCatalogParams()
	}
	ctx, cancel, release, instance, raw, err := b.prepareReadRPC(ctx, id, 60*time.Second)
	if err != nil {
		return ArgumentCallersResult{}, err
	}
	defer cancel()
	defer release()
	c, ok := raw.(BridgeArgumentCallersClient)
	if !ok {
		return ArgumentCallersResult{}, NewError(ErrorCapabilityUnavailable, "caller tracing is unavailable", false)
	}
	result, err := c.TraceArgumentCallers(ctx, instance, wire)
	return convertCatalogDTO[ArgumentCallersResult](result, err)
}
