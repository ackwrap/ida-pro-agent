package ida

import (
	"context"
	"time"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

type BridgeInspectionQueryClient interface {
	SourceFiles(context.Context, rpc.InstanceDescriptor, bridge.IndexListParams) (bridge.SourceFilesResult, error)
	SourceLines(context.Context, rpc.InstanceDescriptor, bridge.SourceLinesParams) (bridge.SourceLinesResult, error)
	NameDemangle(context.Context, rpc.InstanceDescriptor, bridge.NameDemangleParams) (bridge.NameDemangleResult, error)
	CommentGet(context.Context, rpc.InstanceDescriptor, bridge.CommentGetParams) (bridge.CommentResult, error)
	BookmarkList(context.Context, rpc.InstanceDescriptor, bridge.IndexListParams) (bridge.BookmarksResult, error)
	TypeXrefs(context.Context, rpc.InstanceDescriptor, bridge.TypeXrefsParams) (bridge.TypeXrefsResult, error)
	DecompilerLocals(context.Context, rpc.InstanceDescriptor, bridge.DecompilerLocalsParams) (bridge.DecompilerLocalsResult, error)
	DecompilerCtree(context.Context, rpc.InstanceDescriptor, bridge.DecompilerCtreeParams) (bridge.DecompilerCtreeResult, error)
	DecompilerLocalXrefs(context.Context, rpc.InstanceDescriptor, bridge.DecompilerLocalXrefsParams) (bridge.DecompilerLocalXrefsResult, error)
	DebuggerThreads(context.Context, rpc.InstanceDescriptor, bridge.IndexListParams) (bridge.DebuggerThreadsResult, error)
	DebuggerModules(context.Context, rpc.InstanceDescriptor, bridge.IndexListParams) (bridge.DebuggerModulesResult, error)
}

func (backend *BridgeBackend) prepareInspectionQuery(ctx context.Context, instanceID, capability string) (context.Context, context.CancelFunc, func(), rpc.InstanceDescriptor, BridgeInspectionQueryClient, error) {
	timeout := 35 * time.Second
	if capability == "debugger" {
		timeout = writeTimeout
	}
	ctx, cancel, release, instance, raw, err := backend.prepareReadRPC(ctx, instanceID, timeout)
	if err != nil {
		return ctx, cancel, release, instance, nil, err
	}
	if capability == "decompiler" && !instance.Capabilities.Decompiler {
		cancel()
		release()
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil, NewError(ErrorCapabilityUnavailable, capability+" is unavailable", false)
	}
	client, ok := raw.(BridgeInspectionQueryClient)
	if !ok {
		cancel()
		release()
		return ctx, func() {}, func() {}, rpc.InstanceDescriptor{}, nil, NewError(ErrorCapabilityUnavailable, "inspection query backend is unavailable", false)
	}
	return ctx, cancel, release, instance, client, nil
}

func inspectionConverted[T any, W any](ctx context.Context, backend *BridgeBackend, id, capability string, call func(BridgeInspectionQueryClient, context.Context, rpc.InstanceDescriptor) (W, error)) (T, error) {
	var zero T
	ctx, cancel, release, instance, client, err := backend.prepareInspectionQuery(ctx, id, capability)
	if err != nil {
		return zero, err
	}
	defer cancel()
	defer release()
	result, err := call(client, ctx, instance)
	return convertCatalogDTO[T](result, err)
}
func wireIndexList(p IndexListParams) bridge.IndexListParams {
	return bridge.IndexListParams{Limit: p.Limit, Cursor: p.Cursor}
}

func (backend *BridgeBackend) SourceFiles(ctx context.Context, id string, p IndexListParams) (SourceFilesResult, error) {
	return inspectionConverted[SourceFilesResult](ctx, backend, id, "", func(c BridgeInspectionQueryClient, x context.Context, i rpc.InstanceDescriptor) (bridge.SourceFilesResult, error) {
		return c.SourceFiles(x, i, wireIndexList(p))
	})
}
func (backend *BridgeBackend) SourceLines(ctx context.Context, id string, p SourceLinesParams) (SourceLinesResult, error) {
	w := bridge.SourceLinesParams{Start: rpc.Address(p.Start), End: rpc.Address(p.End), Limit: p.Limit}
	if p.Cursor != nil {
		v := rpc.Address(*p.Cursor)
		w.Cursor = &v
	}
	return inspectionConverted[SourceLinesResult](ctx, backend, id, "", func(c BridgeInspectionQueryClient, x context.Context, i rpc.InstanceDescriptor) (bridge.SourceLinesResult, error) {
		return c.SourceLines(x, i, w)
	})
}
func (backend *BridgeBackend) NameDemangle(ctx context.Context, id string, p NameDemangleParams) (NameDemangleResult, error) {
	w := bridge.NameDemangleParams{Name: p.Name}
	if p.Address != nil {
		v := rpc.Address(*p.Address)
		w.Address = &v
	}
	return inspectionConverted[NameDemangleResult](ctx, backend, id, "", func(c BridgeInspectionQueryClient, x context.Context, i rpc.InstanceDescriptor) (bridge.NameDemangleResult, error) {
		return c.NameDemangle(x, i, w)
	})
}
func (backend *BridgeBackend) CommentGet(ctx context.Context, id string, p CommentGetParams) (CommentResult, error) {
	w := bridge.CommentGetParams{Address: rpc.Address(p.Address), Scope: p.Scope, Repeatable: p.Repeatable}
	return inspectionConverted[CommentResult](ctx, backend, id, "", func(c BridgeInspectionQueryClient, x context.Context, i rpc.InstanceDescriptor) (bridge.CommentResult, error) {
		return c.CommentGet(x, i, w)
	})
}
func (backend *BridgeBackend) BookmarkList(ctx context.Context, id string, p IndexListParams) (BookmarksResult, error) {
	return inspectionConverted[BookmarksResult](ctx, backend, id, "", func(c BridgeInspectionQueryClient, x context.Context, i rpc.InstanceDescriptor) (bridge.BookmarksResult, error) {
		return c.BookmarkList(x, i, wireIndexList(p))
	})
}
func (backend *BridgeBackend) TypeXrefs(ctx context.Context, id string, p TypeXrefsParams) (TypeXrefsResult, error) {
	w := bridge.TypeXrefsParams{Name: p.Name, Limit: p.Limit, Cursor: p.Cursor}
	return inspectionConverted[TypeXrefsResult](ctx, backend, id, "", func(c BridgeInspectionQueryClient, x context.Context, i rpc.InstanceDescriptor) (bridge.TypeXrefsResult, error) {
		return c.TypeXrefs(x, i, w)
	})
}
func (backend *BridgeBackend) DecompilerLocals(ctx context.Context, id string, p DecompilerLocalsParams) (DecompilerLocalsResult, error) {
	w := bridge.DecompilerLocalsParams{Address: rpc.Address(p.Address), MaxItems: p.MaxItems}
	return inspectionConverted[DecompilerLocalsResult](ctx, backend, id, "decompiler", func(c BridgeInspectionQueryClient, x context.Context, i rpc.InstanceDescriptor) (bridge.DecompilerLocalsResult, error) {
		return c.DecompilerLocals(x, i, w)
	})
}
func (backend *BridgeBackend) DecompilerCtree(ctx context.Context, id string, p DecompilerCtreeParams) (DecompilerCtreeResult, error) {
	w := bridge.DecompilerCtreeParams{Address: rpc.Address(p.Address), MaxDepth: p.MaxDepth, MaxNodes: p.MaxNodes}
	return inspectionConverted[DecompilerCtreeResult](ctx, backend, id, "decompiler", func(c BridgeInspectionQueryClient, x context.Context, i rpc.InstanceDescriptor) (bridge.DecompilerCtreeResult, error) {
		return c.DecompilerCtree(x, i, w)
	})
}
func (backend *BridgeBackend) DecompilerLocalXrefs(ctx context.Context, id string, p DecompilerLocalXrefsParams) (DecompilerLocalXrefsResult, error) {
	w := bridge.DecompilerLocalXrefsParams{Address: rpc.Address(p.Address), LocalIndex: p.LocalIndex, MaxDepth: p.MaxDepth, MaxNodes: p.MaxNodes, MaxItems: p.MaxItems}
	return inspectionConverted[DecompilerLocalXrefsResult](ctx, backend, id, "decompiler", func(c BridgeInspectionQueryClient, x context.Context, i rpc.InstanceDescriptor) (bridge.DecompilerLocalXrefsResult, error) {
		return c.DecompilerLocalXrefs(x, i, w)
	})
}
func (backend *BridgeBackend) DebuggerThreads(ctx context.Context, id string, p IndexListParams) (DebuggerThreadsResult, error) {
	return inspectionConverted[DebuggerThreadsResult](ctx, backend, id, "debugger", func(c BridgeInspectionQueryClient, x context.Context, i rpc.InstanceDescriptor) (bridge.DebuggerThreadsResult, error) {
		return c.DebuggerThreads(x, i, wireIndexList(p))
	})
}
func (backend *BridgeBackend) DebuggerModules(ctx context.Context, id string, p IndexListParams) (DebuggerModulesResult, error) {
	return inspectionConverted[DebuggerModulesResult](ctx, backend, id, "debugger", func(c BridgeInspectionQueryClient, x context.Context, i rpc.InstanceDescriptor) (bridge.DebuggerModulesResult, error) {
		return c.DebuggerModules(x, i, wireIndexList(p))
	})
}
