package mcpserver

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ToolSourceFiles          = "source.files"
	ToolSourceLines          = "source.lines"
	ToolNameDemangle         = "name.demangle"
	ToolCommentGet           = "comment.get"
	ToolBookmarkList         = "bookmark.list"
	ToolTypeXrefs            = "type.xrefs"
	ToolDecompilerLocals     = "decompiler.locals"
	ToolDecompilerCtree      = "decompiler.ctree"
	ToolDecompilerLocalXrefs = "decompiler.local_xrefs"
	ToolDebuggerThreads      = "debugger.threads"
	ToolDebuggerModules      = "debugger.modules"
)

func (registry *toolRegistry) invokeInspectionQueryMethod(ctx context.Context, request *mcp.CallToolRequest, method string, arguments json.RawMessage) (json.RawMessage, bool, error) {
	switch method {
	case ToolSourceFiles:
		r, e := invokeTypedWithDefaults(ctx, request, arguments, defaultIndexList, registry.sourceFiles)
		return r, true, e
	case ToolSourceLines:
		r, e := invokeTypedWithDefaults(ctx, request, arguments, defaultSourceLines, registry.sourceLines)
		return r, true, e
	case ToolNameDemangle:
		r, e := invokeTyped(ctx, request, arguments, registry.nameDemangle)
		return r, true, e
	case ToolCommentGet:
		r, e := invokeTypedWithDefaults(ctx, request, arguments, func(i *commentGetInput) {
			if i.Scope == "" {
				i.Scope = "item"
			}
		}, registry.commentGet)
		return r, true, e
	case ToolBookmarkList:
		r, e := invokeTypedWithDefaults(ctx, request, arguments, defaultIndexList, registry.bookmarkList)
		return r, true, e
	case ToolTypeXrefs:
		r, e := invokeTypedWithDefaults(ctx, request, arguments, func(i *typeXrefsInput) {
			if i.Limit == 0 {
				i.Limit = 20
			}
		}, registry.typeXrefs)
		return r, true, e
	case ToolDecompilerLocals:
		r, e := invokeTypedWithDefaults(ctx, request, arguments, func(i *decompilerLocalsInput) {
			if i.MaxItems == 0 {
				i.MaxItems = 100
			}
		}, registry.decompilerLocals)
		return r, true, e
	case ToolDecompilerCtree:
		r, e := invokeTypedWithDefaults(ctx, request, arguments, func(i *decompilerCtreeInput) {
			if i.MaxDepth == 0 {
				i.MaxDepth = 8
			}
			if i.MaxNodes == 0 {
				i.MaxNodes = 200
			}
		}, registry.decompilerCtree)
		return r, true, e
	case ToolDecompilerLocalXrefs:
		r, e := invokeTypedWithDefaults(ctx, request, arguments, func(i *decompilerLocalXrefsInput) {
			if i.MaxDepth == 0 {
				i.MaxDepth = 16
			}
			if i.MaxNodes == 0 {
				i.MaxNodes = 1000
			}
			if i.MaxItems == 0 {
				i.MaxItems = 100
			}
		}, registry.decompilerLocalXrefs)
		return r, true, e
	case ToolDebuggerThreads:
		r, e := invokeTypedWithDefaults(ctx, request, arguments, defaultIndexList, registry.debuggerThreads)
		return r, true, e
	case ToolDebuggerModules:
		r, e := invokeTypedWithDefaults(ctx, request, arguments, defaultIndexList, registry.debuggerModules)
		return r, true, e
	default:
		return nil, false, nil
	}
}

func defaultIndexList(i *indexListInput) {
	if i.Limit == 0 {
		i.Limit = 20
	}
}
func defaultSourceLines(i *sourceLinesInput) {
	if i.Limit == 0 {
		i.Limit = 20
	}
}
func (registry *toolRegistry) inspectionCall(ctx context.Context, requested *string) (ida.InspectionQueryBackend, string, context.Context, context.CancelFunc, error) {
	return registry.inspectionCallFor(ctx, requested, 35*time.Second)
}
func (registry *toolRegistry) inspectionCallFor(ctx context.Context, requested *string, timeout time.Duration) (ida.InspectionQueryBackend, string, context.Context, context.CancelFunc, error) {
	b, ok := registry.backend.(ida.InspectionQueryBackend)
	if !ok {
		return nil, "", ctx, func() {}, ida.NewError(ida.ErrorCapabilityUnavailable, "inspection query backend is unavailable", false)
	}
	requestContext, id, cancel, err := registry.catalogInstance(ctx, requested, timeout)
	return b, id, requestContext, cancel, err
}
func indexPageBinding(method, id string, limit uint32, filters ...string) string {
	return method + "\x00" + id + "\x00" + strings.Join(filters, "\x00") + "\x00" + strconv.FormatUint(uint64(limit), 10)
}
func decodeIndexCursor(registry *toolRegistry, kind, binding, cursor string, maximum uint32) (uint32, error) {
	if cursor == "" {
		return 0, nil
	}
	raw, err := registry.cursors.decode(kind, binding, cursor)
	if err != nil {
		return 0, invalidCursorError()
	}
	value, e := strconv.ParseUint(raw, 10, 32)
	if e != nil || value > uint64(maximum) {
		return 0, invalidCursorError()
	}
	return uint32(value), nil
}
func encodeIndexCursor(registry *toolRegistry, kind, binding string, next *uint32) (*string, error) {
	if next == nil {
		return nil, nil
	}
	value, err := registry.cursors.encode(kind, binding, strconv.FormatUint(uint64(*next), 10))
	if err != nil {
		return nil, ida.NewError(ida.ErrorInternal, "index cursor encoding failed", false)
	}
	return &value, nil
}

func (registry *toolRegistry) sourceFiles(ctx context.Context, _ *mcp.CallToolRequest, input indexListInput) (*mcp.CallToolResult, sourceFilesOutput, error) {
	b, id, ctx, cancel, err := registry.inspectionCall(ctx, input.InstanceID)
	if err != nil {
		return nil, sourceFilesOutput{}, err
	}
	defer cancel()
	binding := indexPageBinding(ToolSourceFiles, id, input.Limit)
	cursor, err := decodeIndexCursor(registry, "sf1", binding, input.Cursor, 1_000_000)
	if err != nil {
		return nil, sourceFilesOutput{}, err
	}
	r, err := b.SourceFiles(ctx, id, ida.IndexListParams{Limit: input.Limit, Cursor: cursor})
	if err != nil {
		return nil, sourceFilesOutput{}, sanitizeToolError(err)
	}
	next, err := encodeIndexCursor(registry, "sf1", binding, r.NextCursor)
	if err != nil {
		return nil, sourceFilesOutput{}, err
	}
	out := sourceFilesOutput{Items: r.Items, NextCursor: next, HasMore: r.HasMore}
	return checkedCollectionOutput(out.Items, out)
}
func (registry *toolRegistry) sourceLines(ctx context.Context, _ *mcp.CallToolRequest, input sourceLinesInput) (*mcp.CallToolResult, sourceLinesOutput, error) {
	b, id, ctx, cancel, err := registry.inspectionCall(ctx, input.InstanceID)
	if err != nil {
		return nil, sourceLinesOutput{}, err
	}
	defer cancel()
	start, err := parseToolAddress(input.Start)
	if err != nil {
		return nil, sourceLinesOutput{}, err
	}
	end, err := parseToolAddress(input.End)
	if err != nil || start >= end {
		return nil, sourceLinesOutput{}, ida.NewError(ida.ErrorInvalidArgument, "source range is invalid", false)
	}
	binding := indexPageBinding(ToolSourceLines, id, input.Limit, start.String(), end.String())
	var cursor *ida.Address
	if input.Cursor != "" {
		raw, e := registry.cursors.decode("sl1", binding, input.Cursor)
		if e != nil {
			return nil, sourceLinesOutput{}, invalidCursorError()
		}
		v, e := parseToolAddress(raw)
		if e != nil || v < start || v >= end {
			return nil, sourceLinesOutput{}, invalidCursorError()
		}
		cursor = &v
	}
	r, err := b.SourceLines(ctx, id, ida.SourceLinesParams{Start: start, End: end, Limit: input.Limit, Cursor: cursor})
	if err != nil {
		return nil, sourceLinesOutput{}, sanitizeToolError(err)
	}
	var next *string
	if r.NextCursor != nil {
		v, e := registry.cursors.encode("sl1", binding, r.NextCursor.String())
		if e != nil {
			return nil, sourceLinesOutput{}, ida.NewError(ida.ErrorInternal, "source cursor encoding failed", false)
		}
		next = &v
	}
	out := sourceLinesOutput{Items: r.Items, NextCursor: next, HasMore: r.HasMore}
	return checkedCollectionOutput(out.Items, out)
}
func (registry *toolRegistry) nameDemangle(ctx context.Context, _ *mcp.CallToolRequest, input nameDemangleInput) (*mcp.CallToolResult, ida.NameDemangleResult, error) {
	if input.Name != nil && (len(*input.Name) > 4096 || strings.ContainsRune(*input.Name, 0)) {
		return nil, ida.NameDemangleResult{}, ida.NewError(ida.ErrorInvalidArgument, "name is invalid", false)
	}
	b, id, ctx, cancel, err := registry.inspectionCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.NameDemangleResult{}, err
	}
	defer cancel()
	p := ida.NameDemangleParams{Name: input.Name}
	if input.Address != nil {
		v, e := parseToolAddress(*input.Address)
		if e != nil {
			return nil, ida.NameDemangleResult{}, e
		}
		p.Address = &v
	}
	r, err := b.NameDemangle(ctx, id, p)
	if err != nil {
		return nil, ida.NameDemangleResult{}, sanitizeToolError(err)
	}
	return checkedOutput(r)
}
func (registry *toolRegistry) commentGet(ctx context.Context, _ *mcp.CallToolRequest, input commentGetInput) (*mcp.CallToolResult, ida.CommentResult, error) {
	b, id, ctx, cancel, err := registry.inspectionCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.CommentResult{}, err
	}
	defer cancel()
	address, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, ida.CommentResult{}, err
	}
	r, err := b.CommentGet(ctx, id, ida.CommentGetParams{Address: address, Scope: input.Scope, Repeatable: input.Repeatable})
	if err != nil {
		return nil, ida.CommentResult{}, sanitizeToolError(err)
	}
	return checkedOutput(r)
}
func (registry *toolRegistry) bookmarkList(ctx context.Context, _ *mcp.CallToolRequest, input indexListInput) (*mcp.CallToolResult, bookmarksOutput, error) {
	b, id, ctx, cancel, err := registry.inspectionCall(ctx, input.InstanceID)
	if err != nil {
		return nil, bookmarksOutput{}, err
	}
	defer cancel()
	binding := indexPageBinding(ToolBookmarkList, id, input.Limit)
	cursor, err := decodeIndexCursor(registry, "bm1", binding, input.Cursor, 1024)
	if err != nil {
		return nil, bookmarksOutput{}, err
	}
	r, err := b.BookmarkList(ctx, id, ida.IndexListParams{Limit: input.Limit, Cursor: cursor})
	if err != nil {
		return nil, bookmarksOutput{}, sanitizeToolError(err)
	}
	next, err := encodeIndexCursor(registry, "bm1", binding, r.NextCursor)
	if err != nil {
		return nil, bookmarksOutput{}, err
	}
	out := bookmarksOutput{Items: r.Items, NextCursor: next, HasMore: r.HasMore}
	return checkedCollectionOutput(out.Items, out)
}
func (registry *toolRegistry) typeXrefs(ctx context.Context, _ *mcp.CallToolRequest, input typeXrefsInput) (*mcp.CallToolResult, typeXrefsOutput, error) {
	if len(input.Name) > 4096 || strings.ContainsRune(input.Name, 0) {
		return nil, typeXrefsOutput{}, ida.NewError(ida.ErrorInvalidArgument, "type name is invalid", false)
	}
	b, id, ctx, cancel, err := registry.inspectionCall(ctx, input.InstanceID)
	if err != nil {
		return nil, typeXrefsOutput{}, err
	}
	defer cancel()
	binding := indexPageBinding(ToolTypeXrefs, id, input.Limit, input.Name)
	cursor, err := decodeIndexCursor(registry, "tx1", binding, input.Cursor, 1_000_000)
	if err != nil {
		return nil, typeXrefsOutput{}, err
	}
	r, err := b.TypeXrefs(ctx, id, ida.TypeXrefsParams{Name: input.Name, Limit: input.Limit, Cursor: cursor})
	if err != nil {
		return nil, typeXrefsOutput{}, sanitizeToolError(err)
	}
	next, err := encodeIndexCursor(registry, "tx1", binding, r.NextCursor)
	if err != nil {
		return nil, typeXrefsOutput{}, err
	}
	out := typeXrefsOutput{Items: r.Items, NextCursor: next, HasMore: r.HasMore}
	return checkedCollectionOutput(out.Items, out)
}
func (registry *toolRegistry) decompilerLocals(ctx context.Context, _ *mcp.CallToolRequest, input decompilerLocalsInput) (*mcp.CallToolResult, ida.DecompilerLocalsResult, error) {
	b, id, ctx, cancel, err := registry.inspectionCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.DecompilerLocalsResult{}, err
	}
	defer cancel()
	a, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, ida.DecompilerLocalsResult{}, err
	}
	r, err := b.DecompilerLocals(ctx, id, ida.DecompilerLocalsParams{Address: a, MaxItems: input.MaxItems})
	if err != nil {
		return nil, ida.DecompilerLocalsResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(r.Items, r)
}
func (registry *toolRegistry) decompilerCtree(ctx context.Context, _ *mcp.CallToolRequest, input decompilerCtreeInput) (*mcp.CallToolResult, ida.DecompilerCtreeResult, error) {
	b, id, ctx, cancel, err := registry.inspectionCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.DecompilerCtreeResult{}, err
	}
	defer cancel()
	a, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, ida.DecompilerCtreeResult{}, err
	}
	r, err := b.DecompilerCtree(ctx, id, ida.DecompilerCtreeParams{Address: a, MaxDepth: input.MaxDepth, MaxNodes: input.MaxNodes})
	if err != nil {
		return nil, ida.DecompilerCtreeResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(r.Nodes, r)
}
func (registry *toolRegistry) decompilerLocalXrefs(ctx context.Context, _ *mcp.CallToolRequest, input decompilerLocalXrefsInput) (*mcp.CallToolResult, ida.DecompilerLocalXrefsResult, error) {
	b, id, ctx, cancel, err := registry.inspectionCall(ctx, input.InstanceID)
	if err != nil {
		return nil, ida.DecompilerLocalXrefsResult{}, err
	}
	defer cancel()
	a, err := parseToolAddress(input.Address)
	if err != nil {
		return nil, ida.DecompilerLocalXrefsResult{}, err
	}
	r, err := b.DecompilerLocalXrefs(ctx, id, ida.DecompilerLocalXrefsParams{Address: a, LocalIndex: input.LocalIndex, MaxDepth: input.MaxDepth, MaxNodes: input.MaxNodes, MaxItems: input.MaxItems})
	if err != nil {
		return nil, ida.DecompilerLocalXrefsResult{}, sanitizeToolError(err)
	}
	return checkedCollectionOutput(r.Items, r)
}
func (registry *toolRegistry) debuggerThreads(ctx context.Context, _ *mcp.CallToolRequest, input indexListInput) (*mcp.CallToolResult, debuggerThreadsOutput, error) {
	b, id, ctx, cancel, err := registry.inspectionCallFor(ctx, input.InstanceID, debuggerReadToolTimeout)
	if err != nil {
		return nil, debuggerThreadsOutput{}, err
	}
	defer cancel()
	binding := indexPageBinding(ToolDebuggerThreads, id, input.Limit)
	cursor, err := decodeIndexCursor(registry, "dt1", binding, input.Cursor, 1024)
	if err != nil {
		return nil, debuggerThreadsOutput{}, err
	}
	r, err := b.DebuggerThreads(ctx, id, ida.IndexListParams{Limit: input.Limit, Cursor: cursor})
	if err != nil {
		return nil, debuggerThreadsOutput{}, sanitizeToolError(err)
	}
	next, err := encodeIndexCursor(registry, "dt1", binding, r.NextCursor)
	if err != nil {
		return nil, debuggerThreadsOutput{}, err
	}
	out := debuggerThreadsOutput{Items: r.Items, NextCursor: next, HasMore: r.HasMore}
	return checkedCollectionOutput(out.Items, out)
}
func (registry *toolRegistry) debuggerModules(ctx context.Context, _ *mcp.CallToolRequest, input indexListInput) (*mcp.CallToolResult, debuggerModulesOutput, error) {
	b, id, ctx, cancel, err := registry.inspectionCallFor(ctx, input.InstanceID, debuggerReadToolTimeout)
	if err != nil {
		return nil, debuggerModulesOutput{}, err
	}
	defer cancel()
	binding := indexPageBinding(ToolDebuggerModules, id, input.Limit)
	cursor, err := decodeIndexCursor(registry, "dm1", binding, input.Cursor, 4096)
	if err != nil {
		return nil, debuggerModulesOutput{}, err
	}
	r, err := b.DebuggerModules(ctx, id, ida.IndexListParams{Limit: input.Limit, Cursor: cursor})
	if err != nil {
		return nil, debuggerModulesOutput{}, sanitizeToolError(err)
	}
	next, err := encodeIndexCursor(registry, "dm1", binding, r.NextCursor)
	if err != nil {
		return nil, debuggerModulesOutput{}, err
	}
	out := debuggerModulesOutput{Items: r.Items, NextCursor: next, HasMore: r.HasMore}
	return checkedCollectionOutput(out.Items, out)
}
