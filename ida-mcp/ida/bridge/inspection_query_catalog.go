package bridge

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"ida-mcp/ida/rpc"
)

const (
	methodSourceFiles          rpcMethod = "source.files"
	methodSourceLines          rpcMethod = "source.lines"
	methodNameDemangle         rpcMethod = "name.demangle"
	methodCommentGet           rpcMethod = "comment.get"
	methodBookmarkList         rpcMethod = "bookmark.list"
	methodTypeXrefs            rpcMethod = "type.xrefs"
	methodDecompilerLocals     rpcMethod = "decompiler.locals"
	methodDecompilerCtree      rpcMethod = "decompiler.ctree"
	methodDecompilerLocalXrefs rpcMethod = "decompiler.local_xrefs"
	methodDebuggerThreads      rpcMethod = "debugger.threads"
	methodDebuggerModules      rpcMethod = "debugger.modules"
)

type IndexListParams struct {
	Limit  uint32 `json:"limit,omitempty"`
	Cursor uint32 `json:"cursor,omitempty"`
}
type SourceLinesParams struct {
	Start  rpc.Address  `json:"start"`
	End    rpc.Address  `json:"end"`
	Limit  uint32       `json:"limit,omitempty"`
	Cursor *rpc.Address `json:"cursor,omitempty"`
}
type NameDemangleParams struct {
	Address *rpc.Address `json:"address,omitempty"`
	Name    *string      `json:"name,omitempty"`
}
type CommentGetParams struct {
	Address    rpc.Address `json:"address"`
	Scope      string      `json:"scope,omitempty"`
	Repeatable bool        `json:"repeatable,omitempty"`
}
type TypeXrefsParams struct {
	Name   string `json:"name"`
	Limit  uint32 `json:"limit,omitempty"`
	Cursor uint32 `json:"cursor,omitempty"`
}
type DecompilerLocalsParams struct {
	Address  rpc.Address `json:"address"`
	MaxItems uint32      `json:"maxItems,omitempty"`
}
type DecompilerCtreeParams struct {
	Address  rpc.Address `json:"address"`
	MaxDepth uint32      `json:"maxDepth,omitempty"`
	MaxNodes uint32      `json:"maxNodes,omitempty"`
}
type DecompilerLocalXrefsParams struct {
	Address    rpc.Address `json:"address"`
	LocalIndex uint32      `json:"localIndex"`
	MaxDepth   uint32      `json:"maxDepth,omitempty"`
	MaxNodes   uint32      `json:"maxNodes,omitempty"`
	MaxItems   uint32      `json:"maxItems,omitempty"`
}

type SourceFileItem struct {
	Start    rpc.Address `json:"start"`
	End      rpc.Address `json:"end"`
	Filename string      `json:"filename"`
}
type SourceFilesResult struct {
	Items      []SourceFileItem `json:"items"`
	NextCursor *uint32          `json:"nextCursor"`
	HasMore    bool             `json:"hasMore"`
}
type SourceLineItem struct {
	Address  rpc.Address `json:"address"`
	Line     uint64      `json:"line"`
	Filename *string     `json:"filename"`
}
type SourceLinesResult struct {
	Items      []SourceLineItem `json:"items"`
	NextCursor *rpc.Address     `json:"nextCursor"`
	HasMore    bool             `json:"hasMore"`
}
type NameDemangleResult struct {
	Raw   string  `json:"raw"`
	Short *string `json:"short"`
	Long  *string `json:"long"`
}
type CommentResult struct {
	Address    rpc.Address `json:"address"`
	Scope      string      `json:"scope"`
	Repeatable bool        `json:"repeatable"`
	Text       string      `json:"text"`
}
type BookmarkItem struct {
	Slot        uint32      `json:"slot"`
	Address     rpc.Address `json:"address"`
	Line        uint32      `json:"line"`
	Description string      `json:"description"`
}
type BookmarksResult struct {
	Items      []BookmarkItem `json:"items"`
	NextCursor *uint32        `json:"nextCursor"`
	HasMore    bool           `json:"hasMore"`
}
type TypeXrefItem struct {
	Address     rpc.Address `json:"address"`
	Code        bool        `json:"code"`
	UserDefined bool        `json:"userDefined"`
	XrefType    string      `json:"xrefType"`
}
type TypeXrefsResult struct {
	Items      []TypeXrefItem `json:"items"`
	NextCursor *uint32        `json:"nextCursor"`
	HasMore    bool           `json:"hasMore"`
}
type LvarLocator struct {
	Kind           string   `json:"kind"`
	Text           string   `json:"text"`
	VDStackOffset  *int64   `json:"vdStackOffset,omitempty"`
	IDAStackOffset *int64   `json:"idaStackOffset,omitempty"`
	Registers      []string `json:"registers,omitempty"`
}
type DecompilerLocal struct {
	Index       uint32       `json:"index"`
	Name        string       `json:"name"`
	Declaration string       `json:"declaration"`
	Width       uint32       `json:"width"`
	DefBlock    *uint32      `json:"defBlock"`
	DefEA       *rpc.Address `json:"defEa"`
	Locator     LvarLocator  `json:"locator"`
	Flags       []string     `json:"flags"`
}
type DecompilerLocalsResult struct {
	EntryAddress rpc.Address       `json:"entryAddress"`
	TotalCount   uint32            `json:"totalCount"`
	Truncated    bool              `json:"truncated"`
	Items        []DecompilerLocal `json:"items"`
}
type CtreeNode struct {
	Ordinal   uint32       `json:"ordinal"`
	Depth     uint32       `json:"depth"`
	Kind      string       `json:"kind"`
	Op        string       `json:"op"`
	EA        *rpc.Address `json:"ea"`
	UserFlags []string     `json:"userFlags"`
	Type      *string      `json:"type,omitempty"`
	LvarIndex *uint32      `json:"lvarIndex,omitempty"`
	Name      *string      `json:"name,omitempty"`
}
type DecompilerCtreeResult struct {
	EntryAddress rpc.Address `json:"entryAddress"`
	Count        uint32      `json:"count"`
	Truncated    bool        `json:"truncated"`
	Nodes        []CtreeNode `json:"nodes"`
}
type DecompilerLocalXref struct {
	Ordinal  uint32       `json:"ordinal"`
	Depth    uint32       `json:"depth"`
	EA       *rpc.Address `json:"ea"`
	ParentOp *string      `json:"parentOp"`
	Type     *string      `json:"type"`
}
type DecompilerLocalXrefsResult struct {
	EntryAddress  rpc.Address           `json:"entryAddress"`
	LocalIndex    uint32                `json:"localIndex"`
	Name          string                `json:"name"`
	VisitedNodes  uint32                `json:"visitedNodes"`
	TotalReturned uint32                `json:"totalReturned"`
	Truncated     bool                  `json:"truncated"`
	Items         []DecompilerLocalXref `json:"items"`
}
type DebuggerThreadItem struct {
	ThreadID int64   `json:"threadId"`
	Name     *string `json:"name"`
	Current  bool    `json:"current"`
}
type DebuggerThreadsResult struct {
	Items      []DebuggerThreadItem `json:"items"`
	NextCursor *uint32              `json:"nextCursor"`
	HasMore    bool                 `json:"hasMore"`
}
type DebuggerModuleItem struct {
	Name     string       `json:"name"`
	Base     rpc.Address  `json:"base"`
	Size     uint64       `json:"size"`
	RebaseTo *rpc.Address `json:"rebaseTo"`
}
type DebuggerModulesResult struct {
	Items      []DebuggerModuleItem `json:"items"`
	NextCursor *uint32              `json:"nextCursor"`
	HasMore    bool                 `json:"hasMore"`
}

func effectiveIndexLimit(limit uint32) uint32 {
	if limit == 0 {
		return 20
	}
	return limit
}
func validQueryText(value string, maximum int) bool {
	return utf8.ValidString(value) && len(value) <= maximum && !strings.ContainsRune(value, 0)
}
func validBasename(value string) bool {
	return value != "" && validQueryText(value, 4096) && !strings.ContainsAny(value, `/\\`)
}
func validateIndexPage(count int, limit, cursor uint32, next *uint32, more bool, maximum uint32) error {
	if count > int(effectiveIndexLimit(limit)) || more != (next != nil) || more && count == 0 {
		return errors.New("index pagination is inconsistent")
	}
	if next != nil && (*next <= cursor || *next > maximum) {
		return errors.New("index cursor is invalid")
	}
	return nil
}

func (client *Client) SourceFiles(ctx context.Context, instance rpc.InstanceDescriptor, params IndexListParams) (SourceFilesResult, error) {
	if params.Limit > 100 || params.Cursor > 1_000_000 {
		return SourceFilesResult{}, errors.New("source.files parameters are invalid")
	}
	r, err := callTyped[IndexListParams, SourceFilesResult](client, ctx, instance, methodSourceFiles, params)
	if err == nil {
		err = validateIndexPage(len(r.Items), params.Limit, params.Cursor, r.NextCursor, r.HasMore, 1_000_000)
		for _, item := range r.Items {
			if err == nil && (item.Start >= item.End || !validBasename(item.Filename)) {
				err = errors.New("source.files result is invalid")
			}
		}
	}
	return r, err
}
func (client *Client) SourceLines(ctx context.Context, instance rpc.InstanceDescriptor, params SourceLinesParams) (SourceLinesResult, error) {
	if params.Start >= params.End || params.Limit > 100 || params.Cursor != nil && (*params.Cursor < params.Start || *params.Cursor >= params.End) {
		return SourceLinesResult{}, errors.New("source.lines parameters are invalid")
	}
	r, err := callTyped[SourceLinesParams, SourceLinesResult](client, ctx, instance, methodSourceLines, params)
	if err == nil {
		origin := params.Start
		if params.Cursor != nil {
			origin = *params.Cursor
		}
		if len(r.Items) > int(effectiveIndexLimit(params.Limit)) || r.HasMore != (r.NextCursor != nil) || r.NextCursor != nil && (*r.NextCursor <= origin || *r.NextCursor >= params.End) {
			err = errors.New("source.lines pagination is inconsistent")
		}
		for i, item := range r.Items {
			if err == nil && (item.Address < params.Start || item.Address >= params.End || item.Filename != nil && !validBasename(*item.Filename) || i > 0 && item.Address <= r.Items[i-1].Address) {
				err = errors.New("source.lines result is invalid")
			}
		}
	}
	return r, err
}
func (client *Client) NameDemangle(ctx context.Context, instance rpc.InstanceDescriptor, params NameDemangleParams) (NameDemangleResult, error) {
	if (params.Address == nil) == (params.Name == nil) || params.Name != nil && (!validQueryText(*params.Name, 4096) || *params.Name == "") {
		return NameDemangleResult{}, errors.New("name.demangle parameters are invalid")
	}
	r, err := callTyped[NameDemangleParams, NameDemangleResult](client, ctx, instance, methodNameDemangle, params)
	if err == nil && (!validQueryText(r.Raw, 4096) || r.Raw == "" || r.Short != nil && !validQueryText(*r.Short, 16384) || r.Long != nil && !validQueryText(*r.Long, 16384)) {
		err = errors.New("name.demangle result is invalid")
	}
	return r, err
}
func (client *Client) CommentGet(ctx context.Context, instance rpc.InstanceDescriptor, params CommentGetParams) (CommentResult, error) {
	if params.Scope != "" && params.Scope != "item" && params.Scope != "function" {
		return CommentResult{}, errors.New("comment.get parameters are invalid")
	}
	r, err := callTyped[CommentGetParams, CommentResult](client, ctx, instance, methodCommentGet, params)
	scope := params.Scope
	if scope == "" {
		scope = "item"
	}
	if err == nil && (r.Scope != scope || r.Repeatable != params.Repeatable || !validQueryText(r.Text, 16384) || r.Text == "") {
		err = errors.New("comment.get result is invalid")
	}
	return r, err
}
func (client *Client) BookmarkList(ctx context.Context, instance rpc.InstanceDescriptor, params IndexListParams) (BookmarksResult, error) {
	if params.Limit > 100 || params.Cursor > 1024 {
		return BookmarksResult{}, errors.New("bookmark.list parameters are invalid")
	}
	r, err := callTyped[IndexListParams, BookmarksResult](client, ctx, instance, methodBookmarkList, params)
	if err == nil {
		err = validateIndexPage(len(r.Items), params.Limit, params.Cursor, r.NextCursor, r.HasMore, 1024)
		for _, item := range r.Items {
			if err == nil && (item.Slot >= 1024 || !validQueryText(item.Description, 16384)) {
				err = errors.New("bookmark.list result is invalid")
			}
		}
	}
	return r, err
}
func (client *Client) TypeXrefs(ctx context.Context, instance rpc.InstanceDescriptor, params TypeXrefsParams) (TypeXrefsResult, error) {
	if !validQueryText(params.Name, 4096) || params.Name == "" || params.Limit > 100 || params.Cursor > 1_000_000 {
		return TypeXrefsResult{}, errors.New("type.xrefs parameters are invalid")
	}
	r, err := callTyped[TypeXrefsParams, TypeXrefsResult](client, ctx, instance, methodTypeXrefs, params)
	if err == nil {
		err = validateIndexPage(len(r.Items), params.Limit, params.Cursor, r.NextCursor, r.HasMore, 1_000_000)
		allowed := map[string]bool{"call_far": true, "call_near": true, "jump_far": true, "jump_near": true, "flow": true, "unknown_code": true, "offset": true, "write": true, "read": true, "text": true, "informational": true, "symbolic": true, "unknown_data": true}
		for _, item := range r.Items {
			if err == nil && !allowed[item.XrefType] {
				err = errors.New("type.xrefs result is invalid")
			}
		}
	}
	return r, err
}
func (client *Client) DecompilerLocals(ctx context.Context, instance rpc.InstanceDescriptor, params DecompilerLocalsParams) (DecompilerLocalsResult, error) {
	if params.MaxItems > 512 {
		return DecompilerLocalsResult{}, errors.New("decompiler.locals parameters are invalid")
	}
	r, err := callTyped[DecompilerLocalsParams, DecompilerLocalsResult](client, ctx, instance, methodDecompilerLocals, params)
	maximum := params.MaxItems
	if maximum == 0 {
		maximum = 100
	}
	if err == nil && (len(r.Items) > int(maximum) || r.TotalCount < uint32(len(r.Items)) || r.Truncated != (r.TotalCount > uint32(len(r.Items)))) {
		err = errors.New("decompiler.locals result is invalid")
	}
	allowedFlags := map[string]bool{"used": true, "typed": true, "nice_name": true, "user_name": true, "user_type": true, "result": true, "argument": true, "fake": true, "overlapped": true, "partial_type": true, "this_argument": true, "dummy_argument": true, "address_taken": true, "shared": true}
	for index, item := range r.Items {
		if err != nil {
			break
		}
		if item.Index != uint32(index) || !validQueryText(item.Name, 4096) || !validQueryText(item.Declaration, 16384) || !validQueryText(item.Locator.Text, 4096) || item.Locator.Kind != "stack" && item.Locator.Kind != "register" && item.Locator.Kind != "scattered" && item.Locator.Kind != "other" || len(item.Locator.Registers) > 16 {
			err = errors.New("decompiler.locals item is invalid")
			break
		}
		seen := map[string]bool{}
		for _, flag := range item.Flags {
			if !allowedFlags[flag] || seen[flag] {
				err = errors.New("decompiler.locals flags are invalid")
				break
			}
			seen[flag] = true
		}
		for _, register := range item.Locator.Registers {
			if !validQueryText(register, 128) || register == "" {
				err = errors.New("decompiler.locals register is invalid")
				break
			}
		}
	}
	return r, err
}
func (client *Client) DecompilerCtree(ctx context.Context, instance rpc.InstanceDescriptor, params DecompilerCtreeParams) (DecompilerCtreeResult, error) {
	if params.MaxDepth > 32 || params.MaxNodes > 1000 {
		return DecompilerCtreeResult{}, errors.New("decompiler.ctree parameters are invalid")
	}
	r, err := callTyped[DecompilerCtreeParams, DecompilerCtreeResult](client, ctx, instance, methodDecompilerCtree, params)
	depth, nodes := params.MaxDepth, params.MaxNodes
	if depth == 0 {
		depth = 8
	}
	if nodes == 0 {
		nodes = 200
	}
	if err == nil && (r.Count != uint32(len(r.Nodes)) || r.Count > nodes) {
		err = errors.New("decompiler.ctree result is invalid")
	}
	for i, node := range r.Nodes {
		if err == nil && (node.Ordinal != uint32(i) || node.Depth > depth || node.Kind != "expression" && node.Kind != "statement" || !validQueryText(node.Op, 128) || node.Op == "" || node.Type != nil && !validQueryText(*node.Type, 16384) || node.Name != nil && !validQueryText(*node.Name, 4096) || len(node.UserFlags) > 4) {
			err = errors.New("decompiler.ctree node is invalid")
		}
		seen := map[string]bool{}
		for _, flag := range node.UserFlags {
			if flag != "collapsed" && flag != "inverted" && flag != "then_collapsed" && flag != "else_collapsed" || seen[flag] {
				err = errors.New("decompiler.ctree flags are invalid")
				break
			}
			seen[flag] = true
		}
	}
	return r, err
}
func (client *Client) DecompilerLocalXrefs(ctx context.Context, instance rpc.InstanceDescriptor, params DecompilerLocalXrefsParams) (DecompilerLocalXrefsResult, error) {
	if params.LocalIndex > 1_000_000 || params.MaxDepth > 32 || params.MaxNodes > 5000 || params.MaxItems > 512 {
		return DecompilerLocalXrefsResult{}, errors.New("decompiler.local_xrefs parameters are invalid")
	}
	r, err := callTyped[DecompilerLocalXrefsParams, DecompilerLocalXrefsResult](client, ctx, instance, methodDecompilerLocalXrefs, params)
	depth, nodes, items := params.MaxDepth, params.MaxNodes, params.MaxItems
	if depth == 0 {
		depth = 16
	}
	if nodes == 0 {
		nodes = 1000
	}
	if items == 0 {
		items = 100
	}
	if err == nil && (r.LocalIndex != params.LocalIndex || r.VisitedNodes > nodes || r.TotalReturned != uint32(len(r.Items)) || r.TotalReturned > items || !validQueryText(r.Name, 4096)) {
		err = errors.New("decompiler.local_xrefs result is invalid")
	}
	for index, item := range r.Items {
		if err == nil && (item.Ordinal != uint32(index) || item.Depth > depth || item.ParentOp != nil && (!validQueryText(*item.ParentOp, 128) || *item.ParentOp == "") || item.Type != nil && !validQueryText(*item.Type, 16384)) {
			err = errors.New("decompiler.local_xrefs item is invalid")
		}
	}
	return r, err
}
func (client *Client) DebuggerThreads(ctx context.Context, instance rpc.InstanceDescriptor, params IndexListParams) (DebuggerThreadsResult, error) {
	if params.Limit > 100 || params.Cursor > 1024 {
		return DebuggerThreadsResult{}, errors.New("debugger.threads parameters are invalid")
	}
	r, err := callTyped[IndexListParams, DebuggerThreadsResult](client, ctx, instance, methodDebuggerThreads, params)
	if err == nil {
		err = validateIndexPage(len(r.Items), params.Limit, params.Cursor, r.NextCursor, r.HasMore, 1024)
		for _, item := range r.Items {
			if err == nil && (item.ThreadID <= 0 || item.Name != nil && !validQueryText(*item.Name, 4096)) {
				err = errors.New("debugger.threads result is invalid")
			}
		}
	}
	return r, err
}
func (client *Client) DebuggerModules(ctx context.Context, instance rpc.InstanceDescriptor, params IndexListParams) (DebuggerModulesResult, error) {
	if params.Limit > 100 || params.Cursor > 4096 {
		return DebuggerModulesResult{}, errors.New("debugger.modules parameters are invalid")
	}
	r, err := callTyped[IndexListParams, DebuggerModulesResult](client, ctx, instance, methodDebuggerModules, params)
	if err == nil {
		err = validateIndexPage(len(r.Items), params.Limit, params.Cursor, r.NextCursor, r.HasMore, 4096)
		for _, item := range r.Items {
			if err == nil && !validBasename(item.Name) {
				err = errors.New("debugger.modules result is invalid")
			}
		}
	}
	return r, err
}
