package mcpserver

import "ida-mcp/ida"

type indexListInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Limit      uint32  `json:"limit,omitempty"`
	Cursor     string  `json:"cursor,omitempty"`
}
type sourceLinesInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Start      string  `json:"start"`
	End        string  `json:"end"`
	Limit      uint32  `json:"limit,omitempty"`
	Cursor     string  `json:"cursor,omitempty"`
}
type nameDemangleInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    *string `json:"address,omitempty"`
	Name       *string `json:"name,omitempty"`
}
type commentGetInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
	Scope      string  `json:"scope,omitempty"`
	Repeatable bool    `json:"repeatable,omitempty"`
}
type typeXrefsInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Name       string  `json:"name"`
	Limit      uint32  `json:"limit,omitempty"`
	Cursor     string  `json:"cursor,omitempty"`
}
type decompilerLocalsInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
	MaxItems   uint32  `json:"maxItems,omitempty"`
}
type decompilerCtreeInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
	MaxDepth   uint32  `json:"maxDepth,omitempty"`
	MaxNodes   uint32  `json:"maxNodes,omitempty"`
}
type decompilerLocalXrefsInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
	LocalIndex uint32  `json:"localIndex"`
	MaxDepth   uint32  `json:"maxDepth,omitempty"`
	MaxNodes   uint32  `json:"maxNodes,omitempty"`
	MaxItems   uint32  `json:"maxItems,omitempty"`
}

type sourceFilesOutput struct {
	Items      []ida.SourceFileItem `json:"items"`
	NextCursor *string              `json:"nextCursor"`
	HasMore    bool                 `json:"hasMore"`
}
type sourceLinesOutput struct {
	Items      []ida.SourceLineItem `json:"items"`
	NextCursor *string              `json:"nextCursor"`
	HasMore    bool                 `json:"hasMore"`
}
type bookmarksOutput struct {
	Items      []ida.BookmarkItem `json:"items"`
	NextCursor *string            `json:"nextCursor"`
	HasMore    bool               `json:"hasMore"`
}
type typeXrefsOutput struct {
	Items      []ida.TypeXrefItem `json:"items"`
	NextCursor *string            `json:"nextCursor"`
	HasMore    bool               `json:"hasMore"`
}
type debuggerThreadsOutput struct {
	Items      []ida.DebuggerThreadItem `json:"items"`
	NextCursor *string                  `json:"nextCursor"`
	HasMore    bool                     `json:"hasMore"`
}
type debuggerModulesOutput struct {
	Items      []ida.DebuggerModuleItem `json:"items"`
	NextCursor *string                  `json:"nextCursor"`
	HasMore    bool                     `json:"hasMore"`
}
