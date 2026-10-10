package ida

type IndexListParams struct {
	Limit  uint32
	Cursor uint32
}
type SourceLinesParams struct {
	Start  Address
	End    Address
	Limit  uint32
	Cursor *Address
}
type NameDemangleParams struct {
	Address *Address
	Name    *string
}
type CommentGetParams struct {
	Address    Address
	Scope      string
	Repeatable bool
}
type TypeXrefsParams struct {
	Name   string
	Limit  uint32
	Cursor uint32
}
type DecompilerLocalsParams struct {
	Address  Address
	MaxItems uint32
}
type DecompilerCtreeParams struct {
	Address  Address
	MaxDepth uint32
	MaxNodes uint32
}
type DecompilerLocalXrefsParams struct {
	Address    Address
	LocalIndex uint32
	MaxDepth   uint32
	MaxNodes   uint32
	MaxItems   uint32
}

type SourceFileItem struct {
	Start    Address `json:"start"`
	End      Address `json:"end"`
	Filename string  `json:"filename"`
}
type SourceFilesResult struct {
	Items      []SourceFileItem `json:"items"`
	NextCursor *uint32          `json:"nextCursor"`
	HasMore    bool             `json:"hasMore"`
}
type SourceLineItem struct {
	Address  Address `json:"address"`
	Line     uint64  `json:"line"`
	Filename *string `json:"filename"`
}
type SourceLinesResult struct {
	Items      []SourceLineItem `json:"items"`
	NextCursor *Address         `json:"nextCursor"`
	HasMore    bool             `json:"hasMore"`
}
type NameDemangleResult struct {
	Raw   string  `json:"raw"`
	Short *string `json:"short"`
	Long  *string `json:"long"`
}
type CommentResult struct {
	Address    Address `json:"address"`
	Scope      string  `json:"scope"`
	Repeatable bool    `json:"repeatable"`
	Text       string  `json:"text"`
}
type BookmarkItem struct {
	Slot        uint32  `json:"slot"`
	Address     Address `json:"address"`
	Line        uint32  `json:"line"`
	Description string  `json:"description"`
}
type BookmarksResult struct {
	Items      []BookmarkItem `json:"items"`
	NextCursor *uint32        `json:"nextCursor"`
	HasMore    bool           `json:"hasMore"`
}
type TypeXrefItem struct {
	Address     Address `json:"address"`
	Code        bool    `json:"code"`
	UserDefined bool    `json:"userDefined"`
	XrefType    string  `json:"xrefType"`
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
	Index       uint32      `json:"index"`
	Name        string      `json:"name"`
	Declaration string      `json:"declaration"`
	Width       uint32      `json:"width"`
	DefBlock    *uint32     `json:"defBlock"`
	DefEA       *Address    `json:"defEa"`
	Locator     LvarLocator `json:"locator"`
	Flags       []string    `json:"flags"`
}
type DecompilerLocalsResult struct {
	EntryAddress Address           `json:"entryAddress"`
	TotalCount   uint32            `json:"totalCount"`
	Truncated    bool              `json:"truncated"`
	Items        []DecompilerLocal `json:"items"`
}
type CtreeNode struct {
	Ordinal   uint32   `json:"ordinal"`
	Depth     uint32   `json:"depth"`
	Kind      string   `json:"kind"`
	Op        string   `json:"op"`
	EA        *Address `json:"ea"`
	UserFlags []string `json:"userFlags"`
	Type      *string  `json:"type,omitempty"`
	LvarIndex *uint32  `json:"lvarIndex,omitempty"`
	Name      *string  `json:"name,omitempty"`
}
type DecompilerCtreeResult struct {
	EntryAddress Address     `json:"entryAddress"`
	Count        uint32      `json:"count"`
	Truncated    bool        `json:"truncated"`
	Nodes        []CtreeNode `json:"nodes"`
}
type DecompilerLocalXref struct {
	Ordinal  uint32   `json:"ordinal"`
	Depth    uint32   `json:"depth"`
	EA       *Address `json:"ea"`
	ParentOp *string  `json:"parentOp"`
	Type     *string  `json:"type"`
}
type DecompilerLocalXrefsResult struct {
	EntryAddress  Address               `json:"entryAddress"`
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
	Name     string   `json:"name"`
	Base     Address  `json:"base"`
	Size     uint64   `json:"size"`
	RebaseTo *Address `json:"rebaseTo"`
}
type DebuggerModulesResult struct {
	Items      []DebuggerModuleItem `json:"items"`
	NextCursor *uint32              `json:"nextCursor"`
	HasMore    bool                 `json:"hasMore"`
}
