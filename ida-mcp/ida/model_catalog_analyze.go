package ida

type FunctionAnalyzeParams struct {
	Addresses      []Address
	Sections       []string
	PerSection     uint32
	DecompileBytes uint32
}

type AnalyzeRange struct {
	Start Address `json:"start"`
	End   Address `json:"end"`
}

type AnalyzeMetrics struct {
	SizeBytes    uint64 `json:"sizeBytes"`
	Instructions uint64 `json:"instructions"`
	BasicBlocks  uint64 `json:"basicBlocks"`
	Chunks       uint64 `json:"chunks"`
}

type AnalyzeCaller struct {
	Address   Address   `json:"address"`
	Name      string    `json:"name"`
	CallSites []Address `json:"callSites"`
}

type AnalyzeCallersSection struct {
	EntryAddress Address         `json:"entryAddress,omitempty"`
	Items        []AnalyzeCaller `json:"items"`
	NextOffset   *uint32         `json:"nextOffset,omitempty"`
	HasMore      bool            `json:"hasMore,omitempty"`
	Truncated    bool            `json:"truncated"`
}

type AnalyzeCalleesSection struct {
	EntryAddress Address          `json:"entryAddress,omitempty"`
	Items        []FunctionCallee `json:"items"`
	NextOffset   *uint32          `json:"nextOffset,omitempty"`
	HasMore      bool             `json:"hasMore,omitempty"`
	Truncated    bool             `json:"truncated"`
}

type AnalyzeBlocksSection struct {
	EntryAddress Address              `json:"entryAddress,omitempty"`
	Items        []FunctionBasicBlock `json:"items"`
	NextOffset   *uint32              `json:"nextOffset,omitempty"`
	HasMore      bool                 `json:"hasMore,omitempty"`
	Truncated    bool                 `json:"truncated"`
}

type AnalyzeXref struct {
	From        Address `json:"from"`
	To          Address `json:"to"`
	Type        string  `json:"type"`
	Code        bool    `json:"code"`
	UserDefined bool    `json:"userDefined"`
}

type AnalyzeXrefsSection struct {
	Items     []AnalyzeXref `json:"items"`
	Truncated bool          `json:"truncated"`
}

type AnalyzeStringsSection struct {
	Items     []StringInfo `json:"items"`
	Truncated bool         `json:"truncated"`
}

type AnalyzeConstant struct {
	Address Address `json:"address"`
	Value   string  `json:"value"`
}

type AnalyzeConstantsSection struct {
	Items     []AnalyzeConstant `json:"items"`
	Truncated bool              `json:"truncated"`
}

type AnalyzeComment struct {
	Address Address `json:"address"`
	Text    string  `json:"text"`
}

type AnalyzeCommentsSection struct {
	Items     []AnalyzeComment `json:"items"`
	Truncated bool             `json:"truncated"`
}

type FunctionAnalyzeItem struct {
	Address   Address                  `json:"address"`
	Name      string                   `json:"name,omitempty"`
	Error     string                   `json:"error,omitempty"`
	Range     *AnalyzeRange            `json:"range,omitempty"`
	Flags     *FunctionFlags           `json:"flags,omitempty"`
	Prototype *string                  `json:"prototype,omitempty"`
	Metrics   *AnalyzeMetrics          `json:"metrics,omitempty"`
	Callers   *AnalyzeCallersSection   `json:"callers,omitempty"`
	Callees   *AnalyzeCalleesSection   `json:"callees,omitempty"`
	Blocks    *AnalyzeBlocksSection    `json:"blocks,omitempty"`
	Xrefs     *AnalyzeXrefsSection     `json:"xrefs,omitempty"`
	Strings   *AnalyzeStringsSection   `json:"strings,omitempty"`
	Constants *AnalyzeConstantsSection `json:"constants,omitempty"`
	Comments  *AnalyzeCommentsSection  `json:"comments,omitempty"`
	Decompile *DecompileResult         `json:"decompile,omitempty"`
}

type FunctionAnalyzeResult struct {
	Sections []string              `json:"sections"`
	Items    []FunctionAnalyzeItem `json:"items"`
}
