package mcpserver

type memorySearchBytesInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Pattern    string  `json:"pattern"`
	Start      string  `json:"start"`
	End        string  `json:"end"`
	Limit      uint32  `json:"limit,omitempty"`
}
type instructionSearchInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Start      string  `json:"start"`
	End        string  `json:"end"`
	Mnemonic   string  `json:"mnemonic,omitempty"`
	Operand    string  `json:"operand,omitempty"`
	Limit      uint32  `json:"limit,omitempty"`
	Cursor     string  `json:"cursor,omitempty"`
}
type listingSearchInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Start      string  `json:"start"`
	End        string  `json:"end"`
	Query      string  `json:"query"`
	Limit      uint32  `json:"limit,omitempty"`
}
type listingSearchTextInput struct {
	InstanceID         *string `json:"instanceId,omitempty"`
	Start              string  `json:"start"`
	End                string  `json:"end"`
	Query              *string `json:"query,omitempty"`
	Regex              *string `json:"regex,omitempty"`
	IncludeDisassembly *bool   `json:"includeDisassembly,omitempty"`
	IncludeComments    *bool   `json:"includeComments,omitempty"`
	Limit              uint32  `json:"limit,omitempty"`
	Cursor             string  `json:"cursor,omitempty"`
}
type stringSearchRegexInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Pattern    string  `json:"pattern"`
	MinLength  uint32  `json:"minLength,omitempty"`
	Limit      uint32  `json:"limit,omitempty"`
	Cursor     string  `json:"cursor,omitempty"`
	Refresh    bool    `json:"refresh,omitempty"`
}
type signatureMakeInput struct {
	InstanceID       *string `json:"instanceId,omitempty"`
	Mode             string  `json:"mode,omitempty"`
	Address          *string `json:"address,omitempty"`
	Start            *string `json:"start,omitempty"`
	End              *string `json:"end,omitempty"`
	Format           string  `json:"format,omitempty"`
	WildcardOperands *bool   `json:"wildcardOperands,omitempty"`
	MaxLength        uint32  `json:"maxLength,omitempty"`
}
type signatureXrefsInput struct {
	InstanceID       *string `json:"instanceId,omitempty"`
	Address          string  `json:"address"`
	Format           string  `json:"format,omitempty"`
	WildcardOperands *bool   `json:"wildcardOperands,omitempty"`
	MaxLength        uint32  `json:"maxLength,omitempty"`
	Top              uint32  `json:"top,omitempty"`
}
type structFieldXrefsInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Type       string  `json:"type"`
	Field      string  `json:"field"`
	Limit      uint32  `json:"limit,omitempty"`
}
type globalValueInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    *string `json:"address,omitempty"`
	Name       *string `json:"name,omitempty"`
	MaxBytes   uint32  `json:"maxBytes,omitempty"`
}
type typeSearchInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Name       string  `json:"name,omitempty"`
	Kind       string  `json:"kind,omitempty"`
	Ordinal    uint32  `json:"ordinal,omitempty"`
	Limit      uint32  `json:"limit,omitempty"`
}
type typeGetInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Name       string  `json:"name"`
}
type typeReadValueInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
	Name       string  `json:"name"`
	MaxBytes   uint32  `json:"maxBytes,omitempty"`
}
type typeReadStructInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
	Name       string  `json:"name,omitempty"`
	MaxBytes   uint32  `json:"maxBytes,omitempty"`
}
type typeInferInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
}
type analysisComponentInput struct {
	InstanceID  *string  `json:"instanceId,omitempty"`
	Roots       []string `json:"roots"`
	MaxDepth    *uint32  `json:"maxDepth,omitempty"`
	MaxNodes    uint32   `json:"maxNodes,omitempty"`
	MaxEdges    uint32   `json:"maxEdges,omitempty"`
	PerFunction uint32   `json:"perFunction,omitempty"`
	SharedLimit uint32   `json:"sharedLimit,omitempty"`
}
type traceDataFlowInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
	Direction  string  `json:"direction,omitempty"`
	MaxDepth   *uint32 `json:"maxDepth,omitempty"`
	MaxNodes   uint32  `json:"maxNodes,omitempty"`
	MaxEdges   uint32  `json:"maxEdges,omitempty"`
}
type listingSinglePageOutput struct {
	Items     []idaListingItem `json:"items"`
	Truncated bool             `json:"truncated"`
}
type idaListingItem struct {
	Address string `json:"address"`
	Source  string `json:"source"`
	Text    string `json:"text"`
}
