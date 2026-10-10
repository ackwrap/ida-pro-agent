package ida

type SystemPingResult struct {
	Status string `json:"status"`
}

type SystemMethodsResult struct {
	Methods []string `json:"methods"`
}

type InstanceInfoResult struct {
	InstanceID   string       `json:"instanceId"`
	PID          uint32       `json:"pid"`
	IDAVersion   string       `json:"idaVersion"`
	Database     string       `json:"database"`
	InputFile    string       `json:"inputFile"`
	Processor    string       `json:"processor"`
	Bitness      int          `json:"bitness"`
	Architecture string       `json:"architecture"`
	Capabilities Capabilities `json:"capabilities"`
}

type DatabaseSurveyParams struct {
	Mode   string
	Budget uint32
}

type SurveyStatistics struct {
	SampledFunctions   uint32 `json:"sampledFunctions"`
	SampledStrings     uint32 `json:"sampledStrings"`
	SampledImports     uint32 `json:"sampledImports"`
	FunctionsTruncated bool   `json:"functionsTruncated"`
	StringsTruncated   bool   `json:"stringsTruncated"`
	ImportsTruncated   bool   `json:"importsTruncated"`
}

type SurveyImportCategory struct {
	Module       string `json:"module"`
	SampledCount uint32 `json:"sampledCount"`
}

type SurveyCallGraph struct {
	Roots     uint32 `json:"roots"`
	Nodes     uint32 `json:"nodes"`
	Edges     uint32 `json:"edges"`
	Truncated bool   `json:"truncated"`
}

type SurveyMetricCount struct {
	Sampled uint32 `json:"sampled"`
	HasMore bool   `json:"hasMore"`
}

type SurveyMetrics struct {
	Segments  uint32            `json:"segments"`
	Functions SurveyMetricCount `json:"functions"`
	Strings   SurveyMetricCount `json:"strings"`
	Imports   SurveyMetricCount `json:"imports"`
}

type SurveyBudget struct {
	RequestedItems uint32 `json:"requestedItems"`
	PerSection     uint32 `json:"perSection"`
}

type SurveyFunctions struct {
	Items        []FunctionSummary `json:"items,omitempty"`
	SampledCount *uint32           `json:"sampledCount,omitempty"`
	HasMore      bool              `json:"hasMore"`
}

type SurveyStrings struct {
	Items        []StringInfo `json:"items,omitempty"`
	SampledCount *uint32      `json:"sampledCount,omitempty"`
	HasMore      bool         `json:"hasMore"`
}

type DatabaseSurveyResult struct {
	Mode             string                 `json:"mode"`
	Metadata         DatabaseInfo           `json:"metadata"`
	Statistics       SurveyStatistics       `json:"statistics"`
	ImportCategories []SurveyImportCategory `json:"importCategories"`
	CallGraph        SurveyCallGraph        `json:"callGraph"`
	Metrics          SurveyMetrics          `json:"metrics"`
	Truncated        bool                   `json:"truncated"`
	Budget           SurveyBudget           `json:"budget"`
	Functions        SurveyFunctions        `json:"functions"`
	Strings          SurveyStrings          `json:"strings"`
}

type DatabaseSaveParams struct {
	Compact bool
	Backup  bool
}

type DatabaseSaveResult struct {
	Saved          bool `json:"saved"`
	ExplicitTarget bool `json:"explicitTarget"`
}

type FunctionCallersParams struct {
	Address Address
	Offset  uint32
	Limit   int
}

type FunctionCaller struct {
	Address   Address   `json:"address"`
	Name      string    `json:"name"`
	CallSites []Address `json:"callSites"`
}

type FunctionCallersResult struct {
	EntryAddress Address          `json:"entryAddress"`
	Items        []FunctionCaller `json:"items"`
	NextOffset   *uint32          `json:"nextOffset"`
	HasMore      bool             `json:"hasMore"`
}

type FunctionCallGraphParams struct {
	Roots       []Address
	Direction   string
	MaxDepth    uint32
	MaxNodes    uint32
	MaxEdges    uint32
	PerFunction uint32
}

type FunctionCallGraphNode struct {
	Address Address `json:"address"`
	Name    string  `json:"name"`
	Depth   uint32  `json:"depth"`
}

type FunctionCallGraphEdge struct {
	From Address `json:"from"`
	To   Address `json:"to"`
}

type FunctionCallGraphResult struct {
	Nodes     []FunctionCallGraphNode `json:"nodes"`
	Edges     []FunctionCallGraphEdge `json:"edges"`
	Truncated bool                    `json:"truncated"`
}

type FunctionProfileParams struct {
	Name             string
	MinSize          uint32
	MaxSize          uint32
	Library          *bool
	Thunk            *bool
	IncludePrototype bool
	SampleLimit      uint32
	Limit            uint32
	Cursor           string
}

type FunctionProfileMetrics struct {
	SizeBytes    uint64 `json:"sizeBytes"`
	Instructions uint64 `json:"instructions"`
	BasicBlocks  uint64 `json:"basicBlocks"`
	Chunks       uint64 `json:"chunks"`
}

type FunctionProfileFlags struct {
	Library bool `json:"library"`
	Thunk   bool `json:"thunk"`
}

type FunctionProfileItem struct {
	Address          Address                `json:"address"`
	Name             string                 `json:"name"`
	Metrics          FunctionProfileMetrics `json:"metrics"`
	Flags            FunctionProfileFlags   `json:"flags"`
	Prototype        *string                `json:"prototype,omitempty"`
	Samples          *[]DisassemblyItem     `json:"samples,omitempty"`
	SamplesTruncated *bool                  `json:"samplesTruncated,omitempty"`
}

type FunctionProfileSummary struct {
	Candidates          uint32 `json:"candidates"`
	Matched             uint32 `json:"matched"`
	SampledInstructions uint32 `json:"sampledInstructions"`
}

type FunctionProfileResult struct {
	Items      []FunctionProfileItem  `json:"items"`
	NextCursor *string                `json:"nextCursor"`
	HasMore    bool                   `json:"hasMore"`
	Metrics    FunctionProfileSummary `json:"metrics"`
}

type FunctionExportParams struct {
	Addresses []Address
	Format    string
	MaxBytes  uint32
}

type FunctionExportResult struct {
	Format       string `json:"format"`
	Content      string `json:"content"`
	Truncated    bool   `json:"truncated"`
	OriginalSize uint64 `json:"originalSize"`
}

type FunctionStackFrameParams struct {
	Address Address
}

type StackVariable struct {
	Name        string `json:"name"`
	Declaration string `json:"declaration"`
	BitOffset   int64  `json:"bitOffset"`
	BitSize     uint64 `json:"bitSize"`
	Role        string `json:"role"`
}

type FunctionStackFrameResult struct {
	EntryAddress Address         `json:"entryAddress"`
	Size         uint64          `json:"size"`
	Variables    []StackVariable `json:"variables"`
}
