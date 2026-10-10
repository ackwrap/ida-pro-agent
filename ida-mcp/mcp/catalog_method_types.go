package mcpserver

type catalogInstanceInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
}

type databaseSurveyInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Mode       string  `json:"mode,omitempty"`
	Budget     uint32  `json:"budget,omitempty"`
}

type databaseSaveInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Compact    bool    `json:"compact,omitempty"`
	Backup     bool    `json:"backup,omitempty"`
}

type functionCallersInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
	Offset     uint32  `json:"offset,omitempty"`
	Limit      int     `json:"limit,omitempty"`
}

type functionCallGraphInput struct {
	InstanceID  *string  `json:"instanceId,omitempty"`
	Roots       []string `json:"roots"`
	Direction   string   `json:"direction,omitempty"`
	MaxDepth    *uint32  `json:"maxDepth,omitempty"`
	MaxNodes    uint32   `json:"maxNodes,omitempty"`
	MaxEdges    uint32   `json:"maxEdges,omitempty"`
	PerFunction uint32   `json:"perFunction,omitempty"`
}

type functionProfileInput struct {
	InstanceID       *string `json:"instanceId,omitempty"`
	Name             string  `json:"name,omitempty"`
	MinSize          uint32  `json:"minSize,omitempty"`
	MaxSize          uint32  `json:"maxSize,omitempty"`
	Library          *bool   `json:"library,omitempty"`
	Thunk            *bool   `json:"thunk,omitempty"`
	IncludePrototype bool    `json:"includePrototype,omitempty"`
	SampleLimit      uint32  `json:"sampleLimit,omitempty"`
	Limit            uint32  `json:"limit,omitempty"`
	Cursor           string  `json:"cursor,omitempty"`
}

type functionExportInput struct {
	InstanceID *string  `json:"instanceId,omitempty"`
	Addresses  []string `json:"addresses"`
	Format     string   `json:"format"`
	MaxBytes   uint32   `json:"maxBytes,omitempty"`
}

type functionAnalyzeInput struct {
	InstanceID     *string  `json:"instanceId,omitempty"`
	Addresses      []string `json:"addresses"`
	Sections       []string `json:"sections,omitempty"`
	PerSection     uint32   `json:"perSection,omitempty"`
	DecompileBytes uint32   `json:"decompileBytes,omitempty"`
}

type functionStackFrameInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
}
