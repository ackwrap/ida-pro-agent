package mcpserver

type databaseSegmentsInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Name       string  `json:"name,omitempty"`
	Limit      int     `json:"limit,omitempty"`
	Cursor     string  `json:"cursor,omitempty"`
}

type segmentOutput struct {
	Start       string `json:"start"`
	End         string `json:"end"`
	Name        string `json:"name"`
	Class       string `json:"class"`
	Bitness     uint32 `json:"bitness"`
	Permissions string `json:"permissions"`
	Type        string `json:"type"`
}

type databaseSegmentsOutput struct {
	Items      []segmentOutput `json:"items"`
	NextCursor *string         `json:"nextCursor"`
	HasMore    bool            `json:"hasMore"`
}

type stringSearchInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Query      string  `json:"query,omitempty"`
	MinLength  int     `json:"minLength,omitempty"`
	Limit      int     `json:"limit,omitempty"`
	Cursor     string  `json:"cursor,omitempty"`
	Refresh    bool    `json:"refresh,omitempty"`
}

type stringOutput struct {
	Address      string `json:"address"`
	Length       uint64 `json:"length"`
	Encoding     string `json:"encoding"`
	Value        string `json:"value"`
	Truncated    bool   `json:"truncated"`
	OriginalSize uint64 `json:"originalSize"`
}

type stringSearchOutput struct {
	Items      []stringOutput `json:"items"`
	NextCursor *string        `json:"nextCursor"`
	HasMore    bool           `json:"hasMore"`
}

type symbolImportsInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Module     string  `json:"module,omitempty"`
	Name       string  `json:"name,omitempty"`
	Limit      int     `json:"limit,omitempty"`
	Cursor     string  `json:"cursor,omitempty"`
}

type importOutput struct {
	Address string  `json:"address"`
	Name    string  `json:"name"`
	Module  string  `json:"module"`
	Ordinal *uint64 `json:"ordinal,omitempty"`
}

type symbolImportsOutput struct {
	Items      []importOutput `json:"items"`
	NextCursor *string        `json:"nextCursor"`
	HasMore    bool           `json:"hasMore"`
}
