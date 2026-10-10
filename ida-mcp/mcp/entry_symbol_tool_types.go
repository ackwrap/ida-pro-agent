package mcpserver

type databaseEntryPointsInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Name       string  `json:"name,omitempty"`
	Type       string  `json:"type,omitempty"`
	Limit      int     `json:"limit,omitempty"`
	Cursor     string  `json:"cursor,omitempty"`
}

type entryPointOutput struct {
	Address string  `json:"address"`
	Name    string  `json:"name"`
	Type    string  `json:"type"`
	Ordinal *uint64 `json:"ordinal,omitempty"`
}

type databaseEntryPointsOutput struct {
	Items      []entryPointOutput `json:"items"`
	NextCursor *string            `json:"nextCursor"`
	HasMore    bool               `json:"hasMore"`
}

type symbolExportsInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Name       string  `json:"name,omitempty"`
	Limit      int     `json:"limit,omitempty"`
	Cursor     string  `json:"cursor,omitempty"`
}

type exportOutput struct {
	Address string `json:"address"`
	Name    string `json:"name"`
	Ordinal uint64 `json:"ordinal"`
}

type symbolExportsOutput struct {
	Items      []exportOutput `json:"items"`
	NextCursor *string        `json:"nextCursor"`
	HasMore    bool           `json:"hasMore"`
}

type symbolSearchInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Name       string  `json:"name,omitempty"`
	Kind       string  `json:"kind,omitempty"`
	Limit      int     `json:"limit,omitempty"`
	Cursor     string  `json:"cursor,omitempty"`
}

type symbolOutput struct {
	Address string `json:"address"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
}

type symbolSearchOutput struct {
	Items      []symbolOutput `json:"items"`
	NextCursor *string        `json:"nextCursor"`
	HasMore    bool           `json:"hasMore"`
}
