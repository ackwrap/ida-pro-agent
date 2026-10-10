package ida

type EntryPointListParams struct {
	Name   string
	Type   string
	Limit  int
	Cursor string
}

type EntryPointInfo struct {
	Address Address `json:"address"`
	Name    string  `json:"name"`
	Type    string  `json:"type"`
	Ordinal *uint64 `json:"ordinal,omitempty"`
}

type EntryPointListResult struct {
	Items      []EntryPointInfo `json:"items"`
	NextCursor *string          `json:"nextCursor"`
	HasMore    bool             `json:"hasMore"`
}

type ExportListParams struct {
	Name   string
	Limit  int
	Cursor string
}

type ExportInfo struct {
	Address Address `json:"address"`
	Name    string  `json:"name"`
	Ordinal uint64  `json:"ordinal"`
}

type ExportListResult struct {
	Items      []ExportInfo `json:"items"`
	NextCursor *string      `json:"nextCursor"`
	HasMore    bool         `json:"hasMore"`
}

type SymbolSearchParams struct {
	Name   string
	Kind   string
	Limit  int
	Cursor string
}

type SymbolInfo struct {
	Address Address `json:"address"`
	Name    string  `json:"name"`
	Kind    string  `json:"kind"`
}

type SymbolSearchResult struct {
	Items      []SymbolInfo `json:"items"`
	NextCursor *string      `json:"nextCursor"`
	HasMore    bool         `json:"hasMore"`
}
