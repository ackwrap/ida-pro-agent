package ida

type SegmentListParams struct {
	Name   string
	Limit  int
	Cursor string
}

type SegmentInfo struct {
	Start       Address `json:"start"`
	End         Address `json:"end"`
	Name        string  `json:"name"`
	Class       string  `json:"class"`
	Bitness     uint32  `json:"bitness"`
	Permissions string  `json:"permissions"`
	Type        string  `json:"type"`
}

type SegmentListResult struct {
	Items      []SegmentInfo `json:"items"`
	NextCursor *string       `json:"nextCursor"`
	HasMore    bool          `json:"hasMore"`
}

type StringSearchParams struct {
	Query     string
	MinLength int
	Limit     int
	Cursor    string
	Refresh   bool
}

type StringInfo struct {
	Address      Address `json:"address"`
	Length       uint64  `json:"length"`
	Encoding     string  `json:"encoding"`
	Value        string  `json:"value"`
	Truncated    bool    `json:"truncated"`
	OriginalSize uint64  `json:"originalSize"`
}

type StringSearchResult struct {
	Items      []StringInfo `json:"items"`
	NextCursor *string      `json:"nextCursor"`
	HasMore    bool         `json:"hasMore"`
}

type ImportListParams struct {
	Module string
	Name   string
	Limit  int
	Cursor string
}

type ImportInfo struct {
	Address Address `json:"address"`
	Name    string  `json:"name"`
	Module  string  `json:"module"`
	Ordinal *uint64 `json:"ordinal,omitempty"`
}

type ImportListResult struct {
	Items      []ImportInfo `json:"items"`
	NextCursor *string      `json:"nextCursor"`
	HasMore    bool         `json:"hasMore"`
}
