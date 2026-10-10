package ida

type GlobalValueParams struct {
	Address  *Address
	Name     *string
	MaxBytes uint32
}

type GlobalValueResult struct {
	Address     Address `json:"address"`
	Symbol      *string `json:"symbol"`
	Declaration *string `json:"declaration"`
	Size        uint64  `json:"size"`
	BytesRead   uint64  `json:"bytesRead"`
	Format      string  `json:"format"`
	Value       string  `json:"value"`
	Truncated   bool    `json:"truncated"`
}

type TypeSearchParams struct {
	Name    string
	Kind    string
	Ordinal uint32
	Limit   uint32
}

type TypeMember struct {
	Name        string `json:"name"`
	Declaration string `json:"declaration"`
	BitOffset   uint64 `json:"bitOffset"`
	BitSize     uint64 `json:"bitSize"`
}

type EnumMember struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type TypeDetails struct {
	Ordinal                 uint32       `json:"ordinal"`
	Name                    string       `json:"name"`
	Kind                    string       `json:"kind"`
	Size                    uint64       `json:"size"`
	Declaration             string       `json:"declaration"`
	DeclarationOriginalSize uint64       `json:"declarationOriginalSize"`
	DeclarationTruncated    bool         `json:"declarationTruncated"`
	Members                 []TypeMember `json:"members"`
	MemberCount             uint64       `json:"memberCount"`
	MembersTruncated        bool         `json:"membersTruncated"`
	EnumMembers             []EnumMember `json:"enumMembers"`
	EnumMemberCount         uint64       `json:"enumMemberCount"`
	EnumMembersTruncated    bool         `json:"enumMembersTruncated"`
	RelatedTypes            []string     `json:"relatedTypes"`
	RelatedTypeCount        uint64       `json:"relatedTypeCount"`
	RelatedTypesTruncated   bool         `json:"relatedTypesTruncated"`
}

type TypeSearchResult struct {
	Items       []TypeDetails `json:"items"`
	NextOrdinal *uint32       `json:"nextOrdinal"`
	HasMore     bool          `json:"hasMore"`
}

type TypeGetParams struct{ Name string }

type TypeReadValueParams struct {
	Address  Address
	Name     string
	MaxBytes uint32
}

type TypeReadStructParams struct {
	Address  Address
	Name     string
	MaxBytes uint32
}

type TypedFieldValue struct {
	Name        string `json:"name"`
	Declaration string `json:"declaration"`
	ByteOffset  uint64 `json:"byteOffset"`
	Size        uint64 `json:"size"`
	Format      string `json:"format"`
	Value       string `json:"value"`
	Truncated   bool   `json:"truncated"`
}

type TypedValueResult struct {
	Address         Address           `json:"address"`
	Type            TypeDetails       `json:"type"`
	Bytes           string            `json:"bytes"`
	BytesRead       uint64            `json:"bytesRead"`
	OriginalSize    uint64            `json:"originalSize"`
	Truncated       bool              `json:"truncated"`
	Fields          []TypedFieldValue `json:"fields"`
	FieldsTruncated bool              `json:"fieldsTruncated"`
}

type TypeInferParams struct{ Address Address }

type TypeInferenceResult struct {
	Address     Address `json:"address"`
	Declaration string  `json:"declaration"`
	Source      string  `json:"source"`
}
