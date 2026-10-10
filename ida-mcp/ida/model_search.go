package ida

type MemorySearchBytesParams struct {
	Pattern string
	Start   Address
	End     Address
	Limit   uint32
}

type AddressSearchResult struct {
	Items       []Address `json:"items"`
	NextAddress *Address  `json:"nextAddress"`
	HasMore     bool      `json:"hasMore"`
}

type InstructionSearchParams struct {
	Start    Address
	End      Address
	Mnemonic string
	Operand  string
	Limit    uint32
	Cursor   string
}

type InstructionSearchItem struct {
	Address  Address  `json:"address"`
	Bytes    string   `json:"bytes"`
	Size     uint32   `json:"size"`
	Text     string   `json:"text"`
	Mnemonic string   `json:"mnemonic"`
	Operands []string `json:"operands"`
}

type InstructionSearchResult struct {
	Items      []InstructionSearchItem `json:"items"`
	NextCursor *string                 `json:"nextCursor"`
	HasMore    bool                    `json:"hasMore"`
}

type ListingSearchParams struct {
	Start Address
	End   Address
	Query string
	Limit uint32
}

type ListingTextSearchParams struct {
	Start              Address
	End                Address
	Query              *string
	Regex              *string
	IncludeDisassembly bool
	IncludeComments    bool
	Limit              uint32
	Cursor             string
}

type ListingSearchItem struct {
	Address Address `json:"address"`
	Source  string  `json:"source"`
	Text    string  `json:"text"`
}

type ListingSearchResult struct {
	Items      []ListingSearchItem `json:"items"`
	NextCursor *string             `json:"nextCursor"`
	HasMore    bool                `json:"hasMore"`
}

type StringRegexSearchParams struct {
	Pattern   string
	MinLength uint32
	Limit     uint32
	Cursor    string
	Refresh   bool
}

type SignatureMakeParams struct {
	Mode             string
	Address          *Address
	Start            *Address
	End              *Address
	Format           string
	WildcardOperands bool
	MaxLength        uint32
}

type SignatureResult struct {
	Mode       string   `json:"mode"`
	Address    Address  `json:"address"`
	EndAddress *Address `json:"endAddress"`
	Signature  string   `json:"signature"`
	Format     string   `json:"format"`
	Length     uint32   `json:"length"`
	Unique     bool     `json:"unique"`
}

type SignatureXrefsParams struct {
	Address          Address
	Format           string
	WildcardOperands bool
	MaxLength        uint32
	Top              uint32
}

type XrefSignatureItem struct {
	XrefAddress Address `json:"xrefAddress"`
	Signature   string  `json:"signature"`
	Length      uint32  `json:"length"`
}

type XrefSignatureResult struct {
	Address    Address             `json:"address"`
	Items      []XrefSignatureItem `json:"items"`
	TotalXrefs uint32              `json:"totalXrefs"`
	Truncated  bool                `json:"truncated"`
}

type StructFieldXrefParams struct {
	Type  string
	Field string
	Limit uint32
}

type StructFieldXrefResult struct {
	Items     []Address `json:"items"`
	Truncated bool      `json:"truncated"`
}
