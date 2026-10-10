package ida

type AnalysisComponentParams struct {
	Roots       []Address
	MaxDepth    uint32
	MaxNodes    uint32
	MaxEdges    uint32
	PerFunction uint32
	SharedLimit uint32
}

type ComponentGlobal struct {
	Address      Address   `json:"address"`
	Name         string    `json:"name"`
	Kind         string    `json:"kind"`
	ReferencedBy []Address `json:"referencedBy"`
}

type ComponentString struct {
	Address      Address   `json:"address"`
	Length       uint64    `json:"length"`
	Encoding     string    `json:"encoding"`
	Value        string    `json:"value"`
	Truncated    bool      `json:"truncated"`
	OriginalSize uint64    `json:"originalSize"`
	ReferencedBy []Address `json:"referencedBy"`
}

type ComponentStatistics struct {
	Internal struct {
		Functions uint64 `json:"functions"`
		Calls     uint64 `json:"calls"`
	} `json:"internal"`
	Interface struct {
		IncomingCalls uint64 `json:"incomingCalls"`
		OutgoingCalls uint64 `json:"outgoingCalls"`
	} `json:"interface"`
}

type AnalysisComponentResult struct {
	Graph         FunctionCallGraphResult `json:"graph"`
	Members       []FunctionInfo          `json:"members"`
	SharedGlobals []ComponentGlobal       `json:"sharedGlobals"`
	SharedStrings []ComponentString       `json:"sharedStrings"`
	Statistics    ComponentStatistics     `json:"statistics"`
	Truncated     bool                    `json:"truncated"`
}

type TraceDataFlowParams struct {
	Address   Address
	Direction string
	MaxDepth  uint32
	MaxNodes  uint32
	MaxEdges  uint32
}

type TraceFunction struct {
	EntryAddress Address `json:"entryAddress"`
	Name         string  `json:"name"`
	Prototype    *string `json:"prototype"`
}

type TraceString struct {
	Address      Address `json:"address"`
	Length       uint64  `json:"length"`
	Encoding     string  `json:"encoding"`
	Value        string  `json:"value"`
	Truncated    bool    `json:"truncated"`
	OriginalSize uint64  `json:"originalSize"`
}

type TraceNode struct {
	Address    Address        `json:"address"`
	Kind       string         `json:"kind"`
	Function   *TraceFunction `json:"function,omitempty"`
	String     *TraceString   `json:"string,omitempty"`
	Name       string         `json:"name,omitempty"`
	SymbolKind string         `json:"symbolKind,omitempty"`
}

type TraceDataFlowResult struct {
	Model     string      `json:"model"`
	Nodes     []TraceNode `json:"nodes"`
	Edges     []XrefInfo  `json:"edges"`
	Truncated bool        `json:"truncated"`
}
