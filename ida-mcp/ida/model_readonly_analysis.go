package ida

type AddressParams struct{ Address Address }
type ReadonlyPageParams struct {
	Address Address
	Offset  uint32
	Limit   uint32
}
type InstructionOperand struct {
	Index   uint32   `json:"index"`
	Type    string   `json:"type"`
	Text    string   `json:"text"`
	Value   *string  `json:"value,omitempty"`
	Address *Address `json:"address,omitempty"`
}
type InstructionResult struct {
	RequestedAddress Address               `json:"requestedAddress"`
	Address          Address               `json:"address"`
	End              Address               `json:"end"`
	Size             uint64                `json:"size"`
	Kind             string                `json:"kind"`
	Bytes            *string               `json:"bytes,omitempty"`
	Mnemonic         *string               `json:"mnemonic,omitempty"`
	Text             *string               `json:"text,omitempty"`
	Operands         *[]InstructionOperand `json:"operands,omitempty"`
}
type FunctionChunk struct {
	Start Address `json:"start"`
	End   Address `json:"end"`
	Kind  string  `json:"kind"`
}
type FunctionChunksResult struct {
	EntryAddress Address         `json:"entryAddress"`
	Items        []FunctionChunk `json:"items"`
	NextOffset   *uint32         `json:"nextOffset"`
	HasMore      bool            `json:"hasMore"`
}
type FixupItem struct {
	Source      Address `json:"source"`
	Target      Address `json:"target"`
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Relative    bool    `json:"relative"`
	External    bool    `json:"external"`
	Unused      bool    `json:"unused"`
	Created     bool    `json:"created"`
}
type AddressListParams struct {
	Start       *Address
	End         *Address
	Limit       uint32
	NextAddress *Address
}
type FixupListResult struct {
	Items       []FixupItem `json:"items"`
	NextAddress *Address    `json:"nextAddress"`
	HasMore     bool        `json:"hasMore"`
}
type SwitchCase struct {
	Values []string `json:"values"`
	Target Address  `json:"target"`
}
type SwitchFlags struct {
	Sparse      bool `json:"sparse"`
	Custom      bool `json:"custom"`
	Indirect    bool `json:"indirect"`
	Subtract    bool `json:"subtract"`
	UserDefined bool `json:"userDefined"`
}
type SwitchResult struct {
	Address       Address      `json:"address"`
	Cases         []SwitchCase `json:"cases"`
	DefaultTarget *Address     `json:"defaultTarget"`
	Flags         SwitchFlags  `json:"flags"`
	JumpTable     *Address     `json:"jumpTable"`
	CaseCount     uint32       `json:"caseCount"`
	LowCase       string       `json:"lowCase"`
	Truncated     bool         `json:"truncated"`
}
type ExceptionRange struct {
	Start Address  `json:"start"`
	End   *Address `json:"end"`
}
type ExceptionHandler struct {
	Kind         string           `json:"kind"`
	Ranges       []ExceptionRange `json:"ranges"`
	FilterRanges []ExceptionRange `json:"filterRanges,omitempty"`
	CatchAll     bool             `json:"catchAll"`
}
type TryBlock struct {
	Ranges   []ExceptionRange   `json:"ranges"`
	Kind     string             `json:"kind"`
	Level    uint32             `json:"level"`
	Handlers []ExceptionHandler `json:"handlers"`
}
type TryBlocksResult struct {
	FunctionAddress Address    `json:"functionAddress"`
	Items           []TryBlock `json:"items"`
	Truncated       bool       `json:"truncated"`
}
type AnalysisStatusResult struct {
	Queue          string   `json:"queue"`
	State          string   `json:"state"`
	Enabled        bool     `json:"enabled"`
	Complete       bool     `json:"complete"`
	CurrentAddress *Address `json:"currentAddress"`
}
type AnalysisWaitResult struct {
	AnalysisStatusResult
	TimedOut  bool   `json:"timedOut"`
	PollCount uint32 `json:"pollCount"`
	ElapsedMs uint64 `json:"elapsedMs"`
}
type AnalysisPlanParams struct {
	Start Address
	End   Address
}
type AnalysisPlanResult struct {
	Accepted bool    `json:"accepted"`
	Start    Address `json:"start"`
	End      Address `json:"end"`
	Queue    string  `json:"queue"`
}
type AnalysisProblemsParams struct {
	Type        string
	Start       *Address
	Limit       uint32
	NextAddress *Address
}
type AnalysisProblem struct {
	Address     Address `json:"address"`
	Type        string  `json:"type"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
}
type AnalysisProblemsResult struct {
	Items       []AnalysisProblem `json:"items"`
	NextAddress *Address          `json:"nextAddress"`
	HasMore     bool              `json:"hasMore"`
}
