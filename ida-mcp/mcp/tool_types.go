package mcpserver

type instancesListInput struct{}

type instanceSelectInput struct {
	InstanceID string `json:"instanceId"`
}

type instancesGetActiveInput struct{}

type instanceInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
}

type functionAddressInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
}

type functionSearchInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Name       *string `json:"name,omitempty"`
	Address    *string `json:"address,omitempty"`
	Limit      int     `json:"limit,omitempty"`
	Cursor     string  `json:"cursor,omitempty"`
}

type xrefQueryInput struct {
	InstanceID  *string `json:"instanceId,omitempty"`
	Address     string  `json:"address"`
	Direction   string  `json:"direction"`
	Category    string  `json:"category,omitempty"`
	IncludeFlow bool    `json:"includeFlow,omitempty"`
	Limit       int     `json:"limit,omitempty"`
	Cursor      string  `json:"cursor,omitempty"`
}

type memoryReadInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
	Format     string  `json:"format"`
	Length     int     `json:"length,omitempty"`
	WidthBits  int     `json:"widthBits,omitempty"`
}

type decompileInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
	Offset     uint32  `json:"offset,omitempty"`
	MaxBytes   int     `json:"maxBytes,omitempty"`
}

type capabilitiesOutput struct {
	Decompiler  bool `json:"decompiler"`
	Debugger    bool `json:"debugger"`
	UI          bool `json:"ui"`
	AddressBits int  `json:"addressBits"`
}

type instanceOutput struct {
	InstanceID   string             `json:"instanceId"`
	PID          uint32             `json:"pid"`
	IDAVersion   string             `json:"idaVersion"`
	Database     string             `json:"database"`
	InputFile    string             `json:"inputFile"`
	Processor    string             `json:"processor"`
	Bitness      int                `json:"bitness"`
	Architecture string             `json:"architecture"`
	Capabilities capabilitiesOutput `json:"capabilities"`
}

type instancesListOutput struct {
	Instances []instanceOutput `json:"instances"`
}

type instanceSelectionOutput struct {
	ActiveInstance instanceOutput `json:"activeInstance"`
}

type instancesGetActiveOutput struct {
	ActiveInstance *instanceOutput `json:"activeInstance"`
}

type addressRangeOutput struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type segmentSummaryOutput struct {
	Total      uint32 `json:"total"`
	Code       uint32 `json:"code"`
	Data       uint32 `json:"data"`
	BSS        uint32 `json:"bss"`
	Other      uint32 `json:"other"`
	Readable   uint32 `json:"readable"`
	Writable   uint32 `json:"writable"`
	Executable uint32 `json:"executable"`
}

type databaseInfoOutput struct {
	Database     string               `json:"database"`
	Processor    string               `json:"processor"`
	Architecture string               `json:"architecture"`
	AddressBits  uint32               `json:"addressBits"`
	AddressRange *addressRangeOutput  `json:"addressRange"`
	Segments     segmentSummaryOutput `json:"segments"`
}

type functionFlagsOutput struct {
	NoReturn bool `json:"noReturn"`
	Far      bool `json:"far"`
	Library  bool `json:"library"`
	Static   bool `json:"static"`
	Frame    bool `json:"frame"`
	Hidden   bool `json:"hidden"`
	Thunk    bool `json:"thunk"`
	Lumina   bool `json:"lumina"`
	Outlined bool `json:"outlined"`
}

type functionStatisticsOutput struct {
	SizeBytes        uint64 `json:"sizeBytes"`
	InstructionCount uint64 `json:"instructionCount"`
	BasicBlockCount  uint64 `json:"basicBlockCount"`
	ChunkCount       uint64 `json:"chunkCount"`
}

type functionInfoOutput struct {
	EntryAddress string                   `json:"entryAddress"`
	AddressRange addressRangeOutput       `json:"addressRange"`
	Name         string                   `json:"name"`
	Signature    *string                  `json:"signature"`
	Flags        functionFlagsOutput      `json:"flags"`
	Statistics   functionStatisticsOutput `json:"statistics"`
}

type functionSummaryOutput struct {
	EntryAddress string `json:"entryAddress"`
	Name         string `json:"name"`
}

type functionSearchOutput struct {
	Items      []functionSummaryOutput `json:"items"`
	NextCursor *string                 `json:"nextCursor"`
	HasMore    bool                    `json:"hasMore"`
}

type xrefOutput struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Type        string `json:"type"`
	Code        bool   `json:"code"`
	UserDefined bool   `json:"userDefined"`
}

type xrefQueryOutput struct {
	Items      []xrefOutput `json:"items"`
	NextCursor *string      `json:"nextCursor"`
	HasMore    bool         `json:"hasMore"`
}

type memoryReadOutput struct {
	Address    string  `json:"address"`
	Format     string  `json:"format"`
	BytesRead  uint32  `json:"bytesRead"`
	Value      string  `json:"value"`
	WidthBits  *uint32 `json:"widthBits,omitempty"`
	ByteOrder  *string `json:"byteOrder,omitempty"`
	Terminated *bool   `json:"terminated,omitempty"`
}

type decompileOutput struct {
	EntryAddress string  `json:"entryAddress"`
	Pseudocode   string  `json:"pseudocode"`
	Offset       uint32  `json:"offset"`
	ReturnedSize uint32  `json:"returnedSize"`
	OriginalSize uint32  `json:"originalSize"`
	Truncated    bool    `json:"truncated"`
	NextOffset   *uint32 `json:"nextOffset"`
}
