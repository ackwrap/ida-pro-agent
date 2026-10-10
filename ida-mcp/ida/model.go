package ida

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type Address uint64

func ParseAddress(value string) (Address, error) {
	if !strings.HasPrefix(value, "0x") {
		return 0, fmt.Errorf("address must start with 0x")
	}
	digits := value[2:]
	if len(digits) == 0 || len(digits) > 16 {
		return 0, fmt.Errorf("address must contain 1 to 16 hexadecimal digits")
	}
	parsed, err := strconv.ParseUint(digits, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("address is invalid")
	}
	return Address(parsed), nil
}

func (address Address) String() string {
	return fmt.Sprintf("0x%x", uint64(address))
}

func (address Address) MarshalJSON() ([]byte, error) {
	return json.Marshal(address.String())
}

func (address *Address) UnmarshalJSON(data []byte) error {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return fmt.Errorf("address must be a string")
	}
	parsed, err := ParseAddress(encoded)
	if err != nil {
		return err
	}
	*address = parsed
	return nil
}

type Capabilities struct {
	Decompiler  bool `json:"decompiler"`
	Debugger    bool `json:"debugger"`
	UI          bool `json:"ui"`
	AddressBits int  `json:"addressBits"`
}

type Instance struct {
	InstanceID   string       `json:"instanceId"`
	PID          uint32       `json:"pid"`
	IDAVersion   string       `json:"idaVersion"`
	Database     string       `json:"database"`
	InputFile    string       `json:"inputFile"`
	Processor    string       `json:"processor"`
	Bitness      int          `json:"bitness"`
	Architecture string       `json:"architecture"`
	Capabilities Capabilities `json:"capabilities"`
}

type AddressRange struct {
	Start Address `json:"start"`
	End   Address `json:"end"`
}

type SegmentSummary struct {
	Total      uint32 `json:"total"`
	Code       uint32 `json:"code"`
	Data       uint32 `json:"data"`
	BSS        uint32 `json:"bss"`
	Other      uint32 `json:"other"`
	Readable   uint32 `json:"readable"`
	Writable   uint32 `json:"writable"`
	Executable uint32 `json:"executable"`
}

type DatabaseInfo struct {
	Database     string         `json:"database"`
	Processor    string         `json:"processor"`
	Architecture string         `json:"architecture"`
	AddressBits  uint32         `json:"addressBits"`
	AddressRange *AddressRange  `json:"addressRange"`
	Segments     SegmentSummary `json:"segments"`
}

type FunctionFlags struct {
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

type FunctionStatistics struct {
	SizeBytes        uint64 `json:"sizeBytes"`
	InstructionCount uint64 `json:"instructionCount"`
	BasicBlockCount  uint64 `json:"basicBlockCount"`
	ChunkCount       uint64 `json:"chunkCount"`
}

type FunctionInfo struct {
	EntryAddress Address            `json:"entryAddress"`
	AddressRange AddressRange       `json:"addressRange"`
	Name         string             `json:"name"`
	Signature    *string            `json:"signature"`
	Flags        FunctionFlags      `json:"flags"`
	Statistics   FunctionStatistics `json:"statistics"`
}

type FunctionSearchParams struct {
	Name    *string
	Address *Address
	Limit   int
	Cursor  string
}

type FunctionSummary struct {
	EntryAddress Address `json:"entryAddress"`
	Name         string  `json:"name"`
}

type FunctionSearchResult struct {
	Items      []FunctionSummary `json:"items"`
	NextCursor *string           `json:"nextCursor"`
	HasMore    bool              `json:"hasMore"`
}

type XrefDirection string

const (
	XrefIncoming XrefDirection = "incoming"
	XrefOutgoing XrefDirection = "outgoing"
)

type XrefCategory string

const (
	XrefAll  XrefCategory = "all"
	XrefCode XrefCategory = "code"
	XrefData XrefCategory = "data"
)

type XrefQueryParams struct {
	Address     Address
	Direction   XrefDirection
	Category    XrefCategory
	IncludeFlow bool
	Limit       int
	Cursor      string
}

type XrefInfo struct {
	From        Address `json:"from"`
	To          Address `json:"to"`
	Type        string  `json:"type"`
	Code        bool    `json:"code"`
	UserDefined bool    `json:"userDefined"`
}

type XrefQueryResult struct {
	Items      []XrefInfo `json:"items"`
	NextCursor *string    `json:"nextCursor"`
	HasMore    bool       `json:"hasMore"`
}

type MemoryFormat string

const (
	MemoryBytes   MemoryFormat = "bytes"
	MemoryString  MemoryFormat = "string"
	MemoryInteger MemoryFormat = "integer"
	MemoryPointer MemoryFormat = "pointer"
)

type MemoryReadParams struct {
	Address   Address
	Format    MemoryFormat
	Length    int
	WidthBits int
}

type MemoryReadResult struct {
	Address    Address      `json:"address"`
	Format     MemoryFormat `json:"format"`
	BytesRead  uint32       `json:"bytesRead"`
	Value      string       `json:"value"`
	WidthBits  *uint32      `json:"widthBits,omitempty"`
	ByteOrder  *string      `json:"byteOrder,omitempty"`
	Terminated *bool        `json:"terminated,omitempty"`
}

type DecompileParams struct {
	Address  Address
	Offset   uint32
	MaxBytes int
}

type DecompileResult struct {
	EntryAddress Address `json:"entryAddress"`
	Pseudocode   string  `json:"pseudocode"`
	Offset       uint32  `json:"offset"`
	ReturnedSize uint32  `json:"returnedSize"`
	OriginalSize uint32  `json:"originalSize"`
	Truncated    bool    `json:"truncated"`
	NextOffset   *uint32 `json:"nextOffset"`
}
