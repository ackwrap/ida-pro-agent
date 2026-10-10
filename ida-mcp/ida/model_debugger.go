package ida

import (
	"bytes"
	"encoding/json"
	"errors"
	"unicode/utf8"
)

type NullableString struct {
	Present bool
	Null    bool
	Value   string
}

func (value *NullableString) UnmarshalJSON(data []byte) error {
	value.Present = true
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		value.Null = true
		value.Value = ""
		return nil
	}
	value.Null = false
	return json.Unmarshal(data, &value.Value)
}

func (value NullableString) MarshalJSON() ([]byte, error) {
	if value.Null {
		return []byte("null"), nil
	}
	return json.Marshal(value.Value)
}

func (value NullableString) IsZero() bool { return !value.Present }

type DebuggerControlParams struct {
	Action  string   `json:"action"`
	Address *Address `json:"address,omitempty"`
}

type DebuggerBreakpointsParams struct {
	Action    *string        `json:"action,omitempty"`
	Address   *Address       `json:"address,omitempty"`
	Enabled   *bool          `json:"enabled,omitempty"`
	Condition NullableString `json:"condition,omitempty"`
	Type      *string        `json:"type,omitempty"`
	Size      *uint32        `json:"size,omitempty"`
	Language  *string        `json:"language,omitempty"`
	LowLevel  *bool          `json:"lowLevel,omitempty"`
	PassCount *uint32        `json:"passCount,omitempty"`
}

type DebuggerRegistersParams struct {
	ThreadMode   *string  `json:"threadMode,omitempty"`
	ThreadIDs    []int64  `json:"threadIds,omitempty"`
	RegisterMode *string  `json:"registerMode,omitempty"`
	Names        []string `json:"names,omitempty"`
}

type DebuggerStackTraceParams struct {
	ThreadID *int64  `json:"threadId,omitempty"`
	Limit    *uint32 `json:"limit,omitempty"`
}

type DebuggerMemoryReadParams struct {
	Address Address `json:"address"`
	Length  uint32  `json:"length"`
}

type DebuggerMemoryWriteParams struct {
	Address Address `json:"address"`
	Bytes   string  `json:"bytes"`
}

type DebuggerInfo struct {
	State              string   `json:"state"`
	Running            bool     `json:"running"`
	Suspended          bool     `json:"suspended"`
	InstructionPointer *Address `json:"instructionPointer"`
	ThreadID           *int64   `json:"threadId"`
}

type DebuggerActionResult struct {
	Accepted           bool     `json:"accepted"`
	State              string   `json:"state"`
	Running            bool     `json:"running"`
	Suspended          bool     `json:"suspended"`
	InstructionPointer *Address `json:"instructionPointer"`
	ThreadID           *int64   `json:"threadId"`
}

type BreakpointInfo struct {
	Address           Address `json:"address"`
	Enabled           bool    `json:"enabled"`
	Type              string  `json:"type"`
	Size              uint32  `json:"size"`
	PassCount         uint32  `json:"passCount"`
	LowLevel          bool    `json:"lowLevel"`
	Condition         string  `json:"condition"`
	ConditionLanguage *string `json:"conditionLanguage"`
	Compiled          bool    `json:"compiled"`
	Active            bool    `json:"active"`
}

type DebuggerBreakpointsResult struct {
	Items  *[]BreakpointInfo     `json:"-"`
	Action *DebuggerActionResult `json:"-"`
}

func (result DebuggerBreakpointsResult) MarshalJSON() ([]byte, error) {
	if result.Items != nil && result.Action == nil {
		return json.Marshal(struct {
			Items []BreakpointInfo `json:"items"`
		}{Items: *result.Items})
	}
	if result.Action != nil && result.Items == nil {
		return json.Marshal(result.Action)
	}
	return nil, errors.New("debugger breakpoint result is invalid")
}

type RegisterValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ThreadRegisters struct {
	ThreadID  int64           `json:"threadId"`
	Registers []RegisterValue `json:"registers"`
}

type DebuggerRegistersResult struct {
	Items []ThreadRegisters `json:"items"`
}

type StackTraceFrame struct {
	CallAddress     Address `json:"callAddress"`
	FunctionAddress Address `json:"functionAddress"`
	FramePointer    Address `json:"framePointer"`
	FunctionKnown   bool    `json:"functionKnown"`
	Module          string  `json:"module"`
	Symbol          string  `json:"symbol"`
}

type DebuggerStackTraceResult struct {
	Items []StackTraceFrame `json:"items"`
}

type DebuggerMemoryResult struct {
	Address Address `json:"address"`
	Bytes   string  `json:"bytes"`
}

func (params DebuggerControlParams) Validate() error {
	valid := params.Action == "continue" || params.Action == "step_into" || params.Action == "step_over" ||
		params.Action == "step_until_return" || params.Action == "run_to"
	if !valid || (params.Action == "run_to") != (params.Address != nil) {
		return errors.New("debugger control action is invalid")
	}
	return nil
}

func (params DebuggerBreakpointsParams) Validate() error {
	if params.Action == nil {
		if params.Address != nil || params.Enabled != nil || params.Condition.Present || params.Type != nil || params.Size != nil || params.Language != nil || params.LowLevel != nil || params.PassCount != nil {
			return errors.New("breakpoint list parameters are invalid")
		}
		return nil
	}
	if *params.Action != "add" && *params.Action != "delete" && *params.Action != "toggle" && *params.Action != "condition" {
		return errors.New("breakpoint action is invalid")
	}
	if params.Address == nil || (params.Size != nil && *params.Size > 8) {
		return errors.New("breakpoint parameters are invalid")
	}
	if params.Condition.Present && !params.Condition.Null && (len(params.Condition.Value) > 4096 || !utf8.ValidString(params.Condition.Value)) {
		return errors.New("breakpoint condition is invalid")
	}
	if params.Type != nil && *params.Type != "software" && *params.Type != "hardware" {
		return errors.New("breakpoint type is invalid")
	}
	if params.Language != nil && (*params.Language == "" || len(*params.Language) > 128 || !utf8.ValidString(*params.Language)) {
		return errors.New("breakpoint language is invalid")
	}
	mutationFields := params.Enabled != nil || params.Condition.Present || params.Type != nil || params.Size != nil ||
		params.Language != nil || params.LowLevel != nil || params.PassCount != nil
	switch *params.Action {
	case "add":
		typeName := "software"
		if params.Type != nil {
			typeName = *params.Type
		}
		if params.Size != nil && (typeName == "hardware" && *params.Size != 1 && *params.Size != 2 && *params.Size != 4 && *params.Size != 8 ||
			typeName == "software" && *params.Size > 1) {
			return errors.New("breakpoint size is invalid for its type")
		}
	case "delete":
		if mutationFields {
			return errors.New("breakpoint delete does not accept mutation fields")
		}
	case "toggle":
		if params.Enabled == nil || params.Condition.Present || params.Type != nil || params.Size != nil ||
			params.Language != nil || params.LowLevel != nil || params.PassCount != nil {
			return errors.New("breakpoint toggle requires only enabled")
		}
	case "condition":
		if params.Enabled != nil || params.Type != nil || params.Size != nil ||
			(!params.Condition.Present && params.Language == nil && params.LowLevel == nil && params.PassCount == nil) {
			return errors.New("breakpoint condition parameters are invalid")
		}
	}
	return nil
}

func (params DebuggerRegistersParams) Validate() error {
	if len(params.ThreadIDs) > 256 || len(params.Names) > 256 {
		return errors.New("debugger register selection is too large")
	}
	seenThreads := make(map[int64]struct{}, len(params.ThreadIDs))
	for _, id := range params.ThreadIDs {
		if id <= 0 {
			return errors.New("debugger thread id is invalid")
		}
		if _, duplicate := seenThreads[id]; duplicate {
			return errors.New("debugger thread ids contain a duplicate")
		}
		seenThreads[id] = struct{}{}
	}
	seenNames := make(map[string]struct{}, len(params.Names))
	for _, name := range params.Names {
		if name == "" || len(name) > 128 || !utf8.ValidString(name) {
			return errors.New("debugger register name is invalid")
		}
		if _, duplicate := seenNames[name]; duplicate {
			return errors.New("debugger register names contain a duplicate")
		}
		seenNames[name] = struct{}{}
	}
	threadMode := "current"
	if len(params.ThreadIDs) != 0 {
		threadMode = "specified"
	}
	if params.ThreadMode != nil {
		threadMode = *params.ThreadMode
	}
	registerMode := "all"
	if len(params.Names) != 0 {
		registerMode = "named"
	}
	if params.RegisterMode != nil {
		registerMode = *params.RegisterMode
	}
	if (threadMode != "current" && threadMode != "specified" && threadMode != "all") ||
		(threadMode == "specified") != (len(params.ThreadIDs) != 0) ||
		(registerMode != "all" && registerMode != "named" && registerMode != "general-purpose") ||
		(registerMode == "named") != (len(params.Names) != 0) {
		return errors.New("debugger register selection is inconsistent")
	}
	return nil
}

func (params DebuggerStackTraceParams) Validate() error {
	if params.ThreadID != nil && *params.ThreadID <= 0 {
		return errors.New("debugger thread id is invalid")
	}
	if params.Limit != nil && (*params.Limit == 0 || *params.Limit > 1000) {
		return errors.New("debugger stack limit is invalid")
	}
	return nil
}

func (params DebuggerMemoryReadParams) Validate() error {
	if params.Length == 0 || params.Length > 65536 {
		return errors.New("debugger memory length is invalid")
	}
	return nil
}

func (params DebuggerMemoryWriteParams) Validate() error {
	if len(params.Bytes) == 0 || len(params.Bytes) > 131072 || len(params.Bytes)%2 != 0 {
		return errors.New("debugger memory bytes are invalid")
	}
	for _, character := range params.Bytes {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return errors.New("debugger memory bytes are invalid")
		}
	}
	return nil
}
