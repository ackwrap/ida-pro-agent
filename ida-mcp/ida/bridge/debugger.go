package bridge

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"ida-mcp/ida/rpc"
)

const (
	methodDebuggerInfo        = "debugger.info"
	methodDebuggerStart       = "debugger.start"
	methodDebuggerExit        = "debugger.exit"
	methodDebuggerControl     = "debugger.control"
	methodDebuggerBreakpoints = "debugger.breakpoints"
	methodDebuggerRegisters   = "debugger.registers"
	methodDebuggerStackTrace  = "debugger.stacktrace"
	methodDebuggerMemoryRead  = "debugger.memory_read"
	methodDebuggerMemoryWrite = "debugger.memory_write"
)

type DebuggerControlParams struct {
	Action  string       `json:"action"`
	Address *rpc.Address `json:"address,omitempty"`
}

type DebuggerBreakpointsParams struct {
	Action        *string
	Address       *rpc.Address
	Enabled       *bool
	ConditionSet  bool
	ConditionNull bool
	Condition     string
	Type          *string
	Size          *uint32
	Language      *string
	LowLevel      *bool
	PassCount     *uint32
}

func (params DebuggerBreakpointsParams) MarshalJSON() ([]byte, error) {
	type wire struct {
		Action    *string         `json:"action,omitempty"`
		Address   *rpc.Address    `json:"address,omitempty"`
		Enabled   *bool           `json:"enabled,omitempty"`
		Condition json.RawMessage `json:"condition,omitempty"`
		Type      *string         `json:"type,omitempty"`
		Size      *uint32         `json:"size,omitempty"`
		Language  *string         `json:"language,omitempty"`
		LowLevel  *bool           `json:"lowLevel,omitempty"`
		PassCount *uint32         `json:"passCount,omitempty"`
	}
	var condition json.RawMessage
	if params.ConditionSet {
		if params.ConditionNull {
			condition = json.RawMessage("null")
		} else {
			encoded, err := json.Marshal(params.Condition)
			if err != nil {
				return nil, err
			}
			condition = encoded
		}
	}
	return json.Marshal(wire{params.Action, params.Address, params.Enabled, condition, params.Type, params.Size, params.Language, params.LowLevel, params.PassCount})
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
	Address rpc.Address `json:"address"`
	Length  uint32      `json:"length"`
}
type DebuggerMemoryWriteParams struct {
	Address rpc.Address `json:"address"`
	Bytes   string      `json:"bytes"`
}

type DebuggerInfo struct {
	State              string       `json:"state"`
	Running            bool         `json:"running"`
	Suspended          bool         `json:"suspended"`
	InstructionPointer *rpc.Address `json:"instructionPointer"`
	ThreadID           *int64       `json:"threadId"`
}

func (result *DebuggerInfo) UnmarshalJSON(data []byte) error {
	type wire struct {
		State              *string         `json:"state"`
		Running            *bool           `json:"running"`
		Suspended          *bool           `json:"suspended"`
		InstructionPointer json.RawMessage `json:"instructionPointer"`
		ThreadID           json.RawMessage `json:"threadId"`
	}
	var decoded wire
	if err := decodeDebuggerWire(data, &decoded); err != nil {
		return err
	}
	if decoded.State == nil || decoded.Running == nil || decoded.Suspended == nil || len(decoded.InstructionPointer) == 0 || len(decoded.ThreadID) == 0 {
		return errors.New("debugger info is missing a required field")
	}
	instructionPointer, threadID, err := decodeDebuggerLocation(decoded.InstructionPointer, decoded.ThreadID)
	if err != nil {
		return err
	}
	*result = DebuggerInfo{State: *decoded.State, Running: *decoded.Running, Suspended: *decoded.Suspended, InstructionPointer: instructionPointer, ThreadID: threadID}
	return nil
}

type DebuggerActionResult struct {
	Accepted           bool         `json:"accepted"`
	State              string       `json:"state"`
	Running            bool         `json:"running"`
	Suspended          bool         `json:"suspended"`
	InstructionPointer *rpc.Address `json:"instructionPointer"`
	ThreadID           *int64       `json:"threadId"`
}

func (result *DebuggerActionResult) UnmarshalJSON(data []byte) error {
	type wire struct {
		Accepted           *bool           `json:"accepted"`
		State              *string         `json:"state"`
		Running            *bool           `json:"running"`
		Suspended          *bool           `json:"suspended"`
		InstructionPointer json.RawMessage `json:"instructionPointer"`
		ThreadID           json.RawMessage `json:"threadId"`
	}
	var decoded wire
	if err := decodeDebuggerWire(data, &decoded); err != nil {
		return err
	}
	if decoded.Accepted == nil || decoded.State == nil || decoded.Running == nil || decoded.Suspended == nil || len(decoded.InstructionPointer) == 0 || len(decoded.ThreadID) == 0 {
		return errors.New("debugger action is missing a required field")
	}
	instructionPointer, threadID, err := decodeDebuggerLocation(decoded.InstructionPointer, decoded.ThreadID)
	if err != nil {
		return err
	}
	*result = DebuggerActionResult{Accepted: *decoded.Accepted, State: *decoded.State, Running: *decoded.Running, Suspended: *decoded.Suspended, InstructionPointer: instructionPointer, ThreadID: threadID}
	return nil
}

func decodeDebuggerWire(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return ensureJSONEnd(decoder)
}

func decodeDebuggerLocation(instructionData, threadData json.RawMessage) (*rpc.Address, *int64, error) {
	var instructionPointer *rpc.Address
	if !bytes.Equal(bytes.TrimSpace(instructionData), []byte("null")) {
		var address rpc.Address
		if err := json.Unmarshal(instructionData, &address); err != nil {
			return nil, nil, err
		}
		instructionPointer = &address
	}
	var threadID *int64
	if !bytes.Equal(bytes.TrimSpace(threadData), []byte("null")) {
		var value int64
		if err := json.Unmarshal(threadData, &value); err != nil || value <= 0 {
			return nil, nil, errors.New("debugger thread id is invalid")
		}
		threadID = &value
	}
	return instructionPointer, threadID, nil
}

type BreakpointInfo struct {
	Address           rpc.Address `json:"address"`
	Enabled           bool        `json:"enabled"`
	Type              string      `json:"type"`
	Size              uint32      `json:"size"`
	PassCount         uint32      `json:"passCount"`
	LowLevel          bool        `json:"lowLevel"`
	Condition         string      `json:"condition"`
	ConditionLanguage *string     `json:"conditionLanguage"`
	Compiled          bool        `json:"compiled"`
	Active            bool        `json:"active"`
}
type DebuggerBreakpointsResult struct {
	Items  *[]BreakpointInfo
	Action *DebuggerActionResult
}

func (result *DebuggerBreakpointsResult) UnmarshalJSON(data []byte) error {
	var list struct {
		Items *[]BreakpointInfo `json:"items"`
	}
	listDecoder := json.NewDecoder(bytes.NewReader(data))
	listDecoder.DisallowUnknownFields()
	listError := listDecoder.Decode(&list)
	if listError == nil {
		listError = ensureJSONEnd(listDecoder)
	}
	if listError == nil && list.Items != nil {
		result.Items = list.Items
		result.Action = nil
		return nil
	}
	var action DebuggerActionResult
	actionDecoder := json.NewDecoder(bytes.NewReader(data))
	actionDecoder.DisallowUnknownFields()
	if err := actionDecoder.Decode(&action); err != nil {
		return err
	}
	if err := ensureJSONEnd(actionDecoder); err != nil {
		return err
	}
	if err := action.Validate(); err != nil {
		return err
	}
	result.Items = nil
	result.Action = &action
	return nil
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
	CallAddress     rpc.Address `json:"callAddress"`
	FunctionAddress rpc.Address `json:"functionAddress"`
	FramePointer    rpc.Address `json:"framePointer"`
	FunctionKnown   bool        `json:"functionKnown"`
	Module          string      `json:"module"`
	Symbol          string      `json:"symbol"`
}
type DebuggerStackTraceResult struct {
	Items []StackTraceFrame `json:"items"`
}
type DebuggerMemoryResult struct {
	Address rpc.Address `json:"address"`
	Bytes   string      `json:"bytes"`
}

func (client *Client) DebuggerInfo(ctx context.Context, instance rpc.InstanceDescriptor) (DebuggerInfo, error) {
	result, err := callTyped[struct{}, DebuggerInfo](client, ctx, instance, methodDebuggerInfo, struct{}{})
	if err == nil {
		err = result.Validate()
	}
	return result, err
}
func (client *Client) DebuggerStart(ctx context.Context, instance rpc.InstanceDescriptor) (DebuggerActionResult, error) {
	return callDebuggerAction(client, ctx, instance, methodDebuggerStart, struct{}{})
}
func (client *Client) DebuggerExit(ctx context.Context, instance rpc.InstanceDescriptor) (DebuggerActionResult, error) {
	return callDebuggerAction(client, ctx, instance, methodDebuggerExit, struct{}{})
}
func (client *Client) DebuggerControl(ctx context.Context, instance rpc.InstanceDescriptor, params DebuggerControlParams) (DebuggerActionResult, error) {
	return callDebuggerAction(client, ctx, instance, methodDebuggerControl, params)
}
func (client *Client) DebuggerBreakpoints(ctx context.Context, instance rpc.InstanceDescriptor, params DebuggerBreakpointsParams) (DebuggerBreakpointsResult, error) {
	result, err := callTyped[DebuggerBreakpointsParams, DebuggerBreakpointsResult](client, ctx, instance, methodDebuggerBreakpoints, params)
	if err == nil {
		err = result.Validate()
	}
	return result, err
}
func (client *Client) DebuggerRegisters(ctx context.Context, instance rpc.InstanceDescriptor, params DebuggerRegistersParams) (DebuggerRegistersResult, error) {
	result, err := callTyped[DebuggerRegistersParams, DebuggerRegistersResult](client, ctx, instance, methodDebuggerRegisters, params)
	if err == nil {
		err = result.Validate()
	}
	return result, err
}
func (client *Client) DebuggerStackTrace(ctx context.Context, instance rpc.InstanceDescriptor, params DebuggerStackTraceParams) (DebuggerStackTraceResult, error) {
	result, err := callTyped[DebuggerStackTraceParams, DebuggerStackTraceResult](client, ctx, instance, methodDebuggerStackTrace, params)
	if err == nil {
		err = result.Validate()
	}
	return result, err
}
func (client *Client) DebuggerReadMemory(ctx context.Context, instance rpc.InstanceDescriptor, params DebuggerMemoryReadParams) (DebuggerMemoryResult, error) {
	result, err := callTyped[DebuggerMemoryReadParams, DebuggerMemoryResult](client, ctx, instance, methodDebuggerMemoryRead, params)
	if err == nil {
		err = result.Validate(params)
	}
	return result, err
}
func (client *Client) DebuggerWriteMemory(ctx context.Context, instance rpc.InstanceDescriptor, params DebuggerMemoryWriteParams) (DebuggerActionResult, error) {
	return callDebuggerAction(client, ctx, instance, methodDebuggerMemoryWrite, params)
}

func callDebuggerAction[Params any](
	client *Client, ctx context.Context, instance rpc.InstanceDescriptor, method rpcMethod, params Params,
) (DebuggerActionResult, error) {
	result, err := callTyped[Params, DebuggerActionResult](client, ctx, instance, method, params)
	if err == nil {
		err = result.Validate()
	}
	return result, err
}

func (result DebuggerInfo) Validate() error {
	return validateDebuggerState(result.State, result.Running, result.Suspended)
}
func (result DebuggerActionResult) Validate() error {
	return validateDebuggerState(result.State, result.Running, result.Suspended)
}

func validateDebuggerState(state string, running, suspended bool) error {
	switch state {
	case "not_running":
		if running || suspended {
			return errors.New("debugger state flags are inconsistent")
		}
	case "running":
		if !running || suspended {
			return errors.New("debugger state flags are inconsistent")
		}
	case "suspended":
		// running means executing instructions, matching IDA DSTATE_RUN.
		if running || !suspended {
			return errors.New("debugger state flags are inconsistent")
		}
	case "unknown":
		return nil
	default:
		return errors.New("debugger state is invalid")
	}
	return nil
}

func (result DebuggerBreakpointsResult) Validate() error {
	if (result.Items == nil) == (result.Action == nil) {
		return errors.New("debugger breakpoint result branch is invalid")
	}
	if result.Action != nil {
		return result.Action.Validate()
	}
	if len(*result.Items) > 1000 {
		return errors.New("debugger breakpoint result is too large")
	}
	for _, item := range *result.Items {
		if len(item.Condition) > 4096 || !utf8.ValidString(item.Condition) || (item.ConditionLanguage != nil && !utf8.ValidString(*item.ConditionLanguage)) {
			return errors.New("debugger breakpoint result is invalid")
		}
	}
	return nil
}

func (result DebuggerRegistersResult) Validate() error {
	if result.Items == nil || len(result.Items) > 1024 {
		return errors.New("debugger register result is too large")
	}
	values := 0
	for _, thread := range result.Items {
		if thread.ThreadID <= 0 || thread.Registers == nil || len(thread.Registers) > 4096 {
			return errors.New("debugger register result is invalid")
		}
		values += len(thread.Registers)
		if values > 65536 {
			return errors.New("debugger register result is too large")
		}
		for _, value := range thread.Registers {
			if value.Name == "" || len(value.Name) > 128 || !utf8.ValidString(value.Name) ||
				len(value.Value) > 4096 || !utf8.ValidString(value.Value) {
				return errors.New("debugger register value is invalid")
			}
		}
	}
	return nil
}

func (result DebuggerStackTraceResult) Validate() error {
	if result.Items == nil || len(result.Items) > 1000 {
		return errors.New("debugger stack result is too large")
	}
	for _, frame := range result.Items {
		if len(frame.Module) > 4096 || len(frame.Symbol) > 4096 ||
			!utf8.ValidString(frame.Module) || !utf8.ValidString(frame.Symbol) {
			return errors.New("debugger stack frame is invalid")
		}
	}
	return nil
}

func (result DebuggerMemoryResult) Validate(params DebuggerMemoryReadParams) error {
	decoded, err := hex.DecodeString(result.Bytes)
	if err != nil || result.Address != params.Address || len(decoded) != int(params.Length) {
		return errors.New("debugger memory result is invalid")
	}
	return nil
}
