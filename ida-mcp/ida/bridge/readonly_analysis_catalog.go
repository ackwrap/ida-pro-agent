package bridge

import (
	"context"
	"errors"
	"unicode/utf8"

	"ida-mcp/ida/rpc"
)

const (
	methodInstructionGet     rpcMethod = "instruction.get"
	methodFunctionChunks     rpcMethod = "function.chunks"
	methodFixupGet           rpcMethod = "fixup.get"
	methodFixupList          rpcMethod = "fixup.list"
	methodSwitchGet          rpcMethod = "switch.get"
	methodExceptionTryBlocks rpcMethod = "exception.try_blocks"
	methodAnalysisStatus     rpcMethod = "analysis.status"
	methodAnalysisPlan       rpcMethod = "analysis.plan"
	methodAnalysisProblems   rpcMethod = "analysis.problems"
)

type AddressParams struct {
	Address rpc.Address `json:"address"`
}

type ReadonlyPageParams struct {
	Address rpc.Address `json:"address"`
	Offset  uint32      `json:"offset,omitempty"`
	Limit   uint32      `json:"limit,omitempty"`
}

type InstructionOperand struct {
	Index   uint32       `json:"index"`
	Type    string       `json:"type"`
	Text    string       `json:"text"`
	Value   *string      `json:"value,omitempty"`
	Address *rpc.Address `json:"address,omitempty"`
}

type InstructionResult struct {
	RequestedAddress rpc.Address           `json:"requestedAddress"`
	Address          rpc.Address           `json:"address"`
	End              rpc.Address           `json:"end"`
	Size             uint64                `json:"size"`
	Kind             string                `json:"kind"`
	Bytes            *string               `json:"bytes,omitempty"`
	Mnemonic         *string               `json:"mnemonic,omitempty"`
	Text             *string               `json:"text,omitempty"`
	Operands         *[]InstructionOperand `json:"operands,omitempty"`
}

type FunctionChunk struct {
	Start rpc.Address `json:"start"`
	End   rpc.Address `json:"end"`
	Kind  string      `json:"kind"`
}

type FunctionChunksResult struct {
	EntryAddress rpc.Address     `json:"entryAddress"`
	Items        []FunctionChunk `json:"items"`
	NextOffset   *uint32         `json:"nextOffset"`
	HasMore      bool            `json:"hasMore"`
}

type FixupItem struct {
	Source      rpc.Address `json:"source"`
	Target      rpc.Address `json:"target"`
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Relative    bool        `json:"relative"`
	External    bool        `json:"external"`
	Unused      bool        `json:"unused"`
	Created     bool        `json:"created"`
}

type AddressListParams struct {
	Start       *rpc.Address `json:"start,omitempty"`
	End         *rpc.Address `json:"end,omitempty"`
	Limit       uint32       `json:"limit,omitempty"`
	NextAddress *rpc.Address `json:"nextAddress,omitempty"`
}

type FixupListResult struct {
	Items       []FixupItem  `json:"items"`
	NextAddress *rpc.Address `json:"nextAddress"`
	HasMore     bool         `json:"hasMore"`
}

type SwitchCase struct {
	Values []string    `json:"values"`
	Target rpc.Address `json:"target"`
}

type SwitchFlags struct {
	Sparse      bool `json:"sparse"`
	Custom      bool `json:"custom"`
	Indirect    bool `json:"indirect"`
	Subtract    bool `json:"subtract"`
	UserDefined bool `json:"userDefined"`
}

type SwitchResult struct {
	Address       rpc.Address  `json:"address"`
	Cases         []SwitchCase `json:"cases"`
	DefaultTarget *rpc.Address `json:"defaultTarget"`
	Flags         SwitchFlags  `json:"flags"`
	JumpTable     *rpc.Address `json:"jumpTable"`
	CaseCount     uint32       `json:"caseCount"`
	LowCase       string       `json:"lowCase"`
	Truncated     bool         `json:"truncated"`
}

type ExceptionRange struct {
	Start rpc.Address  `json:"start"`
	End   *rpc.Address `json:"end"`
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
	FunctionAddress rpc.Address `json:"functionAddress"`
	Items           []TryBlock  `json:"items"`
	Truncated       bool        `json:"truncated"`
}

type AnalysisStatusResult struct {
	Queue          string       `json:"queue"`
	State          string       `json:"state"`
	Enabled        bool         `json:"enabled"`
	Complete       bool         `json:"complete"`
	CurrentAddress *rpc.Address `json:"currentAddress"`
}
type AnalysisPlanParams struct {
	Start   rpc.Address `json:"start"`
	End     rpc.Address `json:"end"`
	Confirm bool        `json:"confirm"`
}
type AnalysisPlanResult struct {
	Accepted bool        `json:"accepted"`
	Start    rpc.Address `json:"start"`
	End      rpc.Address `json:"end"`
	Queue    string      `json:"queue"`
}

type AnalysisProblemsParams struct {
	Type        string       `json:"type"`
	Start       *rpc.Address `json:"start,omitempty"`
	Limit       uint32       `json:"limit,omitempty"`
	NextAddress *rpc.Address `json:"nextAddress,omitempty"`
}

type AnalysisProblem struct {
	Address     rpc.Address `json:"address"`
	Type        string      `json:"type"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
}

type AnalysisProblemsResult struct {
	Items       []AnalysisProblem `json:"items"`
	NextAddress *rpc.Address      `json:"nextAddress"`
	HasMore     bool              `json:"hasMore"`
}

func (client *Client) InstructionGet(ctx context.Context, instance rpc.InstanceDescriptor, params AddressParams) (InstructionResult, error) {
	result, err := callTyped[AddressParams, InstructionResult](client, ctx, instance, methodInstructionGet, params)
	if err == nil {
		err = validateInstruction(result)
	}
	return result, err
}

func (client *Client) FunctionChunks(ctx context.Context, instance rpc.InstanceDescriptor, params ReadonlyPageParams) (FunctionChunksResult, error) {
	if err := validateReadonlyPage(params); err != nil {
		return FunctionChunksResult{}, err
	}
	result, err := callTyped[ReadonlyPageParams, FunctionChunksResult](client, ctx, instance, methodFunctionChunks, params)
	if err == nil {
		err = validateFunctionChunks(params, result)
	}
	return result, err
}

func (client *Client) FixupGet(ctx context.Context, instance rpc.InstanceDescriptor, params AddressParams) (FixupItem, error) {
	result, err := callTyped[AddressParams, FixupItem](client, ctx, instance, methodFixupGet, params)
	if err == nil {
		err = validateFixup(result)
	}
	return result, err
}

func (client *Client) FixupList(ctx context.Context, instance rpc.InstanceDescriptor, params AddressListParams) (FixupListResult, error) {
	if err := validateAddressListParams(params, true); err != nil {
		return FixupListResult{}, err
	}
	result, err := callTyped[AddressListParams, FixupListResult](client, ctx, instance, methodFixupList, params)
	if err == nil {
		err = validateAddressPage(len(result.Items), params.effectiveLimit(), result.NextAddress, result.HasMore)
		for _, item := range result.Items {
			if err == nil {
				err = validateFixup(item)
			}
		}
	}
	return result, err
}

func (client *Client) SwitchGet(ctx context.Context, instance rpc.InstanceDescriptor, params AddressParams) (SwitchResult, error) {
	result, err := callTyped[AddressParams, SwitchResult](client, ctx, instance, methodSwitchGet, params)
	if err == nil {
		err = validateSwitch(result)
	}
	return result, err
}

func (client *Client) ExceptionTryBlocks(ctx context.Context, instance rpc.InstanceDescriptor, params ReadonlyPageParams) (TryBlocksResult, error) {
	if params.Offset != 0 {
		return TryBlocksResult{}, errors.New("exception.try_blocks does not accept offset")
	}
	if err := validateReadonlyPage(params); err != nil {
		return TryBlocksResult{}, err
	}
	result, err := callTyped[ReadonlyPageParams, TryBlocksResult](client, ctx, instance, methodExceptionTryBlocks, params)
	if err == nil {
		err = validateTryBlocks(params.effectiveLimit(), result)
	}
	return result, err
}

func (client *Client) AnalysisStatus(ctx context.Context, instance rpc.InstanceDescriptor) (AnalysisStatusResult, error) {
	result, err := callTyped[struct{}, AnalysisStatusResult](client, ctx, instance, methodAnalysisStatus, struct{}{})
	if err == nil {
		err = validateAnalysisStatus(result)
	}
	return result, err
}
func (client *Client) AnalysisPlan(ctx context.Context, instance rpc.InstanceDescriptor, params AnalysisPlanParams) (AnalysisPlanResult, error) {
	if !params.Confirm || params.Start >= params.End || uint64(params.End-params.Start) > 16*1024*1024 {
		return AnalysisPlanResult{}, errors.New("analysis.plan parameters are invalid")
	}
	result, err := callTyped[AnalysisPlanParams, AnalysisPlanResult](client, ctx, instance, methodAnalysisPlan, params)
	if err == nil && (!result.Accepted || result.Start != params.Start || result.End != params.End || result.Queue != "used") {
		err = errors.New("analysis.plan result is invalid")
	}
	return result, err
}

func (client *Client) AnalysisProblems(ctx context.Context, instance rpc.InstanceDescriptor, params AnalysisProblemsParams) (AnalysisProblemsResult, error) {
	if err := validateProblemsParams(params); err != nil {
		return AnalysisProblemsResult{}, err
	}
	result, err := callTyped[AnalysisProblemsParams, AnalysisProblemsResult](client, ctx, instance, methodAnalysisProblems, params)
	if err == nil {
		err = validateAddressPage(len(result.Items), params.effectiveLimit(), result.NextAddress, result.HasMore)
		for _, item := range result.Items {
			if err == nil && (item.Type != params.Type || !boundedUTF8(item.Name, 1, 1024) || !boundedUTF8(item.Description, 0, 4096)) {
				err = errors.New("analysis.problems item is invalid")
			}
		}
	}
	return result, err
}

func (params ReadonlyPageParams) effectiveLimit() uint32 {
	if params.Limit == 0 {
		return 20
	}
	return params.Limit
}
func (params AddressListParams) effectiveLimit() uint32 {
	if params.Limit == 0 {
		return 20
	}
	return params.Limit
}
func (params AnalysisProblemsParams) effectiveLimit() uint32 {
	if params.Limit == 0 {
		return 20
	}
	return params.Limit
}

func validateReadonlyPage(params ReadonlyPageParams) error {
	if params.Offset > 1_000_000 || params.Limit > 100 {
		return errors.New("readonly page parameters are invalid")
	}
	return nil
}
func validateAddressListParams(params AddressListParams, paired bool) error {
	if params.Limit > 100 || paired && ((params.Start == nil) != (params.End == nil)) {
		return errors.New("address list parameters are invalid")
	}
	if params.Start != nil && (*params.Start >= *params.End || params.NextAddress != nil && (*params.NextAddress < *params.Start || *params.NextAddress >= *params.End)) {
		return errors.New("address list range is invalid")
	}
	return nil
}
func validateProblemsParams(params AnalysisProblemsParams) error {
	if !validProblemType(params.Type) || params.Limit > 100 || params.Start != nil && params.NextAddress != nil && *params.NextAddress < *params.Start {
		return errors.New("analysis.problems parameters are invalid")
	}
	return nil
}
func validateAddressPage(count int, limit uint32, next *rpc.Address, more bool) error {
	if count > int(limit) || more != (next != nil) || more && count == 0 {
		return errors.New("address continuation is inconsistent")
	}
	return nil
}
func validateInstruction(result InstructionResult) error {
	if result.End <= result.Address || result.RequestedAddress < result.Address || result.RequestedAddress >= result.End || result.Size == 0 || result.Size > 4096 || uint64(result.End-result.Address) != result.Size {
		return errors.New("instruction item range is invalid")
	}
	if result.Kind == "code" {
		if result.Bytes == nil || result.Mnemonic == nil || result.Text == nil || result.Operands == nil || len(*result.Operands) > 8 || !boundedUTF8(*result.Mnemonic, 1, 128) || !boundedUTF8(*result.Text, 0, 4096) || len(*result.Bytes) != int(result.Size)*2 || !lowerHex(*result.Bytes) {
			return errors.New("decoded instruction is invalid")
		}
		for index, operand := range *result.Operands {
			if operand.Index != uint32(index) || !boundedUTF8(operand.Text, 0, 1024) || !validOperandType(operand.Type) {
				return errors.New("instruction operand is invalid")
			}
		}
	} else if result.Kind != "data" && result.Kind != "unknown" || result.Bytes != nil || result.Mnemonic != nil || result.Text != nil || result.Operands != nil {
		return errors.New("non-code item contains decoded instruction fields")
	}
	return nil
}
func validateFunctionChunks(params ReadonlyPageParams, result FunctionChunksResult) error {
	if len(result.Items) > int(params.effectiveLimit()) || result.HasMore != (result.NextOffset != nil) {
		return errors.New("function.chunks pagination is invalid")
	}
	if result.NextOffset != nil && (len(result.Items) == 0 || *result.NextOffset != params.Offset+uint32(len(result.Items))) {
		return errors.New("function.chunks continuation is invalid")
	}
	for index, item := range result.Items {
		if item.Start >= item.End || item.Kind != "entry" && item.Kind != "tail" || index > 0 && item.Start <= result.Items[index-1].Start {
			return errors.New("function chunk is invalid")
		}
	}
	return nil
}
func validateFixup(item FixupItem) error {
	if !validFixupType(item.Type) || !boundedUTF8(item.Description, 0, 4096) {
		return errors.New("fixup result is invalid")
	}
	return nil
}
func validateSwitch(result SwitchResult) error {
	if result.Truncated || len(result.Cases) > 4096 || result.CaseCount > 4096 {
		return errors.New("switch result is invalid")
	}
	values := 0
	for _, item := range result.Cases {
		if item.Values == nil || len(item.Values) > 4096 {
			return errors.New("switch case is invalid")
		}
		values += len(item.Values)
		for _, value := range item.Values {
			if !decimalInteger(value) {
				return errors.New("switch case value is invalid")
			}
		}
	}
	if uint32(values) != result.CaseCount || !decimalInteger(result.LowCase) {
		return errors.New("switch case count is invalid")
	}
	return nil
}
func validateTryBlocks(limit uint32, result TryBlocksResult) error {
	if len(result.Items) > int(limit) {
		return errors.New("exception.try_blocks exceeds limit")
	}
	for _, block := range result.Items {
		if block.Kind != "cpp" && block.Kind != "seh" || block.Ranges == nil || block.Handlers == nil || len(block.Ranges) > 64 || len(block.Handlers) > 64 {
			return errors.New("try block is invalid")
		}
	}
	return nil
}
func validateAnalysisStatus(result AnalysisStatusResult) error {
	queues := map[string]bool{"none": true, "unknown": true, "code": true, "weak_code": true, "procedure": true, "tail": true, "function_chunk": true, "reanalyze": true, "reanalyze_second_pass": true, "type": true, "signature": true, "signature_second_pass": true, "signature_third_pass": true, "signature_load": true, "final": true, "other": true}
	states := map[string]bool{"ready": true, "thinking": true, "waiting": true, "busy": true, "other": true}
	if !queues[result.Queue] || !states[result.State] {
		return errors.New("analysis.status result is invalid")
	}
	return nil
}
func boundedUTF8(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) >= minimum && utf8.RuneCountInString(value) <= maximum
}
func lowerHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}
func decimalInteger(value string) bool {
	if value == "" {
		return false
	}
	start := 0
	if value[0] == '-' {
		if len(value) == 1 {
			return false
		}
		start = 1
	}
	for _, character := range value[start:] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}
func validOperandType(value string) bool {
	for _, candidate := range []string{"register", "memory", "phrase", "displacement", "immediate", "far_address", "near_address", "processor_specific"} {
		if value == candidate {
			return true
		}
	}
	return false
}
func validFixupType(value string) bool {
	for _, candidate := range []string{"offset8", "offset16", "segment16", "pointer16", "offset32", "pointer32", "high8", "high16", "low8", "low16", "offset64", "signed_offset8", "signed_offset16", "signed_offset32", "custom", "other"} {
		if value == candidate {
			return true
		}
	}
	return false
}
func validProblemType(value string) bool {
	for _, candidate := range []string{"no_base", "no_name", "no_forced_operand", "no_comment", "no_xrefs", "jump_table", "disassembly", "head", "illegal_address", "many_lines", "bad_stack", "attention", "final_decision", "rolled_back", "flair_collision", "flair_indecision"} {
		if value == candidate {
			return true
		}
	}
	return false
}
