package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"ida-mcp/ida/rpc"
)

const (
	maxFunctionAnalysisOffset = 1_000_000
	maxFunctionAnalysisLimit  = 100
	maxFunctionNextOffset     = maxFunctionAnalysisOffset + maxFunctionAnalysisLimit
)

type FunctionPageParams struct {
	Address rpc.Address
	Offset  uint32
	Limit   int
}

type DisassemblyItem struct {
	Address rpc.Address `json:"address"`
	Text    string      `json:"text"`
}

type FunctionDisassemblyResult struct {
	EntryAddress rpc.Address
	Items        []DisassemblyItem
	NextOffset   *uint32
	HasMore      bool
}

type BasicBlockType string

type FunctionBasicBlock struct {
	Start        rpc.Address    `json:"start"`
	End          rpc.Address    `json:"end"`
	Type         BasicBlockType `json:"type"`
	Successors   []rpc.Address  `json:"successors"`
	Predecessors []rpc.Address  `json:"predecessors"`
}

type FunctionBasicBlocksResult struct {
	EntryAddress rpc.Address
	Items        []FunctionBasicBlock
	NextOffset   *uint32
	HasMore      bool
}

type FunctionCallee struct {
	Address  rpc.Address `json:"address"`
	Name     string      `json:"name"`
	Internal bool        `json:"internal"`
}

type FunctionCalleesResult struct {
	EntryAddress rpc.Address
	Items        []FunctionCallee
	NextOffset   *uint32
	HasMore      bool
}

type functionPageResult[T any] struct {
	EntryAddress rpc.Address
	Items        []T
	NextOffset   *uint32
	HasMore      bool
}

type functionPageWire[T any] struct {
	EntryAddress *rpc.Address    `json:"entryAddress"`
	Items        *[]T            `json:"items"`
	NextOffset   json.RawMessage `json:"nextOffset"`
	HasMore      *bool           `json:"hasMore"`
}

func (client *Client) DisassembleFunction(
	ctx context.Context, instance rpc.InstanceDescriptor, params FunctionPageParams,
) (FunctionDisassemblyResult, error) {
	result, err := callFunctionAnalysis[DisassemblyItem](client, ctx, instance, "function.disassemble", params)
	if err != nil {
		return FunctionDisassemblyResult{}, err
	}
	if err := validateDisassembly(result.Items); err != nil {
		return FunctionDisassemblyResult{}, fmt.Errorf("invalid function.disassemble result: %w", err)
	}
	return FunctionDisassemblyResult(result), nil
}

func (client *Client) FunctionBasicBlocks(
	ctx context.Context, instance rpc.InstanceDescriptor, params FunctionPageParams,
) (FunctionBasicBlocksResult, error) {
	result, err := callFunctionAnalysis[FunctionBasicBlock](client, ctx, instance, "function.basic_blocks", params)
	if err != nil {
		return FunctionBasicBlocksResult{}, err
	}
	if err := validateBasicBlocks(result.Items); err != nil {
		return FunctionBasicBlocksResult{}, fmt.Errorf("invalid function.basic_blocks result: %w", err)
	}
	return FunctionBasicBlocksResult(result), nil
}

func (client *Client) FunctionCallees(
	ctx context.Context, instance rpc.InstanceDescriptor, params FunctionPageParams,
) (FunctionCalleesResult, error) {
	result, err := callFunctionAnalysis[FunctionCallee](client, ctx, instance, "function.callees", params)
	if err != nil {
		return FunctionCalleesResult{}, err
	}
	if err := validateCallees(result.Items); err != nil {
		return FunctionCalleesResult{}, fmt.Errorf("invalid function.callees result: %w", err)
	}
	return FunctionCalleesResult(result), nil
}

func callFunctionAnalysis[T any](
	client *Client,
	ctx context.Context,
	instance rpc.InstanceDescriptor,
	method rpcMethod,
	params FunctionPageParams,
) (functionPageResult[T], error) {
	if err := params.Validate(); err != nil {
		return functionPageResult[T]{}, err
	}
	requestID, err := randomRequestID()
	if err != nil {
		return functionPageResult[T]{}, err
	}
	wireParams := struct {
		Address rpc.Address `json:"address"`
		Offset  uint32      `json:"offset,omitempty"`
		Limit   int         `json:"limit,omitempty"`
	}{params.Address, params.Offset, params.Limit}
	encodedParams, err := json.Marshal(wireParams)
	if err != nil {
		return functionPageResult[T]{}, fmt.Errorf("encode %s params: %w", method, err)
	}
	response, err := client.Call(ctx, instance, rpc.Request{
		ProtocolVersion: rpc.ProtocolVersion,
		RequestID:       requestID,
		SessionID:       instance.InstanceID,
		Method:          string(method),
		Params:          encodedParams,
		TimeoutMs:       int(client.callTimeout().Milliseconds()),
	})
	if err != nil {
		return functionPageResult[T]{}, err
	}
	if response.Error != nil {
		return functionPageResult[T]{}, response.Error
	}
	result, err := decodeFunctionPage[T](response.Result)
	if err != nil {
		return functionPageResult[T]{}, fmt.Errorf("decode %s result: %w", method, err)
	}
	if err := validateFunctionPage(params, len(result.Items), result.NextOffset, result.HasMore); err != nil {
		return functionPageResult[T]{}, fmt.Errorf("invalid %s result: %w", method, err)
	}
	return result, nil
}

func (params FunctionPageParams) Validate() error {
	if params.Offset > maxFunctionAnalysisOffset {
		return errors.New("function analysis offset exceeds 1000000")
	}
	if params.Limit < 0 || params.Limit > maxFunctionAnalysisLimit {
		return errors.New("function analysis limit must be from 1 to 100")
	}
	return nil
}

func (params FunctionPageParams) effectiveLimit() int {
	if params.Limit == 0 {
		return 20
	}
	return params.Limit
}

func decodeFunctionPage[T any](data []byte) (functionPageResult[T], error) {
	var wire functionPageWire[T]
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return functionPageResult[T]{}, err
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return functionPageResult[T]{}, err
	}
	if wire.EntryAddress == nil || wire.Items == nil || wire.HasMore == nil || len(wire.NextOffset) == 0 {
		return functionPageResult[T]{}, errors.New("function analysis result is missing a required field")
	}
	result := functionPageResult[T]{EntryAddress: *wire.EntryAddress, Items: *wire.Items, HasMore: *wire.HasMore}
	if !bytes.Equal(bytes.TrimSpace(wire.NextOffset), []byte("null")) {
		var nextOffset uint32
		if err := json.Unmarshal(wire.NextOffset, &nextOffset); err != nil {
			return functionPageResult[T]{}, fmt.Errorf("decode nextOffset: %w", err)
		}
		result.NextOffset = &nextOffset
	}
	return result, nil
}

func validateFunctionPage(params FunctionPageParams, itemCount int, nextOffset *uint32, hasMore bool) error {
	if itemCount > params.effectiveLimit() {
		return errors.New("function analysis result exceeds the requested limit")
	}
	if hasMore != (nextOffset != nil) {
		return errors.New("function analysis pagination metadata is inconsistent")
	}
	if nextOffset != nil {
		expected := uint64(params.Offset) + uint64(itemCount)
		if itemCount == 0 || expected > maxFunctionNextOffset || uint64(*nextOffset) != expected {
			return errors.New("function analysis continuation is invalid")
		}
	}
	return nil
}

func validateDisassembly(items []DisassemblyItem) error {
	var previous rpc.Address
	for index, item := range items {
		if !utf8.ValidString(item.Text) || len(item.Text) > 4096 {
			return errors.New("disassembly text is not valid bounded UTF-8")
		}
		if index > 0 && item.Address <= previous {
			return errors.New("disassembly items are not strictly sorted")
		}
		previous = item.Address
	}
	return nil
}

func validateBasicBlocks(items []FunctionBasicBlock) error {
	validTypes := map[BasicBlockType]bool{
		"normal": true, "indirect_jump": true, "return": true, "conditional_return": true,
		"no_return": true, "external_no_return": true, "external": true, "error": true,
	}
	var previous rpc.Address
	for index, block := range items {
		if block.Start >= block.End || !validTypes[block.Type] {
			return errors.New("basic block range or type is invalid")
		}
		if block.Successors == nil || block.Predecessors == nil ||
			len(block.Successors) > 64 || len(block.Predecessors) > 64 {
			return errors.New("basic block edge list is invalid")
		}
		if index > 0 && block.Start <= previous {
			return errors.New("basic blocks are not strictly sorted")
		}
		previous = block.Start
	}
	return nil
}

func validateCallees(items []FunctionCallee) error {
	var previous rpc.Address
	for index, callee := range items {
		if !utf8.ValidString(callee.Name) {
			return errors.New("callee name is not valid UTF-8")
		}
		if length := utf8.RuneCountInString(callee.Name); length < 1 || length > 1024 {
			return errors.New("callee name must contain 1 to 1024 characters")
		}
		if index > 0 && callee.Address <= previous {
			return errors.New("callees are not strictly sorted")
		}
		previous = callee.Address
	}
	return nil
}
