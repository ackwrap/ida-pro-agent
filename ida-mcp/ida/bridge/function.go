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
	EntryAddress rpc.Address        `json:"entryAddress"`
	AddressRange AddressRange       `json:"addressRange"`
	Name         string             `json:"name"`
	Signature    *string            `json:"signature"`
	Flags        FunctionFlags      `json:"flags"`
	Statistics   FunctionStatistics `json:"statistics"`
}

func (client *Client) GetFunction(
	ctx context.Context,
	instance rpc.InstanceDescriptor,
	address rpc.Address,
) (FunctionInfo, error) {
	requestID, err := randomRequestID()
	if err != nil {
		return FunctionInfo{}, err
	}
	params, err := json.Marshal(struct {
		Address rpc.Address `json:"address"`
	}{Address: address})
	if err != nil {
		return FunctionInfo{}, fmt.Errorf("encode function.get params: %w", err)
	}
	request := rpc.Request{
		ProtocolVersion: rpc.ProtocolVersion,
		RequestID:       requestID,
		SessionID:       instance.InstanceID,
		Method:          "function.get",
		Params:          params,
		TimeoutMs:       int(client.callTimeout().Milliseconds()),
	}
	response, err := client.Call(ctx, instance, request)
	if err != nil {
		return FunctionInfo{}, err
	}
	if response.Error != nil {
		return FunctionInfo{}, response.Error
	}

	var result FunctionInfo
	decoder := json.NewDecoder(bytes.NewReader(response.Result))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return FunctionInfo{}, fmt.Errorf("decode function.get result: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return FunctionInfo{}, fmt.Errorf("decode function.get result: %w", err)
	}
	if err := result.Validate(); err != nil {
		return FunctionInfo{}, fmt.Errorf("invalid function.get result: %w", err)
	}
	return result, nil
}

func (info FunctionInfo) Validate() error {
	if info.AddressRange.Start >= info.AddressRange.End {
		return errors.New("function address range is empty or reversed")
	}
	if info.EntryAddress < info.AddressRange.Start || info.EntryAddress >= info.AddressRange.End {
		return errors.New("function entry is outside the aggregate address range")
	}
	if length := utf8.RuneCountInString(info.Name); length < 1 || length > 1024 {
		return errors.New("function name must contain 1 to 1024 characters")
	}
	if info.Signature != nil {
		if length := utf8.RuneCountInString(*info.Signature); length < 1 || length > 2048 {
			return errors.New("function signature must contain 1 to 2048 characters")
		}
	}
	if info.Statistics.SizeBytes == 0 {
		return errors.New("function size must be positive")
	}
	if info.Statistics.ChunkCount == 0 {
		return errors.New("function chunk count must be positive")
	}
	if info.Statistics.SizeBytes > uint64(info.AddressRange.End-info.AddressRange.Start) {
		return errors.New("function size exceeds its aggregate address range")
	}
	const maxJSONInteger = uint64(9007199254740991)
	if info.Statistics.SizeBytes > maxJSONInteger ||
		info.Statistics.InstructionCount > maxJSONInteger ||
		info.Statistics.BasicBlockCount > maxJSONInteger ||
		info.Statistics.ChunkCount > maxJSONInteger {
		return errors.New("function statistics exceed the protocol integer limit")
	}
	return nil
}
