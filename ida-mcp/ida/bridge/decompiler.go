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
	defaultDecompilerPageBytes = 32 * 1024
	maxDecompilerPageBytes     = 64 * 1024
	maxDecompilerTextBytes     = 16 * 1024 * 1024
)

type DecompileParams struct {
	Address  rpc.Address
	Offset   uint32
	MaxBytes int
}

type DecompileResult struct {
	EntryAddress rpc.Address `json:"entryAddress"`
	Pseudocode   string      `json:"pseudocode"`
	Offset       uint32      `json:"offset"`
	ReturnedSize uint32      `json:"returnedSize"`
	OriginalSize uint32      `json:"originalSize"`
	Truncated    bool        `json:"truncated"`
	NextOffset   *uint32     `json:"nextOffset"`
}

func (result *DecompileResult) UnmarshalJSON(data []byte) error {
	type wireDecompileResult struct {
		EntryAddress *rpc.Address    `json:"entryAddress"`
		Pseudocode   *string         `json:"pseudocode"`
		Offset       *uint32         `json:"offset"`
		ReturnedSize *uint32         `json:"returnedSize"`
		OriginalSize *uint32         `json:"originalSize"`
		Truncated    *bool           `json:"truncated"`
		NextOffset   json.RawMessage `json:"nextOffset"`
	}
	var wire wireDecompileResult
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return err
	}
	if wire.EntryAddress == nil || wire.Pseudocode == nil || wire.Offset == nil ||
		wire.ReturnedSize == nil || wire.OriginalSize == nil || wire.Truncated == nil ||
		len(wire.NextOffset) == 0 {
		return errors.New("decompile result is missing a required field")
	}
	*result = DecompileResult{
		EntryAddress: *wire.EntryAddress,
		Pseudocode:   *wire.Pseudocode,
		Offset:       *wire.Offset,
		ReturnedSize: *wire.ReturnedSize,
		OriginalSize: *wire.OriginalSize,
		Truncated:    *wire.Truncated,
	}
	if !bytes.Equal(bytes.TrimSpace(wire.NextOffset), []byte("null")) {
		var nextOffset uint32
		if err := json.Unmarshal(wire.NextOffset, &nextOffset); err != nil {
			return fmt.Errorf("decode nextOffset: %w", err)
		}
		result.NextOffset = &nextOffset
	}
	return nil
}

func (client *Client) DecompileFunction(
	ctx context.Context,
	instance rpc.InstanceDescriptor,
	params DecompileParams,
) (DecompileResult, error) {
	if err := params.Validate(); err != nil {
		return DecompileResult{}, err
	}
	requestID, err := randomRequestID()
	if err != nil {
		return DecompileResult{}, err
	}
	wireParams := struct {
		Address  rpc.Address `json:"address"`
		Offset   uint32      `json:"offset,omitempty"`
		MaxBytes int         `json:"maxBytes,omitempty"`
	}{params.Address, params.Offset, params.MaxBytes}
	encodedParams, err := json.Marshal(wireParams)
	if err != nil {
		return DecompileResult{}, fmt.Errorf("encode function.decompile params: %w", err)
	}
	response, err := client.Call(ctx, instance, rpc.Request{
		ProtocolVersion: rpc.ProtocolVersion,
		RequestID:       requestID,
		SessionID:       instance.InstanceID,
		Method:          "function.decompile",
		Params:          encodedParams,
		TimeoutMs:       int(client.callTimeout().Milliseconds()),
	})
	if err != nil {
		return DecompileResult{}, err
	}
	if response.Error != nil {
		return DecompileResult{}, response.Error
	}

	var result DecompileResult
	decoder := json.NewDecoder(bytes.NewReader(response.Result))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return DecompileResult{}, fmt.Errorf("decode function.decompile result: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return DecompileResult{}, fmt.Errorf("decode function.decompile result: %w", err)
	}
	if err := result.Validate(params); err != nil {
		return DecompileResult{}, fmt.Errorf("invalid function.decompile result: %w", err)
	}
	return result, nil
}

func (params DecompileParams) Validate() error {
	if params.Offset > maxDecompilerTextBytes {
		return errors.New("decompile offset exceeds the text limit")
	}
	if params.MaxBytes < 0 || params.MaxBytes > maxDecompilerPageBytes ||
		(params.MaxBytes > 0 && params.MaxBytes < 4) {
		return errors.New("decompile maxBytes must be from 4 to 65536")
	}
	return nil
}

func (params DecompileParams) effectiveMaxBytes() int {
	if params.MaxBytes == 0 {
		return defaultDecompilerPageBytes
	}
	return params.MaxBytes
}

func (result DecompileResult) Validate(params DecompileParams) error {
	if result.Offset != params.Offset || result.Offset > result.OriginalSize ||
		result.OriginalSize > maxDecompilerTextBytes {
		return errors.New("decompile result range is invalid")
	}
	if !utf8.ValidString(result.Pseudocode) || result.ReturnedSize != uint32(len(result.Pseudocode)) ||
		result.ReturnedSize > uint32(params.effectiveMaxBytes()) {
		return errors.New("decompile result text size is invalid")
	}
	end := uint64(result.Offset) + uint64(result.ReturnedSize)
	if end > uint64(result.OriginalSize) {
		return errors.New("decompile result exceeds originalSize")
	}
	if result.Truncated {
		if result.NextOffset == nil || result.ReturnedSize == 0 ||
			*result.NextOffset != uint32(end) || *result.NextOffset >= result.OriginalSize {
			return errors.New("decompile continuation metadata is invalid")
		}
	} else if result.NextOffset != nil || end != uint64(result.OriginalSize) {
		return errors.New("complete decompile result metadata is invalid")
	}
	return nil
}
