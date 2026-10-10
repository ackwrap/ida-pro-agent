package bridge

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"ida-mcp/ida/rpc"
)

type MemoryFormat string

const (
	MemoryBytes   MemoryFormat = "bytes"
	MemoryString  MemoryFormat = "string"
	MemoryInteger MemoryFormat = "integer"
	MemoryPointer MemoryFormat = "pointer"
)

type MemoryReadParams struct {
	Address   rpc.Address
	Format    MemoryFormat
	Length    int
	WidthBits int
}

type MemoryReadResult struct {
	Address    rpc.Address  `json:"address"`
	Format     MemoryFormat `json:"format"`
	BytesRead  uint32       `json:"bytesRead"`
	Value      string       `json:"value"`
	WidthBits  *uint32      `json:"widthBits,omitempty"`
	ByteOrder  *string      `json:"byteOrder,omitempty"`
	Terminated *bool        `json:"terminated,omitempty"`
}

func (result *MemoryReadResult) UnmarshalJSON(data []byte) error {
	type wireMemoryReadResult struct {
		Address    *rpc.Address    `json:"address"`
		Format     *MemoryFormat   `json:"format"`
		BytesRead  *uint32         `json:"bytesRead"`
		Value      *string         `json:"value"`
		WidthBits  json.RawMessage `json:"widthBits"`
		ByteOrder  json.RawMessage `json:"byteOrder"`
		Terminated json.RawMessage `json:"terminated"`
	}
	var wire wireMemoryReadResult
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return err
	}
	if wire.Address == nil || wire.Format == nil || wire.BytesRead == nil || wire.Value == nil {
		return errors.New("memory result must contain address, format, bytesRead, and value")
	}
	*result = MemoryReadResult{
		Address:   *wire.Address,
		Format:    *wire.Format,
		BytesRead: *wire.BytesRead,
		Value:     *wire.Value,
	}
	if err := decodeOptionalResultField(wire.WidthBits, "widthBits", &result.WidthBits); err != nil {
		return err
	}
	if err := decodeOptionalResultField(wire.ByteOrder, "byteOrder", &result.ByteOrder); err != nil {
		return err
	}
	if err := decodeOptionalResultField(wire.Terminated, "terminated", &result.Terminated); err != nil {
		return err
	}
	return nil
}

func decodeOptionalResultField[T any](raw json.RawMessage, name string, target **T) error {
	if len(raw) == 0 {
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("%s must not be null", name)
	}
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("decode %s: %w", name, err)
	}
	*target = &value
	return nil
}

func (client *Client) ReadMemory(
	ctx context.Context,
	instance rpc.InstanceDescriptor,
	params MemoryReadParams,
) (MemoryReadResult, error) {
	if err := params.Validate(); err != nil {
		return MemoryReadResult{}, err
	}
	requestID, err := randomRequestID()
	if err != nil {
		return MemoryReadResult{}, err
	}
	wireParams := struct {
		Address   rpc.Address  `json:"address"`
		Format    MemoryFormat `json:"format"`
		Length    int          `json:"length,omitempty"`
		WidthBits int          `json:"widthBits,omitempty"`
	}{params.Address, params.Format, params.Length, params.WidthBits}
	encodedParams, err := json.Marshal(wireParams)
	if err != nil {
		return MemoryReadResult{}, fmt.Errorf("encode memory.read params: %w", err)
	}
	response, err := client.Call(ctx, instance, rpc.Request{
		ProtocolVersion: rpc.ProtocolVersion,
		RequestID:       requestID,
		SessionID:       instance.InstanceID,
		Method:          "memory.read",
		Params:          encodedParams,
		TimeoutMs:       int(client.callTimeout().Milliseconds()),
	})
	if err != nil {
		return MemoryReadResult{}, err
	}
	if response.Error != nil {
		return MemoryReadResult{}, response.Error
	}

	var result MemoryReadResult
	decoder := json.NewDecoder(bytes.NewReader(response.Result))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return MemoryReadResult{}, fmt.Errorf("decode memory.read result: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return MemoryReadResult{}, fmt.Errorf("decode memory.read result: %w", err)
	}
	if err := result.Validate(params, instance.Capabilities.AddressBits); err != nil {
		return MemoryReadResult{}, fmt.Errorf("invalid memory.read result: %w", err)
	}
	return result, nil
}

func (params MemoryReadParams) Validate() error {
	switch params.Format {
	case MemoryBytes, MemoryString:
		if params.Length < 1 || params.Length > 4096 || params.WidthBits != 0 {
			return errors.New("bytes and string reads require length from 1 to 4096")
		}
	case MemoryInteger:
		if params.Length != 0 || (params.WidthBits != 8 && params.WidthBits != 16 &&
			params.WidthBits != 32 && params.WidthBits != 64) {
			return errors.New("integer reads require widthBits of 8, 16, 32, or 64")
		}
	case MemoryPointer:
		if params.Length != 0 || params.WidthBits != 0 {
			return errors.New("pointer reads do not accept length or widthBits")
		}
	default:
		return errors.New("memory format is invalid")
	}
	return nil
}

func (result MemoryReadResult) Validate(params MemoryReadParams, addressBits int) error {
	if result.Address != params.Address || result.Format != params.Format {
		return errors.New("memory result does not match the request")
	}
	if result.BytesRead == 0 || result.BytesRead > 4096 || !utf8.ValidString(result.Value) {
		return errors.New("memory result value is invalid")
	}
	switch result.Format {
	case MemoryBytes:
		if result.WidthBits != nil || result.ByteOrder != nil || result.Terminated != nil {
			return errors.New("byte result contains format-specific metadata")
		}
		decoded, err := hex.DecodeString(result.Value)
		if err != nil || len(decoded) != int(result.BytesRead) || result.BytesRead != uint32(params.Length) {
			return errors.New("byte result length is inconsistent")
		}
	case MemoryString:
		if result.WidthBits != nil || result.ByteOrder != nil || result.Terminated == nil {
			return errors.New("string result metadata is invalid")
		}
		expected := len(result.Value)
		if *result.Terminated {
			expected++
		}
		if expected != int(result.BytesRead) || result.BytesRead > uint32(params.Length) {
			return errors.New("string result length is inconsistent")
		}
	case MemoryInteger, MemoryPointer:
		if result.WidthBits == nil || result.ByteOrder == nil || result.Terminated != nil {
			return errors.New("numeric result metadata is invalid")
		}
		expectedWidth := params.WidthBits
		if result.Format == MemoryPointer {
			expectedWidth = addressBits
		}
		if expectedWidth != 8 && expectedWidth != 16 && expectedWidth != 32 && expectedWidth != 64 {
			return errors.New("numeric result width is unsupported")
		}
		if int(*result.WidthBits) != expectedWidth || result.BytesRead != uint32(expectedWidth/8) ||
			(*result.ByteOrder != "little" && *result.ByteOrder != "big") {
			return errors.New("numeric result metadata is inconsistent")
		}
		value, err := rpc.ParseAddress(result.Value)
		if err != nil || (expectedWidth < 64 && uint64(value) >= uint64(1)<<expectedWidth) {
			return errors.New("numeric result value exceeds its width")
		}
	default:
		return errors.New("memory result format is invalid")
	}
	return nil
}
