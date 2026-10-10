package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"ida-mcp/ida/rpc"
)

type AddressRange struct {
	Start rpc.Address `json:"start"`
	End   rpc.Address `json:"end"`
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

func (client *Client) DatabaseInfo(
	ctx context.Context,
	instance rpc.InstanceDescriptor,
) (DatabaseInfo, error) {
	requestID, err := randomRequestID()
	if err != nil {
		return DatabaseInfo{}, err
	}
	request := rpc.Request{
		ProtocolVersion: rpc.ProtocolVersion,
		RequestID:       requestID,
		SessionID:       instance.InstanceID,
		Method:          "database.info",
		Params:          json.RawMessage(`{}`),
		TimeoutMs:       int(client.callTimeout().Milliseconds()),
	}
	response, err := client.Call(ctx, instance, request)
	if err != nil {
		return DatabaseInfo{}, err
	}
	if response.Error != nil {
		return DatabaseInfo{}, response.Error
	}

	var result DatabaseInfo
	decoder := json.NewDecoder(bytes.NewReader(response.Result))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return DatabaseInfo{}, fmt.Errorf("decode database.info result: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return DatabaseInfo{}, fmt.Errorf("decode database.info result: %w", err)
	}
	if err := result.Validate(); err != nil {
		return DatabaseInfo{}, fmt.Errorf("invalid database.info result: %w", err)
	}
	return result, nil
}

func (info DatabaseInfo) Validate() error {
	if length := utf8.RuneCountInString(info.Database); length < 1 || length > 1024 {
		return errors.New("database must contain 1 to 1024 characters")
	}
	if !validIdentifier(info.Processor) {
		return errors.New("processor must be a 1 to 64 character stable identifier")
	}
	if !validIdentifier(info.Architecture) {
		return errors.New("architecture must be a 1 to 64 character stable identifier")
	}
	if info.AddressBits != 16 && info.AddressBits != 32 && info.AddressBits != 64 {
		return fmt.Errorf("unsupported address width %d", info.AddressBits)
	}
	classified := uint64(info.Segments.Code) + uint64(info.Segments.Data) +
		uint64(info.Segments.BSS) + uint64(info.Segments.Other)
	if classified != uint64(info.Segments.Total) {
		return errors.New("segment type counts do not match total")
	}
	if info.Segments.Readable > info.Segments.Total ||
		info.Segments.Writable > info.Segments.Total ||
		info.Segments.Executable > info.Segments.Total {
		return errors.New("segment permission count exceeds total")
	}
	if info.Segments.Total == 0 {
		if info.AddressRange != nil {
			return errors.New("empty database must not contain an address range")
		}
		return nil
	}
	if info.AddressRange == nil {
		return errors.New("non-empty database is missing its address range")
	}
	if info.AddressRange.Start >= info.AddressRange.End {
		return errors.New("database address range is empty or reversed")
	}
	return nil
}

func validIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '+' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("result contains trailing JSON")
		}
		return err
	}
	return nil
}
