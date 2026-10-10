package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"ida-mcp/ida/rpc"
)

type SegmentListParams struct {
	Name   string
	Limit  int
	Cursor string
}

type SegmentInfo struct {
	Start       rpc.Address `json:"start"`
	End         rpc.Address `json:"end"`
	Name        string      `json:"name"`
	Class       string      `json:"class"`
	Bitness     uint32      `json:"bitness"`
	Permissions string      `json:"permissions"`
	Type        string      `json:"type"`
}

type SegmentListResult struct {
	Items      []SegmentInfo `json:"items"`
	NextCursor *string       `json:"nextCursor"`
	HasMore    bool          `json:"hasMore"`
}

func (client *Client) DatabaseSegments(
	ctx context.Context,
	instance rpc.InstanceDescriptor,
	params SegmentListParams,
) (SegmentListResult, error) {
	if err := params.Validate(); err != nil {
		return SegmentListResult{}, err
	}
	requestID, err := randomRequestID()
	if err != nil {
		return SegmentListResult{}, err
	}
	wireParams := struct {
		Name   string `json:"name,omitempty"`
		Limit  int    `json:"limit,omitempty"`
		Cursor string `json:"cursor,omitempty"`
	}{params.Name, params.Limit, params.Cursor}
	encodedParams, err := json.Marshal(wireParams)
	if err != nil {
		return SegmentListResult{}, fmt.Errorf("encode database.segments params: %w", err)
	}
	response, err := client.Call(ctx, instance, rpc.Request{
		ProtocolVersion: rpc.ProtocolVersion, RequestID: requestID, SessionID: instance.InstanceID,
		Method: "database.segments", Params: encodedParams,
		TimeoutMs: int(client.callTimeout().Milliseconds()),
	})
	if err != nil {
		return SegmentListResult{}, err
	}
	if response.Error != nil {
		return SegmentListResult{}, response.Error
	}
	var result SegmentListResult
	decoder := json.NewDecoder(bytes.NewReader(response.Result))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return SegmentListResult{}, fmt.Errorf("decode database.segments result: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return SegmentListResult{}, fmt.Errorf("decode database.segments result: %w", err)
	}
	if err := result.Validate(params.effectiveLimit()); err != nil {
		return SegmentListResult{}, fmt.Errorf("invalid database.segments result: %w", err)
	}
	return result, nil
}

func (params SegmentListParams) Validate() error {
	if err := validateInventoryFilter(params.Name); err != nil {
		return err
	}
	if err := validateListLimit(params.Limit); err != nil {
		return err
	}
	if params.Cursor != "" && !databaseSegmentsCursorPattern.MatchString(params.Cursor) {
		return errors.New("database.segments cursor is invalid")
	}
	return nil
}

func (params SegmentListParams) effectiveLimit() int { return effectiveListLimit(params.Limit) }

func (result SegmentListResult) Validate(limit int) error {
	if err := validatePagination(len(result.Items), limit, result.HasMore, result.NextCursor, databaseSegmentsCursorPattern); err != nil {
		return err
	}
	validPermissions := map[string]bool{"---": true, "--x": true, "-w-": true, "-wx": true, "r--": true, "r-x": true, "rw-": true, "rwx": true}
	validTypes := map[string]bool{"normal": true, "external": true, "code": true, "data": true, "implementation": true, "group": true, "null": true, "undefined": true, "bss": true, "absolute_symbols": true, "communal": true, "internal_memory": true}
	var previous rpc.Address
	for index, item := range result.Items {
		if item.Start >= item.End || (index > 0 && item.Start <= previous) {
			return errors.New("database.segments results are not strictly sorted")
		}
		if !validRuneLength(item.Name, 1, 1024) || !validRuneLength(item.Class, 0, 1024) {
			return errors.New("database.segments text field is invalid")
		}
		if item.Bitness != 16 && item.Bitness != 32 && item.Bitness != 64 {
			return errors.New("database.segments bitness is invalid")
		}
		if !validPermissions[item.Permissions] || !validTypes[item.Type] {
			return errors.New("database.segments stable enum is invalid")
		}
		previous = item.Start
	}
	return nil
}
