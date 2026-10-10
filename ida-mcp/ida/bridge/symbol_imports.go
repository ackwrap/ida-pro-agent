package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"ida-mcp/ida/rpc"
)

type ImportListParams struct {
	Module string
	Name   string
	Limit  int
	Cursor string
}

type ImportInfo struct {
	Address rpc.Address `json:"address"`
	Name    string      `json:"name"`
	Module  string      `json:"module"`
	Ordinal *uint64     `json:"ordinal,omitempty"`
}

type ImportListResult struct {
	Items      []ImportInfo `json:"items"`
	NextCursor *string      `json:"nextCursor"`
	HasMore    bool         `json:"hasMore"`
}

func (client *Client) SymbolImports(
	ctx context.Context,
	instance rpc.InstanceDescriptor,
	params ImportListParams,
) (ImportListResult, error) {
	if err := params.Validate(); err != nil {
		return ImportListResult{}, err
	}
	requestID, err := randomRequestID()
	if err != nil {
		return ImportListResult{}, err
	}
	wireParams := struct {
		Module string `json:"module,omitempty"`
		Name   string `json:"name,omitempty"`
		Limit  int    `json:"limit,omitempty"`
		Cursor string `json:"cursor,omitempty"`
	}{params.Module, params.Name, params.Limit, params.Cursor}
	encodedParams, err := json.Marshal(wireParams)
	if err != nil {
		return ImportListResult{}, fmt.Errorf("encode symbol.imports params: %w", err)
	}
	response, err := client.Call(ctx, instance, rpc.Request{
		ProtocolVersion: rpc.ProtocolVersion, RequestID: requestID, SessionID: instance.InstanceID,
		Method: "symbol.imports", Params: encodedParams,
		TimeoutMs: int(client.callTimeout().Milliseconds()),
	})
	if err != nil {
		return ImportListResult{}, err
	}
	if response.Error != nil {
		return ImportListResult{}, response.Error
	}
	var result ImportListResult
	decoder := json.NewDecoder(bytes.NewReader(response.Result))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return ImportListResult{}, fmt.Errorf("decode symbol.imports result: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return ImportListResult{}, fmt.Errorf("decode symbol.imports result: %w", err)
	}
	if err := result.Validate(params.effectiveLimit()); err != nil {
		return ImportListResult{}, fmt.Errorf("invalid symbol.imports result: %w", err)
	}
	return result, nil
}

func (params ImportListParams) Validate() error {
	if err := validateInventoryFilter(params.Module); err != nil {
		return err
	}
	if err := validateInventoryFilter(params.Name); err != nil {
		return err
	}
	if err := validateListLimit(params.Limit); err != nil {
		return err
	}
	if params.Cursor != "" && !symbolImportsCursorPattern.MatchString(params.Cursor) {
		return errors.New("symbol.imports cursor is invalid")
	}
	return nil
}

func (params ImportListParams) effectiveLimit() int { return effectiveListLimit(params.Limit) }

func (result ImportListResult) Validate(limit int) error {
	if err := validatePagination(len(result.Items), limit, result.HasMore, result.NextCursor, symbolImportsCursorPattern); err != nil {
		return err
	}
	for _, item := range result.Items {
		if !validRuneLength(item.Name, 1, 1024) || !validRuneLength(item.Module, 1, 1024) {
			return errors.New("symbol.imports text field is invalid")
		}
		if item.Ordinal != nil && (*item.Ordinal == 0 || *item.Ordinal > maxJSONInteger) {
			return errors.New("symbol.imports ordinal is invalid")
		}
	}
	return nil
}
