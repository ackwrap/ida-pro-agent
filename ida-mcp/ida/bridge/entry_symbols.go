package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"ida-mcp/ida/rpc"
)

type EntryPointListParams struct {
	Name   string
	Type   string
	Limit  int
	Cursor string
}

type EntryPointInfo struct {
	Address rpc.Address `json:"address"`
	Name    string      `json:"name"`
	Type    string      `json:"type"`
	Ordinal *uint64     `json:"ordinal,omitempty"`
}

type EntryPointListResult struct {
	Items      []EntryPointInfo `json:"items"`
	NextCursor *string          `json:"nextCursor"`
	HasMore    bool             `json:"hasMore"`
}

type ExportListParams struct {
	Name   string
	Limit  int
	Cursor string
}

type ExportInfo struct {
	Address rpc.Address `json:"address"`
	Name    string      `json:"name"`
	Ordinal uint64      `json:"ordinal"`
}

type ExportListResult struct {
	Items      []ExportInfo `json:"items"`
	NextCursor *string      `json:"nextCursor"`
	HasMore    bool         `json:"hasMore"`
}

type SymbolSearchParams struct {
	Name   string
	Kind   string
	Limit  int
	Cursor string
}

type SymbolInfo struct {
	Address rpc.Address `json:"address"`
	Name    string      `json:"name"`
	Kind    string      `json:"kind"`
}

type SymbolSearchResult struct {
	Items      []SymbolInfo `json:"items"`
	NextCursor *string      `json:"nextCursor"`
	HasMore    bool         `json:"hasMore"`
}

func (client *Client) DatabaseEntryPoints(
	ctx context.Context,
	instance rpc.InstanceDescriptor,
	params EntryPointListParams,
) (EntryPointListResult, error) {
	if err := params.Validate(); err != nil {
		return EntryPointListResult{}, err
	}
	wire := struct {
		Name   string `json:"name,omitempty"`
		Type   string `json:"type,omitempty"`
		Limit  int    `json:"limit,omitempty"`
		Cursor string `json:"cursor,omitempty"`
	}{params.Name, params.Type, params.Limit, params.Cursor}
	var result EntryPointListResult
	if err := client.callInventory(ctx, instance, "database.entry_points", wire, &result); err != nil {
		return EntryPointListResult{}, err
	}
	if err := result.Validate(params.effectiveLimit()); err != nil {
		return EntryPointListResult{}, fmt.Errorf("invalid database.entry_points result: %w", err)
	}
	return result, nil
}

func (client *Client) SymbolExports(
	ctx context.Context,
	instance rpc.InstanceDescriptor,
	params ExportListParams,
) (ExportListResult, error) {
	if err := params.Validate(); err != nil {
		return ExportListResult{}, err
	}
	wire := struct {
		Name   string `json:"name,omitempty"`
		Limit  int    `json:"limit,omitempty"`
		Cursor string `json:"cursor,omitempty"`
	}{params.Name, params.Limit, params.Cursor}
	var result ExportListResult
	if err := client.callInventory(ctx, instance, "symbol.exports", wire, &result); err != nil {
		return ExportListResult{}, err
	}
	if err := result.Validate(params.effectiveLimit()); err != nil {
		return ExportListResult{}, fmt.Errorf("invalid symbol.exports result: %w", err)
	}
	return result, nil
}

func (client *Client) SymbolSearch(
	ctx context.Context,
	instance rpc.InstanceDescriptor,
	params SymbolSearchParams,
) (SymbolSearchResult, error) {
	if err := params.Validate(); err != nil {
		return SymbolSearchResult{}, err
	}
	wire := struct {
		Name   string `json:"name,omitempty"`
		Kind   string `json:"kind,omitempty"`
		Limit  int    `json:"limit,omitempty"`
		Cursor string `json:"cursor,omitempty"`
	}{params.Name, params.Kind, params.Limit, params.Cursor}
	var result SymbolSearchResult
	if err := client.callInventory(ctx, instance, "symbol.search", wire, &result); err != nil {
		return SymbolSearchResult{}, err
	}
	if err := result.Validate(params.effectiveLimit()); err != nil {
		return SymbolSearchResult{}, fmt.Errorf("invalid symbol.search result: %w", err)
	}
	return result, nil
}

func (client *Client) callInventory(
	ctx context.Context,
	instance rpc.InstanceDescriptor,
	method rpcMethod,
	params any,
	result any,
) error {
	requestID, err := randomRequestID()
	if err != nil {
		return err
	}
	encodedParams, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("encode %s params: %w", method, err)
	}
	response, err := client.Call(ctx, instance, rpc.Request{
		ProtocolVersion: rpc.ProtocolVersion, RequestID: requestID, SessionID: instance.InstanceID,
		Method: string(method), Params: encodedParams, TimeoutMs: int(client.callTimeout().Milliseconds()),
	})
	if err != nil {
		return err
	}
	if response.Error != nil {
		return response.Error
	}
	decoder := json.NewDecoder(bytes.NewReader(response.Result))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(result); err != nil {
		return fmt.Errorf("decode %s result: %w", method, err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return fmt.Errorf("decode %s result: %w", method, err)
	}
	return nil
}

func (params EntryPointListParams) Validate() error {
	if err := validateInventoryFilter(params.Name); err != nil {
		return err
	}
	if params.Type != "" && params.Type != "entry" && params.Type != "export" {
		return errors.New("database.entry_points type is invalid")
	}
	if err := validateListLimit(params.Limit); err != nil {
		return err
	}
	if params.Cursor != "" && !databaseEntryPointsCursorPattern.MatchString(params.Cursor) {
		return errors.New("database.entry_points cursor is invalid")
	}
	return nil
}

func (params EntryPointListParams) effectiveLimit() int { return effectiveListLimit(params.Limit) }

func (params ExportListParams) Validate() error {
	if err := validateInventoryFilter(params.Name); err != nil {
		return err
	}
	if err := validateListLimit(params.Limit); err != nil {
		return err
	}
	if params.Cursor != "" && !symbolExportsCursorPattern.MatchString(params.Cursor) {
		return errors.New("symbol.exports cursor is invalid")
	}
	return nil
}

func (params ExportListParams) effectiveLimit() int { return effectiveListLimit(params.Limit) }

func (params SymbolSearchParams) Validate() error {
	if err := validateInventoryFilter(params.Name); err != nil {
		return err
	}
	if params.Kind != "" && params.Kind != "global" && params.Kind != "data" && params.Kind != "label" {
		return errors.New("symbol.search kind is invalid")
	}
	if err := validateListLimit(params.Limit); err != nil {
		return err
	}
	if params.Cursor != "" && !symbolSearchCursorPattern.MatchString(params.Cursor) {
		return errors.New("symbol.search cursor is invalid")
	}
	return nil
}

func (params SymbolSearchParams) effectiveLimit() int { return effectiveListLimit(params.Limit) }

func (result EntryPointListResult) Validate(limit int) error {
	if err := validatePagination(len(result.Items), limit, result.HasMore, result.NextCursor, databaseEntryPointsCursorPattern); err != nil {
		return err
	}
	seen := make(map[uint64]bool, len(result.Items))
	for _, item := range result.Items {
		if !validInventoryItemText(item.Name) || (item.Type != "entry" && item.Type != "export") {
			return errors.New("database.entry_points item is invalid")
		}
		identity := uint64(item.Address)
		if item.Type == "export" {
			if item.Ordinal == nil || *item.Ordinal == 0 || *item.Ordinal > maxJSONInteger {
				return errors.New("database.entry_points export ordinal is invalid")
			}
			identity = *item.Ordinal
		} else if item.Ordinal != nil {
			return errors.New("database.entry_points entry contains an ordinal")
		}
		if seen[identity] {
			return errors.New("database.entry_points contains a duplicate record")
		}
		seen[identity] = true
	}
	return nil
}

func (result ExportListResult) Validate(limit int) error {
	if err := validatePagination(len(result.Items), limit, result.HasMore, result.NextCursor, symbolExportsCursorPattern); err != nil {
		return err
	}
	seen := make(map[uint64]bool, len(result.Items))
	for _, item := range result.Items {
		if !validInventoryItemText(item.Name) || item.Ordinal == 0 || item.Ordinal > maxJSONInteger || seen[item.Ordinal] {
			return errors.New("symbol.exports item is invalid or duplicated")
		}
		seen[item.Ordinal] = true
	}
	return nil
}

func (result SymbolSearchResult) Validate(limit int) error {
	if err := validatePagination(len(result.Items), limit, result.HasMore, result.NextCursor, symbolSearchCursorPattern); err != nil {
		return err
	}
	var previous rpc.Address
	for index, item := range result.Items {
		if (index > 0 && item.Address <= previous) || !validInventoryItemText(item.Name) ||
			(item.Kind != "global" && item.Kind != "data" && item.Kind != "label") {
			return errors.New("symbol.search item is invalid, duplicated, or unsorted")
		}
		previous = item.Address
	}
	return nil
}

func validInventoryItemText(value string) bool {
	return len(value) >= 1 && len(value) <= 1024 && validRuneLength(value, 1, 1024)
}
