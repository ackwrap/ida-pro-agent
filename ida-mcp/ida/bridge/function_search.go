package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"unicode/utf8"

	"ida-mcp/ida/rpc"
)

var functionSearchCursorPattern = regexp.MustCompile(
	`^fs1\.[0-9a-f]{16}\.[0-9a-f]{16}\.[0-9a-f]{16}$`,
)

type FunctionSearchParams struct {
	Name    *string
	Address *rpc.Address
	Limit   int
	Cursor  string
}

type FunctionSummary struct {
	EntryAddress rpc.Address `json:"entryAddress"`
	Name         string      `json:"name"`
}

type FunctionSearchResult struct {
	Items      []FunctionSummary `json:"items"`
	NextCursor *string           `json:"nextCursor"`
	HasMore    bool              `json:"hasMore"`
}

func (client *Client) SearchFunctions(
	ctx context.Context,
	instance rpc.InstanceDescriptor,
	params FunctionSearchParams,
) (FunctionSearchResult, error) {
	if err := params.Validate(); err != nil {
		return FunctionSearchResult{}, err
	}
	requestID, err := randomRequestID()
	if err != nil {
		return FunctionSearchResult{}, err
	}
	wireParams := struct {
		Name    *string      `json:"name,omitempty"`
		Address *rpc.Address `json:"address,omitempty"`
		Limit   int          `json:"limit,omitempty"`
		Cursor  string       `json:"cursor,omitempty"`
	}{params.Name, params.Address, params.Limit, params.Cursor}
	encodedParams, err := json.Marshal(wireParams)
	if err != nil {
		return FunctionSearchResult{}, fmt.Errorf("encode function.search params: %w", err)
	}
	response, err := client.Call(ctx, instance, rpc.Request{
		ProtocolVersion: rpc.ProtocolVersion,
		RequestID:       requestID,
		SessionID:       instance.InstanceID,
		Method:          "function.search",
		Params:          encodedParams,
		TimeoutMs:       int(client.callTimeout().Milliseconds()),
	})
	if err != nil {
		return FunctionSearchResult{}, err
	}
	if response.Error != nil {
		return FunctionSearchResult{}, response.Error
	}

	var result FunctionSearchResult
	decoder := json.NewDecoder(bytes.NewReader(response.Result))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return FunctionSearchResult{}, fmt.Errorf("decode function.search result: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return FunctionSearchResult{}, fmt.Errorf("decode function.search result: %w", err)
	}
	if err := result.Validate(params.effectiveLimit()); err != nil {
		return FunctionSearchResult{}, fmt.Errorf("invalid function.search result: %w", err)
	}
	return result, nil
}

func (params FunctionSearchParams) Validate() error {
	if (params.Name == nil) == (params.Address == nil) {
		return errors.New("function search requires exactly one name or address filter")
	}
	if params.Name != nil && utf8.RuneCountInString(*params.Name) > 256 {
		return errors.New("function search name exceeds 256 characters")
	}
	if params.Address != nil && params.Cursor != "" {
		return errors.New("address search does not accept a cursor")
	}
	if params.Limit < 0 || params.Limit > 100 {
		return errors.New("function search limit must be from 1 to 100")
	}
	if params.Cursor != "" && !functionSearchCursorPattern.MatchString(params.Cursor) {
		return errors.New("function search cursor is invalid")
	}
	return nil
}

func (params FunctionSearchParams) effectiveLimit() int {
	if params.Limit == 0 {
		return 20
	}
	return params.Limit
}

func (result FunctionSearchResult) Validate(limit int) error {
	if len(result.Items) > limit {
		return errors.New("function search result exceeds the requested limit")
	}
	if result.HasMore != (result.NextCursor != nil) {
		return errors.New("function search pagination metadata is inconsistent")
	}
	if result.NextCursor != nil && !functionSearchCursorPattern.MatchString(*result.NextCursor) {
		return errors.New("function search result cursor is invalid")
	}
	var previous rpc.Address
	for index, item := range result.Items {
		if length := utf8.RuneCountInString(item.Name); length < 1 || length > 1024 {
			return fmt.Errorf(
				"function search result name at index %d (%s) has %d characters",
				index, item.EntryAddress, length,
			)
		}
		if index > 0 && item.EntryAddress <= previous {
			return errors.New("function search results are not strictly sorted")
		}
		previous = item.EntryAddress
	}
	return nil
}
