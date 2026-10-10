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

type StringSearchParams struct {
	Query     string
	MinLength int
	Limit     int
	Cursor    string
	Refresh   bool
}

type StringInfo struct {
	Address      rpc.Address `json:"address"`
	Length       uint64      `json:"length"`
	Encoding     string      `json:"encoding"`
	Value        string      `json:"value"`
	Truncated    bool        `json:"truncated"`
	OriginalSize uint64      `json:"originalSize"`
}

type StringSearchResult struct {
	Items      []StringInfo `json:"items"`
	NextCursor *string      `json:"nextCursor"`
	HasMore    bool         `json:"hasMore"`
}

func (client *Client) SearchStrings(
	ctx context.Context,
	instance rpc.InstanceDescriptor,
	params StringSearchParams,
) (StringSearchResult, error) {
	if err := params.Validate(); err != nil {
		return StringSearchResult{}, err
	}
	requestID, err := randomRequestID()
	if err != nil {
		return StringSearchResult{}, err
	}
	wireParams := struct {
		Query     string `json:"query,omitempty"`
		MinLength int    `json:"minLength,omitempty"`
		Limit     int    `json:"limit,omitempty"`
		Cursor    string `json:"cursor,omitempty"`
		Refresh   bool   `json:"refresh,omitempty"`
	}{params.Query, params.MinLength, params.Limit, params.Cursor, params.Refresh}
	encodedParams, err := json.Marshal(wireParams)
	if err != nil {
		return StringSearchResult{}, fmt.Errorf("encode string.search params: %w", err)
	}
	response, err := client.Call(ctx, instance, rpc.Request{
		ProtocolVersion: rpc.ProtocolVersion, RequestID: requestID, SessionID: instance.InstanceID,
		Method: "string.search", Params: encodedParams,
		TimeoutMs: int(client.callTimeout().Milliseconds()),
	})
	if err != nil {
		return StringSearchResult{}, err
	}
	if response.Error != nil {
		return StringSearchResult{}, response.Error
	}
	var result StringSearchResult
	decoder := json.NewDecoder(bytes.NewReader(response.Result))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return StringSearchResult{}, fmt.Errorf("decode string.search result: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return StringSearchResult{}, fmt.Errorf("decode string.search result: %w", err)
	}
	if err := result.Validate(params.effectiveLimit()); err != nil {
		return StringSearchResult{}, fmt.Errorf("invalid string.search result: %w", err)
	}
	return result, nil
}

func (params StringSearchParams) Validate() error {
	if params.Refresh && params.Cursor != "" {
		return errors.New("refresh cannot be combined with cursor; restart from the first page")
	}
	if err := validateInventoryFilter(params.Query); err != nil {
		return err
	}
	if params.MinLength < 0 || params.MinLength > 4096 {
		return errors.New("string.search minLength must be from 1 to 4096")
	}
	if err := validateListLimit(params.Limit); err != nil {
		return err
	}
	if params.Cursor != "" && !stringSearchCursorPattern.MatchString(params.Cursor) {
		return errors.New("string.search cursor is invalid")
	}
	return nil
}

func (params StringSearchParams) effectiveLimit() int { return effectiveListLimit(params.Limit) }

func (params StringSearchParams) effectiveMinLength() int {
	if params.MinLength == 0 {
		return 4
	}
	return params.MinLength
}

func (result StringSearchResult) Validate(limit int) error {
	if err := validatePagination(len(result.Items), limit, result.HasMore, result.NextCursor, stringSearchCursorPattern); err != nil {
		return err
	}
	var previous rpc.Address
	for index, item := range result.Items {
		if index > 0 && item.Address <= previous {
			return errors.New("string.search results are not strictly sorted")
		}
		if item.Length > maxJSONInteger || item.OriginalSize > maxJSONInteger ||
			!validRuneLength(item.Encoding, 1, 128) || !utf8.ValidString(item.Value) || len(item.Value) > 4096 {
			return errors.New("string.search item is invalid")
		}
		visibleLength := uint64(utf8.RuneCountInString(item.Value))
		if item.Length < visibleLength || item.OriginalSize < uint64(len(item.Value)) ||
			item.Truncated != (item.OriginalSize > uint64(len(item.Value))) {
			return errors.New("string.search truncation metadata is inconsistent")
		}
		previous = item.Address
	}
	return nil
}
