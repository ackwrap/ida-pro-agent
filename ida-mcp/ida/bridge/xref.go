package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"ida-mcp/ida/rpc"
)

type XrefDirection string

const (
	XrefIncoming XrefDirection = "incoming"
	XrefOutgoing XrefDirection = "outgoing"
)

type XrefCategory string

const (
	XrefAll  XrefCategory = "all"
	XrefCode XrefCategory = "code"
	XrefData XrefCategory = "data"
)

var xrefCursorPattern = regexp.MustCompile(
	`^xq2\.[0-9a-f]{16}\.[0-9a-f]{16}\.[0-9a-f]{16}$`,
)

type XrefQueryParams struct {
	Address     rpc.Address
	Direction   XrefDirection
	Category    XrefCategory
	IncludeFlow bool
	Limit       int
	Cursor      string
}

type XrefInfo struct {
	From        rpc.Address `json:"from"`
	To          rpc.Address `json:"to"`
	Type        string      `json:"type"`
	Code        bool        `json:"code"`
	UserDefined bool        `json:"userDefined"`
}

type XrefQueryResult struct {
	Items      []XrefInfo `json:"items"`
	NextCursor *string    `json:"nextCursor"`
	HasMore    bool       `json:"hasMore"`
}

func (client *Client) QueryXrefs(
	ctx context.Context,
	instance rpc.InstanceDescriptor,
	params XrefQueryParams,
) (XrefQueryResult, error) {
	if err := params.Validate(); err != nil {
		return XrefQueryResult{}, err
	}
	requestID, err := randomRequestID()
	if err != nil {
		return XrefQueryResult{}, err
	}
	wireParams := struct {
		Address     rpc.Address   `json:"address"`
		Direction   XrefDirection `json:"direction"`
		Category    XrefCategory  `json:"category,omitempty"`
		IncludeFlow bool          `json:"includeFlow,omitempty"`
		Limit       int           `json:"limit,omitempty"`
		Cursor      string        `json:"cursor,omitempty"`
	}{
		params.Address,
		params.Direction,
		params.Category,
		params.IncludeFlow,
		params.Limit,
		params.Cursor,
	}
	encodedParams, err := json.Marshal(wireParams)
	if err != nil {
		return XrefQueryResult{}, fmt.Errorf("encode xref.query params: %w", err)
	}
	response, err := client.Call(ctx, instance, rpc.Request{
		ProtocolVersion: rpc.ProtocolVersion,
		RequestID:       requestID,
		SessionID:       instance.InstanceID,
		Method:          "xref.query",
		Params:          encodedParams,
		TimeoutMs:       int(client.callTimeout().Milliseconds()),
	})
	if err != nil {
		return XrefQueryResult{}, err
	}
	if response.Error != nil {
		return XrefQueryResult{}, response.Error
	}

	var result XrefQueryResult
	decoder := json.NewDecoder(bytes.NewReader(response.Result))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return XrefQueryResult{}, fmt.Errorf("decode xref.query result: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return XrefQueryResult{}, fmt.Errorf("decode xref.query result: %w", err)
	}
	if err := result.Validate(params); err != nil {
		return XrefQueryResult{}, fmt.Errorf("invalid xref.query result: %w", err)
	}
	return result, nil
}

func (params XrefQueryParams) Validate() error {
	if params.Direction != XrefIncoming && params.Direction != XrefOutgoing {
		return errors.New("xref direction is invalid")
	}
	if params.Category != "" && params.Category != XrefAll &&
		params.Category != XrefCode && params.Category != XrefData {
		return errors.New("xref category is invalid")
	}
	if params.Limit < 0 || params.Limit > 100 {
		return errors.New("xref limit must be from 1 to 100")
	}
	if params.Cursor != "" && !xrefCursorPattern.MatchString(params.Cursor) {
		return errors.New("xref cursor is invalid")
	}
	return nil
}

func (params XrefQueryParams) effectiveLimit() int {
	if params.Limit == 0 {
		return 20
	}
	return params.Limit
}

func (result XrefQueryResult) Validate(params XrefQueryParams) error {
	if len(result.Items) > params.effectiveLimit() {
		return errors.New("xref result exceeds the requested limit")
	}
	if result.HasMore != (result.NextCursor != nil) {
		return errors.New("xref pagination metadata is inconsistent")
	}
	if result.NextCursor != nil && !xrefCursorPattern.MatchString(*result.NextCursor) {
		return errors.New("xref result cursor is invalid")
	}
	validTypes := map[string]bool{
		"call_far": true, "call_near": true, "jump_far": true, "jump_near": true,
		"flow": true, "unknown_code": true,
		"offset": false, "write": false, "read": false, "text": false,
		"informational": false, "symbolic": false, "unknown_data": false,
	}
	for _, item := range result.Items {
		code, ok := validTypes[item.Type]
		if !ok || code != item.Code {
			return errors.New("xref result type is invalid")
		}
		if (params.Direction == XrefOutgoing && item.From != params.Address) ||
			(params.Direction == XrefIncoming && item.To != params.Address) {
			return errors.New("xref result does not match the query address")
		}
		if (params.Category == XrefCode && !item.Code) ||
			(params.Category == XrefData && item.Code) {
			return errors.New("xref result does not match the query category")
		}
		if item.Type == "flow" && !params.IncludeFlow {
			return errors.New("xref result contains excluded ordinary flow")
		}
	}
	return nil
}
