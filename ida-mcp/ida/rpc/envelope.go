package rpc

import (
	"encoding/json"
	"errors"
	"fmt"
)

const (
	ProtocolVersion = "ida-rpc/1"
	MinTimeoutMs    = 1
	MaxTimeoutMs    = 120000
)

type Request struct {
	ProtocolVersion string          `json:"protocolVersion"`
	RequestID       string          `json:"requestId"`
	SessionID       string          `json:"sessionId"`
	Method          string          `json:"method"`
	Params          json.RawMessage `json:"params"`
	TimeoutMs       int             `json:"timeoutMs"`
}

func (request *Request) UnmarshalJSON(data []byte) error {
	type wireRequest struct {
		ProtocolVersion string          `json:"protocolVersion"`
		RequestID       string          `json:"requestId"`
		SessionID       string          `json:"sessionId"`
		Method          string          `json:"method"`
		Params          json.RawMessage `json:"params"`
		TimeoutMs       wireUint32      `json:"timeoutMs"`
	}

	var wire wireRequest
	if err := decodeJSONObjectStrict(data, &wire); err != nil {
		return err
	}
	*request = Request{
		ProtocolVersion: wire.ProtocolVersion,
		RequestID:       wire.RequestID,
		SessionID:       wire.SessionID,
		Method:          wire.Method,
		Params:          wire.Params,
		TimeoutMs:       int(wire.TimeoutMs),
	}
	return nil
}

func (request Request) Validate() error {
	if err := validateProtocolVersion(request.ProtocolVersion); err != nil {
		return err
	}
	if !identifierPattern.MatchString(request.RequestID) {
		return errors.New("requestId is invalid")
	}
	if !identifierPattern.MatchString(request.SessionID) {
		return errors.New("sessionId is invalid")
	}
	if !methodPattern.MatchString(request.Method) {
		return errors.New("method is invalid")
	}
	if !isJSONObject(request.Params) {
		return errors.New("params must be a JSON object")
	}
	if request.TimeoutMs < MinTimeoutMs || request.TimeoutMs > MaxTimeoutMs {
		return fmt.Errorf("timeoutMs must be between %d and %d", MinTimeoutMs, MaxTimeoutMs)
	}
	return nil
}

type Response struct {
	ProtocolVersion string          `json:"protocolVersion"`
	RequestID       string          `json:"requestId"`
	SessionID       string          `json:"sessionId"`
	Result          json.RawMessage `json:"result,omitempty"`
	Error           *ResponseError  `json:"error,omitempty"`
}

func (response Response) Validate() error {
	if err := validateProtocolVersion(response.ProtocolVersion); err != nil {
		return err
	}
	if !identifierPattern.MatchString(response.RequestID) {
		return errors.New("requestId is invalid")
	}
	if !identifierPattern.MatchString(response.SessionID) {
		return errors.New("sessionId is invalid")
	}

	hasResult := len(response.Result) != 0
	hasError := response.Error != nil
	if hasResult == hasError {
		return errors.New("response must contain exactly one of result or error")
	}
	if hasResult && !isJSONObject(response.Result) {
		return errors.New("result must be a JSON object")
	}
	if hasError {
		return response.Error.Validate()
	}
	return nil
}
