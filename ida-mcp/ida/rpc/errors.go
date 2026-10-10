package rpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

type ErrorCode string

const (
	ErrorInvalidArgument       ErrorCode = "INVALID_ARGUMENT"
	ErrorInvalidAddress        ErrorCode = "INVALID_ADDRESS"
	ErrorNotFound              ErrorCode = "NOT_FOUND"
	ErrorCapabilityUnavailable ErrorCode = "CAPABILITY_UNAVAILABLE"
	ErrorPermissionDenied      ErrorCode = "PERMISSION_DENIED"
	ErrorIDABusy               ErrorCode = "IDA_BUSY"
	ErrorDecompileFailed       ErrorCode = "DECOMPILE_FAILED"
	ErrorConflict              ErrorCode = "CONFLICT"
	ErrorTimeout               ErrorCode = "TIMEOUT"
	ErrorOutputLimit           ErrorCode = "OUTPUT_LIMIT"
	ErrorInternal              ErrorCode = "INTERNAL_ERROR"
)

var validErrorCodes = map[ErrorCode]struct{}{
	ErrorInvalidArgument:       {},
	ErrorInvalidAddress:        {},
	ErrorNotFound:              {},
	ErrorCapabilityUnavailable: {},
	ErrorPermissionDenied:      {},
	ErrorIDABusy:               {},
	ErrorDecompileFailed:       {},
	ErrorConflict:              {},
	ErrorTimeout:               {},
	ErrorOutputLimit:           {},
	ErrorInternal:              {},
}

type ResponseError struct {
	Code             ErrorCode `json:"code"`
	Message          string    `json:"message"`
	Retryable        bool      `json:"retryable"`
	RecoveryChangeID *string   `json:"recoveryChangeId,omitempty"`
}

func (responseError *ResponseError) UnmarshalJSON(data []byte) error {
	type wireError struct {
		Code             *ErrorCode      `json:"code"`
		Message          *string         `json:"message"`
		Retryable        *bool           `json:"retryable"`
		RecoveryChangeID json.RawMessage `json:"recoveryChangeId"`
	}

	var wire wireError
	if err := decodeJSONObjectStrict(data, &wire); err != nil {
		return err
	}
	if wire.Code == nil || wire.Message == nil || wire.Retryable == nil {
		return errors.New("error must contain code, message, and retryable")
	}
	var recoveryChangeID *string
	if len(wire.RecoveryChangeID) != 0 {
		if bytes.Equal(bytes.TrimSpace(wire.RecoveryChangeID), []byte("null")) {
			return errors.New("recoveryChangeId must be a string")
		}
		var decoded string
		if err := json.Unmarshal(wire.RecoveryChangeID, &decoded); err != nil {
			return errors.New("recoveryChangeId must be a string")
		}
		recoveryChangeID = &decoded
	}
	*responseError = ResponseError{
		Code:             *wire.Code,
		Message:          *wire.Message,
		Retryable:        *wire.Retryable,
		RecoveryChangeID: recoveryChangeID,
	}
	return nil
}

func (responseError ResponseError) Error() string {
	if responseError.RecoveryChangeID != nil {
		return fmt.Sprintf("%s: %s (recoveryChangeId=%s)", responseError.Code, responseError.Message, *responseError.RecoveryChangeID)
	}
	return fmt.Sprintf("%s: %s", responseError.Code, responseError.Message)
}

func (responseError ResponseError) Validate() error {
	if _, ok := validErrorCodes[responseError.Code]; !ok {
		return fmt.Errorf("unknown error code %q", responseError.Code)
	}
	if !utf8.ValidString(responseError.Message) {
		return errors.New("error message must be valid UTF-8")
	}
	messageLength := utf8.RuneCountInString(responseError.Message)
	if messageLength == 0 || messageLength > 1024 {
		return errors.New("error message must contain 1 to 1024 characters")
	}
	if responseError.RecoveryChangeID != nil {
		if responseError.Code != ErrorInternal || !recoveryChangeIDPattern.MatchString(*responseError.RecoveryChangeID) {
			return errors.New("recoveryChangeId is invalid")
		}
	}
	return nil
}
