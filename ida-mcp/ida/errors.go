package ida

import "fmt"

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

type Error struct {
	Code             ErrorCode
	Message          string
	Retryable        bool
	RecoveryChangeID string
}

func (err *Error) Error() string {
	if err.RecoveryChangeID != "" {
		return fmt.Sprintf("%s: %s (recoveryChangeId=%s)", err.Code, err.Message, err.RecoveryChangeID)
	}
	if err.Retryable {
		return fmt.Sprintf("%s (retryable): %s", err.Code, err.Message)
	}
	return fmt.Sprintf("%s: %s", err.Code, err.Message)
}

func NewError(code ErrorCode, message string, retryable bool) *Error {
	return &Error{Code: code, Message: message, Retryable: retryable}
}
