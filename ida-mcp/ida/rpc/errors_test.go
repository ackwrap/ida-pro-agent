package rpc

import (
	"strings"
	"testing"
)

func TestErrorMessageUnicodeLength(t *testing.T) {
	t.Parallel()

	responseError := ResponseError{
		Code:      ErrorInternal,
		Message:   strings.Repeat("界", 1024),
		Retryable: false,
	}
	if err := responseError.Validate(); err != nil {
		t.Fatalf("1024-character message: %v", err)
	}
	responseError.Message += "界"
	if err := responseError.Validate(); err == nil {
		t.Fatal("1025-character message accepted")
	}
}
