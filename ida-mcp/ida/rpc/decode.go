package rpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const MaxMessageBytes = 1 << 20

func DecodeRequest(data []byte) (Request, error) {
	var request Request
	if err := decodeStrict(data, &request); err != nil {
		return Request{}, fmt.Errorf("decode request: %w", err)
	}
	if err := request.Validate(); err != nil {
		return Request{}, fmt.Errorf("validate request: %w", err)
	}
	return request, nil
}

func DecodeResponse(data []byte) (Response, error) {
	var response Response
	if err := decodeStrict(data, &response); err != nil {
		return Response{}, fmt.Errorf("decode response: %w", err)
	}
	if err := response.Validate(); err != nil {
		return Response{}, fmt.Errorf("validate response: %w", err)
	}
	return response, nil
}

func DecodeInstanceDescriptor(data []byte) (InstanceDescriptor, error) {
	var descriptor InstanceDescriptor
	if err := decodeStrict(data, &descriptor); err != nil {
		return InstanceDescriptor{}, fmt.Errorf("decode instance descriptor: %w", err)
	}
	if err := descriptor.Validate(); err != nil {
		return InstanceDescriptor{}, fmt.Errorf("validate instance descriptor: %w", err)
	}
	return descriptor, nil
}

func decodeStrict(data []byte, target any) error {
	if len(data) == 0 {
		return errors.New("message is empty")
	}
	if len(data) > MaxMessageBytes {
		return fmt.Errorf("message exceeds %d bytes", MaxMessageBytes)
	}
	if !utf8.Valid(data) {
		return errors.New("message is not valid UTF-8")
	}
	return decodeJSONObjectStrict(data, target)
}

func decodeJSONObjectStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("message contains multiple JSON values")
		}
		return fmt.Errorf("message contains trailing data: %w", err)
	}
	return nil
}
