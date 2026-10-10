package bridge

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	framingVersion     = 1
	requestHeaderBytes = 9
	responseHeaderSize = 9
	maxPayloadBytes    = 1 << 20
)

var (
	requestMagic  = [4]byte{'I', 'M', 'C', 'P'}
	responseMagic = [4]byte{'I', 'M', 'C', 'R'}
)

func buildRequestFrame(payload []byte) ([]byte, error) {
	if len(payload) == 0 || len(payload) > maxPayloadBytes {
		return nil, fmt.Errorf("request payload size %d is invalid", len(payload))
	}
	frame := make([]byte, requestHeaderBytes+len(payload))
	copy(frame[:4], requestMagic[:])
	frame[4] = framingVersion
	binary.BigEndian.PutUint32(frame[5:9], uint32(len(payload)))
	copy(frame[requestHeaderBytes:], payload)
	return frame, nil
}

func parseResponseHeader(header []byte) (uint32, error) {
	if len(header) != responseHeaderSize {
		return 0, errors.New("response frame header size is invalid")
	}
	if string(header[:4]) != string(responseMagic[:]) {
		return 0, errors.New("response frame magic is invalid")
	}
	if header[4] != framingVersion {
		return 0, errors.New("response framing version is unsupported")
	}
	size := binary.BigEndian.Uint32(header[5:9])
	if size == 0 || size > maxPayloadBytes {
		return 0, errors.New("response payload size is invalid")
	}
	return size, nil
}
