package bridge

import (
	"encoding/binary"
	"testing"
)

func TestBuildRequestFrame(t *testing.T) {
	t.Parallel()

	frame, err := buildRequestFrame([]byte(`{}`))
	if err != nil {
		t.Fatalf("buildRequestFrame: %v", err)
	}
	if string(frame[:4]) != "IMCP" || frame[4] != framingVersion {
		t.Fatalf("frame prefix = %x", frame[:5])
	}
	if got := binary.BigEndian.Uint32(frame[5:9]); got != 2 {
		t.Fatalf("payload size = %d", got)
	}
	if string(frame[9:]) != `{}` {
		t.Fatalf("payload = %s", frame[9:])
	}
}

func TestParseResponseHeader(t *testing.T) {
	t.Parallel()

	header := []byte{'I', 'M', 'C', 'R', framingVersion, 0, 0, 0, 16}
	size, err := parseResponseHeader(header)
	if err != nil {
		t.Fatalf("parseResponseHeader: %v", err)
	}
	if size != 16 {
		t.Fatalf("size = %d", size)
	}
	header[0] = 'X'
	if _, err := parseResponseHeader(header); err == nil {
		t.Fatal("invalid magic accepted")
	}
}
