package mcpserver

import (
	"strings"
	"testing"
)

func TestCursorCodecBindsAndAuthenticatesPayload(t *testing.T) {
	t.Parallel()
	codec, err := newCursorCodec()
	if err != nil {
		t.Fatalf("newCursorCodec: %v", err)
	}
	internal := "fs1.14650fb0739d0383.0000000140001080.68e99ec5f626926e"
	cursor, err := codec.encode("fs2", "session-a\x00main", internal)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := codec.decode("fs2", "session-a\x00main", cursor)
	if err != nil || decoded != internal {
		t.Fatalf("decode = %q, %v", decoded, err)
	}

	for name, candidate := range map[string]struct {
		cursor  string
		binding string
	}{
		"modified":      {cursor[:len(cursor)-1] + alternateCursorCharacter(cursor[len(cursor)-1]), "session-a\x00main"},
		"other query":   {cursor, "session-a\x00other"},
		"other session": {cursor, "session-b\x00main"},
		"wrong kind":    {strings.Replace(cursor, "fs2.", "xq3.", 1), "session-a\x00main"},
	} {
		candidate := candidate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := codec.decode("fs2", candidate.binding, candidate.cursor); err == nil {
				t.Fatal("decode accepted invalid cursor")
			}
		})
	}
}

func TestCursorCodecInvalidatesCursorAfterRestart(t *testing.T) {
	t.Parallel()
	first, err := newCursorCodec()
	if err != nil {
		t.Fatalf("first codec: %v", err)
	}
	second, err := newCursorCodec()
	if err != nil {
		t.Fatalf("second codec: %v", err)
	}
	cursor, err := first.encode("xq3", "session-a\x00query", "xq2.internal")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := second.decode("xq3", "session-a\x00query", cursor); err == nil {
		t.Fatal("new codec accepted cursor signed before restart")
	}
}

func TestInvalidCursorErrorExplainsBindingAndLifetime(t *testing.T) {
	t.Parallel()
	message := invalidCursorError().Error()
	for _, detail := range []string{"method", "instance", "filters", "Gateway process"} {
		if !strings.Contains(message, detail) {
			t.Errorf("cursor error omitted %q: %s", detail, message)
		}
	}
}

func alternateCursorCharacter(value byte) string {
	if value == 'A' {
		return "B"
	}
	return "A"
}
