package rpc

import (
	"encoding/json"
	"math"
	"testing"
)

func TestParseAddress(t *testing.T) {
	t.Parallel()

	valid := map[string]Address{
		"0x0":                0,
		"0x401000":           0x401000,
		"0xFFFFFFFFFFFFFFFF": Address(math.MaxUint64),
	}
	for encoded, want := range valid {
		encoded, want := encoded, want
		t.Run(encoded, func(t *testing.T) {
			t.Parallel()
			got, err := ParseAddress(encoded)
			if err != nil {
				t.Fatalf("ParseAddress(%q): %v", encoded, err)
			}
			if got != want {
				t.Fatalf("ParseAddress(%q) = %s, want %s", encoded, got, want)
			}
		})
	}

	invalid := []string{"", "0x", "0X10", "10", "-0x1", "0xgg", "0x10000000000000000"}
	for _, encoded := range invalid {
		encoded := encoded
		t.Run("invalid_"+encoded, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseAddress(encoded); err == nil {
				t.Fatalf("ParseAddress(%q) succeeded", encoded)
			}
		})
	}
}

func TestAddressJSON(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(Address(0x401000))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(encoded) != `"0x401000"` {
		t.Fatalf("Marshal = %s", encoded)
	}

	var decoded Address
	if err := json.Unmarshal([]byte(`"0xffffffffffffffff"`), &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded != Address(math.MaxUint64) {
		t.Fatalf("Unmarshal = %s", decoded)
	}
}
