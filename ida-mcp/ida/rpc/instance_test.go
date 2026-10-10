package rpc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUnixInstanceRoundTrip(t *testing.T) {
	descriptor, err := DecodeInstanceDescriptor(readFixture(t, "valid", "instance-unix.json"))
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.Version != 2 || descriptor.Endpoint == nil || descriptor.Endpoint.Kind != "unix" {
		t.Fatal(descriptor)
	}
	encoded, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if _, exists := fields["pipe"]; exists {
		t.Fatal("v2 serialized a pipe field")
	}
	decoded, err := DecodeInstanceDescriptor(encoded)
	if err != nil || decoded.Locator() != descriptor.Locator() {
		t.Fatalf("round trip: %+v, %v", decoded, err)
	}
	descriptor.Endpoint.Path = "/tmp/ida-agent-4242-deadbeef.sock"
	if descriptor.Validate() == nil {
		t.Fatal("mismatched endpoint identity accepted")
	}
}

func TestDecodeValidInstanceFixture(t *testing.T) {
	t.Parallel()

	descriptor, err := DecodeInstanceDescriptor(readFixture(t, "valid", "instance-named-pipe.json"))
	if err != nil {
		t.Fatalf("DecodeInstanceDescriptor: %v", err)
	}
	if descriptor.Pipe != `\\.\pipe\ida-agent-4242-8dd304b5` {
		t.Fatalf("pipe = %q", descriptor.Pipe)
	}
}

func TestDecodeEquivalentIntegerInstanceFixture(t *testing.T) {
	t.Parallel()

	descriptor, err := DecodeInstanceDescriptor(readFixture(t, "valid", "instance-integer-number-forms.json"))
	if err != nil {
		t.Fatalf("DecodeInstanceDescriptor: %v", err)
	}
	if descriptor.PID != 4242 || descriptor.StartedAt != 1788063000 || descriptor.Capabilities.AddressBits != 64 {
		t.Fatalf("descriptor = %+v", descriptor)
	}
}

func TestDecodeInvalidInstanceFixtures(t *testing.T) {
	t.Parallel()

	for _, fixture := range []string{
		"instance-unix-unknown-field.json", "instance-unix-traversal.json", "instance-unix-relative.json", "instance-mixed-endpoints.json", "instance-v1-unix.json", "instance-invalid-id.json",
		"instance-missing-capability.json",
		"instance-invalid-pipe.json",
		"instance-mismatched-pipe.json",
		"instance-overflow-number.json",
	} {
		fixture := fixture
		t.Run(fixture, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeInstanceDescriptor(readFixture(t, "invalid", fixture)); err == nil {
				t.Fatal("DecodeInstanceDescriptor succeeded")
			}
		})
	}
}

func TestDatabaseUnicodeLength(t *testing.T) {
	t.Parallel()

	descriptor, err := DecodeInstanceDescriptor(readFixture(t, "valid", "instance-named-pipe.json"))
	if err != nil {
		t.Fatalf("DecodeInstanceDescriptor: %v", err)
	}
	descriptor.Database = strings.Repeat("界", 1024)
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("1024-character database: %v", err)
	}
	descriptor.Database += "界"
	if err := descriptor.Validate(); err == nil {
		t.Fatal("1025-character database accepted")
	}
}
