package ida

import "testing"

func TestDatabaseMutationOperationsValidate(t *testing.T) {
	address, target := Address(0x401000), Address(0x402000)
	targetText := target.String()
	tests := []ChangeOperation{
		{Kind: "segment.rename", Address: &address, Value: "TEXT_RENAMED"},
		{Kind: "segment.permissions", Address: &address, Value: "r-x"},
		{Kind: "function.flags", Address: &address, Value: "noreturn,library"},
		{Kind: "function.flags", Address: &address, Value: ""},
		{Kind: "xref.code.add", Address: &address, Value: targetText, Subject: stringPointer("jump_near")},
		{Kind: "xref.data.delete", Address: &address, Value: targetText, Subject: stringPointer("read")},
		{Kind: "function.end", Address: &address, Value: targetText},
		{Kind: "function.chunk.add", Address: &address, Value: address.String(), Subject: &targetText},
	}
	for _, operation := range tests {
		if err := validateOperations([]ChangeOperation{operation}); err != nil {
			t.Errorf("%s rejected: %v", operation.Kind, err)
		}
	}
}

func TestDatabaseMutationOperationsRejectInvalidContracts(t *testing.T) {
	address := Address(0x401000)
	tests := []ChangeOperation{
		{Kind: "segment.rename", Address: &address, Value: ""},
		{Kind: "segment.permissions", Address: &address, Value: "rwx!"},
		{Kind: "function.flags", Address: &address, Value: "library,library"},
		{Kind: "function.flags", Address: &address, Value: "unknown"},
		{Kind: "xref.code.add", Address: &address, Value: "0x402000"},
		{Kind: "xref.code.add", Address: &address, Value: "0x402000", Subject: stringPointer("read")},
		{Kind: "xref.data.add", Address: &address, Value: "not-an-address", Subject: stringPointer("read")},
		{Kind: "function.end", Address: &address, Value: "not-an-address"},
		{Kind: "function.chunk.add", Address: &address, Value: "0x402000"},
		{Kind: "function.chunk.delete", Address: &address, Value: "0x402000", Subject: stringPointer("0x401000")},
	}
	for _, operation := range tests {
		if err := validateOperations([]ChangeOperation{operation}); err == nil {
			t.Errorf("%s accepted invalid contract: %+v", operation.Kind, operation)
		}
	}
}

func stringPointer(value string) *string { return &value }
