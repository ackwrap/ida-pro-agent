package rpc

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func protocolRoot(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate fixture_test.go")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", "protocol"))
}

func readFixture(t *testing.T, category, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(protocolRoot(t), "testdata", category, name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

func TestProtocolFilesContainValidJSON(t *testing.T) {
	t.Parallel()

	invalidJSON := filepath.Join(protocolRoot(t), "testdata", "invalid", "request-malformed.json")
	err := filepath.WalkDir(protocolRoot(t), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".json" || path == invalidJSON {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !json.Valid(data) {
			t.Errorf("invalid JSON: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk protocol files: %v", err)
	}
}

func TestStableErrorCodeFixture(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(protocolRoot(t), "testdata", "valid", "error-codes.json"))
	if err != nil {
		t.Fatalf("read error codes: %v", err)
	}
	var codes []ErrorCode
	if err := json.Unmarshal(data, &codes); err != nil {
		t.Fatalf("decode error codes: %v", err)
	}
	if len(codes) != len(validErrorCodes) {
		t.Fatalf("error code count = %d, want %d", len(codes), len(validErrorCodes))
	}
	for _, code := range codes {
		if _, ok := validErrorCodes[code]; !ok {
			t.Fatalf("unknown fixture error code %q", code)
		}
	}
}
