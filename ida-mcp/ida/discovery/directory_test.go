package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultInstanceDirectoryOverride(t *testing.T) {
	t.Setenv("IDA_MCP_INSTANCE_DIR", filepath.Join(t.TempDir(), "legacy"))
	t.Setenv(instanceDirectoryEnvironment, filepath.Join(t.TempDir(), "instances"))
	want := filepath.Clean(os.Getenv(instanceDirectoryEnvironment))
	got, err := DefaultInstanceDirectory()
	if err != nil {
		t.Fatalf("DefaultInstanceDirectory: %v", err)
	}
	if got != want {
		t.Fatalf("directory = %q, want %q", got, want)
	}
}

func TestDefaultInstanceDirectoryIgnoresOldOverride(t *testing.T) {
	t.Setenv(instanceDirectoryEnvironment, "")
	t.Setenv("IDA_MCP_INSTANCE_DIR", filepath.Join(t.TempDir(), "legacy"))
	want, err := defaultInstanceDirectory()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DefaultInstanceDirectory()
	if err != nil || got != want {
		t.Fatalf("directory with old override = %q, %v; want %q", got, err, want)
	}
}
