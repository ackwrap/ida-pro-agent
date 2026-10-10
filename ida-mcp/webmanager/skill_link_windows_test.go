//go:build windows

package webmanager

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateDirectoryLinkFailureLeavesNoDirectory(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "skill")
	overlongTarget := `C:\` + strings.Repeat("a", 40000)
	if err := createDirectoryLink(destination, overlongTarget); err == nil {
		t.Fatal("overlong junction target was accepted")
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed junction left destination behind: %v", err)
	}

	target := filepath.Join(root, "source")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := createDirectoryLink(destination, target); err != nil {
		t.Fatalf("retry after failed junction: %v", err)
	}
	if err := removeManagedDirectoryLink(destination, target); err != nil {
		t.Fatalf("remove retry junction: %v", err)
	}
}
