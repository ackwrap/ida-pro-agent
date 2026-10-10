//go:build windows

package webmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func missingCodexCommand(string) (string, error) { return "", exec.ErrNotFound }

func writeClientExecutable(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireClientExecutable(t *testing.T, got string, lookupErr error, want string) {
	t.Helper()
	if lookupErr != nil {
		t.Fatalf("native lookup = %q, %v; want %q", got, lookupErr, want)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("native lookup returned a non-absolute path: %q", got)
	}
	gotInfo, err := os.Stat(got)
	if err != nil {
		t.Fatalf("stat native lookup %q: %v", got, err)
	}
	wantInfo, err := os.Stat(want)
	if err != nil {
		t.Fatalf("stat expected executable %q: %v", want, err)
	}
	// Windows may expand an 8.3 path (RUNNER~1) while resolving an npm launcher.
	// Compare file identity so aliases pass but selecting another binary fails.
	if !os.SameFile(gotInfo, wantInfo) {
		t.Fatalf("native lookup = %q; want the file at %q", got, want)
	}
}

func TestCodexFindsNPMNativeBinaryWithoutNode(t *testing.T) {
	architecture, target := "x64", "x86_64-pc-windows-msvc"
	if runtime.GOARCH == "arm64" {
		architecture, target = "arm64", "aarch64-pc-windows-msvc"
	}
	for _, layout := range []string{"nested", "hoisted", "bundled"} {
		for _, binaryDirectory := range []string{"bin", "codex"} {
			t.Run(layout+"/"+binaryDirectory, func(t *testing.T) {
				isolateClientEnvironment(t)
				home := t.TempDir()
				prefix := filepath.Join(home, "npm with spaces & symbols")
				launcher := writeClientExecutable(t, filepath.Join(prefix, "codex.cmd"))
				root := filepath.Join(prefix, "node_modules", "@openai", "codex")
				if layout == "nested" {
					root = filepath.Join(root, "node_modules", "@openai", "codex-win32-"+architecture)
				} else if layout == "hoisted" {
					root = filepath.Join(prefix, "node_modules", "@openai", "codex-win32-"+architecture)
				}
				executable := writeClientExecutable(t, filepath.Join(root, "vendor", target, binaryDirectory, "codex.exe"))
				t.Setenv("PATH", t.TempDir())
				got, err := findCodexCommand(home, func(string) (string, error) { return launcher, nil })
				requireClientExecutable(t, got, err, executable)
			})
		}
	}
}

func TestCodexFindsCommonInstallsWithoutPATH(t *testing.T) {
	for _, installation := range []string{"npm", "scoop-node", "desktop"} {
		t.Run(installation, func(t *testing.T) {
			isolateClientEnvironment(t)
			home := t.TempDir()
			var executable string
			switch installation {
			case "npm":
				executable = filepath.Join(os.Getenv("APPDATA"), "npm", "codex.exe")
			case "scoop-node":
				executable = filepath.Join(os.Getenv("SCOOP"), "apps", "nodejs", "current", "bin", "codex.exe")
			case "desktop":
				root := filepath.Join(os.Getenv("LOCALAPPDATA"), "OpenAI", "Codex", "bin")
				old := writeClientExecutable(t, filepath.Join(root, "old", "codex.exe"))
				past := time.Now().Add(-24 * time.Hour)
				if err := os.Chtimes(old, past, past); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(root, "unfinished-update"), 0o700); err != nil {
					t.Fatal(err)
				}
				executable = filepath.Join(root, "current", "codex.exe")
			}
			writeClientExecutable(t, executable)
			got, err := findCodexCommand(home, missingCodexCommand)
			requireClientExecutable(t, got, err, executable)
		})
	}
}

func TestCodexOverrideAndPATHPrecedence(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	pathCLI := writeClientExecutable(t, filepath.Join(home, "path", "codex.exe"))
	override := writeClientExecutable(t, filepath.Join(home, "explicit", "codex.exe"))
	lookup := func(string) (string, error) { return pathCLI, nil }
	t.Setenv("IDA_MCP_CODEX_PATH", override)
	got, err := findCodexCommand(home, lookup)
	requireClientExecutable(t, got, err, override)
	t.Setenv("IDA_MCP_CODEX_PATH", "relative/codex.exe")
	if _, err := findCodexCommand(home, lookup); err == nil || !strings.Contains(err.Error(), "IDA_MCP_CODEX_PATH") {
		t.Fatalf("invalid explicit path silently fell back: %v", err)
	}
	t.Setenv("IDA_MCP_CODEX_PATH", "")
	got, err = findCodexCommand(home, lookup)
	requireClientExecutable(t, got, err, pathCLI)
}

func TestCodexMissingAndUnsafeLaunchersAreRejected(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	launcher := writeClientExecutable(t, filepath.Join(home, "codex.cmd"))
	for _, command := range []string{launcher, "codex.exe", filepath.Join(home, "directory.exe")} {
		if got := nativeCodexCommand(command); got != "" {
			t.Fatalf("accepted non-native or relative command %q: %q", command, got)
		}
	}
	manager := newClientManager(filepath.Join(home, "gateway.exe"), home, missingCodexCommand, nil)
	status := manager.codexStatus(context.Background())
	if status.Available || !strings.Contains(status.Detail, "IDA_MCP_CODEX_PATH") {
		t.Fatalf("missing CLI status = %+v", status)
	}
	if err := manager.configureCodex(context.Background(), true); err == nil {
		t.Fatal("configuration accepted a missing CLI")
	}
}

func TestClientCommandKeepsJSONSeparateFromStderr(t *testing.T) {
	t.Setenv("IDA_AGENT_TEST_CLIENT_COMMAND", "1")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	arguments := []string{`C:\with spaces\a&b\%value%.exe`, "mcp", "list", "--json"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := runCommand(ctx, executable, append([]string{"-test.run=^TestClientCommandHelper$", "--"}, arguments...)...)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := json.Unmarshal(output, &got); err != nil || !reflect.DeepEqual(got, arguments) {
		t.Fatalf("CLI stdout/arguments = %q, %v", output, err)
	}
}

func TestClientCommandHelper(t *testing.T) {
	if os.Getenv("IDA_AGENT_TEST_CLIENT_COMMAND") != "1" {
		return
	}
	for i, argument := range os.Args {
		if argument == "--" {
			fmt.Fprintln(os.Stderr, "CLI startup diagnostic")
			_ = json.NewEncoder(os.Stdout).Encode(os.Args[i+1:])
			os.Exit(0)
		}
	}
	os.Exit(2)
}

func TestCodexInstalledCLIWithoutPATH(t *testing.T) {
	if os.Getenv("IDA_AGENT_CODEX_INTEGRATION") != "1" {
		t.Skip("set IDA_AGENT_CODEX_INTEGRATION=1 to test the installed CLI with an isolated config")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", t.TempDir())
	t.Setenv("IDA_MCP_CODEX_PATH", "")
	t.Setenv("PATH", t.TempDir())
	if _, err := exec.LookPath("codex"); err == nil || !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("integration fixture unexpectedly finds Codex in PATH: %v", err)
	}
	gateway, _ := os.Executable()
	manager := newClientManager(gateway, home, exec.LookPath, runCommand)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if status := manager.codexStatus(ctx); !status.Available || status.Configured || status.Detail != "ida-mcp is not configured." {
		t.Fatalf("initial installed CLI status = %+v", status)
	}
	if err := manager.configureCodex(ctx, true); err != nil {
		t.Fatal(err)
	}
	if status := manager.codexStatus(ctx); !status.Current {
		t.Fatalf("configured CLI status = %+v", status)
	}
	if err := manager.configureCodex(ctx, false); err != nil {
		t.Fatal(err)
	}
	if status := manager.codexStatus(ctx); status.Configured || !status.Available {
		t.Fatalf("removed CLI status = %+v", status)
	}
}
