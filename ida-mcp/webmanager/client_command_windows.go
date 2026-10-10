//go:build windows

package webmanager

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
)

func runCommand(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// CLI diagnostics on stderr must not corrupt the MCP list's JSON on stdout.
	return command.Output()
}

func findCodexCommand(home string, lookPath func(string) (string, error)) (string, error) {
	if override := strings.TrimSpace(os.Getenv("IDA_MCP_CODEX_PATH")); override != "" {
		if executable := nativeCodexCommand(override); executable != "" {
			return executable, nil
		}
		return "", fmt.Errorf("IDA_MCP_CODEX_PATH must point to an installed Codex executable or npm launcher with its native binary")
	}
	if command, err := lookPath("codex"); err == nil {
		if executable := nativeCodexCommand(command); executable != "" {
			return executable, nil
		}
	}
	// Explorer/tray processes can retain a PATH from before the CLI was installed.
	appData := absoluteEnvironmentPath("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	localAppData := absoluteEnvironmentPath("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	scoop := absoluteEnvironmentPath("SCOOP", filepath.Join(home, "scoop"))
	prefixes := []string{
		absoluteEnvironmentPath("NPM_CONFIG_PREFIX", filepath.Join(appData, "npm")),
		filepath.Join(appData, "npm"),
		filepath.Join(home, ".local", "bin"),
		filepath.Join(scoop, "apps", "nodejs", "current", "bin"),
		filepath.Join(scoop, "apps", "nodejs-lts", "current", "bin"),
		filepath.Join(scoop, "apps", "codex", "current"),
	}
	for _, prefix := range prefixes {
		for _, name := range []string{"codex.exe", "codex.cmd", "codex.ps1"} {
			if executable := nativeCodexCommand(filepath.Join(prefix, name)); executable != "" {
				return executable, nil
			}
		}
	}
	// The desktop app keeps versioned CLI binaries outside the user's PATH.
	root := filepath.Join(localAppData, "OpenAI", "Codex", "bin")
	entries, _ := os.ReadDir(root)
	type candidate struct {
		path string
		info os.FileInfo
	}
	var candidates []candidate
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(root, entry.Name(), "codex.exe")
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			candidates = append(candidates, candidate{path, info})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].info.ModTime().After(candidates[j].info.ModTime())
	})
	if len(candidates) != 0 {
		return candidates[0].path, nil
	}
	return "", fmt.Errorf("Codex CLI was not found. Install Codex or set IDA_MCP_CODEX_PATH to codex.exe, then restart this manager")
}

func absoluteEnvironmentPath(name, fallback string) string {
	if path := strings.TrimSpace(os.Getenv(name)); filepath.IsAbs(path) {
		return path
	}
	return fallback
}

func nativeCodexCommand(command string) string {
	// Do not reintroduce implicit executable lookup in the current directory.
	if !filepath.IsAbs(command) {
		return ""
	}
	if info, err := os.Stat(command); err != nil || !info.Mode().IsRegular() {
		return ""
	}
	if strings.EqualFold(filepath.Ext(command), ".exe") {
		return command
	}
	if !strings.EqualFold(filepath.Base(command), "codex.cmd") && !strings.EqualFold(filepath.Base(command), "codex.ps1") {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(command); err == nil {
		command = resolved
	}
	var architecture, target string
	switch runtime.GOARCH {
	case "amd64":
		architecture, target = "x64", "x86_64-pc-windows-msvc"
	case "arm64":
		architecture, target = "arm64", "aarch64-pc-windows-msvc"
	default:
		return ""
	}
	packages := filepath.Join(filepath.Dir(command), "node_modules", "@openai")
	platformPackage := "codex-win32-" + architecture
	for _, root := range []string{
		filepath.Join(packages, "codex", "node_modules", "@openai", platformPackage),
		filepath.Join(packages, platformPackage),
		filepath.Join(packages, "codex"),
	} {
		for _, directory := range []string{"bin", "codex"} {
			native := filepath.Join(root, "vendor", target, directory, "codex.exe")
			if info, err := os.Stat(native); err == nil && info.Mode().IsRegular() {
				return native
			}
		}
	}
	return ""
}
