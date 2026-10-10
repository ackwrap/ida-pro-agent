//go:build !windows

package webmanager

import (
	"context"
	"os/exec"
)

func runCommand(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	return exec.CommandContext(ctx, executable, arguments...).Output()
}

func findCodexCommand(_ string, lookPath func(string) (string, error)) (string, error) {
	return lookPath("codex")
}
