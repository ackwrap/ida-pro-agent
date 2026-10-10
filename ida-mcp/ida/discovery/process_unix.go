//go:build !windows && !linux && !darwin

package discovery

import (
	"errors"
	"os"
	"syscall"
	"time"
)

func isProcessAlive(pid uint32, _ time.Time) bool {
	process, err := os.FindProcess(int(pid))
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}
