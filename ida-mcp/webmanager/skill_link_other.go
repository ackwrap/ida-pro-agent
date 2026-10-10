//go:build !windows

package webmanager

import (
	"fmt"
	"os"
)

func createDirectoryLink(path, target string) error {
	return os.Symlink(target, path)
}

func removeManagedDirectoryLink(path, expectedTarget string) error {
	state, err := directoryLinkState(path, expectedTarget)
	if err != nil || state == linkAbsent {
		return err
	}
	if state != linkCurrent {
		return fmt.Errorf("directory link is not managed by this installation: %w", os.ErrPermission)
	}
	return os.Remove(path)
}
