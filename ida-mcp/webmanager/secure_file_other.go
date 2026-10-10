//go:build !windows

package webmanager

import "os"

func secureNewFile(string) error {
	return nil
}

func replaceFile(source, target string, _ bool) error {
	return os.Rename(source, target)
}
