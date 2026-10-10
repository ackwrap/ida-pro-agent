//go:build !windows && !linux && !darwin

package discovery

import "os"

func openInstanceFile(path string) (*os.File, error) {
	return os.Open(path)
}
