//go:build !windows && !linux && !darwin

package discovery

import (
	"os"
	"path/filepath"
)

func defaultInstanceDirectory() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cache, "ida-agent", "instances"), nil
}
