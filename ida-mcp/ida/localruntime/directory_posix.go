//go:build linux || darwin

package localruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

func DefaultDirectory() string {
	// /tmp is a symlink on macOS; the private-directory walker rejects symlinks.
	if runtime.GOOS == "darwin" {
		return fmt.Sprintf("/private/tmp/ida-agent-%d/instances", os.Getuid())
	}
	return fmt.Sprintf("/tmp/ida-agent-%d/instances", os.Getuid())
}

// Do not follow symlinks or accept directories writable by other users.
// /tmp is allowed as a root-owned sticky ancestor, never as the final directory.
func ValidateDirectory(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return fmt.Errorf("instance directory must be an absolute normalized path")
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(directory, "/"), "/") {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || (stat.Uid != 0 && stat.Uid != uint32(os.Getuid())) {
			return fmt.Errorf("unsafe instance directory: %s", current)
		}
		if current == directory {
			if stat.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0077 != 0 {
				return fmt.Errorf("instance directory must be owned by this user with mode 0700")
			}
		} else if info.Mode().Perm()&0022 != 0 && !(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return fmt.Errorf("instance directory ancestor is writable by other users: %s", current)
		}
	}
	if directory == "/" {
		return fmt.Errorf("root cannot be an instance directory")
	}
	return nil
}
