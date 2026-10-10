//go:build linux || darwin

package discovery

import (
	"os"
	"syscall"

	"ida-mcp/ida/rpc"
)

// Called only after descriptor validation, directory checks, and a dead/stale PID check.
func removeStaleEndpoint(descriptor rpc.InstanceDescriptor) {
	if descriptor.Endpoint == nil {
		return
	}
	info, err := os.Lstat(descriptor.Endpoint.Path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok && stat.Uid == uint32(os.Getuid()) && info.Mode().Perm()&0077 == 0 {
		_ = os.Remove(descriptor.Endpoint.Path)
	}
}
