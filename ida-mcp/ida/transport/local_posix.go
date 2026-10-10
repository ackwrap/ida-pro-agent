//go:build linux || darwin

package transport

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"ida-mcp/ida/localruntime"
)

type UnixDialer struct{ Timeout time.Duration }

func NewLocalDialer() *UnixDialer { return &UnixDialer{Timeout: 500 * time.Millisecond} }

func (dialer *UnixDialer) DialContext(ctx context.Context, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := localruntime.ValidateDirectory(filepath.Dir(address)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(address)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("IDA socket must be owned by this user with mode 0600")
	}
	d := net.Dialer{Timeout: dialer.Timeout}
	return d.DialContext(ctx, "unix", address)
}

// The kernel identity must match the registry before any RPC bytes are sent.
func ValidatePeer(connection net.Conn, pid uint32) error {
	socket, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("expected a Unix socket connection")
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return err
	}
	var credentialErr error
	if err = raw.Control(func(fd uintptr) {
		credentialErr = validatePeerIdentity(int(fd), pid)
	}); err != nil {
		return err
	}
	return credentialErr
}
