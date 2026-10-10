//go:build linux || darwin

package transport

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixSocketIdentityPermissionsAndDeadline(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "ida-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "test.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	connection, err := NewLocalDialer().DialContext(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if err := ValidatePeer(connection, uint32(os.Getpid())); err != nil {
		t.Fatal(err)
	}
	if ValidatePeer(connection, uint32(os.Getpid()+1)) == nil {
		t.Fatal("wrong server PID accepted")
	}
	if err := connection.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("read ignored deadline")
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if c, err := NewLocalDialer().DialContext(context.Background(), path); err == nil {
		c.Close()
		t.Fatal("public socket accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if c, err := NewLocalDialer().DialContext(context.Background(), path); err == nil {
		c.Close()
		t.Fatal("non-private directory accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c, err := NewLocalDialer().DialContext(ctx, path); err == nil {
		c.Close()
		t.Fatal("cancelled context accepted")
	}
}
