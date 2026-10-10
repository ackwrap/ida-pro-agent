//go:build linux || darwin

package discovery

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ida-mcp/ida/rpc"
)

func TestUnixRegistryRejectsPublicFilesAndSymlinks(t *testing.T) {
	directory := canonicalTempDir(t)
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "registry.json")
	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if f, err := openInstanceFile(path); err == nil {
		f.Close()
		t.Fatal("public registry accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "alias.json")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if f, err := openInstanceFile(alias); err == nil {
		f.Close()
		t.Fatal("symlink registry accepted")
	}
	if !isProcessAlive(uint32(os.Getpid()), time.Now()) {
		t.Fatal("current process was rejected")
	}
	if isProcessAlive(uint32(os.Getpid()), time.Unix(1, 0)) {
		t.Fatal("PID reuse was not rejected")
	}
}

func TestUnixDiscoveryRemovesStaleSocket(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "ida-stale-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := testDescriptor("11111111", uint32(os.Getpid()))
	path := filepath.Join(directory, "ida-agent-"+registryFilename(descriptor)[:len(registryFilename(descriptor))-5]+".sock")
	descriptor.Version, descriptor.Pipe = 2, ""
	descriptor.Endpoint = &rpc.LocalEndpoint{Kind: "unix", Path: path}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	listener.Close()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	writeDescriptor(t, directory, descriptor)
	d := testDiscovery(directory, testProber{}, false)
	if _, err := d.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("stale socket retained: %v", err)
	}
}
