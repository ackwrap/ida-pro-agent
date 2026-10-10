package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

type testProber struct{ err error }

func (prober testProber) InstanceInfo(
	_ context.Context,
	descriptor rpc.InstanceDescriptor,
) (bridge.InstanceInfo, error) {
	if prober.err != nil {
		return bridge.InstanceInfo{}, prober.err
	}
	return bridge.InstanceInfo{
		InstanceID: descriptor.InstanceID, PID: descriptor.PID,
		IDAVersion: descriptor.IDAVersion, Database: descriptor.Database,
		InputFile: descriptor.InputFile, Processor: descriptor.Processor,
		Bitness: descriptor.Bitness, Architecture: descriptor.Arch,
		Capabilities: descriptor.Capabilities,
	}, nil
}

func TestDiscoveryListsValidatedInstance(t *testing.T) {
	t.Parallel()
	directory := canonicalTempDir(t)
	descriptor := testDescriptor("11111111", 1)
	writeDescriptor(t, directory, descriptor)
	discovery := testDiscovery(directory, testProber{}, true)
	discovery.ReportError = func(err error) { t.Log(err) }
	instances, err := discovery.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(instances) != 1 || instances[0].InstanceID != descriptor.InstanceID {
		t.Fatalf("instances = %+v", instances)
	}
}

func TestDiscoverySortsMultipleInstances(t *testing.T) {
	t.Parallel()
	directory := canonicalTempDir(t)
	second := testDescriptor("22222222", 2)
	first := testDescriptor("11111111", 1)
	writeDescriptor(t, directory, second)
	writeDescriptor(t, directory, first)
	discovery := testDiscovery(directory, testProber{}, true)
	instances, err := discovery.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(instances) != 2 || instances[0].InstanceID != first.InstanceID {
		t.Fatalf("instances = %+v", instances)
	}
}

func TestDiscoveryRemovesDeadInstance(t *testing.T) {
	t.Parallel()
	directory := canonicalTempDir(t)
	descriptor := testDescriptor("11111111", 1)
	path := writeDescriptor(t, directory, descriptor)
	discovery := testDiscovery(directory, testProber{}, false)
	instances, err := discovery.List(context.Background())
	if err != nil || len(instances) != 0 {
		t.Fatalf("List = %+v, %v", instances, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale instance was not removed: %v", err)
	}
}

func TestDiscoveryKeepsTemporarilyUnreachableRegistry(t *testing.T) {
	t.Parallel()
	directory := canonicalTempDir(t)
	descriptor := testDescriptor("11111111", 1)
	path := writeDescriptor(t, directory, descriptor)
	discovery := testDiscovery(directory, testProber{err: errors.New("busy")}, true)
	instances, err := discovery.List(context.Background())
	if err != nil || len(instances) != 0 {
		t.Fatalf("List = %+v, %v", instances, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("live registry was removed: %v", err)
	}
}

func TestDiscoveryReturnsEmptyWithoutDirectory(t *testing.T) {
	t.Parallel()
	discovery := testDiscovery(filepath.Join(canonicalTempDir(t), "missing"), testProber{}, true)
	instances, err := discovery.List(context.Background())
	if err != nil || len(instances) != 0 {
		t.Fatalf("List = %+v, %v", instances, err)
	}
}

func testDiscovery(directory string, prober Prober, alive bool) *Discovery {
	discovery := New(directory)
	discovery.Prober = prober
	discovery.processAlive = func(uint32, time.Time) bool { return alive }
	return discovery
}

func testDescriptor(prefix string, pid uint32) rpc.InstanceDescriptor {
	instanceID := fmt.Sprintf("%s-0000-4000-8000-%012d", prefix, pid)
	return rpc.InstanceDescriptor{
		Version: 1, ProtocolVersion: rpc.ProtocolVersion, InstanceID: instanceID, PID: pid,
		Pipe: fmt.Sprintf(`\\.\pipe\ida-agent-%d-%s`, pid, prefix), IDAVersion: "9.4",
		Database: `D:\samples\test.i64`, InputFile: "test.exe", Processor: "metapc",
		Bitness: 64, StartedAt: 1788063000, Arch: "x86_64",
		Capabilities: rpc.InstanceCapabilities{AddressBits: 64},
	}
}

func writeDescriptor(t *testing.T, directory string, descriptor rpc.InstanceDescriptor) string {
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Helper()
	data, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := filepath.Join(directory, registryFilename(descriptor))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}
