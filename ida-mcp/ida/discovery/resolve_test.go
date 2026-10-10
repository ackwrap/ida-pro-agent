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

type forbiddenProber struct{ t *testing.T }

func (p forbiddenProber) InstanceInfo(context.Context, rpc.InstanceDescriptor) (bridge.InstanceInfo, error) {
	p.t.Error("targeted resolution made a health probe")
	return bridge.InstanceInfo{}, errors.New("busy")
}

func TestResolveDoesNotProbeAndRevalidatesRegistry(t *testing.T) {
	dir := canonicalTempDir(t)
	a, b := testDescriptor("11111111", 1), testDescriptor("22222222", 2)
	path := writeDescriptor(t, dir, a)
	writeDescriptor(t, dir, b)
	d := testDiscovery(dir, forbiddenProber{t}, true)
	got, err := d.Resolve(context.Background(), a.InstanceID)
	if err != nil || got.InstanceID != a.InstanceID {
		t.Fatalf("Resolve = %+v, %v", got, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	_, err = d.Resolve(context.Background(), a.InstanceID)
	var failure *rpc.ResponseError
	if !errors.As(err, &failure) || failure.Code != rpc.ErrorNotFound {
		t.Fatalf("removed registry: %v", err)
	}
}

func TestResolveRejectsDuplicateIdentity(t *testing.T) {
	dir := canonicalTempDir(t)
	a := testDescriptor("11111111", 1)
	b := a
	b.PID = 2
	b.Pipe = `\\.\pipe\ida-agent-2-11111111`
	writeDescriptor(t, dir, a)
	writeDescriptor(t, dir, b)
	d := testDiscovery(dir, forbiddenProber{t}, true)
	_, err := d.Resolve(context.Background(), a.InstanceID)
	var failure *rpc.ResponseError
	if !errors.As(err, &failure) || failure.Code != rpc.ErrorConflict {
		t.Fatalf("duplicate: %v", err)
	}
}

func BenchmarkResolveSelectedInstance(b *testing.B) {
	// Registry enumeration is bounded to 64 entries; resolution does not open
	// pipes for any of the other databases.
	d := New(b.TempDir())
	d.processAlive = func(uint32, time.Time) bool { return true }
	var target string
	for index := 1; index <= maxInstanceFiles; index++ {
		descriptor := testDescriptor(fmt.Sprintf("%08x", index), uint32(index))
		data, err := json.Marshal(descriptor)
		if err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d.Directory, registryFilename(descriptor)), data, 0o600); err != nil {
			b.Fatal(err)
		}
		target = descriptor.InstanceID
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := d.Resolve(context.Background(), target); err != nil {
			b.Fatal(err)
		}
	}
}
