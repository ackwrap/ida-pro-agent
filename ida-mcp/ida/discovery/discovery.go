package discovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"ida-mcp/ida/bridge"
	"ida-mcp/ida/rpc"
)

const (
	maxInstanceFiles    = 64
	maxConcurrentProbes = 16
	defaultProbeTimeout = 250 * time.Millisecond
)

type Prober interface {
	InstanceInfo(context.Context, rpc.InstanceDescriptor) (bridge.InstanceInfo, error)
}

type Discovery struct {
	Directory    string
	Prober       Prober
	ProbeTimeout time.Duration
	ReportError  func(error)
	processAlive func(uint32, time.Time) bool
}

func New(directory string) *Discovery {
	client := bridge.NewClient()
	client.Timeout = defaultProbeTimeout
	return &Discovery{
		Directory: directory, Prober: client, ProbeTimeout: defaultProbeTimeout,
		processAlive: isProcessAlive,
	}
}

func NewDefault() (*Discovery, error) {
	directory, err := DefaultInstanceDirectory()
	if err != nil {
		return nil, err
	}
	return New(directory), nil
}

type candidate struct {
	descriptor rpc.InstanceDescriptor
	path       string
}

type probeResult struct {
	descriptor rpc.InstanceDescriptor
	err        error
}

func (discovery *Discovery) List(ctx context.Context) ([]rpc.InstanceDescriptor, error) {
	entries, err := os.ReadDir(discovery.Directory)
	if errors.Is(err, os.ErrNotExist) {
		return []rpc.InstanceDescriptor{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read instance directory: %w", err)
	}
	if len(entries) > maxInstanceFiles {
		return nil, fmt.Errorf("instance directory contains more than %d entries", maxInstanceFiles)
	}
	if discovery.Prober == nil || discovery.processAlive == nil {
		return nil, errors.New("instance discovery dependencies are not configured")
	}

	candidates := make([]candidate, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(discovery.Directory, entry.Name())
		data, publishedAt, err := readInstanceFile(path)
		if err != nil {
			discovery.report(fmt.Errorf("read registry %s: %w", entry.Name(), err))
			continue
		}
		descriptor, err := rpc.DecodeInstanceDescriptor(data)
		if err != nil {
			discovery.report(fmt.Errorf("decode registry %s: %w", entry.Name(), err))
			continue
		}
		if descriptor.Endpoint != nil && filepath.Dir(descriptor.Endpoint.Path) != filepath.Clean(discovery.Directory) {
			discovery.report(fmt.Errorf("registry endpoint is outside the instance directory"))
			continue
		}
		if entry.Name() != registryFilename(descriptor) {
			discovery.report(fmt.Errorf("registry filename %s does not match identity", entry.Name()))
			continue
		}
		if !discovery.processAlive(descriptor.PID, publishedAt) {
			removeStaleEndpoint(descriptor)
			_ = os.Remove(path)
			continue
		}
		candidates = append(candidates, candidate{descriptor: descriptor, path: path})
	}

	results := make(chan probeResult, len(candidates))
	semaphore := make(chan struct{}, maxConcurrentProbes)
	var wait sync.WaitGroup
	for _, item := range candidates {
		item := item
		wait.Add(1)
		go func() {
			defer wait.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				results <- probeResult{err: ctx.Err()}
				return
			}
			probeTimeout := discovery.ProbeTimeout
			if probeTimeout <= 0 {
				probeTimeout = defaultProbeTimeout
			}
			probeContext, cancel := context.WithTimeout(ctx, probeTimeout)
			defer cancel()
			info, err := discovery.Prober.InstanceInfo(probeContext, item.descriptor)
			if err != nil {
				if discovery.ReportError != nil {
					discovery.ReportError(fmt.Errorf("instance %s probe failed: %w", item.descriptor.InstanceID, err))
				}
				results <- probeResult{err: err}
				return
			}
			descriptor := item.descriptor
			descriptor.IDAVersion = info.IDAVersion
			descriptor.Database = info.Database
			descriptor.InputFile = info.InputFile
			descriptor.Processor = info.Processor
			descriptor.Bitness = info.Bitness
			descriptor.Arch = info.Architecture
			descriptor.Capabilities = info.Capabilities
			if err := descriptor.Validate(); err != nil {
				results <- probeResult{err: err}
				return
			}
			results <- probeResult{descriptor: descriptor}
		}()
	}
	go func() {
		wait.Wait()
		close(results)
	}()

	instances := make([]rpc.InstanceDescriptor, 0, len(candidates))
	for result := range results {
		if result.err == nil {
			instances = append(instances, result.descriptor)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(instances, func(left, right int) bool {
		return strings.Compare(instances[left].InstanceID, instances[right].InstanceID) < 0
	})
	return instances, nil
}

func (discovery *Discovery) report(err error) {
	if discovery.ReportError != nil {
		discovery.ReportError(err)
	}
}

func registryFilename(descriptor rpc.InstanceDescriptor) string {
	return fmt.Sprintf("%d-%s.json", descriptor.PID, descriptor.InstanceID[:8])
}

func readInstanceFile(path string) ([]byte, time.Time, error) {
	file, err := openInstanceFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > rpc.MaxMessageBytes {
		return nil, time.Time{}, errors.New("instance file size or type is invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, rpc.MaxMessageBytes+1))
	if err != nil || len(data) > rpc.MaxMessageBytes {
		return nil, time.Time{}, errors.New("instance file exceeds size limit")
	}
	return data, info.ModTime(), nil
}
