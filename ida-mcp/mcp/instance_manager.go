package mcpserver

import (
	"context"
	"sync"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type instanceManager struct {
	backend  ida.Backend
	mutex    sync.Mutex
	sessions map[*mcp.ServerSession]*instanceSelection
	fallback instanceSelection
}

type instanceSelection struct {
	mutex  sync.RWMutex
	active string
}

type instanceSelectionKey struct{}

func newInstanceManager(backend ida.Backend) *instanceManager {
	return &instanceManager{backend: backend, sessions: make(map[*mcp.ServerSession]*instanceSelection)}
}

func (manager *instanceManager) withSession(ctx context.Context, session *mcp.ServerSession) context.Context {
	if session == nil {
		return ctx
	}
	manager.mutex.Lock()
	selection := manager.sessions[session]
	if selection == nil {
		selection = &instanceSelection{}
		manager.sessions[session] = selection
		go func() {
			_ = session.Wait()
			manager.mutex.Lock()
			delete(manager.sessions, session)
			manager.mutex.Unlock()
		}()
	}
	manager.mutex.Unlock()
	return context.WithValue(ctx, instanceSelectionKey{}, selection)
}

func (manager *instanceManager) selection(ctx context.Context) *instanceSelection {
	if selection, ok := ctx.Value(instanceSelectionKey{}).(*instanceSelection); ok {
		return selection
	}
	return &manager.fallback
}

func (manager *instanceManager) list(ctx context.Context) ([]ida.Instance, error) {
	if manager == nil || manager.backend == nil {
		return nil, ida.NewError(ida.ErrorInternal, "IDA backend is unavailable", false)
	}
	instances, err := manager.backend.ListInstances(ctx)
	if err != nil {
		return nil, err
	}
	// A failed health probe must not silently change an explicit selection.
	return instances, nil
}

func (manager *instanceManager) selectInstance(ctx context.Context, instanceID string) (ida.Instance, error) {
	instances, err := manager.list(ctx)
	if err != nil {
		return ida.Instance{}, err
	}
	for _, instance := range instances {
		if instance.InstanceID == instanceID {
			selection := manager.selection(ctx)
			selection.mutex.Lock()
			selection.active = instanceID
			selection.mutex.Unlock()
			return instance, nil
		}
	}
	return ida.Instance{}, ida.NewError(ida.ErrorNotFound, "IDA instance was not found", false)
}

func (manager *instanceManager) activeInstance(ctx context.Context) (*ida.Instance, error) {
	instances, err := manager.list(ctx)
	if err != nil {
		return nil, err
	}
	selection := manager.selection(ctx)
	selection.mutex.RLock()
	active := selection.active
	selection.mutex.RUnlock()
	for _, instance := range instances {
		if instance.InstanceID == active {
			copy := instance
			return &copy, nil
		}
	}
	return nil, nil
}

func (manager *instanceManager) resolve(ctx context.Context, instanceID *string) (string, error) {
	if instanceID != nil {
		return *instanceID, nil
	}
	selection := manager.selection(ctx)
	selection.mutex.RLock()
	active := selection.active
	selection.mutex.RUnlock()
	if active == "" {
		return "", ida.NewError(
			ida.ErrorNotFound,
			"no active IDA instance; call ida.instances.select or provide instanceId",
			false,
		)
	}
	return active, nil
}
