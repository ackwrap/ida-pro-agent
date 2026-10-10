package mcpserver

import (
	"context"
	"sync"

	"ida-mcp/ida"
)

type instanceManager struct {
	backend ida.Backend
	mutex   sync.RWMutex
	active  string
}

func newInstanceManager(backend ida.Backend) *instanceManager {
	return &instanceManager{backend: backend}
}

func (manager *instanceManager) list(ctx context.Context) ([]ida.Instance, error) {
	if manager == nil || manager.backend == nil {
		return nil, ida.NewError(ida.ErrorInternal, "IDA backend is unavailable", false)
	}
	instances, err := manager.backend.ListInstances(ctx)
	if err != nil {
		return nil, err
	}
	manager.mutex.Lock()
	if manager.active != "" && !containsInstance(instances, manager.active) {
		manager.active = ""
	}
	manager.mutex.Unlock()
	return instances, nil
}

func (manager *instanceManager) selectInstance(ctx context.Context, instanceID string) (ida.Instance, error) {
	instances, err := manager.list(ctx)
	if err != nil {
		return ida.Instance{}, err
	}
	for _, instance := range instances {
		if instance.InstanceID == instanceID {
			manager.mutex.Lock()
			manager.active = instanceID
			manager.mutex.Unlock()
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
	manager.mutex.RLock()
	active := manager.active
	manager.mutex.RUnlock()
	for _, instance := range instances {
		if instance.InstanceID == active {
			copy := instance
			return &copy, nil
		}
	}
	return nil, nil
}

func (manager *instanceManager) resolve(instanceID *string) (string, error) {
	if instanceID != nil {
		return *instanceID, nil
	}
	manager.mutex.RLock()
	active := manager.active
	manager.mutex.RUnlock()
	if active == "" {
		return "", ida.NewError(
			ida.ErrorNotFound,
			"no active IDA instance; call ida.instances.select or provide instanceId",
			false,
		)
	}
	return active, nil
}

func containsInstance(instances []ida.Instance, instanceID string) bool {
	for _, instance := range instances {
		if instance.InstanceID == instanceID {
			return true
		}
	}
	return false
}
