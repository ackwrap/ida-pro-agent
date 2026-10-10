package ida

import (
	"context"
	"sync"
	"time"
)

const (
	maxConcurrentRequestsPerInstance = 2
	maxQueuedRequestsPerInstance     = 8
	admissionWaitTimeout             = 5 * time.Second
)

type admissionWaiter struct {
	ready   chan struct{}
	granted bool
}
type admissionController struct {
	mutex   sync.Mutex
	active  map[string]int
	waiting map[string][]*admissionWaiter
}

func newAdmissionController() *admissionController {
	return &admissionController{active: make(map[string]int), waiting: make(map[string][]*admissionWaiter)}
}

func (controller *admissionController) acquire(ctx context.Context, instanceID string) error {
	if err := ctx.Err(); err != nil {
		return normalizeBridgeError(err)
	}
	waitContext, cancel := context.WithTimeout(ctx, admissionWaitTimeout)
	defer cancel()
	controller.mutex.Lock()
	if controller.active[instanceID] < maxConcurrentRequestsPerInstance && len(controller.waiting[instanceID]) == 0 {
		controller.active[instanceID]++
		controller.mutex.Unlock()
		return nil
	}
	if len(controller.waiting[instanceID]) >= maxQueuedRequestsPerInstance {
		controller.mutex.Unlock()
		return NewError(ErrorIDABusy, "IDA request queue is full", true)
	}
	waiter := &admissionWaiter{ready: make(chan struct{})}
	controller.waiting[instanceID] = append(controller.waiting[instanceID], waiter)
	controller.mutex.Unlock()
	select {
	case <-waiter.ready:
		if waitContext.Err() == nil {
			return nil
		}
	case <-waitContext.Done():
	}
	controller.mutex.Lock()
	if waiter.granted {
		controller.releaseLocked(instanceID)
	} else {
		queue := controller.waiting[instanceID]
		for i, entry := range queue {
			if entry == waiter {
				queue = append(queue[:i], queue[i+1:]...)
				break
			}
		}
		if len(queue) == 0 {
			delete(controller.waiting, instanceID)
		} else {
			controller.waiting[instanceID] = queue
		}
	}
	controller.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return normalizeBridgeError(err)
	}
	return NewError(ErrorIDABusy, "IDA request queue wait expired", true)
}

func (controller *admissionController) release(instanceID string) {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()
	controller.releaseLocked(instanceID)
}

func (controller *admissionController) releaseLocked(instanceID string) {
	queue := controller.waiting[instanceID]
	if len(queue) > 0 {
		next := queue[0]
		if len(queue) == 1 {
			delete(controller.waiting, instanceID)
		} else {
			controller.waiting[instanceID] = queue[1:]
		}
		next.granted = true
		close(next.ready)
		return // Transfer the slot without increasing concurrency or bypassing FIFO.
	}
	if controller.active[instanceID] <= 1 {
		delete(controller.active, instanceID)
	} else {
		controller.active[instanceID]--
	}
}
