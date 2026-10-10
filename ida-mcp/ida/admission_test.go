package ida

import (
	"context"
	"errors"
	"testing"
	"time"
)

func awaitQueueSize(t *testing.T, controller *admissionController, id string, size int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		controller.mutex.Lock()
		count := len(controller.waiting[id])
		controller.mutex.Unlock()
		if count == size {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("queue did not reach %d", size)
}
func TestAdmissionFIFOAndInstanceIsolation(t *testing.T) {
	controller := newAdmissionController()
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := controller.acquire(ctx, "a"); err != nil {
			t.Fatal(err)
		}
	}
	acquired := make(chan int, 3)
	results := make(chan error, 3)
	release := make([]chan struct{}, 3)
	for i := 0; i < 3; i++ {
		release[i] = make(chan struct{})
		go func(i int) {
			err := controller.acquire(ctx, "a")
			results <- err
			if err == nil {
				acquired <- i
				<-release[i]
				controller.release("a")
			}
		}(i)
		awaitQueueSize(t, controller, "a", i+1)
	}
	if err := controller.acquire(ctx, "b"); err != nil {
		t.Fatalf("another instance blocked: %v", err)
	}
	controller.release("b")
	controller.release("a")
	for i := 0; i < 3; i++ {
		select {
		case value := <-acquired:
			if value != i {
				t.Fatalf("FIFO=%d, want %d", value, i)
			}
		case <-time.After(time.Second):
			t.Fatal("queued request did not resume")
		}
		if err := <-results; err != nil {
			t.Fatal(err)
		}
		close(release[i])
	}
	controller.release("a")
	// Wait until the last worker returns its transferred slot.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		controller.mutex.Lock()
		empty := len(controller.active) == 0 && len(controller.waiting) == 0
		controller.mutex.Unlock()
		if empty {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("admission retained a slot")
}
func TestAdmissionQueueBoundAndCancellation(t *testing.T) {
	controller := newAdmissionController()
	for i := 0; i < 2; i++ {
		_ = controller.acquire(context.Background(), "a")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan error, maxQueuedRequestsPerInstance)
	for i := 0; i < maxQueuedRequestsPerInstance; i++ {
		go func() { results <- controller.acquire(ctx, "a") }()
		awaitQueueSize(t, controller, "a", i+1)
	}
	started := time.Now()
	err := controller.acquire(context.Background(), "a")
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != ErrorIDABusy || time.Since(started) > time.Second {
		t.Fatalf("full queue: %v", err)
	}
	cancel()
	for i := 0; i < maxQueuedRequestsPerInstance; i++ {
		select {
		case err := <-results:
			if !errors.As(err, &failure) || failure.Code != ErrorTimeout {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("cancelled queue blocked")
		}
	}
	awaitQueueSize(t, controller, "a", 0)
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	err = controller.acquire(ctx, "a")
	if !errors.As(err, &failure) || failure.Code != ErrorTimeout {
		t.Fatalf("deadline: %v", err)
	}
	controller.release("a")
	controller.release("a")
	if err := controller.acquire(context.Background(), "a"); err != nil {
		t.Fatal("cancelled wait leaked a slot")
	}
	controller.release("a")
}
func TestAdmissionCancellationGrantRace(t *testing.T) {
	for i := 0; i < 100; i++ {
		controller := newAdmissionController()
		_ = controller.acquire(context.Background(), "a")
		_ = controller.acquire(context.Background(), "a")
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- controller.acquire(ctx, "a") }()
		awaitQueueSize(t, controller, "a", 1)
		go cancel()
		controller.release("a")
		select {
		case err := <-done:
			if err == nil {
				controller.release("a")
			}
		case <-time.After(time.Second):
			t.Fatal("grant/cancel race blocked")
		}
		controller.release("a")
		controller.mutex.Lock()
		retained := len(controller.active) + len(controller.waiting)
		controller.mutex.Unlock()
		if retained != 0 {
			t.Fatal("grant/cancel race leaked a slot")
		}
	}
}
