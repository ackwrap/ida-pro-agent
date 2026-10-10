package ida

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Existing cancellation tests use short caller deadlines; this covers the
// controller's own five-second wait budget with a still-live caller context.
func TestAdmissionQueueWaitExpiresWithoutLeakingSlot(t *testing.T) {
	controller := newAdmissionController()
	for i := 0; i < maxConcurrentRequestsPerInstance; i++ {
		if err := controller.acquire(context.Background(), "a"); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), admissionWaitTimeout+5*time.Second)
	defer cancel()
	started := time.Now()
	err := controller.acquire(ctx, "a")
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != ErrorIDABusy || !failure.Retryable {
		t.Fatalf("queue expiry: %v", err)
	}
	if ctx.Err() != nil || time.Since(started) < admissionWaitTimeout {
		t.Fatal("caller deadline replaced admission budget")
	}
	awaitQueueSize(t, controller, "a", 0)
	for i := 0; i < maxConcurrentRequestsPerInstance; i++ {
		controller.release("a")
	}
	if err := controller.acquire(context.Background(), "a"); err != nil {
		t.Fatalf("expired waiter retained a slot: %v", err)
	}
	controller.release("a")
}
