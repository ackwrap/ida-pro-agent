//go:build !windows

package main

import (
	"context"
	"testing"
	"time"
)

func TestHeadlessWebModeWaitsForCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runSystemTray(ctx, cancel, "http://127.0.0.1") }()
	select {
	case err := <-done:
		t.Fatalf("web mode exited before cancellation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("web mode ignored cancellation")
	}
}
