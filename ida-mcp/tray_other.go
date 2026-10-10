//go:build !windows

package main

import (
	"context"
)

func runSystemTray(ctx context.Context, _ context.CancelFunc, _ string) error {
	<-ctx.Done()
	return nil
}
