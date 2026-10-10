// Package diagnostics carries optional, metadata-only call timings across the
// Gateway layers without coupling the bridge to the MCP transport.
package diagnostics

import (
	"context"
	"time"
)

type recorderKey struct{}
type Recorder func(string, time.Duration)

func WithRecorder(ctx context.Context, recorder Recorder) context.Context {
	return context.WithValue(ctx, recorderKey{}, recorder)
}

func Measure(ctx context.Context, phase string) func() {
	recorder, _ := ctx.Value(recorderKey{}).(Recorder)
	if recorder == nil {
		return func() {}
	}
	started := time.Now()
	return func() { recorder(phase, time.Since(started)) }
}
