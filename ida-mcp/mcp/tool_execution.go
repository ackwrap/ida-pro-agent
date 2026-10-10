package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ServerOption func(*serverConfig)
type serverConfig struct{ diagnostics io.Writer }

// WithDiagnostics writes metadata only. CLI callers use stderr, never MCP stdout.
func WithDiagnostics(writer io.Writer) ServerOption {
	return func(config *serverConfig) { config.diagnostics = writer }
}

type diagnosticLogger struct {
	mutex  sync.Mutex
	writer io.Writer
}
type callTrace struct {
	method, stage string
	retries       int
}
type callTraceKey struct{}

func traceStage(ctx context.Context, method, stage string) {
	if trace, ok := ctx.Value(callTraceKey{}).(*callTrace); ok {
		trace.method, trace.stage = method, stage
	}
}

func (logger *diagnosticLogger) record(tool string, trace *callTrace, duration time.Duration, code ida.ErrorCode) {
	if logger == nil || logger.writer == nil {
		return
	}
	entry := struct {
		Tool       string        `json:"tool"`
		Method     string        `json:"method,omitempty"`
		Stage      string        `json:"stage"`
		DurationMs int64         `json:"durationMs"`
		Code       ida.ErrorCode `json:"code"`
		Retries    int           `json:"retries"`
	}{tool, trace.method, trace.stage, duration.Milliseconds(), code, trace.retries}
	logger.mutex.Lock()
	defer logger.mutex.Unlock()
	_ = json.NewEncoder(logger.writer).Encode(entry)
}

func methodContext(ctx context.Context, method *catalogMethod) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, time.Duration(method.TimeoutMs)*time.Millisecond)
}

func (registry *toolRegistry) executeMethod(ctx context.Context, request *mcp.CallToolRequest, method *catalogMethod, arguments json.RawMessage) (json.RawMessage, error) {
	traceStage(ctx, method.Name, "execute")
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, methodFailure(method, err)
		}
		output, err := registry.invokeDomainMethod(ctx, request, method.Name, arguments)
		var failure *ida.Error
		// Retry only an explicit busy rejection of an IDB read, never writes or timeouts.
		if err == nil || method.SideEffect != "none" || method.Domain == DomainInstances || attempt >= 2 || !errors.As(err, &failure) || failure.Code != ida.ErrorIDABusy || !failure.Retryable {
			if err != nil {
				return nil, methodFailure(method, err)
			}
			return output, nil
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, methodFailure(method, ctx.Err())
		case <-timer.C:
		}
		if trace, ok := ctx.Value(callTraceKey{}).(*callTrace); ok {
			trace.retries++
		}
	}
}
