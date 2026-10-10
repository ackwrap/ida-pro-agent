package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"ida-mcp/ida"
	"ida-mcp/ida/diagnostics"

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
	mutex         sync.Mutex
	method, stage string
	retries       int
	phaseMs       map[string]float64
}
type callTraceKey struct{}

func traceStage(ctx context.Context, method, stage string) {
	if trace, ok := ctx.Value(callTraceKey{}).(*callTrace); ok {
		trace.mutex.Lock()
		trace.method, trace.stage = method, stage
		trace.mutex.Unlock()
	}
}

func (logger *diagnosticLogger) record(tool string, trace *callTrace, duration time.Duration, code ida.ErrorCode) {
	if logger == nil || logger.writer == nil {
		return
	}
	trace.mutex.Lock()
	defer trace.mutex.Unlock()
	entry := struct {
		Tool       string             `json:"tool"`
		Method     string             `json:"method,omitempty"`
		Stage      string             `json:"stage"`
		DurationMs int64              `json:"durationMs"`
		Code       ida.ErrorCode      `json:"code"`
		Retries    int                `json:"retries"`
		PhaseMs    map[string]float64 `json:"phaseMs,omitempty"`
	}{tool, trace.method, trace.stage, duration.Milliseconds(), code, trace.retries, trace.phaseMs}
	logger.mutex.Lock()
	defer logger.mutex.Unlock()
	_ = json.NewEncoder(logger.writer).Encode(entry)
}

func (trace *callTrace) recordPhase(phase string, duration time.Duration) {
	trace.mutex.Lock()
	defer trace.mutex.Unlock()
	if trace.phaseMs == nil {
		trace.phaseMs = make(map[string]float64)
	}
	trace.phaseMs[phase] += float64(duration.Microseconds()) / 1000
}

func methodContext(ctx context.Context, method *catalogMethod) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, time.Duration(method.TimeoutMs)*time.Millisecond)
}

func (registry *toolRegistry) executeMethod(ctx context.Context, request *mcp.CallToolRequest, method *catalogMethod, arguments json.RawMessage) (json.RawMessage, error) {
	defer diagnostics.Measure(ctx, "execute")()
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
			trace.mutex.Lock()
			trace.retries++
			trace.mutex.Unlock()
		}
	}
}
