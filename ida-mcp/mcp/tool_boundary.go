package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"ida-mcp/ida"
	"ida-mcp/ida/diagnostics"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type boundaryHandler func(context.Context, *mcp.CallToolRequest) (any, error)

// Own validation at this boundary: SDK generic AddTool reports input schema
// failures as protocol errors before a typed handler can make them actionable.
func (registry *toolRegistry) addBoundaryTool(server *mcp.Server, tool *mcp.Tool, handler boundaryHandler) {
	server.AddTool(tool, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ctx = registry.instances.withSession(ctx, request.Session)
		started := time.Now()
		trace := &callTrace{stage: "validate"}
		ctx = context.WithValue(ctx, callTraceKey{}, trace)
		if registry.diagnostics.writer != nil {
			ctx = diagnostics.WithRecorder(ctx, trace.recordPhase)
		}
		code := ida.ErrorCode("OK")
		defer func() { registry.diagnostics.record(tool.Name, trace, time.Since(started), code) }()
		output, err := handler(ctx, request)
		if err != nil {
			var failure *toolFailure
			if !errors.As(err, &failure) {
				failure = methodFailure(&catalogMethod{SideEffect: "none"}, err)
			}
			output = failure
			code = failure.Code
		}
		encoded, encodingError := json.Marshal(output)
		if encodingError != nil {
			code = ida.ErrorInternal
			encoded, _ = json.Marshal(&toolFailure{Code: code, Message: "Tool result encoding failed", Hint: "Report this Gateway error."})
			err = encodingError
		}
		return &mcp.CallToolResult{
			IsError: err != nil, StructuredContent: json.RawMessage(encoded),
			Content: []mcp.Content{&mcp.TextContent{Text: string(encoded)}},
		}, nil
	})
}
