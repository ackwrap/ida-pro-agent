package main

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	mcpserver "ida-mcp/mcp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The integration fixture runs headless. Never execute setup mutations in a
// user-controlled GUI session just to measure method coverage.
func verifyDebuggerSetupDenied(ctx context.Context, session *mcp.ClientSession, instanceID string, info *mcp.CallToolResult) {
	encoded, err := json.Marshal(info)
	if err != nil || !strings.Contains(string(encoded), "PERMISSION_DENIED") {
		log.Fatal("debugger setup integration requires denied headless consent")
	}
	for method, args := range map[string]map[string]any{
		mcpserver.ToolDebuggerBackends: {}, mcpserver.ToolDebuggerConfiguration: {}, mcpserver.ToolDebuggerProcesses: {"limit": 1},
		mcpserver.ToolDebuggerSelect: {"name": "win32", "remote": false}, mcpserver.ToolDebuggerConfigure: {"host": "localhost"},
		mcpserver.ToolDebuggerAttach: {"pid": 1234}, mcpserver.ToolDebuggerDetach: {}, mcpserver.ToolDebuggerSuspend: {},
	} {
		args["instanceId"] = instanceID
		result, err := callMethod(ctx, session, method, args)
		if err != nil || result == nil || !result.IsError {
			log.Fatalf("%s bypassed headless debugger consent: %v", method, err)
		}
		encoded, err = json.Marshal(result)
		if err != nil || !strings.Contains(string(encoded), "PERMISSION_DENIED") {
			log.Fatalf("%s did not return permission denial", method)
		}
	}
}
