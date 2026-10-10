package main

import (
	"context"
	"encoding/json"
	"log"
	"strconv"
	"strings"

	mcpserver "ida-mcp/mcp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func verifyRemainingMethods(ctx context.Context, session *mcp.ClientSession, instanceID, functionAddress, memoryPattern string) {
	end := addAddress(functionAddress, 0x1000)
	decodeToolResult(ctx, session, mcpserver.ToolMemorySearchBytes, map[string]any{"instanceId": instanceID, "pattern": memoryPattern, "start": functionAddress, "end": end, "limit": 2}, &struct {
		Items []string `json:"items"`
	}{})
	for _, method := range []string{mcpserver.ToolInstructionSearch, mcpserver.ToolInstructionQuery} {
		var page struct {
			Items      []json.RawMessage `json:"items"`
			NextCursor *string           `json:"nextCursor"`
		}
		arguments := map[string]any{"instanceId": instanceID, "start": functionAddress, "end": end, "limit": 2}
		decodeToolResult(ctx, session, method, arguments, &page)
		if page.NextCursor != nil {
			arguments["cursor"] = *page.NextCursor
			decodeToolResult(ctx, session, method, arguments, &page)
		}
	}
	decodeToolResult(ctx, session, mcpserver.ToolListingSearch, map[string]any{"instanceId": instanceID, "start": functionAddress, "end": end, "query": " ", "limit": 2}, &struct {
		Items     []json.RawMessage `json:"items"`
		Truncated bool              `json:"truncated"`
	}{})
	verifyCursorMethod(ctx, session, mcpserver.ToolListingSearchText, map[string]any{"instanceId": instanceID, "start": functionAddress, "end": end, "regex": ".", "limit": 2})
	verifyCursorMethod(ctx, session, mcpserver.ToolStringSearchRegex, map[string]any{"instanceId": instanceID, "pattern": ".", "minLength": 1, "limit": 2})
	decodeToolResult(ctx, session, mcpserver.ToolSignatureMake, map[string]any{
		"instanceId": instanceID, "mode": "function", "address": functionAddress,
		"wildcardOperands": false, "maxLength": 1000,
	}, &struct {
		Signature string `json:"signature"`
	}{})
	decodeToolResult(ctx, session, mcpserver.ToolSignatureXrefs, map[string]any{"instanceId": instanceID, "address": functionAddress, "top": 2}, &struct {
		Items []json.RawMessage `json:"items"`
	}{})

	typeName, fieldName := verifyTypeInventory(ctx, session, instanceID, functionAddress)
	verifyCursorMethod(ctx, session, mcpserver.ToolSourceFiles, map[string]any{"instanceId": instanceID, "limit": 1})
	verifyCursorMethod(ctx, session, mcpserver.ToolSourceLines, map[string]any{"instanceId": instanceID, "start": functionAddress, "end": end, "limit": 1})
	decodeToolResult(ctx, session, mcpserver.ToolNameDemangle, map[string]any{"instanceId": instanceID, "address": functionAddress}, &struct {
		Raw string `json:"raw"`
	}{})
	callEnvironmentDependent(ctx, session, mcpserver.ToolCommentGet, map[string]any{"instanceId": instanceID, "address": functionAddress})
	verifyCursorMethod(ctx, session, mcpserver.ToolBookmarkList, map[string]any{"instanceId": instanceID, "limit": 1})
	callEnvironmentDependent(ctx, session, mcpserver.ToolTypeXrefs, map[string]any{"instanceId": instanceID, "name": typeName, "limit": 1})
	var locals struct {
		Items []struct {
			Index uint32 `json:"index"`
		} `json:"items"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolDecompilerLocals, map[string]any{"instanceId": instanceID, "address": functionAddress, "maxItems": 100}, &locals)
	decodeToolResult(ctx, session, mcpserver.ToolDecompilerCtree, map[string]any{"instanceId": instanceID, "address": functionAddress, "maxDepth": 8, "maxNodes": 200}, &struct {
		Nodes []json.RawMessage `json:"nodes"`
	}{})
	if len(locals.Items) > 0 {
		decodeToolResult(ctx, session, mcpserver.ToolDecompilerLocalXrefs, map[string]any{"instanceId": instanceID, "address": functionAddress, "localIndex": locals.Items[0].Index}, &struct {
			Items []json.RawMessage `json:"items"`
		}{})
	} else {
		log.Fatal("decompiler.locals returned no local for decompiler.local_xrefs")
	}
	callEnvironmentDependent(ctx, session, mcpserver.ToolDebuggerThreads, map[string]any{"instanceId": instanceID, "limit": 1})
	callEnvironmentDependent(ctx, session, mcpserver.ToolDebuggerModules, map[string]any{"instanceId": instanceID, "limit": 1})
	callEnvironmentDependent(ctx, session, mcpserver.ToolXrefStructField, map[string]any{"instanceId": instanceID, "type": typeName, "field": fieldName, "limit": 2})
	decodeToolResult(ctx, session, mcpserver.ToolGlobalValue, map[string]any{"instanceId": instanceID, "address": functionAddress, "maxBytes": 16}, &struct {
		Value string `json:"value"`
	}{})
	callEnvironmentDependent(ctx, session, mcpserver.ToolTypeGet, map[string]any{"instanceId": instanceID, "name": typeName})
	callEnvironmentDependent(ctx, session, mcpserver.ToolTypeReadValue, map[string]any{"instanceId": instanceID, "address": functionAddress, "name": typeName, "maxBytes": 16})
	callEnvironmentDependent(ctx, session, mcpserver.ToolTypeReadStruct, map[string]any{"instanceId": instanceID, "address": functionAddress, "maxBytes": 16})
	callEnvironmentDependent(ctx, session, mcpserver.ToolTypeInfer, map[string]any{"instanceId": instanceID, "address": functionAddress})
	decodeToolResult(ctx, session, mcpserver.ToolAnalysisComponent, map[string]any{"instanceId": instanceID, "roots": []any{functionAddress}, "maxDepth": 1, "maxNodes": 20, "maxEdges": 40, "perFunction": 10, "sharedLimit": 10}, &struct {
		Members []json.RawMessage `json:"members"`
	}{})
	var trace struct {
		Model string `json:"model"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolAnalysisTraceDataFlow, map[string]any{"instanceId": instanceID, "address": functionAddress, "maxDepth": 1, "maxNodes": 20, "maxEdges": 40}, &trace)
	if trace.Model != "xref_bfs" {
		log.Fatal("analysis.trace_data_flow returned a non-xref_bfs model")
	}
	// This fixture is arbitrary code. Fixed argument/guard semantics are tested
	// separately against semantic_sample.cpp in the isolated IDA harness.
	for _, method := range []string{mcpserver.ToolTraceArgument, mcpserver.ToolGuardEvidence, mcpserver.ToolTraceArgumentCallers} {
		callEnvironmentDependent(ctx, session, method, map[string]any{"instanceId": instanceID, "callAddress": functionAddress, "argumentIndex": 0})
	}
}

func verifyCursorMethod(ctx context.Context, session *mcp.ClientSession, method string, arguments map[string]any) {
	var page struct {
		NextCursor *string `json:"nextCursor"`
	}
	decodeToolResult(ctx, session, method, arguments, &page)
	if page.NextCursor != nil {
		arguments["cursor"] = *page.NextCursor
		decodeToolResult(ctx, session, method, arguments, &page)
	}
}

func verifyTypeInventory(ctx context.Context, session *mcp.ClientSession, instanceID, address string) (string, string) {
	var search struct {
		Items []struct {
			Name    string `json:"name"`
			Members []struct {
				Name string `json:"name"`
			} `json:"members"`
		} `json:"items"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolTypeSearch, map[string]any{"instanceId": instanceID, "ordinal": 1, "limit": 1}, &search)
	decodeToolResult(ctx, session, mcpserver.ToolTypeQuery, map[string]any{"instanceId": instanceID, "ordinal": 1, "limit": 1}, &struct {
		Items []json.RawMessage `json:"items"`
	}{})
	if len(search.Items) == 0 {
		return "ida_agent_missing_type", "ida_agent_missing_field"
	}
	field := "ida_agent_missing_field"
	if len(search.Items[0].Members) != 0 {
		field = search.Items[0].Members[0].Name
	}
	return search.Items[0].Name, field
}

func callEnvironmentDependent(ctx context.Context, session *mcp.ClientSession, method string, arguments map[string]any) {
	if _, err := callMethod(ctx, session, method, arguments); err != nil {
		log.Fatalf("%s transport call failed: %v", method, err)
	}
}

func addAddress(encoded string, delta uint64) string {
	value, err := strconv.ParseUint(strings.TrimPrefix(encoded, "0x"), 16, 64)
	if err != nil || value > ^uint64(0)-delta {
		log.Fatalf("invalid ping address %q", encoded)
	}
	return "0x" + strconv.FormatUint(value+delta, 16)
}
