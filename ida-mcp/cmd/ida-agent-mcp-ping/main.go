package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"time"
	"unicode/utf8"

	idabackend "ida-mcp/ida"
	"ida-mcp/ida/bridge"
	"ida-mcp/ida/discovery"
	mcpserver "ida-mcp/mcp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	instanceDirectory := flag.String("instance-dir", "", "directory containing IDA Agent instances")
	gatewayExecutable := flag.String("gateway-executable", "", "external Gateway executable for stdio verification")
	functionAddress := flag.String("function-address", "", "function address for MCP verification")
	xrefAddress := flag.String("xref-address", "", "xref source address for MCP verification")
	memoryBytes := flag.String("memory-bytes", "", "expected bytes at the function address")
	stringAddress := flag.String("string-address", "", "expected UTF-8 string address")
	stringValue := flag.String("string-value", "", "base64-encoded expected UTF-8 string")
	stackFrameAddress := flag.String("stack-frame-address", "", "function address with a stack frame, when available")
	nonFunctionAddress := flag.String("non-function-address", "", "mapped non-function address for mutation verification")
	boundsFunctionAddress := flag.String("bounds-function-address", "", "function entry for end mutation verification")
	boundsExtendedEnd := flag.String("bounds-extended-end", "", "extended function end for mutation verification")
	tailStart := flag.String("tail-start", "", "unowned code range start for function tail verification")
	tailEnd := flag.String("tail-end", "", "unowned code range end for function tail verification")
	timeout := flag.Duration("timeout", 90*time.Second, "MCP verification timeout")
	flag.Parse()
	if *instanceDirectory == "" || *functionAddress == "" || *xrefAddress == "" || *memoryBytes == "" ||
		*stringAddress == "" || *stringValue == "" || *nonFunctionAddress == "" || *boundsFunctionAddress == "" ||
		*boundsExtendedEnd == "" || *tailStart == "" || *tailEnd == "" {
		log.Fatal("instance-dir and all verification addresses are required")
	}
	expectedBytes, err := hex.DecodeString(*memoryBytes)
	if err != nil || len(expectedBytes) == 0 || len(expectedBytes) > 4096 {
		log.Fatal("memory-bytes is invalid")
	}
	expectedString, err := base64.StdEncoding.DecodeString(*stringValue)
	if err != nil || len(expectedString) == 0 || len(expectedString) > 1024 || !utf8.Valid(expectedString) {
		log.Fatal("string-value is invalid")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	client := mcp.NewClient(
		&mcp.Implementation{Name: "ida-agent-integration", Version: "1.0.0"},
		nil,
	)
	var transport mcp.Transport
	var closeHTTP func()
	if *gatewayExecutable == "" {
		instances := discovery.New(*instanceDirectory)
		instances.ReportError = func(error) {}
		bridgeClient := bridge.NewClient()
		bridgeClient.Timeout = 120 * time.Second
		backend := idabackend.NewBridgeBackend(instances, bridgeClient)
		handler, err := mcpserver.NewHTTPHandler("integration-test", backend)
		if err != nil {
			log.Fatal(err)
		}
		httpServer := httptest.NewServer(handler)
		closeHTTP = httpServer.Close
		transport = &mcp.StreamableClientTransport{
			Endpoint: httpServer.URL + "/mcp", HTTPClient: &http.Client{Timeout: 45 * time.Second},
			MaxRetries: -1,
		}
	} else {
		command := exec.Command(
			*gatewayExecutable,
			"-transport", "stdio",
			"-instance-dir", *instanceDirectory,
		)
		command.Stderr = os.Stderr
		transport = &mcp.CommandTransport{
			Command:           command,
			TerminateDuration: 5 * time.Second,
		}
	}
	if closeHTTP != nil {
		defer closeHTTP()
	}
	clientSession, err := client.Connect(ctx, transport, nil)
	if err != nil {
		log.Fatal(err)
	}

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	if len(tools.Tools) != 23 {
		log.Fatalf("tools/list returned %d tools", len(tools.Tools))
	}

	var listed struct {
		Instances []struct {
			InstanceID string `json:"instanceId"`
		} `json:"instances"`
	}
	decodeToolResult(ctx, clientSession, mcpserver.ToolInstancesList, map[string]any{}, &listed)
	if len(listed.Instances) != 1 {
		log.Fatalf("ida.instances.list returned %d instances", len(listed.Instances))
	}
	instanceID := listed.Instances[0].InstanceID
	decodeToolResult(ctx, clientSession, mcpserver.ToolInstancesSelect, map[string]any{
		"instanceId": instanceID,
	}, &map[string]any{})
	var active struct {
		ActiveInstance *struct {
			InstanceID string `json:"instanceId"`
		} `json:"activeInstance"`
	}
	decodeToolResult(ctx, clientSession, mcpserver.ToolInstancesGetActive, map[string]any{}, &active)
	if active.ActiveInstance == nil || active.ActiveInstance.InstanceID != instanceID {
		log.Fatalf("ida.instances.get_active did not return %q", instanceID)
	}
	var database map[string]any
	decodeToolResult(ctx, clientSession, mcpserver.ToolDatabaseInfo, map[string]any{}, &database)
	verifyBoundedInventory(ctx, clientSession, mcpserver.ToolDatabaseSegments, map[string]any{
		"instanceId": instanceID, "limit": 1,
	})
	verifyBoundedInventory(ctx, clientSession, mcpserver.ToolStringSearch, map[string]any{
		"instanceId": instanceID, "limit": 1,
	})
	verifyBoundedInventory(ctx, clientSession, mcpserver.ToolSymbolImports, map[string]any{
		"instanceId": instanceID, "limit": 1,
	})
	verifyBoundedInventory(ctx, clientSession, mcpserver.ToolDatabaseEntryPoints, map[string]any{
		"instanceId": instanceID, "limit": 1,
	})
	verifyBoundedInventory(ctx, clientSession, mcpserver.ToolSymbolExports, map[string]any{
		"instanceId": instanceID, "limit": 1,
	})
	verifySparseBoundedInventory(ctx, clientSession, mcpserver.ToolSymbolSearch, map[string]any{
		"instanceId": instanceID, "limit": 1,
	})
	var expectedStringSearch struct {
		Items []struct {
			Address string `json:"address"`
			Value   string `json:"value"`
		} `json:"items"`
	}
	decodeToolResult(ctx, clientSession, mcpserver.ToolStringSearch, map[string]any{
		"instanceId": instanceID, "query": string(expectedString), "minLength": 1, "limit": 20,
	}, &expectedStringSearch)
	foundExpectedString := false
	for _, item := range expectedStringSearch.Items {
		foundExpectedString = foundExpectedString ||
			(item.Address == *stringAddress && item.Value == string(expectedString))
	}
	if !foundExpectedString {
		log.Fatal("string.search did not return the expected UTF-8 string")
	}
	var function map[string]any
	decodeToolResult(ctx, clientSession, mcpserver.ToolFunctionGet, map[string]any{
		"instanceId": instanceID,
		"address":    *functionAddress,
	}, &function)
	for _, analysisTool := range []string{
		mcpserver.ToolFunctionDisassemble,
		mcpserver.ToolFunctionBasicBlocks,
		mcpserver.ToolFunctionCallees,
	} {
		var analysis struct {
			EntryAddress string            `json:"entryAddress"`
			Items        []json.RawMessage `json:"items"`
			NextOffset   *uint32           `json:"nextOffset"`
			HasMore      bool              `json:"hasMore"`
		}
		decodeToolResult(ctx, clientSession, analysisTool, map[string]any{
			"instanceId": instanceID,
			"address":    *functionAddress,
			"limit":      1,
		}, &analysis)
		if analysis.EntryAddress == "" || analysis.HasMore != (analysis.NextOffset != nil) {
			log.Fatalf("%s returned invalid analysis metadata", analysisTool)
		}
	}
	var search struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor *string           `json:"nextCursor"`
		HasMore    bool              `json:"hasMore"`
	}
	decodeToolResult(ctx, clientSession, mcpserver.ToolFunctionSearch, map[string]any{
		"instanceId": instanceID,
		"name":       "",
		"limit":      1,
	}, &search)
	if len(search.Items) != 1 {
		log.Fatal("function.search returned no result")
	}
	if !search.HasMore || search.NextCursor == nil {
		log.Fatal("function.search did not return a continuation")
	}
	var searchContinuation struct {
		Items []json.RawMessage `json:"items"`
	}
	decodeToolResult(ctx, clientSession, mcpserver.ToolFunctionSearch, map[string]any{
		"instanceId": instanceID,
		"name":       "",
		"limit":      1,
		"cursor":     *search.NextCursor,
	}, &searchContinuation)
	if len(searchContinuation.Items) != 1 {
		log.Fatal("function.search continuation returned no result")
	}
	assertTamperedCursorRejected(ctx, clientSession, mcpserver.ToolFunctionSearch, map[string]any{
		"instanceId": instanceID,
		"name":       "",
		"limit":      1,
	}, *search.NextCursor)
	var xrefs struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor *string           `json:"nextCursor"`
		HasMore    bool              `json:"hasMore"`
	}
	decodeToolResult(ctx, clientSession, mcpserver.ToolXrefQuery, map[string]any{
		"instanceId": instanceID,
		"address":    *xrefAddress,
		"direction":  "outgoing",
		"limit":      1,
	}, &xrefs)
	if len(xrefs.Items) != 1 {
		log.Fatal("xref.query returned no result")
	}
	if !xrefs.HasMore || xrefs.NextCursor == nil {
		log.Fatal("xref.query did not return a continuation")
	}
	var xrefContinuation struct {
		Items []json.RawMessage `json:"items"`
	}
	decodeToolResult(ctx, clientSession, mcpserver.ToolXrefQuery, map[string]any{
		"instanceId": instanceID,
		"address":    *xrefAddress,
		"direction":  "outgoing",
		"limit":      1,
		"cursor":     *xrefs.NextCursor,
	}, &xrefContinuation)
	if len(xrefContinuation.Items) != 1 {
		log.Fatal("xref.query continuation returned no result")
	}
	assertTamperedCursorRejected(ctx, clientSession, mcpserver.ToolXrefQuery, map[string]any{
		"instanceId": instanceID,
		"address":    *xrefAddress,
		"direction":  "outgoing",
		"limit":      1,
	}, *xrefs.NextCursor)
	var memory struct {
		Value string `json:"value"`
	}
	decodeToolResult(ctx, clientSession, mcpserver.ToolMemoryRead, map[string]any{
		"instanceId": instanceID,
		"address":    *functionAddress,
		"format":     "bytes",
		"length":     len(expectedBytes),
	}, &memory)
	if memory.Value != hex.EncodeToString(expectedBytes) {
		log.Fatal("memory.read returned unexpected bytes")
	}
	var decompiled struct {
		ReturnedSize uint32  `json:"returnedSize"`
		Truncated    bool    `json:"truncated"`
		NextOffset   *uint32 `json:"nextOffset"`
	}
	decodeToolResult(ctx, clientSession, mcpserver.ToolFunctionDecompile, map[string]any{
		"instanceId": instanceID,
		"address":    *functionAddress,
		"maxBytes":   64,
	}, &decompiled)
	if decompiled.ReturnedSize == 0 {
		log.Fatal("function.decompile returned no text")
	}
	if decompiled.Truncated {
		if decompiled.NextOffset == nil {
			log.Fatal("function.decompile omitted continuation")
		}
		var continuation struct {
			Offset       uint32 `json:"offset"`
			ReturnedSize uint32 `json:"returnedSize"`
		}
		decodeToolResult(ctx, clientSession, mcpserver.ToolFunctionDecompile, map[string]any{
			"instanceId": instanceID,
			"address":    *functionAddress,
			"offset":     *decompiled.NextOffset,
			"maxBytes":   64,
		}, &continuation)
		if continuation.Offset != *decompiled.NextOffset || continuation.ReturnedSize == 0 {
			log.Fatal("function.decompile continuation is invalid")
		}
	}
	verifyCatalogMethods(ctx, clientSession, instanceID, *functionAddress, *stackFrameAddress)
	verifyMutationDebuggerDomains(ctx, clientSession, instanceID, *functionAddress)
	verifyDatabaseMutations(ctx, clientSession, instanceID, *functionAddress, *nonFunctionAddress, *stringAddress,
		*boundsFunctionAddress, *boundsExtendedEnd, *tailStart, *tailEnd)
	verifyRemainingMethods(ctx, clientSession, instanceID, *functionAddress, *memoryBytes)
	planEnd := addAddress(*functionAddress, 1)
	var planned struct {
		Accepted bool   `json:"accepted"`
		Queue    string `json:"queue"`
	}
	decodeToolResult(ctx, clientSession, mcpserver.ToolAnalysisPlan, map[string]any{"instanceId": instanceID, "start": *functionAddress, "end": planEnd, "confirm": true}, &planned)
	if !planned.Accepted || planned.Queue != "used" {
		log.Fatal("analysis.plan did not accept the mapped range")
	}

	verifiedTransport := "http"
	if *gatewayExecutable != "" {
		verifiedTransport = "stdio"
	}
	if err := clientSession.Close(); err != nil {
		log.Fatalf("close %s MCP session: %v", verifiedTransport, err)
	}
	fmt.Println("databaseMutations=ok")
	fmt.Printf("mcpDomains=ok callableMethods=98 transport=%s instance=%s\n", verifiedTransport, instanceID)
}

func verifyMutationDebuggerDomains(ctx context.Context, session *mcp.ClientSession, instanceID, address string) {
	operation := map[string]any{"kind": "comment.set", "address": address, "value": "ida-mcp-domain-ping"}
	var preview struct {
		PreviewID  string `json:"previewId"`
		Applicable bool   `json:"applicable"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolChangeSetPreview, map[string]any{
		"instanceId": instanceID, "operations": []any{operation},
	}, &preview)
	if preview.PreviewID == "" || !preview.Applicable {
		log.Fatal("changeset.preview did not return an applicable preview")
	}
	var applied struct {
		ChangeID string `json:"changeId"`
		Applied  bool   `json:"applied"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolChangeSetApply, map[string]any{
		"instanceId": instanceID, "previewId": preview.PreviewID, "operations": []any{operation},
	}, &applied)
	if applied.ChangeID == "" || !applied.Applied {
		log.Fatal("changeset.apply did not apply the preview")
	}
	verifyChangeAudit(ctx, session, instanceID, applied.ChangeID)
	rollbackChange(ctx, session, instanceID, applied.ChangeID)

	var assembly struct {
		Bytes string `json:"bytes"`
		Size  uint32 `json:"size"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolPatchAssemble, map[string]any{
		"instanceId": instanceID, "address": address, "instruction": "nop",
	}, &assembly)
	if assembly.Bytes == "" || assembly.Size == 0 {
		log.Fatal("patch.assemble returned no bytes")
	}
	decodeToolResult(ctx, session, mcpserver.ToolPatchWriteBytes, map[string]any{
		"instanceId": instanceID, "address": address, "bytes": assembly.Bytes,
	}, &applied)
	if applied.ChangeID == "" || !applied.Applied {
		log.Fatal("patch.write_bytes did not apply the patch")
	}
	verifyChangeAudit(ctx, session, instanceID, applied.ChangeID)
	rollbackChange(ctx, session, instanceID, applied.ChangeID)
	decodeToolResult(ctx, session, mcpserver.ToolPatchWriteInteger, map[string]any{
		"instanceId": instanceID, "address": address, "value": "0", "integerType": "u8",
	}, &applied)
	if applied.ChangeID == "" || !applied.Applied {
		log.Fatal("patch.write_integer did not apply the patch")
	}
	verifyChangeAudit(ctx, session, instanceID, applied.ChangeID)
	rollbackChange(ctx, session, instanceID, applied.ChangeID)

	diffAction := map[string]any{"kind": "comment.set", "address": address, "value": "ida-mcp-diff-ping"}
	var diff struct {
		Changed bool `json:"changed"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolDiffBeforeAfter, map[string]any{
		"instanceId": instanceID, "action": diffAction,
	}, &diff)
	verifyDebuggerWithoutProcess(ctx, session, instanceID, address)
}

func rollbackChange(ctx context.Context, session *mcp.ClientSession, instanceID, changeID string) {
	var rollback struct {
		Applied bool `json:"applied"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolChangeSetRollback, map[string]any{
		"instanceId": instanceID, "changeId": changeID,
	}, &rollback)
	if !rollback.Applied {
		log.Fatal("changeset.rollback did not restore the change")
	}
}

func verifyChangeAudit(ctx context.Context, session *mcp.ClientSession, instanceID, changeID string) {
	var audit struct {
		Items []struct {
			ChangeID string `json:"changeId"`
		} `json:"items"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolChangeSetAudit, map[string]any{
		"instanceId": instanceID, "limit": 1000,
	}, &audit)
	for _, item := range audit.Items {
		if item.ChangeID == changeID {
			return
		}
	}
	log.Fatal("changeset.audit did not contain the applied change")
}

func verifyDebuggerWithoutProcess(ctx context.Context, session *mcp.ClientSession, instanceID, address string) {
	info, err := callMethod(ctx, session, mcpserver.ToolDebuggerInfo, map[string]any{"instanceId": instanceID})
	if err != nil {
		log.Fatalf("debugger.info: %v", err)
	}
	if info.IsError {
		verifyDebuggerSetupDenied(ctx, session, instanceID, info)
		verifyDebuggerErrors(ctx, session, instanceID, address, false)
		return
	}
	var state struct {
		State   string `json:"state"`
		Running bool   `json:"running"`
	}
	decodeDomainResult(info, &state)
	if state.State != "not_running" || state.Running {
		log.Fatal("debugger.info did not report the no-process branch")
	}
	var breakpoints struct {
		Items []json.RawMessage `json:"items"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolDebuggerBreakpoints, map[string]any{"instanceId": instanceID}, &breakpoints)
	verifyDebuggerErrors(ctx, session, instanceID, address, true)
}

func verifyDebuggerErrors(ctx context.Context, session *mcp.ClientSession, instanceID, address string, invalidStart bool) {
	start := map[string]any{}
	if invalidStart {
		start["doNotStart"] = true
	}
	for method, arguments := range map[string]map[string]any{
		mcpserver.ToolDebuggerStart: start, mcpserver.ToolDebuggerExit: {},
		mcpserver.ToolDebuggerControl:   {"action": "continue"},
		mcpserver.ToolDebuggerRegisters: {}, mcpserver.ToolDebuggerStackTrace: {},
		mcpserver.ToolDebuggerMemoryRead:  {"address": address, "length": 1},
		mcpserver.ToolDebuggerMemoryWrite: {"address": address, "bytes": "00"},
	} {
		arguments["instanceId"] = instanceID
		result, err := callMethod(ctx, session, method, arguments)
		if err != nil || !result.IsError {
			log.Fatalf("%s did not reject the no-process request: %v", method, err)
		}
	}
	if !invalidStart {
		result, err := callMethod(ctx, session, mcpserver.ToolDebuggerBreakpoints, map[string]any{"instanceId": instanceID})
		if err != nil || !result.IsError {
			log.Fatalf("debugger.breakpoints did not report unavailable debugger: %v", err)
		}
	}
}

func decodeDomainResult(result *mcp.CallToolResult, target any) {
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		log.Fatal(err)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(envelope.Result, target); err != nil {
		log.Fatal(err)
	}
}

func decodeToolResult(
	ctx context.Context,
	session *mcp.ClientSession,
	name string,
	arguments map[string]any,
	target any,
) {
	result, err := callMethod(ctx, session, name, arguments)
	if err != nil {
		log.Fatalf("%s: %v", name, err)
	}
	if result.IsError {
		log.Fatalf("%s returned a tool error", name)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		log.Fatalf("%s structured output: %v", name, err)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		log.Fatalf("%s domain output: %v", name, err)
	}
	if err := json.Unmarshal(envelope.Result, target); err != nil {
		log.Fatalf("%s structured output: %v", name, err)
	}
}

func callMethod(
	ctx context.Context,
	session *mcp.ClientSession,
	name string,
	arguments map[string]any,
) (*mcp.CallToolResult, error) {
	domain, ok := mcpserver.DomainToolForMethod(name)
	if !ok {
		return nil, fmt.Errorf("no domain tool for %s", name)
	}
	return session.CallTool(ctx, &mcp.CallToolParams{Name: domain, Arguments: map[string]any{
		"action": "call", "method": name, "arguments": arguments,
	}})
}

func assertTamperedCursorRejected(
	ctx context.Context,
	session *mcp.ClientSession,
	name string,
	arguments map[string]any,
	cursor string,
) {
	last := "A"
	if cursor[len(cursor)-1] == 'A' {
		last = "B"
	}
	arguments["cursor"] = cursor[:len(cursor)-1] + last
	result, err := callMethod(ctx, session, name, arguments)
	if err != nil {
		log.Fatalf("%s tampered cursor: %v", name, err)
	}
	if !result.IsError {
		log.Fatalf("%s accepted a tampered cursor", name)
	}
}

func verifyBoundedInventory(
	ctx context.Context,
	session *mcp.ClientSession,
	name string,
	arguments map[string]any,
) {
	var first struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor *string           `json:"nextCursor"`
		HasMore    bool              `json:"hasMore"`
	}
	decodeToolResult(ctx, session, name, arguments, &first)
	if len(first.Items) != 1 || first.HasMore != (first.NextCursor != nil) {
		log.Fatalf("%s returned invalid bounded inventory metadata", name)
	}
	if first.NextCursor == nil {
		return
	}
	continuationArguments := make(map[string]any, len(arguments)+1)
	for key, value := range arguments {
		continuationArguments[key] = value
	}
	continuationArguments["cursor"] = *first.NextCursor
	var continuation struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor *string           `json:"nextCursor"`
		HasMore    bool              `json:"hasMore"`
	}
	decodeToolResult(ctx, session, name, continuationArguments, &continuation)
	if len(continuation.Items) > 1 || continuation.HasMore != (continuation.NextCursor != nil) {
		log.Fatalf("%s continuation returned invalid metadata", name)
	}
	tamperArguments := make(map[string]any, len(arguments))
	for key, value := range arguments {
		tamperArguments[key] = value
	}
	assertTamperedCursorRejected(ctx, session, name, tamperArguments, *first.NextCursor)
}

func verifySparseBoundedInventory(
	ctx context.Context,
	session *mcp.ClientSession,
	name string,
	arguments map[string]any,
) {
	var first struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor *string           `json:"nextCursor"`
		HasMore    bool              `json:"hasMore"`
	}
	decodeToolResult(ctx, session, name, arguments, &first)
	if len(first.Items) > 1 || first.HasMore != (first.NextCursor != nil) {
		log.Fatalf("%s returned invalid sparse inventory metadata", name)
	}
	if first.NextCursor == nil {
		return
	}
	tamperArguments := make(map[string]any, len(arguments))
	continuationArguments := make(map[string]any, len(arguments)+1)
	for key, value := range arguments {
		tamperArguments[key] = value
		continuationArguments[key] = value
	}
	assertTamperedCursorRejected(ctx, session, name, tamperArguments, *first.NextCursor)
	continuationArguments["cursor"] = *first.NextCursor
	var continuation struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor *string           `json:"nextCursor"`
		HasMore    bool              `json:"hasMore"`
	}
	decodeToolResult(ctx, session, name, continuationArguments, &continuation)
	if len(continuation.Items) > 1 || continuation.HasMore != (continuation.NextCursor != nil) {
		log.Fatalf("%s sparse continuation returned invalid metadata", name)
	}
}
