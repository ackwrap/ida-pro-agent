package main

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	mcpserver "ida-mcp/mcp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const verificationPythonSource = "print('ida-agent-script-ok')"

func verifyCatalogMethods(ctx context.Context, session *mcp.ClientSession, instanceID, functionAddress, stackFrameAddress string) {
	var ping struct {
		Status string `json:"status"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolSystemPing, map[string]any{"instanceId": instanceID}, &ping)
	if ping.Status != "ok" {
		log.Fatal("system.ping returned an invalid status")
	}
	var methods struct {
		Methods []string `json:"methods"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolSystemMethods, map[string]any{"instanceId": instanceID}, &methods)
	if len(methods.Methods) != 90 {
		log.Fatalf("system.methods returned %d methods, want 90", len(methods.Methods))
	}
	var info struct {
		Database  string `json:"database"`
		InputFile string `json:"inputFile"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolInstanceInfo, map[string]any{"instanceId": instanceID}, &info)
	if strings.ContainsAny(info.Database+info.InputFile, `/\`) {
		log.Fatal("instance.info exposed a path")
	}
	var survey struct {
		Mode string `json:"mode"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolDatabaseSurvey, map[string]any{"instanceId": instanceID, "mode": "minimal", "budget": 6}, &survey)
	if survey.Mode != "minimal" {
		log.Fatal("database.survey returned an invalid mode")
	}
	var saved struct {
		Saved          bool `json:"saved"`
		ExplicitTarget bool `json:"explicitTarget"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolDatabaseSave, map[string]any{"instanceId": instanceID}, &saved)
	if !saved.Saved || saved.ExplicitTarget {
		log.Fatal("database.save did not save the current IDB safely")
	}
	var callers struct {
		EntryAddress string `json:"entryAddress"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolFunctionCallers, map[string]any{"instanceId": instanceID, "address": functionAddress, "limit": 20}, &callers)
	if callers.EntryAddress == "" {
		log.Fatal("function.callers omitted entryAddress")
	}
	var chunks struct {
		EntryAddress string            `json:"entryAddress"`
		Items        []json.RawMessage `json:"items"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolFunctionChunks, map[string]any{"instanceId": instanceID, "address": functionAddress, "limit": 100}, &chunks)
	if chunks.EntryAddress == "" || len(chunks.Items) == 0 {
		log.Fatal("function.chunks returned no function ranges")
	}
	var tryBlocks struct {
		FunctionAddress string `json:"functionAddress"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolExceptionTryBlocks, map[string]any{"instanceId": instanceID, "address": functionAddress, "limit": 100}, &tryBlocks)
	if tryBlocks.FunctionAddress == "" {
		log.Fatal("exception.try_blocks omitted functionAddress")
	}
	var graph struct {
		Nodes []json.RawMessage `json:"nodes"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolFunctionCallGraph, map[string]any{"instanceId": instanceID, "roots": []any{functionAddress}, "maxDepth": 1, "maxNodes": 20, "maxEdges": 40, "perFunction": 20}, &graph)
	if len(graph.Nodes) == 0 {
		log.Fatal("function.callgraph returned no root")
	}
	var profile struct {
		Items []json.RawMessage `json:"items"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolFunctionProfile, map[string]any{"instanceId": instanceID, "limit": 1}, &profile)
	if len(profile.Items) == 0 {
		log.Fatal("function.profile returned no function")
	}
	var exported struct {
		Content string `json:"content"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolFunctionExport, map[string]any{"instanceId": instanceID, "addresses": []any{functionAddress}, "format": "prototypes", "maxBytes": 4096}, &exported)
	if exported.Content == "" {
		log.Fatal("function.export returned no content")
	}
	for _, method := range []string{mcpserver.ToolFunctionAnalyze, mcpserver.ToolFunctionAnalyzeBatch} {
		var analyzed struct {
			Items []json.RawMessage `json:"items"`
		}
		decodeToolResult(ctx, session, method, map[string]any{"instanceId": instanceID, "addresses": []any{functionAddress}, "sections": []any{"overview", "metrics"}, "perSection": 10, "decompileBytes": 4096}, &analyzed)
		if len(analyzed.Items) != 1 {
			log.Fatalf("%s returned invalid items", method)
		}
	}
	address := stackFrameAddress
	if address == "" {
		address = functionAddress
	}
	result, err := callMethod(ctx, session, mcpserver.ToolFunctionStackFrame, map[string]any{"instanceId": instanceID, "address": address})
	if err != nil {
		log.Fatalf("function.stack_frame: %v", err)
	}
	if stackFrameAddress != "" && result.IsError {
		log.Fatal("function.stack_frame failed for the published frame")
	}
	var instruction struct {
		Kind string `json:"kind"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolInstructionGet, map[string]any{"instanceId": instanceID, "address": functionAddress}, &instruction)
	if instruction.Kind != "code" {
		log.Fatal("instruction.get did not decode the function entry")
	}
	var fixups struct {
		Items []json.RawMessage `json:"items"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolFixupList, map[string]any{"instanceId": instanceID, "limit": 20}, &fixups)
	for _, method := range []string{mcpserver.ToolFixupGet, mcpserver.ToolSwitchGet} {
		if _, err := callMethod(ctx, session, method, map[string]any{"instanceId": instanceID, "address": functionAddress}); err != nil {
			log.Fatalf("%s transport call: %v", method, err)
		}
	}
	var analysisStatus struct {
		Queue string `json:"queue"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolAnalysisStatus, map[string]any{"instanceId": instanceID}, &analysisStatus)
	if analysisStatus.Queue == "" {
		log.Fatal("analysis.status omitted queue")
	}
	var waited struct {
		Complete  bool   `json:"complete"`
		TimedOut  bool   `json:"timedOut"`
		PollCount uint32 `json:"pollCount"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolAnalysisWait, map[string]any{"instanceId": instanceID}, &waited)
	if waited.PollCount == 0 || !waited.Complete && !waited.TimedOut {
		log.Fatal("analysis.wait returned neither completion nor its bounded timeout")
	}
	var problems struct {
		Items []json.RawMessage `json:"items"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolAnalysisProblems, map[string]any{"instanceId": instanceID, "type": "disassembly", "limit": 20}, &problems)
	var script struct {
		Success bool   `json:"success"`
		Stdout  string `json:"stdout"`
	}
	decodeToolResult(ctx, session, mcpserver.ToolScriptExecute, map[string]any{
		"instanceId": instanceID, "language": "python", "code": verificationPythonSource,
	}, &script)
	if !script.Success || script.Stdout != "ida-agent-script-ok\n" {
		log.Fatal("script.execute did not return captured Python output")
	}
}
