package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestHTTPHandlerHealthAndSecurityBoundary(t *testing.T) {
	handler, err := NewHTTPHandler("test", &fakeBackend{empty: true})
	if err != nil {
		t.Fatalf("NewHTTPHandler: %v", err)
	}
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"status":"ok"`) {
		t.Fatalf("health = %d %s", health.Code, health.Body.String())
	}
	remote := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	remote.Header.Set("Origin", "https://example.com")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, remote)
	if response.Code != http.StatusForbidden {
		t.Fatalf("remote origin status = %d", response.Code)
	}
	oversized := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("x"))
	oversized.ContentLength = maxRequestBodyBytes + 1
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, oversized)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d", response.Code)
	}
}

func TestHTTPInitializeAndToolsListDoNotDiscoverIDA(t *testing.T) {
	backend := &fakeBackend{empty: true}
	handler, err := NewHTTPHandler("test", backend)
	if err != nil {
		t.Fatalf("NewHTTPHandler: %v", err)
	}
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "http-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: httpServer.URL + "/mcp", HTTPClient: httpServer.Client(), MaxRetries: -1,
	}, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()
	tools, err := session.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 23 {
		t.Fatalf("ListTools = %d, %v", len(tools.Tools), err)
	}
	for _, tool := range tools.Tools {
		if !strings.HasPrefix(tool.Name, "ida_") || strings.Contains(tool.Name, ".") {
			t.Errorf("HTTP tools/list exposed incompatible tool name %q", tool.Name)
		}
	}
	backend.mutex.Lock()
	listCalls := backend.listCalls
	backend.mutex.Unlock()
	if listCalls != 0 {
		t.Fatalf("HTTP initialize/tools.list performed %d discovery calls", listCalls)
	}
	result, err := callCatalogMethod(ctx, session, ToolInstancesList, map[string]any{})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("ida.instances.list = %+v, %v", result, err)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal instance list: %v", err)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatalf("domain output = %v", err)
	}
	var listed instancesListOutput
	if err := json.Unmarshal(envelope.Result, &listed); err != nil || listed.Instances == nil || len(listed.Instances) != 0 {
		t.Fatalf("instances = %+v, %v", listed.Instances, err)
	}
}

func TestHTTPScriptExecuteWithoutClientCallback(t *testing.T) {
	backend := &scriptFakeBackend{fakeBackend: &fakeBackend{}}
	handler, err := NewHTTPHandler("test", backend)
	if err != nil {
		t.Fatalf("NewHTTPHandler: %v", err)
	}
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "http-test", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: httpServer.URL + "/mcp", HTTPClient: httpServer.Client(), MaxRetries: -1,
	}, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()
	var output struct {
		Success bool `json:"success"`
	}
	callTool(t, session, ToolScriptExecute, map[string]any{
		"instanceId": testInstanceA, "language": "python", "code": "print('approved')",
	}, &output)
	callTool(t, session, ToolScriptExecute, map[string]any{
		"instanceId": testInstanceA, "language": "idc", "code": "1+1;",
	}, &output)
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if !output.Success || backend.calls != 2 {
		t.Fatalf("HTTP script execution = output %+v, calls %d", output, backend.calls)
	}
}
