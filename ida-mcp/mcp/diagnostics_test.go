package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type diagnosticBuffer struct {
	mutex  sync.Mutex
	buffer bytes.Buffer
}

func (buffer *diagnosticBuffer) Write(data []byte) (int, error) {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	return buffer.buffer.Write(data)
}
func (buffer *diagnosticBuffer) String() string {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	return buffer.buffer.String()
}
func TestHTTPArgumentRecoveryAndPrivateDiagnostics(t *testing.T) {
	backend := &retryBackend{typedDomainBackend: newTypedDomainBackend(), busyAttempts: 1}
	var log diagnosticBuffer
	handler, err := NewHTTPHandler("test", backend, WithDiagnostics(&log))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "compatibility-http", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp", HTTPClient: server.Client(), MaxRetries: -1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for _, args := range []map[string]any{
		{"action": "call", "method": ToolFunctionGet, "arguments": "SECRET-data"},
		{"action": "call", "method": ToolFunctionGet, "arguments": map[string]any{"address": "SECRET-data"}},
	} {
		decodeToolFailure(t, callDomainResult(t, session, "ida_functions", args))
	}
	result := callDomainResult(t, session, "ida_get_function", map[string]any{"instanceId": testInstanceA, "address": "0x401000"})
	if result.IsError {
		t.Fatal(result.Content)
	}
	assertTextMatchesStructured(t, result)
	entries := strings.Split(strings.TrimSpace(log.String()), "\n")
	if len(entries) != 3 {
		t.Fatalf("diagnostic entries: %s", log.String())
	}
	for _, entry := range entries {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(entry), &decoded); err != nil {
			t.Fatal(err)
		}
		for key := range decoded {
			switch key {
			case "tool", "method", "stage", "durationMs", "code", "retries":
			default:
				t.Fatalf("unexpected diagnostic field %s", key)
			}
		}
	}
	if !strings.Contains(entries[2], `"retries":1`) || strings.Contains(log.String(), "SECRET-data") || strings.Contains(log.String(), testInstanceA) || strings.Contains(log.String(), "0x401000") {
		t.Fatalf("private or incomplete diagnostics: %s", log.String())
	}
}
