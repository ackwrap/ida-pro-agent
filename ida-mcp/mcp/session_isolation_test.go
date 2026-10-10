package mcpserver

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type routedBackend struct{ *fakeBackend }

func (*routedBackend) DatabaseInfo(_ context.Context, instance string) (ida.DatabaseInfo, error) {
	return ida.DatabaseInfo{Database: instance, Processor: "metapc", Architecture: "x86_64", AddressBits: 64}, nil
}

func TestHTTPInstanceSelectionIsSessionScoped(t *testing.T) {
	backend := &routedBackend{&fakeBackend{}}
	handler, err := NewHTTPHandler("test", backend)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connect := func() *mcp.ClientSession {
		client := mcp.NewClient(&mcp.Implementation{Name: "isolation-test", Version: "1"}, nil)
		session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp", HTTPClient: server.Client(), MaxRetries: -1}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = session.Close() })
		return session
	}
	a, b, unselected := connect(), connect(), connect()
	var selection instanceSelectionOutput
	callTool(t, a, ToolInstancesSelect, map[string]any{"instanceId": testInstanceA}, &selection)
	callTool(t, b, ToolInstancesSelect, map[string]any{"instanceId": testInstanceB}, &selection)
	for _, test := range []struct {
		session *mcp.ClientSession
		want    string
	}{{a, testInstanceA}, {b, testInstanceB}} {
		var info databaseInfoOutput
		callTool(t, test.session, ToolDatabaseInfo, map[string]any{}, &info)
		if info.Database != test.want {
			t.Fatalf("domain routed to %s, want %s", info.Database, test.want)
		}
		result, err := test.session.CallTool(ctx, &mcp.CallToolParams{Name: "ida_database_info", Arguments: map[string]any{}})
		if err != nil || result.IsError {
			t.Fatalf("direct call: %+v, %v", result, err)
		}
		encoded, err := json.Marshal(result.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, &info); err != nil {
			t.Fatal(err)
		}
		if info.Database != test.want {
			t.Fatalf("direct routed to %s, want %s", info.Database, test.want)
		}
	}
	result, err := unselected.CallTool(ctx, &mcp.CallToolParams{Name: "ida_database_info", Arguments: map[string]any{}})
	if err != nil || !result.IsError {
		t.Fatalf("unselected session inherited selection: %+v, %v", result, err)
	}
	backend.mutex.Lock()
	backend.empty = true
	backend.mutex.Unlock()
	var listed instancesListOutput
	callTool(t, a, ToolInstancesList, map[string]any{}, &listed)
	var info databaseInfoOutput
	callTool(t, a, ToolDatabaseInfo, map[string]any{}, &info)
	if info.Database != testInstanceA {
		t.Fatal("transient empty discovery discarded selection")
	}
}
