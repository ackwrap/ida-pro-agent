package mcpserver

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestToolCatalogBeforeInitialized(t *testing.T) {
	for _, clientName := range []string{"default", "grok"} {
		t.Run(clientName, func(t *testing.T) {
			server, err := NewServer("test", &fakeBackend{empty: true})
			if err != nil {
				t.Fatal(err)
			}
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			go server.Run(ctx, &mcp.IOTransport{Reader: peer, Writer: peer})
			encoder, decoder := json.NewEncoder(client), json.NewDecoder(client)
			request := func(id int, method string, params any) map[string]json.RawMessage {
				t.Helper()
				if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
					t.Fatal(err)
				}
				for {
					var response struct {
						ID     json.RawMessage            `json:"id"`
						Method string                     `json:"method"`
						Result map[string]json.RawMessage `json:"result"`
						Error  json.RawMessage            `json:"error"`
					}
					if err := decoder.Decode(&response); err != nil {
						t.Fatal(err)
					}
					if response.Method != "" && len(response.ID) == 0 {
						t.Fatalf("unexpected notification: %s", response.Method)
					}
					var responseID int
					if err := json.Unmarshal(response.ID, &responseID); err != nil || responseID != id {
						t.Fatalf("unexpected response id: %s", response.ID)
					}
					if len(response.Error) != 0 {
						t.Fatalf("RPC error: %s", response.Error)
					}
					return response.Result
				}
			}
			result := request(1, "initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": clientName, "version": "test"}})
			var caps mcp.ServerCapabilities
			if err := json.Unmarshal(result["capabilities"], &caps); err != nil {
				t.Fatal(err)
			}
			if caps.Tools == nil || caps.Tools.ListChanged {
				t.Fatalf("unexpected tools capabilities: %+v", caps.Tools)
			}
			for _, initialized := range []bool{false, true} {
				if initialized {
					if err := encoder.Encode(map[string]string{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
						t.Fatal(err)
					}
				}
				result := request(2, "tools/list", map[string]any{})
				var tools []mcp.Tool
				if err := json.Unmarshal(result["tools"], &tools); err != nil {
					t.Fatal(err)
				}
				if len(tools) != 23 {
					t.Fatalf("initialized=%v: tools=%d", initialized, len(tools))
				}
				seen := map[string]bool{}
				for _, tool := range tools {
					if !strings.HasPrefix(tool.Name, "ida_") || strings.Contains(tool.Name, ".") || seen[tool.Name] {
						t.Fatalf("invalid or duplicate tool name: %s", tool.Name)
					}
					seen[tool.Name] = true
				}
			}
			toolName := "ida_instances"
			for _, arguments := range []map[string]any{
				{"action": "list"},
				{"action": "describe", "method": "ida.instances.list"},
				{"action": "call", "method": "ida.instances.list", "arguments": map[string]any{}},
			} {
				result := request(3, "tools/call", map[string]any{"name": toolName, "arguments": arguments})
				if string(result["isError"]) == "true" {
					t.Fatalf("dispatch failed: %v", result)
				}
				if len(result["structuredContent"]) == 0 {
					t.Fatal("missing structured result")
				}
			}
		})
	}
}
