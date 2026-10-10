package bridge

import (
	"context"
	"encoding/json"
	"testing"

	"ida-mcp/ida/rpc"
)

func TestInspectionQueryClientsUseStaticTypedMethods(t *testing.T) {
	instance := testInstanceDescriptor()
	address := rpc.Address(0x401000)
	name := "?f@@YAXXZ"
	tests := []struct {
		method string
		result any
		call   func(*Client) error
	}{
		{string(methodSourceFiles), map[string]any{"items": []any{map[string]any{"start": "0x401000", "end": "0x401010", "filename": "a.cpp"}}, "nextCursor": 1, "hasMore": true}, func(c *Client) error {
			_, e := c.SourceFiles(context.Background(), instance, IndexListParams{Limit: 1})
			return e
		}},
		{string(methodSourceLines), map[string]any{"items": []any{map[string]any{"address": "0x401000", "line": 1, "filename": nil}}, "nextCursor": "0x401001", "hasMore": true}, func(c *Client) error {
			_, e := c.SourceLines(context.Background(), instance, SourceLinesParams{Start: address, End: address + 16, Limit: 1})
			return e
		}},
		{string(methodNameDemangle), map[string]any{"raw": name, "short": "f()", "long": nil}, func(c *Client) error {
			_, e := c.NameDemangle(context.Background(), instance, NameDemangleParams{Name: &name})
			return e
		}},
		{string(methodCommentGet), map[string]any{"address": "0x401000", "scope": "item", "repeatable": false, "text": "comment"}, func(c *Client) error {
			_, e := c.CommentGet(context.Background(), instance, CommentGetParams{Address: address})
			return e
		}},
		{string(methodBookmarkList), map[string]any{"items": []any{map[string]any{"slot": 0, "address": "0x401000", "line": 0, "description": "entry"}}, "nextCursor": 1, "hasMore": true}, func(c *Client) error {
			_, e := c.BookmarkList(context.Background(), instance, IndexListParams{Limit: 1})
			return e
		}},
		{string(methodTypeXrefs), map[string]any{"items": []any{map[string]any{"address": "0x401000", "code": false, "userDefined": false, "xrefType": "offset"}}, "nextCursor": 1, "hasMore": true}, func(c *Client) error {
			_, e := c.TypeXrefs(context.Background(), instance, TypeXrefsParams{Name: "T", Limit: 1})
			return e
		}},
		{string(methodDecompilerLocals), map[string]any{"entryAddress": "0x401000", "totalCount": 1, "truncated": false, "items": []any{map[string]any{"index": 0, "name": "v", "declaration": "int v;", "width": 4, "defBlock": nil, "defEa": nil, "locator": map[string]any{"kind": "stack", "text": "stk0"}, "flags": []any{"used"}}}}, func(c *Client) error {
			_, e := c.DecompilerLocals(context.Background(), instance, DecompilerLocalsParams{Address: address, MaxItems: 1})
			return e
		}},
		{string(methodDecompilerCtree), map[string]any{"entryAddress": "0x401000", "count": 1, "truncated": false, "nodes": []any{map[string]any{"ordinal": 0, "depth": 0, "kind": "statement", "op": "block", "ea": "0x401000", "userFlags": []any{}}}}, func(c *Client) error {
			_, e := c.DecompilerCtree(context.Background(), instance, DecompilerCtreeParams{Address: address, MaxDepth: 8, MaxNodes: 1})
			return e
		}},
		{string(methodDecompilerLocalXrefs), map[string]any{"entryAddress": "0x401000", "localIndex": 0, "name": "v", "visitedNodes": 3, "totalReturned": 1, "truncated": false, "items": []any{map[string]any{"ordinal": 0, "depth": 2, "ea": "0x401004", "parentOp": "asg", "type": "int"}}}, func(c *Client) error {
			_, e := c.DecompilerLocalXrefs(context.Background(), instance, DecompilerLocalXrefsParams{Address: address, LocalIndex: 0, MaxDepth: 16, MaxNodes: 1000, MaxItems: 100})
			return e
		}},
		{string(methodDebuggerThreads), map[string]any{"items": []any{map[string]any{"threadId": 1, "name": nil, "current": true}}, "nextCursor": nil, "hasMore": false}, func(c *Client) error {
			_, e := c.DebuggerThreads(context.Background(), instance, IndexListParams{Limit: 1})
			return e
		}},
		{string(methodDebuggerModules), map[string]any{"items": []any{map[string]any{"name": "a.exe", "base": "0x400000", "size": 4096, "rebaseTo": nil}}, "nextCursor": nil, "hasMore": false}, func(c *Client) error {
			_, e := c.DebuggerModules(context.Background(), instance, IndexListParams{Limit: 1})
			return e
		}},
	}
	for _, test := range tests {
		t.Run(test.method, func(t *testing.T) {
			client := functionAnalysisTestClient(t, instance, test.method, test.result)
			if err := test.call(client); err != nil {
				t.Fatalf("call: %v", err)
			}
		})
	}
}

func TestInspectionQueryClientsRejectUnknownBoundsAndBadPagination(t *testing.T) {
	instance := testInstanceDescriptor()
	client := functionAnalysisTestClient(t, instance, string(methodSourceFiles), json.RawMessage(`{"items":[],"nextCursor":null,"hasMore":false,"rawCursor":1}`))
	if _, err := client.SourceFiles(context.Background(), instance, IndexListParams{}); err == nil {
		t.Fatal("unknown output field was accepted")
	}
	client = functionAnalysisTestClient(t, instance, string(methodSourceFiles), json.RawMessage(`{"items":[],"nextCursor":1,"hasMore":true}`))
	if _, err := client.SourceFiles(context.Background(), instance, IndexListParams{Limit: 1}); err == nil {
		t.Fatal("empty continuation page was accepted")
	}
	name := "T"
	address := rpc.Address(0x401000)
	invalid := []struct {
		name string
		call func() error
	}{
		{"source.files", func() error {
			_, e := client.SourceFiles(context.Background(), instance, IndexListParams{Limit: 101})
			return e
		}},
		{"source.lines", func() error {
			_, e := client.SourceLines(context.Background(), instance, SourceLinesParams{Start: address, End: address})
			return e
		}},
		{"name.demangle", func() error {
			_, e := client.NameDemangle(context.Background(), instance, NameDemangleParams{Name: &name, Address: &address})
			return e
		}},
		{"comment.get", func() error {
			_, e := client.CommentGet(context.Background(), instance, CommentGetParams{Address: address, Scope: "pseudocode"})
			return e
		}},
		{"bookmark.list", func() error {
			_, e := client.BookmarkList(context.Background(), instance, IndexListParams{Cursor: 1025})
			return e
		}},
		{"type.xrefs", func() error { _, e := client.TypeXrefs(context.Background(), instance, TypeXrefsParams{}); return e }},
		{"decompiler.locals", func() error {
			_, e := client.DecompilerLocals(context.Background(), instance, DecompilerLocalsParams{Address: address, MaxItems: 513})
			return e
		}},
		{"decompiler.ctree", func() error {
			_, e := client.DecompilerCtree(context.Background(), instance, DecompilerCtreeParams{Address: address, MaxDepth: 33})
			return e
		}},
		{"decompiler.local_xrefs", func() error {
			_, e := client.DecompilerLocalXrefs(context.Background(), instance, DecompilerLocalXrefsParams{Address: address, MaxNodes: 5001})
			return e
		}},
		{"debugger.threads", func() error {
			_, e := client.DebuggerThreads(context.Background(), instance, IndexListParams{Cursor: 1025})
			return e
		}},
		{"debugger.modules", func() error {
			_, e := client.DebuggerModules(context.Background(), instance, IndexListParams{Cursor: 4097})
			return e
		}},
	}
	for _, test := range invalid {
		t.Run("bounds_"+test.name, func(t *testing.T) {
			if err := test.call(); err == nil {
				t.Fatal("invalid parameters were accepted")
			}
		})
	}
	pages := []struct {
		name, method, result string
		call                 func(*Client) error
	}{
		{"source.files", string(methodSourceFiles), `{"items":[],"nextCursor":1,"hasMore":true}`, func(c *Client) error {
			_, e := c.SourceFiles(context.Background(), instance, IndexListParams{Limit: 1})
			return e
		}},
		{"source.lines", string(methodSourceLines), `{"items":[],"nextCursor":"0x401000","hasMore":true}`, func(c *Client) error {
			_, e := c.SourceLines(context.Background(), instance, SourceLinesParams{Start: address, End: address + 16, Limit: 1})
			return e
		}},
		{"bookmark.list", string(methodBookmarkList), `{"items":[],"nextCursor":1,"hasMore":true}`, func(c *Client) error {
			_, e := c.BookmarkList(context.Background(), instance, IndexListParams{Limit: 1})
			return e
		}},
		{"type.xrefs", string(methodTypeXrefs), `{"items":[],"nextCursor":1,"hasMore":true}`, func(c *Client) error {
			_, e := c.TypeXrefs(context.Background(), instance, TypeXrefsParams{Name: "T", Limit: 1})
			return e
		}},
		{"debugger.threads", string(methodDebuggerThreads), `{"items":[],"nextCursor":1,"hasMore":true}`, func(c *Client) error {
			_, e := c.DebuggerThreads(context.Background(), instance, IndexListParams{Limit: 1})
			return e
		}},
		{"debugger.modules", string(methodDebuggerModules), `{"items":[],"nextCursor":1,"hasMore":true}`, func(c *Client) error {
			_, e := c.DebuggerModules(context.Background(), instance, IndexListParams{Limit: 1})
			return e
		}},
	}
	for _, test := range pages {
		t.Run("pagination_"+test.name, func(t *testing.T) {
			c := functionAnalysisTestClient(t, instance, test.method, json.RawMessage(test.result))
			if err := test.call(c); err == nil {
				t.Fatal("inconsistent pagination was accepted")
			}
		})
	}
}
