package mcpserver

import (
	"context"
	"errors"
	"testing"

	"ida-mcp/ida"
)

func TestStringSearchRefreshAndContinuation(t *testing.T) {
	for _, method := range []string{ToolStringSearch, ToolStringSearchRegex} {
		t.Run(method, func(t *testing.T) {
			backend := &fakeBackend{}
			session := connectTestClient(t, backend)
			args := map[string]any{"instanceId": testInstanceA, "limit": 1}
			if method == ToolStringSearch {
				args["query"] = "hello"
			} else {
				args["pattern"] = "sample"
			}
			var page ida.StringSearchResult
			callTool(t, session, method, args, &page) // omitted refresh
			args["refresh"] = true
			callTool(t, session, method, args, &page)
			if page.NextCursor == nil {
				t.Fatal("missing continuation")
			}
			args["cursor"] = *page.NextCursor
			if !callToolRejected(t, session, method, args) {
				t.Fatal("refresh with cursor reached the backend")
			}
			args["refresh"] = false
			callTool(t, session, method, args, &page)
			delete(args, "refresh")
			callTool(t, session, method, args, &page) // omitted refresh is also legal on continuation
			delete(args, "cursor")
			for _, invalid := range []any{nil, 0, 1, "true", []any{}, map[string]any{}} {
				args["refresh"] = invalid
				if !callToolRejected(t, session, method, args) {
					t.Fatalf("invalid refresh accepted: %#v", invalid)
				}
			}
			backend.mutex.Lock()
			defer backend.mutex.Unlock()
			if method == ToolStringSearch {
				p := backend.stringParams
				if len(p) != 4 || p[0].Refresh || !p[1].Refresh || p[2].Refresh || p[3].Refresh || p[2].Cursor == "" || p[3].Cursor == "" {
					t.Fatalf("forwarded parameters: %+v", p)
				}
			} else {
				p := backend.regexParams
				if len(p) != 4 || p[0].Refresh || !p[1].Refresh || p[2].Refresh || p[3].Refresh || p[2].Cursor == "" || p[3].Cursor == "" {
					t.Fatalf("forwarded parameters: %+v", p)
				}
			}
		})
	}
}

func TestStringRefreshTypedHandlersRejectConflictBeforeBackend(t *testing.T) {
	registry := &toolRegistry{} // no backend; validation must reject without dereferencing it
	_, _, err := registry.stringSearchRegex(context.Background(), nil, stringSearchRegexInput{Refresh: true, Cursor: "cursor"})
	var typed *ida.Error
	if !errors.As(err, &typed) || typed.Code != ida.ErrorInvalidArgument {
		t.Fatalf("regex conflict error: %v", err)
	}
	// stringSearch checks backend availability first; use a registry with a real test backend.
	registry.backend = &fakeBackend{}
	_, _, err = registry.stringSearch(context.Background(), nil, stringSearchInput{Refresh: true, Cursor: "cursor"})
	if !errors.As(err, &typed) || typed.Code != ida.ErrorInvalidArgument {
		t.Fatalf("string conflict error: %v", err)
	}
}
