package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	"ida-mcp/ida"
)

type p1FakeBackend struct {
	*fakeBackend
	calls           map[string]int
	sourceFiles     []ida.IndexListParams
	sourceLines     []ida.SourceLinesParams
	typeXrefsParams []ida.TypeXrefsParams
}

func (b *p1FakeBackend) hit(name string) {
	if b.calls == nil {
		b.calls = map[string]int{}
	}
	b.calls[name]++
}
func (b *p1FakeBackend) SourceFiles(_ context.Context, _ string, p ida.IndexListParams) (ida.SourceFilesResult, error) {
	b.hit(ToolSourceFiles)
	b.sourceFiles = append(b.sourceFiles, p)
	if p.Cursor == 0 {
		next := uint32(1)
		return ida.SourceFilesResult{Items: []ida.SourceFileItem{{Start: 0x401000, End: 0x401010, Filename: "a.cpp"}}, NextCursor: &next, HasMore: true}, nil
	}
	return ida.SourceFilesResult{Items: []ida.SourceFileItem{}}, nil
}
func (b *p1FakeBackend) SourceLines(_ context.Context, _ string, p ida.SourceLinesParams) (ida.SourceLinesResult, error) {
	b.hit(ToolSourceLines)
	b.sourceLines = append(b.sourceLines, p)
	if p.Cursor == nil {
		next := p.Start + 1
		return ida.SourceLinesResult{Items: []ida.SourceLineItem{{Address: p.Start, Line: 1}}, NextCursor: &next, HasMore: true}, nil
	}
	return ida.SourceLinesResult{Items: []ida.SourceLineItem{}}, nil
}
func (b *p1FakeBackend) NameDemangle(context.Context, string, ida.NameDemangleParams) (ida.NameDemangleResult, error) {
	b.hit(ToolNameDemangle)
	return ida.NameDemangleResult{Raw: "?f@@", Short: stringPtr("f")}, nil
}
func (b *p1FakeBackend) CommentGet(_ context.Context, _ string, p ida.CommentGetParams) (ida.CommentResult, error) {
	b.hit(ToolCommentGet)
	return ida.CommentResult{Address: p.Address, Scope: p.Scope, Repeatable: p.Repeatable, Text: "comment"}, nil
}
func (b *p1FakeBackend) BookmarkList(_ context.Context, _ string, p ida.IndexListParams) (ida.BookmarksResult, error) {
	b.hit(ToolBookmarkList)
	if p.Cursor == 0 {
		next := uint32(1)
		return ida.BookmarksResult{Items: []ida.BookmarkItem{{Slot: 0, Address: 0x401000, Description: "entry"}}, NextCursor: &next, HasMore: true}, nil
	}
	return ida.BookmarksResult{Items: []ida.BookmarkItem{}}, nil
}
func (b *p1FakeBackend) TypeXrefs(_ context.Context, _ string, p ida.TypeXrefsParams) (ida.TypeXrefsResult, error) {
	b.hit(ToolTypeXrefs)
	b.typeXrefsParams = append(b.typeXrefsParams, p)
	if p.Cursor == 0 {
		next := uint32(1)
		return ida.TypeXrefsResult{Items: []ida.TypeXrefItem{{Address: 0x401000, XrefType: "offset"}}, NextCursor: &next, HasMore: true}, nil
	}
	return ida.TypeXrefsResult{Items: []ida.TypeXrefItem{}}, nil
}
func (b *p1FakeBackend) DecompilerLocals(context.Context, string, ida.DecompilerLocalsParams) (ida.DecompilerLocalsResult, error) {
	b.hit(ToolDecompilerLocals)
	return ida.DecompilerLocalsResult{EntryAddress: 0x401000, Items: []ida.DecompilerLocal{}}, nil
}
func (b *p1FakeBackend) DecompilerCtree(context.Context, string, ida.DecompilerCtreeParams) (ida.DecompilerCtreeResult, error) {
	b.hit(ToolDecompilerCtree)
	return ida.DecompilerCtreeResult{EntryAddress: 0x401000, Nodes: []ida.CtreeNode{}}, nil
}
func (b *p1FakeBackend) DecompilerLocalXrefs(context.Context, string, ida.DecompilerLocalXrefsParams) (ida.DecompilerLocalXrefsResult, error) {
	b.hit(ToolDecompilerLocalXrefs)
	return ida.DecompilerLocalXrefsResult{EntryAddress: 0x401000, Name: "v", Items: []ida.DecompilerLocalXref{}}, nil
}
func (b *p1FakeBackend) DebuggerThreads(_ context.Context, _ string, p ida.IndexListParams) (ida.DebuggerThreadsResult, error) {
	b.hit(ToolDebuggerThreads)
	if p.Cursor == 0 {
		next := uint32(1)
		return ida.DebuggerThreadsResult{Items: []ida.DebuggerThreadItem{{ThreadID: 1, Current: true}}, NextCursor: &next, HasMore: true}, nil
	}
	return ida.DebuggerThreadsResult{Items: []ida.DebuggerThreadItem{}}, nil
}
func (b *p1FakeBackend) DebuggerModules(_ context.Context, _ string, p ida.IndexListParams) (ida.DebuggerModulesResult, error) {
	b.hit(ToolDebuggerModules)
	if p.Cursor == 0 {
		next := uint32(1)
		return ida.DebuggerModulesResult{Items: []ida.DebuggerModuleItem{{Name: "a.exe", Base: 0x400000, Size: 4096}}, NextCursor: &next, HasMore: true}, nil
	}
	return ida.DebuggerModulesResult{Items: []ida.DebuggerModuleItem{}}, nil
}
func stringPtr(v string) *string { return &v }

func TestInspectionQueryTypedDispatchAndStrictInput(t *testing.T) {
	b := &p1FakeBackend{fakeBackend: &fakeBackend{}}
	s := connectTestClient(t, b)
	tests := []struct {
		domain, method string
		arguments      map[string]any
	}{
		{ToolDomainSearch, ToolSourceFiles, map[string]any{}}, {ToolDomainSearch, ToolSourceLines, map[string]any{"start": "0x401000", "end": "0x402000"}},
		{ToolDomainSymbols, ToolNameDemangle, map[string]any{"name": "?f@@"}}, {ToolDomainAnalysis, ToolCommentGet, map[string]any{"address": "0x401000"}},
		{ToolDomainDatabase, ToolBookmarkList, map[string]any{}}, {ToolDomainTypes, ToolTypeXrefs, map[string]any{"name": "T"}},
		{ToolDomainFunctions, ToolDecompilerLocals, map[string]any{"address": "0x401000"}}, {ToolDomainFunctions, ToolDecompilerCtree, map[string]any{"address": "0x401000"}},
		{ToolDomainFunctions, ToolDecompilerLocalXrefs, map[string]any{"address": "0x401000", "localIndex": 0}},
		{ToolDomainDebugger, ToolDebuggerThreads, map[string]any{}}, {ToolDomainDebugger, ToolDebuggerModules, map[string]any{}},
	}
	for _, test := range tests {
		args := test.arguments
		args["instanceId"] = testInstanceA
		r := callDomainResult(t, s, test.domain, map[string]any{"action": "call", "method": test.method, "arguments": args})
		if r.IsError {
			t.Fatalf("%s typed dispatch failed: %+v", test.method, r.Content)
		}
	}
	for _, test := range tests {
		if b.calls[test.method] != 1 {
			t.Fatalf("%s calls=%d", test.method, b.calls[test.method])
		}
	}
	r := callDomainResult(t, s, ToolDomainSearch, map[string]any{"action": "call", "method": ToolSourceFiles, "arguments": map[string]any{"instanceId": testInstanceA, "unknown": true}})
	if !r.IsError || b.calls[ToolSourceFiles] != 1 {
		t.Fatal("unknown field reached P1 backend")
	}
}

func TestInspectionQueryPublicCursorsAuthenticateAllBindings(t *testing.T) {
	b := &p1FakeBackend{fakeBackend: &fakeBackend{}}
	s := connectTestClient(t, b)
	var envelope domainCallOutput
	callDomainAction(t, s, ToolDomainSearch, map[string]any{"action": "call", "method": ToolSourceFiles, "arguments": map[string]any{"instanceId": testInstanceA}}, &envelope)
	var files sourceFilesOutput
	if err := json.Unmarshal(envelope.Result, &files); err != nil || files.NextCursor == nil {
		t.Fatalf("source cursor: %v %+v", err, files)
	}
	bad := callDomainResult(t, s, ToolDomainSearch, map[string]any{"action": "call", "method": ToolSourceFiles, "arguments": map[string]any{"instanceId": testInstanceA, "limit": 21, "cursor": *files.NextCursor}})
	if !bad.IsError || len(b.sourceFiles) != 1 {
		t.Fatal("cursor was not bound to effective limit")
	}
	bad = callDomainResult(t, s, ToolDomainDatabase, map[string]any{"action": "call", "method": ToolBookmarkList, "arguments": map[string]any{"instanceId": testInstanceA, "cursor": *files.NextCursor}})
	if !bad.IsError {
		t.Fatal("cursor was not bound to method")
	}
	bad = callDomainResult(t, s, ToolDomainSearch, map[string]any{"action": "call", "method": ToolSourceFiles, "arguments": map[string]any{"instanceId": testInstanceB, "cursor": *files.NextCursor}})
	if !bad.IsError {
		t.Fatal("cursor was not bound to instance")
	}
	tampered := *files.NextCursor
	if tampered[len(tampered)-1] == 'A' {
		tampered = tampered[:len(tampered)-1] + "B"
	} else {
		tampered = tampered[:len(tampered)-1] + "A"
	}
	bad = callDomainResult(t, s, ToolDomainSearch, map[string]any{"action": "call", "method": ToolSourceFiles, "arguments": map[string]any{"instanceId": testInstanceA, "cursor": tampered}})
	if !bad.IsError {
		t.Fatal("source.files accepted a tampered cursor")
	}

	callDomainAction(t, s, ToolDomainSearch, map[string]any{"action": "call", "method": ToolSourceLines, "arguments": map[string]any{"instanceId": testInstanceA, "start": "0x401000", "end": "0x402000", "limit": 1}}, &envelope)
	var lines sourceLinesOutput
	if err := json.Unmarshal(envelope.Result, &lines); err != nil || lines.NextCursor == nil {
		t.Fatalf("line cursor: %v %+v", err, lines)
	}
	bad = callDomainResult(t, s, ToolDomainSearch, map[string]any{"action": "call", "method": ToolSourceLines, "arguments": map[string]any{"instanceId": testInstanceA, "start": "0x401000", "end": "0x403000", "limit": 1, "cursor": *lines.NextCursor}})
	if !bad.IsError || len(b.sourceLines) != 1 {
		t.Fatal("source cursor was not bound to normalized range")
	}

	callDomainAction(t, s, ToolDomainTypes, map[string]any{"action": "call", "method": ToolTypeXrefs, "arguments": map[string]any{"instanceId": testInstanceA, "name": "T", "limit": 1}}, &envelope)
	var xrefs typeXrefsOutput
	if err := json.Unmarshal(envelope.Result, &xrefs); err != nil || xrefs.NextCursor == nil {
		t.Fatalf("type cursor: %v %+v", err, xrefs)
	}
	bad = callDomainResult(t, s, ToolDomainTypes, map[string]any{"action": "call", "method": ToolTypeXrefs, "arguments": map[string]any{"instanceId": testInstanceA, "name": "U", "limit": 1, "cursor": *xrefs.NextCursor}})
	if !bad.IsError || len(b.typeXrefsParams) != 1 {
		t.Fatal("type cursor was not bound to normalized name filter")
	}

	for _, test := range []struct{ domain, method string }{
		{ToolDomainDatabase, ToolBookmarkList}, {ToolDomainDebugger, ToolDebuggerThreads}, {ToolDomainDebugger, ToolDebuggerModules},
	} {
		callDomainAction(t, s, test.domain, map[string]any{"action": "call", "method": test.method, "arguments": map[string]any{"instanceId": testInstanceA, "limit": 1}}, &envelope)
		var page struct {
			NextCursor *string `json:"nextCursor"`
		}
		if err := json.Unmarshal(envelope.Result, &page); err != nil || page.NextCursor == nil {
			t.Fatalf("%s cursor: %v %+v", test.method, err, page)
		}
		value := *page.NextCursor
		if value[len(value)-1] == 'A' {
			value = value[:len(value)-1] + "B"
		} else {
			value = value[:len(value)-1] + "A"
		}
		bad = callDomainResult(t, s, test.domain, map[string]any{"action": "call", "method": test.method, "arguments": map[string]any{"instanceId": testInstanceA, "limit": 1, "cursor": value}})
		if !bad.IsError {
			t.Fatalf("%s accepted a tampered cursor", test.method)
		}
	}
}
