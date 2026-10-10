package mcpserver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"ida-mcp/ida"
)

type scriptFakeBackend struct {
	*fakeBackend
	mutex  sync.Mutex
	calls  int
	params ida.ScriptExecuteParams
}

func (backend *scriptFakeBackend) ExecuteScript(_ context.Context, _ string, params ida.ScriptExecuteParams) (ida.ScriptExecutionResult, error) {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	backend.calls++
	backend.params = params
	stdout := "executed\n"
	return ida.ScriptExecutionResult{Language: params.Language, Success: true, Stdout: stdout, OriginalSize: uint64(len(stdout))}, nil
}

func TestScriptExecuteRunsInlineCode(t *testing.T) {
	backend := &scriptFakeBackend{fakeBackend: &fakeBackend{}}
	code := "print('executed')"
	session := connectTestClient(t, backend)
	var output ida.ScriptExecutionResult
	callTool(t, session, ToolScriptExecute, map[string]any{
		"instanceId": testInstanceA, "language": "python", "code": code,
	}, &output)
	if !output.Success || output.Stdout != "executed\n" {
		t.Fatalf("script output = %+v", output)
	}
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if backend.calls != 1 || backend.params.Language != "python" || backend.params.Code != code {
		t.Fatalf("backend execution = %d, %+v", backend.calls, backend.params)
	}
}

func TestScriptExecuteLoadsPath(t *testing.T) {
	backend := &scriptFakeBackend{fakeBackend: &fakeBackend{}}
	original := "print('from file')"
	path := filepath.Join(t.TempDir(), "script.py")
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	session := connectTestClient(t, backend)
	var output ida.ScriptExecutionResult
	callTool(t, session, ToolScriptExecute, map[string]any{
		"instanceId": testInstanceA, "language": "python", "path": path,
	}, &output)
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if backend.calls != 1 || backend.params.Language != "python" || backend.params.Code != original {
		t.Fatalf("backend execution = %d, %+v", backend.calls, backend.params)
	}
}

func TestScriptExecuteRejectsInvalidInput(t *testing.T) {
	backend := &scriptFakeBackend{fakeBackend: &fakeBackend{}}
	session := connectTestClient(t, backend)
	for _, arguments := range []map[string]any{
		{"instanceId": testInstanceA, "language": "javascript", "code": "1"},
		{"instanceId": testInstanceA, "language": "python", "code": ""},
		{"instanceId": testInstanceA, "language": "python", "code": strings.Repeat("界", 11000)},
		{"instanceId": testInstanceA, "language": "python", "code": "print(1)", "confirmed": true},
		{"instanceId": testInstanceA, "language": "python", "code": "print(1)", "scope": "session"},
		{"instanceId": testInstanceA, "language": "python"},
		{"instanceId": testInstanceA, "language": "python", "code": "print(1)", "path": "script.py"},
		{"instanceId": testInstanceA, "language": "python", "path": ""},
		{"instanceId": testInstanceA, "language": "python", "path": strings.Repeat("p", maxScriptPathBytes+1)},
		{"instanceId": testInstanceA, "language": "python", "path": strings.Repeat("界", maxScriptPathBytes/3+1)},
		{"instanceId": testInstanceA, "language": "python", "path": "bad\x00script.py"},
	} {
		if !callToolRejected(t, session, ToolScriptExecute, arguments) {
			t.Fatalf("invalid script arguments were accepted: %+v", arguments)
		}
	}
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if backend.calls != 0 {
		t.Fatalf("invalid inputs caused %d backend calls", backend.calls)
	}
}

func TestScriptExecuteRejectsInvalidFiles(t *testing.T) {
	backend := &scriptFakeBackend{fakeBackend: &fakeBackend{}}
	directory := t.TempDir()
	emptyPath := filepath.Join(directory, "empty.py")
	oversizedPath := filepath.Join(directory, "oversized.py")
	invalidUTF8Path := filepath.Join(directory, "invalid.py")
	nulPath := filepath.Join(directory, "nul.py")
	for path, contents := range map[string][]byte{
		emptyPath: {}, oversizedPath: []byte(strings.Repeat("x", ida.MaxScriptSourceBytes+1)),
		invalidUTF8Path: {0xff}, nulPath: {'x', 0, 'y'},
	} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
	}
	session := connectTestClient(t, backend)
	paths := []string{
		filepath.Join(directory, "missing.py"), directory, emptyPath, oversizedPath, invalidUTF8Path, nulPath,
	}
	for _, path := range paths {
		if !callToolRejected(t, session, ToolScriptExecute, map[string]any{
			"instanceId": testInstanceA, "language": "python", "path": path,
		}) {
			t.Fatalf("invalid script file was accepted: %s", path)
		}
	}
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if backend.calls != 0 {
		t.Fatalf("invalid files caused %d backend calls", backend.calls)
	}
}

func TestScriptExecuteAcceptsFileSizeBoundaries(t *testing.T) {
	for _, size := range []int{1, ida.MaxScriptSourceBytes} {
		t.Run(fmt.Sprintf("bytes_%d", size), func(t *testing.T) {
			backend := &scriptFakeBackend{fakeBackend: &fakeBackend{}}
			code := strings.Repeat("x", size)
			path := filepath.Join(t.TempDir(), "script.idc")
			if err := os.WriteFile(path, []byte(code), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			session := connectTestClient(t, backend)
			var output ida.ScriptExecutionResult
			callTool(t, session, ToolScriptExecute, map[string]any{
				"instanceId": testInstanceA, "language": "idc", "path": path,
			}, &output)
			backend.mutex.Lock()
			defer backend.mutex.Unlock()
			if backend.calls != 1 || backend.params.Code != code {
				t.Fatalf("backend execution = %d, source bytes = %d", backend.calls, len(backend.params.Code))
			}
		})
	}
}
