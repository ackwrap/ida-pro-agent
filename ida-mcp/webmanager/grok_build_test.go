package webmanager

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGrokBuildUsesUserScopedCLI(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	gateway := filepath.Join(home, "app with spaces", "gateway.exe")
	var calls [][]string
	manager := newClientManager(gateway, home, func(name string) (string, error) {
		if name != "grok" {
			return "", errors.New("not installed")
		}
		return "grok.exe", nil
	}, func(_ context.Context, executable string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{executable}, args...))
		return []byte("[]"), nil
	})
	for _, enabled := range []bool{true, false} {
		if err := manager.SetEnabled(context.Background(), "grokbuild", enabled); err != nil {
			t.Fatal(err)
		}
	}
	want := [][]string{
		{"grok.exe", "mcp", "add", "--scope", "user", "--transport", "stdio", "ida-mcp", "--", gateway},
		{"grok.exe", "mcp", "remove", "ida-mcp", "--scope", "user"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %#v", calls)
	}
	if got := manager.grokDirectory(); got != filepath.Join(home, ".grok") {
		t.Fatal(got)
	}
	override := filepath.Join(home, "custom-grok")
	t.Setenv("GROK_HOME", override)
	if got := manager.skillDestinationRoot("grokbuild"); got != filepath.Join(override, "skills") {
		t.Fatal(got)
	}
	if got := manager.grokBuildStatus(context.Background()).ConfigPath; got != filepath.Join(override, "config.toml") {
		t.Fatal(got)
	}
	manager.run = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("failed") }
	if err := manager.configureGrokBuild(context.Background(), true); err == nil {
		t.Fatal("CLI error ignored")
	}
	if manager.grokBuildStatus(context.Background()).Current {
		t.Fatal("failed CLI is current")
	}
	manager.lookPath = func(string) (string, error) { return "", errors.New("missing") }
	if manager.grokBuildStatus(context.Background()).Available {
		t.Fatal("missing CLI is available")
	}
	if err := manager.configureGrokBuild(context.Background(), false); err == nil {
		t.Fatal("missing CLI accepted")
	}
}

func TestGrokBuildStatus(t *testing.T) {
	for _, field := range []string{"current", "legacy_args", "enabled", "scope", "command", "args", "url", "blocked_reason", "invalid", "empty"} {
		t.Run(field, func(t *testing.T) {
			home := t.TempDir()
			gateway := filepath.Join(home, "gateway.exe")
			entry := map[string]any{"name": "ida-mcp", "scope": "user", "command": gateway, "args": []string{}, "enabled": true}
			switch field {
			case "legacy_args":
				entry["args"] = []string{"--grok"}
			case "enabled":
				entry[field] = false
			case "scope":
				entry[field] = "project"
			case "command":
				entry[field] = "other.exe"
			case "args":
				entry[field] = []string{"--web"}
			case "url", "blocked_reason":
				entry[field] = "blocked"
			}
			output, _ := json.Marshal([]any{entry})
			if field == "invalid" {
				output = []byte("not json")
			}
			if field == "empty" {
				output = []byte("[]")
			}
			manager := newClientManager(gateway, home, func(string) (string, error) { return "grok.exe", nil }, func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if !reflect.DeepEqual(args, []string{"mcp", "list", "--json"}) {
					t.Fatalf("args = %v", args)
				}
				return output, nil
			})
			if got := manager.grokBuildStatus(context.Background()); got.Current != (field == "current" || field == "legacy_args") {
				t.Fatalf("status = %+v", got)
			}
		})
	}
}

func TestGrokBuildExecutableAliases(t *testing.T) {
	for index, available := range []string{"gork", "agent", "grok"} {
		t.Run(available, func(t *testing.T) {
			var searched []string
			manager := newClientManager("gateway.exe", t.TempDir(), func(name string) (string, error) {
				searched = append(searched, name)
				if name == available {
					return name + ".exe", nil
				}
				return "", errors.New("missing")
			}, func(_ context.Context, executable string, _ ...string) ([]byte, error) {
				if executable != available+".exe" {
					t.Fatalf("executable = %s", executable)
				}
				return []byte("[]"), nil
			})
			if err := manager.configureGrokBuild(context.Background(), true); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(searched, []string{"gork", "agent", "grok"}[:index+1]) {
				t.Fatalf("search order = %v", searched)
			}
			if !manager.grokBuildStatus(context.Background()).Available {
				t.Fatal("alias unavailable")
			}
			if err := manager.configureGrokBuild(context.Background(), false); err != nil {
				t.Fatal(err)
			}
		})
	}
}
