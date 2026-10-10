package webmanager

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJSONMCPClientsCreateAndPreserveConfiguration(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	gateway := filepath.Join(home, "app", "ida-mcp.exe")
	manager := newClientManager(gateway, home, nil, nil)
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, "claude-override"))

	clients := []struct {
		name      string
		path      string
		configure func(bool) error
		status    func() ClientStatus
	}{
		{"Antigravity CLI", manager.antigravityConfigPath(), manager.configureAntigravity, manager.antigravityStatus},
		{"Claude Code", manager.claudeCodeConfigPath(), manager.configureClaudeCode, manager.claudeCodeStatus},
	}
	for _, client := range clients {
		t.Run(client.name+" create", func(t *testing.T) {
			if err := client.configure(true); err != nil {
				t.Fatal(err)
			}
			status := client.status()
			if !status.Available || !status.Configured || !status.Current {
				t.Fatalf("created status = %+v", status)
			}
			if err := client.configure(false); err != nil {
				t.Fatal(err)
			}
		})

		initial := "{\n  \"counter\": 900719925474099312345,\n  \"projects\": {\"keep\": true},\n  \"mcpServers\": {\"other\": {\"command\": \"other\", \"args\": []}, \"ida-mcp\": {\"command\": \"stale\", \"args\": [\"old\"]}}\n}\n"
		if err := os.MkdirAll(filepath.Dir(client.path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(client.path, []byte(initial), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := client.configure(true); err != nil {
			t.Fatalf("install into existing config: %v", err)
		}
		if status := client.status(); !status.Current {
			t.Fatalf("existing ida-mcp entry was not updated: %+v", status)
		}
		contents, err := os.ReadFile(client.path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(contents), "900719925474099312345") {
			t.Fatalf("large number was changed:\n%s", contents)
		}
		var root map[string]json.RawMessage
		if err := json.Unmarshal(contents, &root); err != nil {
			t.Fatal(err)
		}
		servers, _, err := jsonObjectField(root, "mcpServers")
		if err != nil || servers["other"] == nil || servers[serverName] == nil || root["projects"] == nil {
			t.Fatalf("unrelated configuration was not preserved: %v\n%s", err, contents)
		}
		if err := client.configure(false); err != nil {
			t.Fatalf("remove from existing config: %v", err)
		}
		contents, err = os.ReadFile(client.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(contents, &root); err != nil {
			t.Fatal(err)
		}
		servers, _, err = jsonObjectField(root, "mcpServers")
		if err != nil || servers[serverName] != nil || servers["other"] == nil || root["projects"] == nil ||
			!strings.Contains(string(contents), "900719925474099312345") {
			t.Fatalf("removal changed unrelated configuration: %v\n%s", err, contents)
		}
	}
}

func TestJSONMCPClientsRejectInvalidConfigurationWithoutOverwrite(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	manager := newClientManager(filepath.Join(home, "gateway.exe"), home, nil, nil)
	clients := []struct {
		name      string
		path      string
		configure func(bool) error
	}{
		{"antigravity", manager.antigravityConfigPath(), manager.configureAntigravity},
		{"claudecode", manager.claudeCodeConfigPath(), manager.configureClaudeCode},
	}
	invalidDocuments := []string{"{invalid", "[]", `{"mcpServers":null}`, `{"mcpServers":[]}`}
	for _, client := range clients {
		for _, initial := range invalidDocuments {
			if client.name == "antigravity" && (initial == "{invalid" || initial == "[]") {
				continue // Antigravity repairs invalid roots on installation.
			}
			if err := os.MkdirAll(filepath.Dir(client.path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(client.path, []byte(initial), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, enabled := range []bool{true, false} {
				if err := client.configure(enabled); err == nil {
					t.Fatalf("%s configure(%v) accepted %q", client.name, enabled, initial)
				}
				contents, err := os.ReadFile(client.path)
				if err != nil || string(contents) != initial {
					t.Fatalf("%s configure(%v) overwrote invalid config: %v, %q", client.name, enabled, err, contents)
				}
			}
		}
	}
}

func TestAntigravityInitializesInvalidConfiguration(t *testing.T) {
	for _, initial := range []string{"", " \r\n", "not json", "[]", "null"} {
		t.Run(initial, func(t *testing.T) {
			home := t.TempDir()
			manager := newClientManager(filepath.Join(home, "gateway.exe"), home, nil, nil)
			path := manager.antigravityConfigPath()
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := manager.configureAntigravity(true); err != nil {
				t.Fatal(err)
			}
			if !manager.antigravityStatus().Current {
				t.Fatal("configuration was not initialized")
			}
			if strings.TrimSpace(initial) != "" {
				backup, err := os.ReadFile(path + ".invalid.bak")
				if err != nil || string(backup) != initial {
					t.Fatalf("backup mismatch: %q, %v", backup, err)
				}
				if err := os.WriteFile(path, []byte("another invalid file"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := manager.configureAntigravity(true); err == nil {
					t.Fatal("existing backup overwritten")
				}
				contents, err := os.ReadFile(path)
				if err != nil || string(contents) != "another invalid file" {
					t.Fatal("failed backup changed configuration")
				}
			}
		})
	}
}

func TestJSONMCPRemoveMissingDoesNotCreateConfiguration(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	manager := newClientManager(filepath.Join(home, "gateway.exe"), home, nil, nil)
	for _, client := range []struct {
		path      string
		configure func(bool) error
	}{
		{manager.antigravityConfigPath(), manager.configureAntigravity},
		{manager.claudeCodeConfigPath(), manager.configureClaudeCode},
	} {
		if err := client.configure(false); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(client.path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("remove created %s: %v", client.path, err)
		}
	}
}

func TestJSONMCPStatusRejectsMismatchedEntries(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	gateway := filepath.Join(home, "gateway.exe")
	manager := newClientManager(gateway, home, nil, nil)
	tests := []struct {
		name       string
		claudeCode bool
		entry      string
	}{
		{"Antigravity transport", false, `{"type":"http","command":"` + jsonPath(gateway) + `","args":[]}`},
		{"Antigravity arguments", false, `{"command":"` + jsonPath(gateway) + `","args":["extra"]}`},
		{"Antigravity disabled", false, `{"command":"` + jsonPath(gateway) + `","args":[],"disabled":true}`},
		{"Antigravity remote URL", false, `{"command":"` + jsonPath(gateway) + `","args":[],"url":"https://example.test/mcp"}`},
		{"Antigravity server URL", false, `{"command":"` + jsonPath(gateway) + `","args":[],"serverUrl":"https://example.test/mcp"}`},
		{"Claude missing transport", true, `{"command":"` + jsonPath(gateway) + `","args":[]}`},
		{"Claude remote transport", true, `{"type":"sse","command":"` + jsonPath(gateway) + `","args":[],"url":"https://example.test/mcp"}`},
		{"Claude disabled", true, `{"type":"stdio","command":"` + jsonPath(gateway) + `","args":[],"disabled":true}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := manager.antigravityConfigPath()
			status := manager.antigravityStatus
			if test.claudeCode {
				path = manager.claudeCodeConfigPath()
				status = manager.claudeCodeStatus
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			contents := `{"mcpServers":{"ida-mcp":` + test.entry + `}}`
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			got := status()
			if !got.Available || !got.Configured || got.Current {
				t.Fatalf("mismatched status = %+v", got)
			}
		})
	}
}

func TestClaudeConfigDirectoryOverride(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	override := filepath.Join(home, "claude-config")
	t.Setenv("CLAUDE_CONFIG_DIR", override)
	manager := newClientManager(filepath.Join(home, "gateway.exe"), home, nil, nil)
	if got, want := manager.claudeCodeConfigPath(), filepath.Join(override, ".claude.json"); got != want {
		t.Fatalf("Claude config path = %s, want %s", got, want)
	}
	if got, want := manager.skillDestinationRoot("claudecode"), filepath.Join(override, "skills"); got != want {
		t.Fatalf("Claude skills path = %s, want %s", got, want)
	}
}

func TestStatusIncludesDirectlyConfigurableClients(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	manager := newClientManager(filepath.Join(home, "gateway.exe"), home, func(string) (string, error) {
		return "", errors.New("not installed")
	}, nil)
	statuses := manager.Status(context.Background())
	if len(statuses) != len(managedClientIDs) {
		t.Fatalf("status clients = %+v", statuses)
	}
	for index, id := range managedClientIDs {
		if statuses[index].ID != id {
			t.Fatalf("status[%d].ID = %q, want %q", index, statuses[index].ID, id)
		}
		if (id == "antigravity" || id == "claudecode" || id == "zcode") && !statuses[index].Available {
			t.Fatalf("directly configurable client is unavailable: %+v", statuses[index])
		}
	}
}

func isolateClientEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("CODEX_HOME", "")
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("GROK_HOME", "")
	t.Setenv("IDA_MCP_CODEX_PATH", "")
	for _, name := range []string{"APPDATA", "LOCALAPPDATA", "SCOOP", "NPM_CONFIG_PREFIX"} {
		t.Setenv(name, t.TempDir())
	}
}

func jsonPath(path string) string {
	encoded, _ := json.Marshal(path)
	return string(encoded[1 : len(encoded)-1])
}
