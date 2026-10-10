package webmanager

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestOpenCode2ConfigurationMigratesOnlyManagedServer(t *testing.T) {
	for _, initial := range []string{
		`{
			// keep provider and other servers
			"model": "provider/model",
			"mcp": {
				"ida-mcp": {"type": "local", "command": ["old.exe"], "enabled": true},
				"other": {"type": "remote", "url": "https://example.test/mcp"},
			}
		}`,
		`{
			// keep provider and other servers
			"model": "provider/model",
			"mcp": {
				"timeout": {"startup": 45000},
				"servers": {
					"ida-mcp": {"type": "local", "command": ["old.exe"], "disabled": true},
					"other": {"type": "remote", "url": "https://example.test/mcp"},
				}
			}
		}`,
		`{
			// keep provider and other servers
			"model": "provider/model",
			"mcp": {
				"ida-mcp": {"type": "local", "command": ["old.exe"], "enabled": true},
				"other": {"type": "remote", "url": "https://example.test/mcp"},
				"timeout": {"startup": 45000},
				"servers": {
					"ida-mcp": {"type": "local", "command": ["disabled.exe"], "disabled": true},
					"native-other": {"type": "local", "command": ["other.exe"]},
				}
			}
		}`,
	} {
		t.Run(initial, func(t *testing.T) {
			manager, path := openCodeTestManager(t, initial)
			_, before, err := readOpenCodeConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if status := manager.openCodeStatus(); !status.Configured || status.Current {
				t.Fatalf("old configuration status = %+v", status)
			}
			if err := manager.configureOpenCode(true); err != nil {
				t.Fatal(err)
			}
			assertOpenCode2Entry(t, manager, path)
			if status := manager.openCodeStatus(); !status.Configured || !status.Current || status.Name != "OpenCode 2" {
				t.Fatalf("updated status = %+v", status)
			}
			contents, err := os.ReadFile(path)
			if err != nil || !strings.Contains(string(contents), "keep provider and other servers") {
				t.Fatalf("comment lost: %v\n%s", err, contents)
			}
			if err := manager.configureOpenCode(false); err != nil {
				t.Fatal(err)
			}
			_, after, err := readOpenCodeConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if status := manager.openCodeStatus(); status.Configured || status.Current {
				t.Fatalf("removed status = %+v", status)
			}
			removeTestManagedOpenCodeEntries(before)
			removeTestManagedOpenCodeEntries(after)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("unrelated settings changed:\nbefore: %#v\nafter: %#v", before, after)
			}
		})
	}
}

func TestOpenCode2ConfigurationCreatesNativeEntry(t *testing.T) {
	manager, path := openCodeTestManager(t, "")
	if err := manager.configureOpenCode(false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("removing missing configuration created a file: %v", err)
	}
	if err := manager.configureOpenCode(true); err != nil {
		t.Fatal(err)
	}
	assertOpenCode2Entry(t, manager, path)
}

func TestOpenCode2ConfigurationRejectsMalformedNamespaces(t *testing.T) {
	for _, initial := range []string{
		`{"mcp": null}`,
		`{"mcp": []}`,
		`{"mcp": {"servers": null}}`,
		`{"mcp": {"servers": []}}`,
		`{"mcp": {"servers": "occupied"}}`,
		`{"mcp": {"servers": {"type": "local", "command": ["other.exe"]}}}`,
	} {
		t.Run(initial, func(t *testing.T) {
			manager, path := openCodeTestManager(t, initial)
			for _, enabled := range []bool{true, false} {
				if err := manager.configureOpenCode(enabled); err == nil {
					t.Fatalf("accepted invalid namespace with enabled=%v", enabled)
				}
				contents, err := os.ReadFile(path)
				if err != nil || string(contents) != initial {
					t.Fatalf("invalid configuration changed: %v\n%s", err, contents)
				}
			}
		})
	}
}

func TestOpenCode2StatusUsesNativeEnablementAndTransport(t *testing.T) {
	for _, test := range []struct {
		name    string
		fields  map[string]any
		current bool
	}{
		{"native defaults", map[string]any{}, true},
		{"enabled", map[string]any{"disabled": false}, true},
		{"disabled", map[string]any{"disabled": true}, false},
		{"invalid disabled", map[string]any{"disabled": "false"}, false},
		{"legacy enablement", map[string]any{"enabled": true}, false},
		{"code mode", map[string]any{"codemode": true}, false},
		{"missing code mode", map[string]any{"codemode": nil}, false},
		{"modern protocol", map[string]any{"protocol": "2026-07-28"}, false},
		{"invalid protocol", map[string]any{"protocol": map[string]any{}}, false},
		{"native timeout", map[string]any{"timeout": map[string]any{"execution": 300000}}, true},
		{"legacy timeout", map[string]any{"timeout": 120000}, false},
		{"invalid timeout", map[string]any{"timeout": map[string]any{"execution": "120000"}}, false},
		{"zero timeout", map[string]any{"timeout": map[string]any{"execution": 0}}, false},
		{"fractional timeout", map[string]any{"timeout": map[string]any{"execution": 1.5}}, false},
		{"unknown timeout", map[string]any{"timeout": map[string]any{"request": 120000}}, false},
		{"other path", map[string]any{"command": []string{"other.exe"}}, false},
		{"extra argument", map[string]any{"command": []string{"gateway.exe", "-web"}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, path := openCodeTestManager(t, "")
			entry := map[string]any{"type": "local", "command": []string{manager.gatewayPath}, "codemode": false}
			for key, value := range test.fields {
				entry[key] = value
			}
			contents, err := json.Marshal(map[string]any{"mcp": map[string]any{"servers": map[string]any{serverName: entry}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			if status := manager.openCodeStatus(); !status.Configured || status.Current != test.current {
				t.Fatalf("status = %+v, want current=%v", status, test.current)
			}
		})
	}
}

func TestOpenCode2RemovalDeletesBothManagedFormats(t *testing.T) {
	manager, path := openCodeTestManager(t, `{"mcp": {
		"ida-mcp": {"enabled": true}, "other": {"enabled": false},
		"servers": {"ida-mcp": {"disabled": true}, "native-other": {"disabled": false}}
	}}`)
	if err := manager.configureOpenCode(false); err != nil {
		t.Fatal(err)
	}
	_, root, err := readOpenCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	mcp, servers, err := openCodeMCPObjects(root)
	if err != nil || len(mcp) != 2 || len(servers) != 1 || mcp[serverName] != nil || servers[serverName] != nil {
		t.Fatalf("removal left managed entries or removed unrelated ones: %#v, %v", root, err)
	}
}

func TestOpenCode2UsesSupportedGlobalFiles(t *testing.T) {
	manager, path := openCodeTestManager(t, "")
	legacyPath := filepath.Join(filepath.Dir(path), "config.json")
	if err := os.WriteFile(legacyPath, []byte(`{"model":"legacy/model"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.configureOpenCode(true); err != nil {
		t.Fatal(err)
	}
	if contents, err := os.ReadFile(legacyPath); err != nil || string(contents) != `{"model":"legacy/model"}` {
		t.Fatalf("obsolete config.json changed: %v\n%s", err, contents)
	}
	if manager.openCodeConfigPath() != path {
		t.Fatalf("global path = %s, want %s", manager.openCodeConfigPath(), path)
	}
	jsoncPath := filepath.Join(filepath.Dir(path), "opencode.jsonc")
	if err := os.WriteFile(jsoncPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if manager.openCodeConfigPath() != jsoncPath {
		t.Fatalf("JSONC did not take precedence: %s", manager.openCodeConfigPath())
	}
}

func openCodeTestManager(t *testing.T, initial string) (*ClientManager, string) {
	t.Helper()
	isolateClientEnvironment(t)
	home := t.TempDir()
	configDirectory := filepath.Join(home, "custom-config")
	t.Setenv("OPENCODE_CONFIG_DIR", configDirectory)
	if err := os.MkdirAll(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(configDirectory, "opencode.json")
	if initial != "" {
		if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return newClientManager(filepath.Join(home, "app path", "ida-mcp.exe"), home, nil, nil), path
}

func assertOpenCode2Entry(t *testing.T, manager *ClientManager, path string) {
	t.Helper()
	_, root, err := readOpenCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	mcp, servers, err := openCodeMCPObjects(root)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := servers[serverName].(map[string]any)
	if !ok {
		t.Fatalf("missing native server: %#v", root)
	}
	command, ok := entry["command"].([]any)
	if !ok || len(command) != 1 || command[0] != manager.gatewayPath || entry["type"] != "local" ||
		entry["disabled"] != false || entry["codemode"] != false || entry["protocol"] != "legacy" {
		t.Fatalf("incorrect native entry: %#v", entry)
	}
	if _, exists := mcp[serverName]; exists {
		t.Fatalf("legacy entry remained: %#v", mcp)
	}
	if _, exists := entry["enabled"]; exists {
		t.Fatalf("legacy enablement remained: %#v", entry)
	}
	wantTimeout := map[string]any{"catalog": float64(120000), "execution": float64(120000)}
	if !reflect.DeepEqual(entry["timeout"], wantTimeout) {
		t.Fatalf("timeout = %#v, want %#v", entry["timeout"], wantTimeout)
	}
}

func removeTestManagedOpenCodeEntries(root map[string]any) {
	mcp := root["mcp"].(map[string]any)
	delete(mcp, serverName)
	if servers, ok := mcp["servers"].(map[string]any); ok {
		delete(servers, serverName)
		if len(servers) == 0 {
			delete(mcp, "servers")
		}
	}
}
