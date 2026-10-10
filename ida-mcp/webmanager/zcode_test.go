package webmanager

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeZCodeFixture(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestZCodeUsesNativeUserConfigurationAndSkills(t *testing.T) {
	home := t.TempDir()
	manager := newClientManager(filepath.Join(home, "app with spaces", "gateway.exe"), home, nil, nil)
	if got, want := manager.zcodeConfigPath(), filepath.Join(home, ".zcode", "cli", "config.json"); got != want {
		t.Fatalf("config path = %q, want %q", got, want)
	}
	if got, want := manager.skillDestinationRoot("zcode"), filepath.Join(home, ".zcode", "skills"); got != want {
		t.Fatalf("skill path = %q, want %q", got, want)
	}
	if err := manager.SetEnabled(context.Background(), "zcode", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(manager.zcodeConfigPath()); !os.IsNotExist(err) {
		t.Fatalf("removing an absent entry created a file: %v", err)
	}
	if status := manager.zcodeStatus(); !status.Available || status.Configured {
		t.Fatalf("initial status = %+v", status)
	}
	if err := manager.SetEnabled(context.Background(), "zcode", true); err != nil {
		t.Fatal(err)
	}
	config, err := readZCodeConfig(manager.zcodeConfigPath())
	if err != nil || config.root["mcpServers"] != nil || !zcodeEntryCurrent(config.servers[serverName], manager.gatewayPath) {
		t.Fatalf("wrong native config shape: %+v, %v", config, err)
	}
	if !manager.zcodeStatus().Current {
		t.Fatal("installed entry was not detected")
	}
	if err := manager.SetEnabled(context.Background(), "zcode", false); err != nil {
		t.Fatal(err)
	}
	if manager.zcodeStatus().Configured {
		t.Fatal("removed entry still configured")
	}
}

func TestZCodePreservesOtherServersAndSettings(t *testing.T) {
	home := t.TempDir()
	manager := newClientManager(filepath.Join(home, "gateway.exe"), home, nil, nil)
	initial := `{"counter":900719925474099312345,"models":{"keep":"value"},"mcp":{"timeout":1234,"servers":{"other":{"url":"https://example.invalid/mcp","enable":false},"ida-mcp":{"command":"stale","args":["old"]}}}}`
	writeZCodeFixture(t, manager.zcodeConfigPath(), initial)
	for _, enabled := range []bool{true, false} {
		if err := manager.configureZCode(enabled); err != nil {
			t.Fatal(err)
		}
		config, err := readZCodeConfig(manager.zcodeConfigPath())
		if err != nil || string(config.root["counter"]) != "900719925474099312345" ||
			!strings.Contains(string(config.root["models"]), "value") || string(config.mcp["timeout"]) != "1234" ||
			!strings.Contains(string(config.servers["other"]), "https://example.invalid/mcp") ||
			!strings.Contains(string(config.servers["other"]), "false") {
			t.Fatalf("unrelated config changed: %+v, %v", config, err)
		}
		if status := manager.zcodeStatus(); status.Configured != enabled || status.Current != enabled {
			t.Fatalf("configure(%v): %+v", enabled, status)
		}
	}
}

func TestZCodeRecognizesEnableFlagAndTransport(t *testing.T) {
	home := t.TempDir()
	manager := newClientManager(filepath.Join(home, "gateway.exe"), home, nil, nil)
	for _, change := range []map[string]any{
		{}, {"enable": false}, {"enable": "true"}, {"command": "stale"},
		{"args": []string{"--other"}}, {"type": "http"}, {"url": "https://example.invalid/mcp"},
	} {
		entry := map[string]any{"command": manager.gatewayPath, "args": []string{}}
		for name, value := range change {
			entry[name] = value
		}
		encoded, _ := json.Marshal(map[string]any{"mcp": map[string]any{"servers": map[string]any{serverName: entry}}})
		writeZCodeFixture(t, manager.zcodeConfigPath(), string(encoded))
		if status := manager.zcodeStatus(); !status.Configured || status.Current != (len(change) == 0) {
			t.Fatalf("status for %v = %+v", change, status)
		}
	}
}

func TestZCodeRejectsInvalidNativeConfigWithoutOverwrite(t *testing.T) {
	home := t.TempDir()
	manager := newClientManager(filepath.Join(home, "gateway.exe"), home, nil, nil)
	for _, initial := range []string{"{invalid", "null", "[]", `{"mcp":null}`, `{"mcp":[]}`, `{"mcp":{"servers":null}}`, `{"mcp":{"servers":[]}}`} {
		writeZCodeFixture(t, manager.zcodeConfigPath(), initial)
		for _, enabled := range []bool{true, false} {
			if err := manager.configureZCode(enabled); err == nil {
				t.Fatalf("configure(%v) accepted %q", enabled, initial)
			}
			contents, err := os.ReadFile(manager.zcodeConfigPath())
			if err != nil || string(contents) != initial {
				t.Fatalf("invalid config overwritten: %q, %v", contents, err)
			}
		}
		if status := manager.zcodeStatus(); status.Configured || !strings.Contains(status.Detail, "invalid") {
			t.Fatalf("invalid config status = %+v", status)
		}
	}
}

func TestZCodeImportsOnlyAnActiveSharedFallback(t *testing.T) {
	for _, nativeActive := range []bool{false, true} {
		home := t.TempDir()
		manager := newClientManager(filepath.Join(home, "gateway.exe"), home, nil, nil)
		shared := `{"mcpServers":{"shared":{"command":"other.exe","args":[],"env":{"KEEP":"value"}},"ida-mcp":{"command":"old","args":[]}}}`
		writeZCodeFixture(t, manager.zcodeSharedConfigPath(), shared)
		if nativeActive {
			writeZCodeFixture(t, manager.zcodeConfigPath(), `{"mcp":{"servers":{"native":{"command":"native.exe","args":[]}}}}`)
		}
		if status := manager.zcodeStatus(); status.Configured == nativeActive {
			t.Fatalf("wrong fallback precedence: %+v", status)
		}
		if err := manager.configureZCode(true); err != nil {
			t.Fatal(err)
		}
		config, err := readZCodeConfig(manager.zcodeConfigPath())
		if err != nil || (config.servers["shared"] != nil) == nativeActive || (config.servers["native"] != nil) != nativeActive {
			t.Fatalf("active peers not preserved: %+v, %v", config, err)
		}
		contents, err := os.ReadFile(manager.zcodeSharedConfigPath())
		if err != nil || string(contents) != shared || !manager.zcodeStatus().Current {
			t.Fatalf("shared config changed or installation failed: %v", err)
		}
	}
}

func TestZCodeRemovalDoesNotReactivateSharedIdaAgent(t *testing.T) {
	for _, nativeInitiallyPresent := range []bool{false, true} {
		home := t.TempDir()
		manager := newClientManager(filepath.Join(home, "gateway.exe"), home, nil, nil)
		entry := map[string]any{"command": manager.gatewayPath, "args": []string{}}
		shared, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{serverName: entry}})
		writeZCodeFixture(t, manager.zcodeSharedConfigPath(), string(shared))
		if nativeInitiallyPresent {
			if err := manager.configureZCode(true); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < 2; i++ {
			if err := manager.configureZCode(false); err != nil {
				t.Fatal(err)
			}
			if status := manager.zcodeStatus(); status.Current || status.ConfigPath != manager.zcodeConfigPath() {
				t.Fatalf("shared entry reactivated after removal: %+v", status)
			}
		}
		contents, err := os.ReadFile(manager.zcodeSharedConfigPath())
		if err != nil || string(contents) != string(shared) {
			t.Fatalf("removal changed shared config: %v", err)
		}
	}
}

func TestZCodeRejectsInvalidActiveFallbackBeforeCreatingNativeConfig(t *testing.T) {
	home := t.TempDir()
	manager := newClientManager(filepath.Join(home, "gateway.exe"), home, nil, nil)
	writeZCodeFixture(t, manager.zcodeSharedConfigPath(), `{"mcpServers":null}`)
	if err := manager.configureZCode(true); err == nil {
		t.Fatal("invalid active fallback was silently hidden")
	}
	if _, err := os.Stat(manager.zcodeConfigPath()); !os.IsNotExist(err) {
		t.Fatalf("native config was created: %v", err)
	}
	writeZCodeFixture(t, manager.zcodeConfigPath(), `{"mcp":{"servers":{"other":{"command":"other.exe","args":[]}}}}`)
	if err := manager.configureZCode(true); err != nil {
		t.Fatalf("inactive fallback blocked a valid native update: %v", err)
	}
}
