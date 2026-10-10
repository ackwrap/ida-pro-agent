package webmanager

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenCodeConfigurationPreservesOtherFieldsAndComments(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	gateway := filepath.Join(home, "ida-mcp.exe")
	configPath := filepath.Join(home, ".config", "opencode", "opencode.jsonc")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	initial := "{\n  // keep this comment\n  \"model\": \"provider/model\",\n  \"mcp\": {\n    \"other\": {\"type\": \"local\", \"command\": [\"other.exe\"]},\n  },\n}\n"
	if err := os.WriteFile(configPath, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := newClientManager(gateway, home, nil, nil)
	if err := manager.configureOpenCode(true); err != nil {
		t.Fatalf("configureOpenCode: %v", err)
	}
	contents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "keep this comment") || !strings.Contains(string(contents), `"other"`) {
		t.Fatalf("unrelated OpenCode configuration was not preserved:\n%s", contents)
	}
	status := manager.openCodeStatus()
	if !status.Configured || !status.Current {
		t.Fatalf("OpenCode status = %+v", status)
	}
	if err := manager.configureOpenCode(false); err != nil {
		t.Fatalf("remove OpenCode configuration: %v", err)
	}
	status = manager.openCodeStatus()
	if status.Configured || status.Current {
		t.Fatalf("OpenCode configuration remained after removal: %+v", status)
	}
	contents, err = os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "keep this comment") || !strings.Contains(string(contents), `"other"`) {
		t.Fatalf("OpenCode removal changed unrelated configuration:\n%s", contents)
	}
}

func TestOpenCodeConfigurationCreatesStrictGlobalConfig(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	gateway := filepath.Join(home, "ida-mcp.exe")
	manager := newClientManager(gateway, home, nil, nil)
	if err := manager.configureOpenCode(true); err != nil {
		t.Fatalf("configureOpenCode: %v", err)
	}
	path := filepath.Join(home, ".config", "opencode", "opencode.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(contents, &root); err != nil {
		t.Fatalf("created config is not JSON: %v", err)
	}
	if root["$schema"] != "https://opencode.ai/config.json" {
		t.Fatalf("created config omitted schema: %s", contents)
	}
}

func TestCodexConfigurationUsesOfficialCLI(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	gateway := filepath.Join(home, "ida-mcp.exe")
	executable := filepath.Join(home, "codex.exe")
	if err := os.WriteFile(executable, []byte("test CLI"), 0o700); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	runner := func(_ context.Context, executable string, arguments ...string) ([]byte, error) {
		call := append([]string{executable}, arguments...)
		calls = append(calls, call)
		if len(arguments) >= 3 && arguments[0] == "mcp" && arguments[1] == "list" {
			return []byte(`[{"name":"ida-mcp","enabled":true,"transport":{"type":"stdio","command":"` + strings.ReplaceAll(gateway, `\`, `\\`) + `","args":[]}}]`), nil
		}
		return nil, nil
	}
	manager := newClientManager(gateway, home, func(name string) (string, error) {
		if name != "codex" {
			return "", errors.New("unexpected executable")
		}
		return executable, nil
	}, runner)
	status := manager.codexStatus(context.Background())
	if !status.Available || !status.Configured || !status.Current {
		t.Fatalf("Codex status = %+v", status)
	}
	if err := manager.configureCodex(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if err := manager.configureCodex(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	wantAdd := strings.Join([]string{executable, "mcp", "add", serverName, "--", gateway}, "\x00")
	wantRemove := strings.Join([]string{executable, "mcp", "remove", serverName}, "\x00")
	joined := make([]string, 0, len(calls))
	for _, call := range calls {
		joined = append(joined, strings.Join(call, "\x00"))
	}
	if !contains(joined, wantAdd) || !contains(joined, wantRemove) {
		t.Fatalf("Codex CLI calls = %#v", calls)
	}
}

func TestAtomicWriteRejectsConcurrentConfigurationChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opencode.json")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := writeFileAtomic(path, []byte("replacement"), []byte("stale"))
	if err == nil || !strings.Contains(err.Error(), "configuration changed") {
		t.Fatalf("concurrent update error = %v", err)
	}
	contents, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(contents) != "current" {
		t.Fatalf("concurrent update overwrote config: %q", contents)
	}
}

func TestManagedSkillsUseSharedDirectoryLinks(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	gateway := filepath.Join(home, "app", "ida-mcp.exe")
	writePackagedSkills(t, gateway)
	t.Setenv("CODEX_HOME", filepath.Join(home, "codex"))
	t.Setenv("OPENCODE_CONFIG_DIR", filepath.Join(home, "opencode"))
	manager := newClientManager(gateway, home, nil, nil)

	for _, clientID := range managedClientIDs {
		if err := manager.configureSkills(clientID, true); err != nil {
			t.Fatalf("configureSkills(%s): %v", clientID, err)
		}
		status := manager.skillStatus(clientID)
		if !status.Available || !status.Configured || !status.Current || status.Conflict {
			t.Fatalf("skill status for %s = %+v", clientID, status)
		}
		for _, name := range managedSkillNames {
			destination := filepath.Join(status.Root, name)
			target, err := os.Readlink(destination)
			if err != nil {
				t.Fatalf("Readlink(%s): %v", destination, err)
			}
			if !samePath(target, filepath.Join(manager.skillSourceRoot(), name)) {
				t.Fatalf("skill link %s targets %s", destination, target)
			}
		}
	}

	updated := []byte("---\nname: idapython\n---\nupdated in one place\n")
	source := filepath.Join(manager.skillSourceRoot(), "idapython", "SKILL.md")
	if err := os.WriteFile(source, updated, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, clientID := range managedClientIDs {
		linked := filepath.Join(manager.skillDestinationRoot(clientID), "idapython", "SKILL.md")
		contents, err := os.ReadFile(linked)
		if err != nil || string(contents) != string(updated) {
			t.Fatalf("shared skill for %s was copied instead of linked: %v", clientID, err)
		}
	}

	if err := manager.RemoveManagedSkillLinks(); err != nil {
		t.Fatal(err)
	}
	for _, clientID := range managedClientIDs {
		for _, name := range managedSkillNames {
			if _, err := os.Lstat(filepath.Join(manager.skillDestinationRoot(clientID), name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("managed skill link remained for %s/%s: %v", clientID, name, err)
			}
		}
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("unlink removed packaged skill source: %v", err)
	}
}

func TestManagedSkillsRefuseExistingDirectories(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	gateway := filepath.Join(home, "app", "ida-mcp.exe")
	writePackagedSkills(t, gateway)
	t.Setenv("CODEX_HOME", filepath.Join(home, "codex"))
	manager := newClientManager(gateway, home, nil, nil)
	conflict := filepath.Join(manager.skillDestinationRoot("codex"), "idapython")
	if err := os.MkdirAll(conflict, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(conflict, "user-content.txt")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.configureSkills("codex", true); err == nil || !strings.Contains(err.Error(), "not managed") {
		t.Fatalf("skill conflict error = %v", err)
	}
	if err := manager.configureSkills("codex", false); err == nil || !strings.Contains(err.Error(), "not managed") {
		t.Fatalf("skill unlink conflict error = %v", err)
	}
	if contents, err := os.ReadFile(marker); err != nil || string(contents) != "keep" {
		t.Fatalf("conflicting user skill was changed: %q, %v", contents, err)
	}
	other := filepath.Join(manager.skillDestinationRoot("codex"), "ida-reverse-analysis")
	if _, err := os.Lstat(other); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preflight conflict left a partial skill link: %v", err)
	}
}

func TestManagedSkillsRefuseOtherDirectoryLinks(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	gateway := filepath.Join(home, "app", "ida-mcp.exe")
	writePackagedSkills(t, gateway)
	t.Setenv("CODEX_HOME", filepath.Join(home, "codex"))
	manager := newClientManager(gateway, home, nil, nil)
	root := manager.skillDestinationRoot("codex")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	otherTarget := filepath.Join(home, "user-skill")
	if err := os.MkdirAll(otherTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	conflict := filepath.Join(root, "idapython")
	if err := createDirectoryLink(conflict, otherTarget); err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(manager.skillSourceRoot(), "idapython")
	if err := removeManagedDirectoryLink(conflict, expected); err == nil || !strings.Contains(err.Error(), "not managed") {
		t.Fatalf("direct other junction removal error = %v", err)
	}
	if target, err := os.Readlink(conflict); err != nil || !samePath(target, otherTarget) {
		t.Fatalf("direct removal changed other junction: target=%q error=%v", target, err)
	}
	if err := manager.configureSkills("codex", false); err == nil || !strings.Contains(err.Error(), "not managed") {
		t.Fatalf("other junction unlink error = %v", err)
	}
	target, err := os.Readlink(conflict)
	if err != nil || !samePath(target, otherTarget) {
		t.Fatalf("other junction was changed: target=%q error=%v", target, err)
	}
}

func TestOpenCodeDiscoversManagedSkillLinks(t *testing.T) {
	isolateClientEnvironment(t)
	if os.Getenv("IDA_AGENT_OPENCODE_INTEGRATION") != "1" {
		t.Skip("set IDA_AGENT_OPENCODE_INTEGRATION=1 to run with an installed OpenCode CLI")
	}
	home := t.TempDir()
	gateway := filepath.Join(home, "app", "ida-mcp.exe")
	writePackagedSkills(t, gateway)
	configDirectory := filepath.Join(home, "opencode")
	t.Setenv("OPENCODE_CONFIG_DIR", configDirectory)
	manager := newClientManager(gateway, home, nil, nil)
	if err := manager.configureSkills("opencode", true); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("opencode", "debug", "skill")
	command.Env = append(os.Environ(), "OPENCODE_CONFIG_DIR="+configDirectory)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("opencode debug skill: %v", err)
	}
	var skills []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(output, &skills); err != nil {
		t.Fatalf("decode OpenCode skills: %v", err)
	}
	found := make(map[string]bool)
	for _, skill := range skills {
		found[skill.Name] = true
	}
	for _, name := range managedSkillNames {
		if !found[name] {
			t.Errorf("OpenCode did not discover junction-backed skill %s", name)
		}
	}
}

func writePackagedSkills(t *testing.T, gateway string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(gateway), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gateway, []byte("gateway"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range managedSkillNames {
		path := filepath.Join(filepath.Dir(gateway), "skills", name, "SKILL.md")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("---\nname: "+name+"\n---\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
