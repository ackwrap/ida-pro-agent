package webmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/tailscale/hujson"
)

const serverName = "ida-mcp"

var managedSkillNames = [...]string{"ida-reverse-analysis", "idapython"}

var managedClientIDs = [...]string{"codex", "opencode", "antigravity", "claudecode", "grokbuild", "zcode"}

type SkillStatus struct {
	Available  bool   `json:"available"`
	Configured bool   `json:"configured"`
	Current    bool   `json:"current"`
	Conflict   bool   `json:"conflict"`
	Root       string `json:"root"`
	Detail     string `json:"detail"`
}

type ClientStatus struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Available  bool        `json:"available"`
	Configured bool        `json:"configured"`
	Current    bool        `json:"current"`
	ConfigPath string      `json:"configPath"`
	Detail     string      `json:"detail"`
	Skills     SkillStatus `json:"skills"`
}

type commandRunner func(context.Context, string, ...string) ([]byte, error)

type ClientManager struct {
	gatewayPath string
	home        string
	lookPath    func(string) (string, error)
	run         commandRunner
	mutex       sync.Mutex
}

func NewClientManager(gatewayPath string) (*ClientManager, error) {
	abs, err := filepath.Abs(gatewayPath)
	if err != nil {
		return nil, fmt.Errorf("resolve Gateway path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("Gateway executable is unavailable")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve user home: %w", err)
	}
	return newClientManager(abs, home, exec.LookPath, runCommand), nil
}

func RemoveManagedSkillLinks(gatewayPath string) error {
	manager, err := NewClientManager(gatewayPath)
	if err != nil {
		return err
	}
	return manager.RemoveManagedSkillLinks()
}

func newClientManager(
	gatewayPath, home string,
	lookPath func(string) (string, error),
	run commandRunner,
) *ClientManager {
	return &ClientManager{gatewayPath: gatewayPath, home: home, lookPath: lookPath, run: run}
}

func (manager *ClientManager) GatewayPath() string {
	return manager.gatewayPath
}

func (manager *ClientManager) Status(ctx context.Context) []ClientStatus {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	codex := manager.codexStatus(ctx)
	codex.Skills = manager.skillStatus("codex")
	openCode := manager.openCodeStatus()
	openCode.Skills = manager.skillStatus("opencode")
	antigravity := manager.antigravityStatus()
	antigravity.Skills = manager.skillStatus("antigravity")
	claudeCode := manager.claudeCodeStatus()
	claudeCode.Skills = manager.skillStatus("claudecode")
	grok := manager.grokBuildStatus(ctx)
	grok.Skills = manager.skillStatus("grokbuild")
	zcode := manager.zcodeStatus()
	zcode.Skills = manager.skillStatus("zcode")
	return []ClientStatus{codex, openCode, antigravity, claudeCode, grok, zcode}
}

func (manager *ClientManager) SetEnabled(ctx context.Context, clientID string, enabled bool) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	switch clientID {
	case "codex":
		return manager.configureCodex(ctx, enabled)
	case "opencode":
		return manager.configureOpenCode(enabled)
	case "antigravity":
		return manager.configureAntigravity(enabled)
	case "claudecode":
		return manager.configureClaudeCode(enabled)
	case "grokbuild":
		return manager.configureGrokBuild(ctx, enabled)
	case "zcode":
		return manager.configureZCode(enabled)
	default:
		return fmt.Errorf("unsupported AI client")
	}
}

func (manager *ClientManager) SetSkillsEnabled(clientID string, enabled bool) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if !isManagedClient(clientID) {
		return fmt.Errorf("unsupported AI client")
	}
	return manager.configureSkills(clientID, enabled)
}

func (manager *ClientManager) RemoveManagedSkillLinks() error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	var failures []string
	for _, clientID := range managedClientIDs {
		if err := manager.configureSkills(clientID, false); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) != 0 {
		return fmt.Errorf("remove managed skill links: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (manager *ClientManager) codexConfigPath() string {
	if value := strings.TrimSpace(os.Getenv("CODEX_HOME")); value != "" {
		return filepath.Join(value, "config.toml")
	}
	return filepath.Join(manager.home, ".codex", "config.toml")
}

func (manager *ClientManager) codexStatus(ctx context.Context) ClientStatus {
	status := ClientStatus{ID: "codex", Name: "Codex", ConfigPath: manager.codexConfigPath()}
	executable, err := findCodexCommand(manager.home, manager.lookPath)
	if err != nil {
		status.Detail = err.Error()
		return status
	}
	status.Available = true
	output, err := manager.run(ctx, executable, "mcp", "list", "--json")
	if err != nil {
		status.Detail = "Codex MCP configuration could not be read."
		return status
	}
	var entries []struct {
		Name      string `json:"name"`
		Enabled   bool   `json:"enabled"`
		Transport struct {
			Type    string   `json:"type"`
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"transport"`
	}
	if err := json.Unmarshal(output, &entries); err != nil {
		status.Detail = "Codex returned an invalid MCP configuration response."
		return status
	}
	for _, entry := range entries {
		if entry.Name != serverName {
			continue
		}
		status.Configured = true
		status.Current = entry.Enabled && entry.Transport.Type == "stdio" &&
			samePath(entry.Transport.Command, manager.gatewayPath) && len(entry.Transport.Args) == 0
		if status.Current {
			status.Detail = "Ready. Restart Codex after changing this configuration."
		} else {
			status.Detail = "An ida-mcp entry exists but points to a different command."
		}
		return status
	}
	status.Detail = "ida-mcp is not configured."
	return status
}

func (manager *ClientManager) configureCodex(ctx context.Context, enabled bool) error {
	executable, err := findCodexCommand(manager.home, manager.lookPath)
	if err != nil {
		return err
	}
	arguments := []string{"mcp", "remove", serverName}
	if enabled {
		arguments = []string{"mcp", "add", serverName, "--", manager.gatewayPath}
	}
	if _, err := manager.run(ctx, executable, arguments...); err != nil {
		return fmt.Errorf("Codex rejected the MCP configuration")
	}
	return nil
}

func (manager *ClientManager) openCodeConfigPath() string {
	directory := manager.openCodeDirectory()
	for _, name := range []string{"opencode.jsonc", "opencode.json"} {
		path := filepath.Join(directory, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	return filepath.Join(directory, "opencode.json")
}

func (manager *ClientManager) openCodeDirectory() string {
	if value := strings.TrimSpace(os.Getenv("OPENCODE_CONFIG_DIR")); value != "" {
		return value
	}
	return filepath.Join(manager.home, ".config", "opencode")
}

func (manager *ClientManager) antigravityConfigPath() string {
	return filepath.Join(manager.home, ".gemini", "config", "mcp_config.json")
}

func (manager *ClientManager) claudeConfigDirectory() string {
	if value := strings.TrimSpace(os.Getenv("CLAUDE_CONFIG_DIR")); value != "" {
		return value
	}
	return filepath.Join(manager.home, ".claude")
}

func (manager *ClientManager) claudeCodeConfigPath() string {
	if value := strings.TrimSpace(os.Getenv("CLAUDE_CONFIG_DIR")); value != "" {
		return filepath.Join(value, ".claude.json")
	}
	return filepath.Join(manager.home, ".claude.json")
}

func (manager *ClientManager) skillSourceRoot() string {
	return filepath.Join(filepath.Dir(manager.gatewayPath), "skills")
}

func (manager *ClientManager) skillDestinationRoot(clientID string) string {
	switch clientID {
	case "codex":
		return filepath.Join(filepath.Dir(manager.codexConfigPath()), "skills")
	case "antigravity":
		return filepath.Join(manager.home, ".gemini", "antigravity-cli", "skills")
	case "claudecode":
		return filepath.Join(manager.claudeConfigDirectory(), "skills")
	case "grokbuild":
		return filepath.Join(manager.grokDirectory(), "skills")
	case "zcode":
		return filepath.Join(manager.home, ".zcode", "skills")
	default:
		return filepath.Join(manager.openCodeDirectory(), "skills")
	}
}

func isManagedClient(clientID string) bool {
	for _, managedID := range managedClientIDs {
		if clientID == managedID {
			return true
		}
	}
	return false
}

func (manager *ClientManager) skillStatus(clientID string) SkillStatus {
	root := manager.skillDestinationRoot(clientID)
	status := SkillStatus{Root: root, Available: true}
	currentCount := 0
	for _, name := range managedSkillNames {
		source := filepath.Join(manager.skillSourceRoot(), name)
		if info, err := os.Stat(filepath.Join(source, "SKILL.md")); err != nil || !info.Mode().IsRegular() {
			status.Available = false
			status.Detail = "Packaged ida-mcp skills are unavailable."
			return status
		}
		destination := filepath.Join(root, name)
		state, err := directoryLinkState(destination, source)
		if err != nil || state == linkConflict {
			status.Conflict = true
			continue
		}
		if state == linkCurrent {
			currentCount++
		}
	}
	status.Configured = currentCount != 0
	status.Current = currentCount == len(managedSkillNames) && !status.Conflict
	switch {
	case status.Conflict:
		status.Detail = "A skill path is occupied by content not managed by this ida-mcp installation."
	case status.Current:
		status.Detail = "Both ida-mcp skills share the packaged source through directory links."
	case currentCount != 0:
		status.Detail = "Only some ida-mcp skill links are installed."
	default:
		status.Detail = "ida-mcp skills are not linked."
	}
	return status
}

func (manager *ClientManager) configureSkills(clientID string, enabled bool) error {
	root := manager.skillDestinationRoot(clientID)
	type pair struct{ destination, source string }
	pairs := make([]pair, 0, len(managedSkillNames))
	for _, name := range managedSkillNames {
		pairs = append(pairs, pair{
			destination: filepath.Join(root, name),
			source:      filepath.Join(manager.skillSourceRoot(), name),
		})
	}
	for _, item := range pairs {
		if enabled {
			if info, err := os.Stat(filepath.Join(item.source, "SKILL.md")); err != nil || !info.Mode().IsRegular() {
				return fmt.Errorf("packaged skill %s is unavailable", filepath.Base(item.source))
			}
		}
		state, err := directoryLinkState(item.destination, item.source)
		if err != nil {
			return err
		}
		if state == linkConflict {
			return fmt.Errorf("skill path %s is not managed by this ida-mcp installation", item.destination)
		}
	}
	if enabled {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return fmt.Errorf("create skill directory: %w", err)
		}
		created := make([]string, 0, len(pairs))
		for _, item := range pairs {
			state, _ := directoryLinkState(item.destination, item.source)
			if state == linkCurrent {
				continue
			}
			if err := createDirectoryLink(item.destination, item.source); err != nil {
				for _, path := range created {
					_ = removeManagedDirectoryLink(path, filepath.Join(manager.skillSourceRoot(), filepath.Base(path)))
				}
				return fmt.Errorf("link skill %s: %w", filepath.Base(item.source), err)
			}
			created = append(created, item.destination)
		}
		return nil
	}
	for _, item := range pairs {
		state, _ := directoryLinkState(item.destination, item.source)
		if state == linkCurrent {
			if err := removeManagedDirectoryLink(item.destination, item.source); err != nil {
				return fmt.Errorf("remove skill link %s: %w", filepath.Base(item.destination), err)
			}
		}
	}
	return nil
}

type linkState uint8

const (
	linkAbsent linkState = iota
	linkCurrent
	linkConflict
)

func directoryLinkState(path, expectedTarget string) (linkState, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return linkAbsent, nil
	}
	if err != nil {
		return linkConflict, fmt.Errorf("inspect skill path: %w", err)
	}
	target, err := os.Readlink(path)
	if err != nil {
		return linkConflict, nil
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	if samePath(target, expectedTarget) {
		return linkCurrent, nil
	}
	return linkConflict, nil
}

func (manager *ClientManager) openCodeStatus() ClientStatus {
	path := manager.openCodeConfigPath()
	status := ClientStatus{ID: "opencode", Name: "OpenCode 2", Available: true, ConfigPath: path}
	_, root, err := readOpenCodeConfig(path)
	if errors.Is(err, os.ErrNotExist) {
		status.Detail = "Install OpenCode 2 (Scoop: versions/opencode2; npm: @opencode/cli@2), then add the ida-mcp configuration."
		return status
	}
	if err != nil {
		status.Detail = "The OpenCode global configuration is invalid and was not changed."
		return status
	}
	mcp, servers, err := openCodeMCPObjects(root)
	if err != nil {
		status.Detail = err.Error()
		return status
	}
	_, legacy := mcp[serverName]
	value, native := servers[serverName]
	status.Configured = legacy || native
	if !status.Configured {
		status.Detail = "ida-mcp is not configured."
		return status
	}
	entry, ok := value.(map[string]any)
	if !native || !ok {
		status.Detail = "Update the ida-mcp entry to the OpenCode 2 configuration format."
		return status
	}
	command, commandOK := entry["command"].([]any)
	disabled, disabledOK := entry["disabled"].(bool)
	_, disabledExists := entry["disabled"]
	codemode, codemodeOK := entry["codemode"].(bool)
	protocol, protocolExists := entry["protocol"]
	_, legacyEnabled := entry["enabled"]
	typeName, _ := entry["type"].(string)
	status.Current = !legacy && !legacyEnabled && typeName == "local" && commandOK && len(command) == 1 &&
		(!disabledExists || disabledOK && !disabled) && codemodeOK && !codemode &&
		(!protocolExists || protocol == "legacy")
	if timeout, exists := entry["timeout"]; exists {
		status.Current = status.Current && validOpenCode2Timeout(timeout)
	}
	if status.Current {
		configuredPath, ok := command[0].(string)
		status.Current = ok && samePath(configuredPath, manager.gatewayPath)
	}
	if status.Current {
		status.Detail = "OpenCode 2 configuration is ready. Restart OpenCode after changing this configuration."
	} else {
		status.Detail = "An ida-mcp entry exists but does not match this Gateway."
	}
	return status
}

func validOpenCode2Timeout(value any) bool {
	values, ok := value.(map[string]any)
	if !ok {
		return false
	}
	for key, value := range values {
		if key != "startup" && key != "catalog" && key != "execution" {
			return false
		}
		milliseconds, ok := value.(float64)
		if !ok || milliseconds <= 0 || milliseconds > 9007199254740991 ||
			milliseconds != float64(int64(milliseconds)) {
			return false
		}
	}
	return true
}

func openCodeMCPObjects(root map[string]any) (map[string]any, map[string]any, error) {
	value, exists := root["mcp"]
	if !exists {
		return nil, nil, nil
	}
	mcp, ok := value.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("OpenCode mcp configuration must be an object")
	}
	value, exists = mcp["servers"]
	if !exists {
		return mcp, nil, nil
	}
	servers, ok := value.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("OpenCode 2 mcp.servers configuration must be an object")
	}
	// A V1 server named "servers" occupies the V2 namespace. Do not overwrite it.
	if _, hasType := servers["type"].(string); hasType {
		return nil, nil, fmt.Errorf("Rename the legacy MCP server named servers before configuring OpenCode 2")
	}
	return mcp, servers, nil
}

func readOpenCodeConfig(path string) (*hujson.Value, map[string]any, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	document, err := hujson.Parse(contents)
	if err != nil {
		return nil, nil, fmt.Errorf("parse OpenCode configuration: %w", err)
	}
	standard := document.Clone()
	standard.Standardize()
	var root map[string]any
	if err := json.Unmarshal(standard.Pack(), &root); err != nil || root == nil {
		return nil, nil, fmt.Errorf("OpenCode configuration root must be an object")
	}
	return &document, root, nil
}

func (manager *ClientManager) configureOpenCode(enabled bool) error {
	path := manager.openCodeConfigPath()
	document, root, err := readOpenCodeConfig(path)
	var expected []byte
	if errors.Is(err, os.ErrNotExist) {
		initial, parseErr := hujson.Parse([]byte("{\n  \"$schema\": \"https://opencode.ai/config.json\"\n}\n"))
		if parseErr != nil {
			return fmt.Errorf("initialize OpenCode configuration: %w", parseErr)
		}
		document = &initial
		root = map[string]any{"$schema": "https://opencode.ai/config.json"}
	} else if err != nil {
		return err
	} else {
		expected = document.Pack()
	}

	mcp, servers, err := openCodeMCPObjects(root)
	if err != nil {
		return err
	}
	patch := make([]map[string]any, 0, 2)
	if enabled {
		entry := map[string]any{
			"type": "local", "command": []string{manager.gatewayPath}, "disabled": false,
			"codemode": false, "protocol": "legacy",
			"timeout": map[string]int{"catalog": 120000, "execution": 120000},
		}
		switch {
		case mcp == nil:
			patch = append(patch, map[string]any{"op": "add", "path": "/mcp", "value": map[string]any{
				"servers": map[string]any{serverName: entry},
			}})
		case servers == nil:
			patch = append(patch, map[string]any{"op": "add", "path": "/mcp/servers", "value": map[string]any{serverName: entry}})
		default:
			patch = append(patch, map[string]any{"op": "add", "path": "/mcp/servers/" + serverName, "value": entry})
		}
	} else {
		if _, exists := servers[serverName]; exists {
			patch = append(patch, map[string]any{"op": "remove", "path": "/mcp/servers/" + serverName})
		}
	}
	if _, exists := mcp[serverName]; exists {
		patch = append(patch, map[string]any{"op": "remove", "path": "/mcp/" + serverName})
	}
	if len(patch) == 0 {
		return nil
	}

	encodedPatch, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("encode OpenCode configuration update: %w", err)
	}
	updated := document.Clone()
	if err := updated.Patch(encodedPatch); err != nil {
		return fmt.Errorf("update OpenCode configuration: %w", err)
	}
	updated.Format()
	if err := writeFileAtomic(path, updated.Pack(), expected); err != nil {
		return fmt.Errorf("save OpenCode configuration: %w", err)
	}
	return nil
}

func writeFileAtomic(path string, contents, expected []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	temporary, err := os.CreateTemp(directory, ".ida-mcp-config-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := secureNewFile(temporaryPath); err != nil {
		return err
	}
	if expected == nil {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("configuration changed while it was being updated")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return replaceFile(temporaryPath, path, false)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, expected) {
		return fmt.Errorf("configuration changed while it was being updated")
	}
	return replaceFile(temporaryPath, path, true)
}

func samePath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}
