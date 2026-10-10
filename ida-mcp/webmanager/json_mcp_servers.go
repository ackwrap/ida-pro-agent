package webmanager

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

type jsonMCPClient struct {
	id               string
	name             string
	configPath       string
	requireStdioType bool
}

func (manager *ClientManager) antigravityStatus() ClientStatus {
	return manager.jsonMCPStatus(jsonMCPClient{
		id: "antigravity", name: "Antigravity CLI", configPath: manager.antigravityConfigPath(),
	})
}

func (manager *ClientManager) claudeCodeStatus() ClientStatus {
	return manager.jsonMCPStatus(jsonMCPClient{
		id: "claudecode", name: "Claude Code", configPath: manager.claudeCodeConfigPath(), requireStdioType: true,
	})
}

func (manager *ClientManager) configureAntigravity(enabled bool) error {
	if enabled {
		path := manager.antigravityConfigPath()
		contents, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read Antigravity configuration: %w", err)
		}
		var root map[string]json.RawMessage
		if err != nil || json.Unmarshal(contents, &root) != nil || root == nil {
			if len(bytes.TrimSpace(contents)) != 0 {
				if err := writeFileAtomic(path+".invalid.bak", contents, nil); err != nil {
					return fmt.Errorf("back up invalid Antigravity configuration: %w", err)
				}
			}
			if err := writeFileAtomic(path, []byte("{}\n"), contents); err != nil {
				return fmt.Errorf("initialize Antigravity configuration: %w", err)
			}
		}
	}
	entry := map[string]any{"command": manager.gatewayPath, "args": []string{}}
	if err := configureJSONMCPServer(manager.antigravityConfigPath(), entry, enabled); err != nil {
		return fmt.Errorf("update Antigravity CLI configuration: %w", err)
	}
	return nil
}

func (manager *ClientManager) configureClaudeCode(enabled bool) error {
	entry := map[string]any{"type": "stdio", "command": manager.gatewayPath, "args": []string{}}
	if err := configureJSONMCPServer(manager.claudeCodeConfigPath(), entry, enabled); err != nil {
		return fmt.Errorf("update Claude Code configuration: %w", err)
	}
	return nil
}

func (manager *ClientManager) jsonMCPStatus(client jsonMCPClient) ClientStatus {
	status := ClientStatus{
		ID: client.id, Name: client.name, Available: true, ConfigPath: client.configPath,
	}
	_, root, err := readJSONMCPConfig(client.configPath)
	if errors.Is(err, os.ErrNotExist) {
		status.Detail = "ida-mcp is not configured."
		return status
	}
	if err != nil {
		status.Detail = "The global configuration is invalid and was not changed."
		return status
	}
	servers, exists, err := jsonObjectField(root, "mcpServers")
	if err != nil {
		status.Detail = "The global mcpServers configuration is invalid and was not changed."
		return status
	}
	if !exists {
		status.Detail = "ida-mcp is not configured."
		return status
	}
	entry, exists := servers[serverName]
	if !exists {
		status.Detail = "ida-mcp is not configured."
		return status
	}
	status.Configured = true
	status.Current = jsonMCPEntryCurrent(entry, manager.gatewayPath, client.requireStdioType)
	if status.Current {
		status.Detail = "Ready. Restart " + client.name + " after changing this configuration."
	} else {
		status.Detail = "An ida-mcp entry exists but does not match this Gateway."
	}
	return status
}

func readJSONMCPConfig(path string) ([]byte, map[string]json.RawMessage, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(contents, &root); err != nil || root == nil {
		return nil, nil, fmt.Errorf("configuration root must be a JSON object")
	}
	return contents, root, nil
}

func jsonObjectField(root map[string]json.RawMessage, name string) (map[string]json.RawMessage, bool, error) {
	raw, exists := root[name]
	if !exists {
		return nil, false, nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, true, fmt.Errorf("%s must be a JSON object", name)
	}
	return object, true, nil
}

func configureJSONMCPServer(path string, entry map[string]any, enabled bool) error {
	expected, root, err := readJSONMCPConfig(path)
	if errors.Is(err, os.ErrNotExist) {
		if !enabled {
			return nil
		}
		expected = nil
		root = make(map[string]json.RawMessage)
	} else if err != nil {
		return err
	}

	servers, exists, err := jsonObjectField(root, "mcpServers")
	if err != nil {
		return err
	}
	if !exists {
		if !enabled {
			return nil
		}
		servers = make(map[string]json.RawMessage)
	}
	if enabled {
		encodedEntry, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("encode ida-mcp entry: %w", err)
		}
		servers[serverName] = encodedEntry
	} else {
		if _, exists := servers[serverName]; !exists {
			return nil
		}
		delete(servers, serverName)
	}
	encodedServers, err := json.Marshal(servers)
	if err != nil {
		return fmt.Errorf("encode mcpServers: %w", err)
	}
	root["mcpServers"] = encodedServers
	contents, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return fmt.Errorf("encode configuration: %w", err)
	}
	contents = append(contents, '\n')
	if err := writeFileAtomic(path, contents, expected); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	return nil
}

func jsonMCPEntryCurrent(raw json.RawMessage, gatewayPath string, requireStdioType bool) bool {
	var entry map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entry); err != nil || entry == nil {
		return false
	}
	var command string
	if rawCommand, exists := entry["command"]; !exists || json.Unmarshal(rawCommand, &command) != nil || !samePath(command, gatewayPath) {
		return false
	}
	var arguments []string
	if rawArguments, exists := entry["args"]; !exists || json.Unmarshal(rawArguments, &arguments) != nil || arguments == nil || len(arguments) != 0 {
		return false
	}
	if rawType, exists := entry["type"]; exists {
		var typeName string
		if json.Unmarshal(rawType, &typeName) != nil || typeName != "stdio" {
			return false
		}
	} else if requireStdioType {
		return false
	}
	if rawDisabled, exists := entry["disabled"]; exists {
		var disabled bool
		if json.Unmarshal(rawDisabled, &disabled) != nil || disabled {
			return false
		}
	}
	if rawEnabled, exists := entry["enabled"]; exists {
		var enabled bool
		if json.Unmarshal(rawEnabled, &enabled) != nil || !enabled {
			return false
		}
	}
	for _, field := range []string{"url", "serverUrl", "transport"} {
		if _, exists := entry[field]; exists {
			return false
		}
	}
	return true
}
