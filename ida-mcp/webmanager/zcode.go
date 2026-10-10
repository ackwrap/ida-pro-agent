package webmanager

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func (manager *ClientManager) zcodeConfigPath() string {
	return filepath.Join(manager.home, ".zcode", "cli", "config.json")
}

func (manager *ClientManager) zcodeSharedConfigPath() string {
	return filepath.Join(manager.home, ".agents", "mcp.json")
}

type zcodeConfig struct {
	expected []byte
	root     map[string]json.RawMessage
	mcp      map[string]json.RawMessage
	servers  map[string]json.RawMessage
}

func readZCodeConfig(path string) (zcodeConfig, error) {
	expected, root, err := readJSONMCPConfig(path)
	if errors.Is(err, os.ErrNotExist) {
		root = make(map[string]json.RawMessage)
	} else if err != nil {
		return zcodeConfig{}, err
	}
	mcp, exists, err := jsonObjectField(root, "mcp")
	if err != nil {
		return zcodeConfig{}, err
	}
	if !exists {
		mcp = make(map[string]json.RawMessage)
	}
	servers, exists, err := jsonObjectField(mcp, "servers")
	if err != nil {
		return zcodeConfig{}, err
	}
	if !exists {
		servers = make(map[string]json.RawMessage)
	}
	return zcodeConfig{expected, root, mcp, servers}, nil
}

func (manager *ClientManager) zcodeSharedServers() (map[string]json.RawMessage, error) {
	_, root, err := readJSONMCPConfig(manager.zcodeSharedConfigPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read ZCode shared .agents configuration: %w", err)
	}
	servers, _, err := jsonObjectField(root, "mcpServers")
	if err != nil {
		return nil, fmt.Errorf("read ZCode shared .agents configuration: %w", err)
	}
	return servers, nil
}

func (manager *ClientManager) zcodeStatus() ClientStatus {
	status := ClientStatus{ID: "zcode", Name: "ZCode", Available: true, ConfigPath: manager.zcodeConfigPath()}
	config, err := readZCodeConfig(status.ConfigPath)
	if err != nil {
		status.Detail = "The ZCode global configuration is invalid and was not changed."
		return status
	}
	servers := config.servers
	if len(servers) == 0 {
		servers, err = manager.zcodeSharedServers()
		if err != nil {
			status.Detail = "The ZCode shared .agents configuration is invalid and was not changed."
			return status
		}
		if len(servers) != 0 {
			status.ConfigPath = manager.zcodeSharedConfigPath()
		}
	}
	entry, exists := servers[serverName]
	if !exists {
		status.Detail = "ida-mcp is not configured."
		return status
	}
	status.Configured = true
	status.Current = zcodeEntryCurrent(entry, manager.gatewayPath)
	if status.Current {
		status.Detail = "Ready. Restart ZCode after changing this configuration."
	} else {
		status.Detail = "An ida-mcp entry exists but is disabled or does not match this Gateway."
	}
	return status
}

func zcodeEntryCurrent(raw json.RawMessage, gateway string) bool {
	var entry map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entry); err != nil || entry == nil {
		return false
	}
	if value, exists := entry["enable"]; exists {
		var enabled bool
		if json.Unmarshal(value, &enabled) != nil || !enabled {
			return false
		}
	}
	return jsonMCPEntryCurrent(raw, gateway, false)
}

func (manager *ClientManager) configureZCode(enabled bool) error {
	path := manager.zcodeConfigPath()
	config, err := readZCodeConfig(path)
	if err != nil {
		return fmt.Errorf("read ZCode configuration: %w", err)
	}
	// Native servers replace the entire user-level .agents fallback in ZCode.
	// Import only an active fallback so adding our entry does not hide its peers.
	var shared map[string]json.RawMessage
	if len(config.servers) == 0 {
		shared, err = manager.zcodeSharedServers()
		if err != nil {
			return err
		}
		for name, entry := range shared {
			config.servers[name] = entry
		}
	}
	entry := map[string]any{"type": "stdio", "command": manager.gatewayPath, "args": []string{}, "enable": enabled}
	if enabled {
		config.servers[serverName], err = json.Marshal(entry)
	} else {
		if _, exists := config.servers[serverName]; !exists {
			return nil
		}
		delete(config.servers, serverName)
		if len(config.servers) == 0 {
			shared, err = manager.zcodeSharedServers()
			if err != nil {
				return err
			}
			if _, wouldReappear := shared[serverName]; wouldReappear {
				// Keep a disabled native entry to mask a shared ida-mcp without
				// deleting configuration used by other clients. Preserve its peers.
				for name, value := range shared {
					config.servers[name] = value
				}
				config.servers[serverName], err = json.Marshal(entry)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("encode ZCode MCP entry: %w", err)
	}
	config.mcp["servers"], err = json.Marshal(config.servers)
	if err != nil {
		return fmt.Errorf("encode ZCode MCP servers: %w", err)
	}
	config.root["mcp"], err = json.Marshal(config.mcp)
	if err != nil {
		return fmt.Errorf("encode ZCode MCP configuration: %w", err)
	}
	contents, err := json.MarshalIndent(config.root, "", "  ")
	if err != nil {
		return fmt.Errorf("encode ZCode configuration: %w", err)
	}
	if err := writeFileAtomic(path, append(contents, '\n'), config.expected); err != nil {
		return fmt.Errorf("save ZCode configuration: %w", err)
	}
	return nil
}
