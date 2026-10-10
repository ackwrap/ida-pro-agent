package webmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (manager *ClientManager) grokDirectory() string {
	if value := strings.TrimSpace(os.Getenv("GROK_HOME")); value != "" {
		return value
	}
	return filepath.Join(manager.home, ".grok")
}

func (manager *ClientManager) grokExecutable() (string, error) {
	for _, name := range []string{"gork", "agent", "grok"} {
		if executable, err := manager.lookPath(name); err == nil {
			return executable, nil
		}
	}
	return "", fmt.Errorf("Grok Build CLI (gork, agent, or grok) was not found in PATH")
}

func (manager *ClientManager) grokBuildStatus(ctx context.Context) ClientStatus {
	status := ClientStatus{ID: "grokbuild", Name: "Grok Build", ConfigPath: filepath.Join(manager.grokDirectory(), "config.toml")}
	executable, err := manager.grokExecutable()
	if err != nil {
		status.Detail = err.Error()
		return status
	}
	status.Available = true
	output, err := manager.run(ctx, executable, "mcp", "list", "--json")
	if err != nil {
		status.Detail = "Grok Build MCP configuration could not be read."
		return status
	}
	var entries []struct {
		Name          string   `json:"name"`
		Scope         string   `json:"scope"`
		Command       string   `json:"command"`
		Args          []string `json:"args"`
		Enabled       bool     `json:"enabled"`
		URL           string   `json:"url"`
		BlockedReason string   `json:"blocked_reason"`
	}
	if err := json.Unmarshal(output, &entries); err != nil || entries == nil {
		status.Detail = "Grok Build returned an invalid MCP configuration response."
		return status
	}
	for _, entry := range entries {
		if entry.Name != serverName {
			continue
		}
		status.Configured = entry.Scope == "user"
		status.Current = status.Configured && entry.Enabled && entry.BlockedReason == "" && entry.URL == "" && entry.Command != "" && samePath(entry.Command, manager.gatewayPath) && (len(entry.Args) == 0 || (len(entry.Args) == 1 && entry.Args[0] == "--grok"))
		if status.Current {
			status.Detail = "Ready. Restart Grok Build after changing this configuration."
		} else {
			status.Detail = "ida-mcp is disabled, blocked, project-scoped, or does not match this Gateway."
		}
		return status
	}
	status.Detail = "ida-mcp is not configured."
	return status
}

func (manager *ClientManager) configureGrokBuild(ctx context.Context, enabled bool) error {
	executable, err := manager.grokExecutable()
	if err != nil {
		return err
	}
	arguments := []string{"mcp", "remove", serverName, "--scope", "user"}
	if enabled {
		arguments = []string{"mcp", "add", "--scope", "user", "--transport", "stdio", serverName, "--", manager.gatewayPath}
	}
	if _, err := manager.run(ctx, executable, arguments...); err != nil {
		return fmt.Errorf("Grok Build rejected the MCP configuration; check grok mcp list for disabled or policy-blocked entries")
	}
	return nil
}
