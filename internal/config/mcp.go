package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// MCPServerConfig describes one MCP server entry in .tr/mcp.yaml.
type MCPServerConfig struct {
	Name      string   `yaml:"name"`
	Transport string   `yaml:"transport"` // "stdio" or "sse"
	Command   string   `yaml:"command"`   // stdio: executable path
	Args      []string `yaml:"args"`      // stdio: command arguments
	URL       string   `yaml:"url"`       // sse: server URL
}

// MCPConfig is the top-level structure for .tr/mcp.yaml.
type MCPConfig struct {
	Servers []MCPServerConfig `yaml:"servers"`
}

// LoadMCPConfig reads and parses the mcp.yaml file at path.
func LoadMCPConfig(path string) (*MCPConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read mcp config %s: %w", path, err)
	}
	var cfg MCPConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse mcp config %s: %w", path, err)
	}
	return &cfg, nil
}

// StdioServers returns the subset of servers with transport "stdio".
func (c *MCPConfig) StdioServers() []MCPServerConfig {
	var out []MCPServerConfig
	for _, s := range c.Servers {
		if s.Transport == "stdio" {
			out = append(out, s)
		}
	}
	return out
}
