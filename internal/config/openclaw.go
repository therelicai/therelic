// Package config handles loading and adapting configuration files for The Relic.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// OpenClawConfig is the parsed, The Relic–oriented view of openclaw.json.
// It holds only the fields The Relic cares about; all other top-level keys
// are preserved verbatim in the raw bytes for GenerateModifiedConfig.
type OpenClawConfig struct {
	// Servers holds the MCP server definitions converted to The Relic's
	// MCPServerConfig format. Stdio entries have Transport="stdio";
	// URL-based entries have Transport="sse".
	Servers []MCPServerConfig

	// Agents is the parsed agents.list array. Empty when the key is absent.
	Agents []AgentConfig

	// AgentToAgent holds the tools.agentToAgent settings when present.
	AgentToAgent AgentToAgentConfig
}

// AgentConfig represents one entry from agents.list in openclaw.json.
type AgentConfig struct {
	ID        string `json:"id"`
	Workspace string `json:"workspace"`
	Default   bool   `json:"default"`
}

// AgentToAgentConfig holds inter-agent communication settings from
// tools.agentToAgent in openclaw.json.
type AgentToAgentConfig struct {
	Enabled bool     `json:"enabled"`
	Allow   []string `json:"allow"`
}

// ---------------------------------------------------------------------------
// Raw JSON shapes (unexported — only used for unmarshalling)
// ---------------------------------------------------------------------------

type rawOpenClawConfig struct {
	MCPServers map[string]rawOpenClawServer `json:"mcpServers"`
	Agents     rawOpenClawAgents            `json:"agents"`
	Tools      rawOpenClawTools             `json:"tools"`
}

type rawOpenClawServer struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	URL     string   `json:"url"`
}

type rawOpenClawAgents struct {
	List []AgentConfig `json:"list"`
}

type rawOpenClawTools struct {
	AgentToAgent AgentToAgentConfig `json:"agentToAgent"`
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

// ParseOpenClawConfig reads the openclaw.json at path and returns the
// The Relic–oriented view.
//
//   - mcpServers entries with a "command" field become Transport="stdio".
//   - mcpServers entries with a "url" field become Transport="sse".
//   - Missing mcpServers key → empty Servers slice, no error.
//   - Missing agents or tools keys → zero values, no error.
//   - Invalid JSON → error.
func ParseOpenClawConfig(path string) (*OpenClawConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("openclaw: read %s: %w", path, err)
	}

	var raw rawOpenClawConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("openclaw: parse %s: %w", path, err)
	}

	cfg := &OpenClawConfig{
		Agents:       raw.Agents.List,
		AgentToAgent: raw.Tools.AgentToAgent,
	}

	// Convert mcpServers map → []MCPServerConfig in a stable order (sorted by
	// name for determinism in tests and generated configs).
	names := sortedKeys(raw.MCPServers)
	for _, name := range names {
		srv := raw.MCPServers[name]
		if srv.Command != "" {
			cfg.Servers = append(cfg.Servers, MCPServerConfig{
				Name:      name,
				Transport: "stdio",
				Command:   srv.Command,
				Args:      srv.Args,
			})
		} else if srv.URL != "" {
			cfg.Servers = append(cfg.Servers, MCPServerConfig{
				Name:      name,
				Transport: "sse",
				URL:       srv.URL,
			})
		}
		// Entries with neither command nor URL are silently skipped.
	}

	return cfg, nil
}

// ---------------------------------------------------------------------------
// Default path
// ---------------------------------------------------------------------------

// DefaultOpenClawConfigPath returns the default location of openclaw.json:
// $HOME/.openclaw/openclaw.json.
func DefaultOpenClawConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("openclaw: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".openclaw", "openclaw.json"), nil
}

// ---------------------------------------------------------------------------
// Modified config generation
// ---------------------------------------------------------------------------

// GenerateModifiedConfig rewrites the openclaw.json bytes so that:
//   - stdio MCP server entries are replaced with commands that invoke
//     `relicExe proxy-stdio [--run-id <id>] [--trace-dir <dir>] -- <original-cmd> [args...]`
//   - URL (SSE) entries are left unchanged.
//   - All other top-level JSON keys are preserved verbatim.
//
// runID and traceDir are embedded in the proxy-stdio args so the subprocess
// can append its trace events to the correct file.
// When runID is empty, proxy-stdio will operate in standalone mode.
func GenerateModifiedConfig(originalJSON []byte, servers []MCPServerConfig, relicExe, runID, traceDir string) ([]byte, error) {
	// Parse the original document as a generic map so we preserve unknown keys.
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(originalJSON, &doc); err != nil {
		return nil, fmt.Errorf("openclaw: parse original config: %w", err)
	}

	// Decode the existing mcpServers map (may be absent).
	var rawServers map[string]json.RawMessage
	if raw, ok := doc["mcpServers"]; ok {
		if err := json.Unmarshal(raw, &rawServers); err != nil {
			rawServers = make(map[string]json.RawMessage)
		}
	} else {
		rawServers = make(map[string]json.RawMessage)
	}

	// Build the set of stdio server names we want to wrap, keyed by name.
	wrap := make(map[string]MCPServerConfig, len(servers))
	for _, s := range servers {
		if s.Transport == "stdio" {
			wrap[s.Name] = s
		}
	}

	// Rewrite stdio entries; leave everything else (including SSE entries and
	// servers not in the `servers` slice) unchanged.
	for name, srv := range wrap {
		args := proxyStdioArgs(relicExe, runID, traceDir, srv)
		entry := map[string]any{
			"command": args[0],
			"args":    args[1:],
		}
		b, err := json.Marshal(entry)
		if err != nil {
			return nil, fmt.Errorf("openclaw: encode proxy entry for %q: %w", name, err)
		}
		rawServers[name] = b
	}

	// Re-encode the mcpServers map.
	newServers, err := json.Marshal(rawServers)
	if err != nil {
		return nil, fmt.Errorf("openclaw: encode mcpServers: %w", err)
	}
	doc["mcpServers"] = newServers

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("openclaw: encode modified config: %w", err)
	}
	return out, nil
}

// proxyStdioArgs builds the command + args slice for a proxy-stdio wrapper.
// Result: ["<relicExe>", "proxy-stdio", "--run-id", "<id>", "--trace-dir", "<dir>",
//
//	"--", "<original-cmd>", <original-args...>]
func proxyStdioArgs(relicExe, runID, traceDir string, srv MCPServerConfig) []string {
	args := []string{relicExe, "proxy-stdio"}
	if runID != "" {
		args = append(args, "--run-id", runID)
	}
	if traceDir != "" {
		args = append(args, "--trace-dir", traceDir)
	}
	args = append(args, "--")
	args = append(args, srv.Command)
	args = append(args, srv.Args...)
	return args
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// sortedKeys returns the keys of m in lexicographic order.
func sortedKeys(m map[string]rawOpenClawServer) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Simple insertion sort — map sizes are small.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
