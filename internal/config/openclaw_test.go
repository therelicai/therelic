package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeJSON(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writeJSON: %v", err)
	}
	return path
}

// ---------------------------------------------------------------------------
// ParseOpenClawConfig
// ---------------------------------------------------------------------------

func TestParseOpenClawConfig_TwoServers(t *testing.T) {
	dir := t.TempDir()
	path := writeJSON(t, dir, "openclaw.json", `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
			},
			"search": {
				"url": "http://localhost:3001/mcp"
			}
		}
	}`)

	cfg, err := ParseOpenClawConfig(path)
	if err != nil {
		t.Fatalf("ParseOpenClawConfig: %v", err)
	}
	if len(cfg.Servers) != 2 {
		t.Fatalf("len(Servers) = %d, want 2", len(cfg.Servers))
	}

	// Servers are sorted by name: filesystem < search.
	fs := cfg.Servers[0]
	if fs.Name != "filesystem" {
		t.Errorf("Servers[0].Name = %q, want \"filesystem\"", fs.Name)
	}
	if fs.Transport != "stdio" {
		t.Errorf("Servers[0].Transport = %q, want \"stdio\"", fs.Transport)
	}
	if fs.Command != "npx" {
		t.Errorf("Servers[0].Command = %q, want \"npx\"", fs.Command)
	}
	if len(fs.Args) != 3 || fs.Args[0] != "-y" {
		t.Errorf("Servers[0].Args = %v, want [\"-y\", ...]", fs.Args)
	}

	se := cfg.Servers[1]
	if se.Name != "search" {
		t.Errorf("Servers[1].Name = %q, want \"search\"", se.Name)
	}
	if se.Transport != "sse" {
		t.Errorf("Servers[1].Transport = %q, want \"sse\"", se.Transport)
	}
	if se.URL != "http://localhost:3001/mcp" {
		t.Errorf("Servers[1].URL = %q, want URL", se.URL)
	}
}

func TestParseOpenClawConfig_MultiAgent(t *testing.T) {
	dir := t.TempDir()
	path := writeJSON(t, dir, "openclaw.json", `{
		"mcpServers": {},
		"agents": {
			"list": [
				{"id": "home", "default": true},
				{"id": "work"}
			]
		}
	}`)

	cfg, err := ParseOpenClawConfig(path)
	if err != nil {
		t.Fatalf("ParseOpenClawConfig: %v", err)
	}
	if len(cfg.Agents) != 2 {
		t.Fatalf("len(Agents) = %d, want 2", len(cfg.Agents))
	}
	if cfg.Agents[0].ID != "home" {
		t.Errorf("Agents[0].ID = %q, want \"home\"", cfg.Agents[0].ID)
	}
	if !cfg.Agents[0].Default {
		t.Error("Agents[0].Default = false, want true")
	}
	if cfg.Agents[1].ID != "work" {
		t.Errorf("Agents[1].ID = %q, want \"work\"", cfg.Agents[1].ID)
	}
	if cfg.Agents[1].Default {
		t.Error("Agents[1].Default = true, want false")
	}
}

func TestParseOpenClawConfig_MissingMCPServers(t *testing.T) {
	dir := t.TempDir()
	path := writeJSON(t, dir, "openclaw.json", `{
		"agents": {
			"list": [{"id": "home"}]
		}
	}`)

	cfg, err := ParseOpenClawConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Servers) != 0 {
		t.Errorf("len(Servers) = %d, want 0", len(cfg.Servers))
	}
	if len(cfg.Agents) != 1 {
		t.Errorf("len(Agents) = %d, want 1", len(cfg.Agents))
	}
}

func TestParseOpenClawConfig_EmptyObject(t *testing.T) {
	dir := t.TempDir()
	path := writeJSON(t, dir, "openclaw.json", `{}`)

	cfg, err := ParseOpenClawConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Servers) != 0 {
		t.Errorf("len(Servers) = %d, want 0", len(cfg.Servers))
	}
	if len(cfg.Agents) != 0 {
		t.Errorf("len(Agents) = %d, want 0", len(cfg.Agents))
	}
}

func TestParseOpenClawConfig_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := writeJSON(t, dir, "openclaw.json", `not valid json {{`)

	_, err := ParseOpenClawConfig(path)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParseOpenClawConfig_FileNotFound(t *testing.T) {
	_, err := ParseOpenClawConfig("/nonexistent/openclaw.json")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestParseOpenClawConfig_AgentToAgent(t *testing.T) {
	dir := t.TempDir()
	path := writeJSON(t, dir, "openclaw.json", `{
		"mcpServers": {},
		"tools": {
			"agentToAgent": {
				"enabled": true,
				"allow": ["home", "work"]
			}
		}
	}`)

	cfg, err := ParseOpenClawConfig(path)
	if err != nil {
		t.Fatalf("ParseOpenClawConfig: %v", err)
	}
	if !cfg.AgentToAgent.Enabled {
		t.Error("AgentToAgent.Enabled = false, want true")
	}
	if len(cfg.AgentToAgent.Allow) != 2 {
		t.Fatalf("len(AgentToAgent.Allow) = %d, want 2", len(cfg.AgentToAgent.Allow))
	}
	if cfg.AgentToAgent.Allow[0] != "home" {
		t.Errorf("Allow[0] = %q, want \"home\"", cfg.AgentToAgent.Allow[0])
	}
}

func TestParseOpenClawConfig_ServerSortedByName(t *testing.T) {
	dir := t.TempDir()
	// Insert in reverse alphabetical order to verify sorting.
	path := writeJSON(t, dir, "openclaw.json", `{
		"mcpServers": {
			"zebra": {"command": "z", "args": []},
			"alpha": {"command": "a", "args": []},
			"middle": {"command": "m", "args": []}
		}
	}`)

	cfg, err := ParseOpenClawConfig(path)
	if err != nil {
		t.Fatalf("ParseOpenClawConfig: %v", err)
	}
	if len(cfg.Servers) != 3 {
		t.Fatalf("len(Servers) = %d, want 3", len(cfg.Servers))
	}
	names := []string{cfg.Servers[0].Name, cfg.Servers[1].Name, cfg.Servers[2].Name}
	want := []string{"alpha", "middle", "zebra"}
	for i, n := range names {
		if n != want[i] {
			t.Errorf("Servers[%d].Name = %q, want %q", i, n, want[i])
		}
	}
}

func TestParseOpenClawConfig_SkipsEmptyEntries(t *testing.T) {
	dir := t.TempDir()
	// Entry with neither command nor url should be silently skipped.
	path := writeJSON(t, dir, "openclaw.json", `{
		"mcpServers": {
			"valid": {"command": "echo"},
			"empty": {}
		}
	}`)

	cfg, err := ParseOpenClawConfig(path)
	if err != nil {
		t.Fatalf("ParseOpenClawConfig: %v", err)
	}
	if len(cfg.Servers) != 1 {
		t.Fatalf("len(Servers) = %d, want 1 (empty entry skipped)", len(cfg.Servers))
	}
	if cfg.Servers[0].Name != "valid" {
		t.Errorf("Servers[0].Name = %q, want \"valid\"", cfg.Servers[0].Name)
	}
}

func TestParseOpenClawConfig_FullExample(t *testing.T) {
	dir := t.TempDir()
	path := writeJSON(t, dir, "openclaw.json", `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
			},
			"search": {
				"url": "http://localhost:3001/mcp"
			}
		},
		"agents": {
			"list": [
				{"id": "home", "default": true},
				{"id": "work"}
			]
		},
		"tools": {
			"agentToAgent": {
				"enabled": true,
				"allow": ["home", "work"]
			}
		}
	}`)

	cfg, err := ParseOpenClawConfig(path)
	if err != nil {
		t.Fatalf("ParseOpenClawConfig: %v", err)
	}
	if len(cfg.Servers) != 2 {
		t.Errorf("len(Servers) = %d, want 2", len(cfg.Servers))
	}
	if len(cfg.Agents) != 2 {
		t.Errorf("len(Agents) = %d, want 2", len(cfg.Agents))
	}
	if !cfg.AgentToAgent.Enabled {
		t.Error("AgentToAgent.Enabled = false, want true")
	}
}

// ---------------------------------------------------------------------------
// GenerateModifiedConfig
// ---------------------------------------------------------------------------

func TestGenerateModifiedConfig_WrapsStdioServers(t *testing.T) {
	original := []byte(`{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
			}
		}
	}`)

	servers := []MCPServerConfig{
		{Name: "filesystem", Transport: "stdio", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem", "/data"}},
	}

	out, err := GenerateModifiedConfig(original, servers, "/usr/local/bin/relic", "run-123", ".tr/traces")
	if err != nil {
		t.Fatalf("GenerateModifiedConfig: %v", err)
	}

	// The output must be valid JSON.
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}

	// Decode the rewritten mcpServers entry.
	var mcpServers map[string]json.RawMessage
	if err := json.Unmarshal(doc["mcpServers"], &mcpServers); err != nil {
		t.Fatalf("decode mcpServers: %v", err)
	}
	var entry map[string]json.RawMessage
	if err := json.Unmarshal(mcpServers["filesystem"], &entry); err != nil {
		t.Fatalf("decode filesystem entry: %v", err)
	}

	// Command must be the relic executable.
	var cmd string
	json.Unmarshal(entry["command"], &cmd)
	if cmd != "/usr/local/bin/relic" {
		t.Errorf("command = %q, want \"/usr/local/bin/relic\"", cmd)
	}

	// Args must start with "proxy-stdio".
	var args []string
	json.Unmarshal(entry["args"], &args)
	if len(args) == 0 || args[0] != "proxy-stdio" {
		t.Errorf("args[0] = %q, want \"proxy-stdio\"; full args: %v", args[0], args)
	}

	// Run ID must be present.
	found := false
	for _, a := range args {
		if a == "run-123" {
			found = true
		}
	}
	if !found {
		t.Errorf("run-id not found in args: %v", args)
	}

	// Separator "--" must appear before the original command.
	sepIdx := -1
	for i, a := range args {
		if a == "--" {
			sepIdx = i
			break
		}
	}
	if sepIdx < 0 {
		t.Fatalf("\"--\" separator not found in args: %v", args)
	}
	if args[sepIdx+1] != "npx" {
		t.Errorf("original command after \"--\" = %q, want \"npx\"", args[sepIdx+1])
	}
}

func TestGenerateModifiedConfig_KeepsURLServers(t *testing.T) {
	original := []byte(`{
		"mcpServers": {
			"search": {"url": "http://localhost:3001/mcp"}
		}
	}`)

	// No stdio servers to wrap.
	servers := []MCPServerConfig{
		{Name: "search", Transport: "sse", URL: "http://localhost:3001/mcp"},
	}

	out, err := GenerateModifiedConfig(original, servers, "/usr/local/bin/relic", "", "")
	if err != nil {
		t.Fatalf("GenerateModifiedConfig: %v", err)
	}

	var doc map[string]json.RawMessage
	json.Unmarshal(out, &doc)
	var mcpServers map[string]json.RawMessage
	json.Unmarshal(doc["mcpServers"], &mcpServers)

	var entry map[string]json.RawMessage
	if err := json.Unmarshal(mcpServers["search"], &entry); err != nil {
		t.Fatalf("decode search entry: %v", err)
	}

	// URL entry must not be rewritten — it should still have a "url" key, not "command".
	if _, hasCmd := entry["command"]; hasCmd {
		t.Error("URL server entry was unexpectedly wrapped with proxy-stdio command")
	}
	var url string
	json.Unmarshal(entry["url"], &url)
	if url != "http://localhost:3001/mcp" {
		t.Errorf("url = %q, want original URL", url)
	}
}

func TestGenerateModifiedConfig_PreservesUnknownKeys(t *testing.T) {
	original := []byte(`{
		"mcpServers": {},
		"agents": {"list": [{"id": "home"}]},
		"customKey": {"value": 42}
	}`)

	out, err := GenerateModifiedConfig(original, nil, "/relic", "", "")
	if err != nil {
		t.Fatalf("GenerateModifiedConfig: %v", err)
	}

	outStr := string(out)
	if !strings.Contains(outStr, "customKey") {
		t.Error("customKey was not preserved in output")
	}
	if !strings.Contains(outStr, "agents") {
		t.Error("agents key was not preserved in output")
	}
}

func TestGenerateModifiedConfig_InvalidJSON(t *testing.T) {
	_, err := GenerateModifiedConfig([]byte(`not json`), nil, "/relic", "", "")
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestGenerateModifiedConfig_NoRunID(t *testing.T) {
	original := []byte(`{"mcpServers": {"s": {"command": "cmd"}}}`)
	servers := []MCPServerConfig{{Name: "s", Transport: "stdio", Command: "cmd"}}

	out, err := GenerateModifiedConfig(original, servers, "/relic", "", "")
	if err != nil {
		t.Fatalf("GenerateModifiedConfig: %v", err)
	}

	outStr := string(out)
	// --run-id flag must NOT be present when runID is empty.
	if strings.Contains(outStr, "--run-id") {
		t.Error("--run-id unexpectedly present when runID is empty")
	}
}

// ---------------------------------------------------------------------------
// DefaultOpenClawConfigPath
// ---------------------------------------------------------------------------

func TestDefaultOpenClawConfigPath(t *testing.T) {
	p, err := DefaultOpenClawConfigPath()
	if err != nil {
		t.Fatalf("DefaultOpenClawConfigPath: %v", err)
	}
	if !strings.Contains(p, ".openclaw") {
		t.Errorf("path %q does not contain \".openclaw\"", p)
	}
	if !strings.HasSuffix(p, "openclaw.json") {
		t.Errorf("path %q does not end with \"openclaw.json\"", p)
	}
}
