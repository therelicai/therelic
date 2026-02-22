package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPolicy_ValidFile(t *testing.T) {
	yaml := `
version: "1"
agent:
  name: "test-agent"
  version: "1.0.0"
mode: permissive
default: deny
rules:
  - id: allow-web
    protocol: mcp
    method: tool_call
    target: "web_search"
    action: allow
`
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if p.Version != "1" {
		t.Errorf("Version = %q, want \"1\"", p.Version)
	}
	if p.Agent.Name != "test-agent" {
		t.Errorf("Agent.Name = %q, want \"test-agent\"", p.Agent.Name)
	}
	if p.Mode != "permissive" {
		t.Errorf("Mode = %q, want \"permissive\"", p.Mode)
	}
	if p.Default != "deny" {
		t.Errorf("Default = %q, want \"deny\"", p.Default)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("len(Rules) = %d, want 1", len(p.Rules))
	}
	if p.Rules[0].ID != "allow-web" {
		t.Errorf("Rules[0].ID = %q, want \"allow-web\"", p.Rules[0].ID)
	}
}

func TestLoadPolicy_FileNotFound(t *testing.T) {
	_, err := LoadPolicy("/nonexistent/policy.yaml")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestLoadPolicy_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte("invalid yaml {{{{"), 0o644)

	_, err := LoadPolicy(path)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestDefaultPaths(t *testing.T) {
	paths := DefaultPaths()
	if paths.Root != ".tr" {
		t.Errorf("Root = %q, want \".tr\"", paths.Root)
	}
	if paths.PolicyFile != ".tr/policy.yaml" {
		t.Errorf("PolicyFile = %q, want \".tr/policy.yaml\"", paths.PolicyFile)
	}
	if paths.TracesDir != ".tr/traces" {
		t.Errorf("TracesDir = %q, want \".tr/traces\"", paths.TracesDir)
	}
}
