package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/therelicai/therelic/internal/config"
)

// runCmd executes a `relic` command in a temp project directory, captures stdout
// and stderr, and returns both plus any error.
func runCmd(t *testing.T, projectDir string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := NewRootCmd("test")
	root.SilenceErrors = true

	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs(args)

	// Change to the project dir so .tr/ is created there.
	orig, _ := os.Getwd()
	if changeErr := os.Chdir(projectDir); changeErr != nil {
		t.Fatalf("chdir: %v", changeErr)
	}
	t.Cleanup(func() { os.Chdir(orig) })

	err = root.Execute()
	return outBuf.String(), errBuf.String(), err
}

// ---------------------------------------------------------------------------
// relic init
// ---------------------------------------------------------------------------

func TestRelicInit_CreatesExpectedStructure(t *testing.T) {
	dir := t.TempDir()
	stdout, _, err := runCmd(t, dir, "init")
	if err != nil {
		t.Fatalf("relic init: %v (stdout: %s)", err, stdout)
	}

	paths := config.PathsFor(filepath.Join(dir, ".tr"))

	// .tr/ directory
	if _, err := os.Stat(paths.Root); os.IsNotExist(err) {
		t.Error(".tr/ directory not created")
	}
	// policy.yaml
	if _, err := os.Stat(paths.PolicyFile); os.IsNotExist(err) {
		t.Error(".tr/policy.yaml not created")
	}
	// mcp.yaml
	if _, err := os.Stat(paths.MCPFile); os.IsNotExist(err) {
		t.Error(".tr/mcp.yaml not created")
	}
	// traces/
	if _, err := os.Stat(paths.TracesDir); os.IsNotExist(err) {
		t.Error(".tr/traces/ directory not created")
	}
}

func TestRelicInit_PolicyYAMLIsValid(t *testing.T) {
	dir := t.TempDir()
	runCmd(t, dir, "init") //nolint

	policyPath := filepath.Join(dir, ".tr", "policy.yaml")
	stdout, stderr, err := runCmd(t, dir, "policy", "validate", "--policy", policyPath)
	if err != nil {
		t.Fatalf("generated starter policy is invalid: %v\nstdout: %s\nstderr: %s",
			err, stdout, stderr)
	}
	if !strings.Contains(stdout, "Policy valid") {
		t.Errorf("expected 'Policy valid' in output, got: %s", stdout)
	}
}

func TestRelicInit_WarnOnExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	// Run init twice.
	runCmd(t, dir, "init") //nolint
	stdout, _, _ := runCmd(t, dir, "init")

	if !strings.Contains(stdout, "already exists") {
		t.Errorf("expected warning about existing .tr/ on second init, got: %q", stdout)
	}
}

func TestRelicInit_ForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	runCmd(t, dir, "init") //nolint

	// Corrupt the policy file.
	policyPath := filepath.Join(dir, ".tr", "policy.yaml")
	os.WriteFile(policyPath, []byte("corrupted"), 0o644)

	// Force overwrite.
	runCmd(t, dir, "init", "--force") //nolint

	// Should be valid again.
	stdout, _, err := runCmd(t, dir, "policy", "validate", "--policy", policyPath)
	if err != nil {
		t.Fatalf("policy invalid after --force reinit: %v", err)
	}
	if !strings.Contains(stdout, "Policy valid") {
		t.Errorf("expected 'Policy valid', got: %s", stdout)
	}
}

func TestRelicInit_DoesNotOverwriteExistingFiles(t *testing.T) {
	dir := t.TempDir()
	runCmd(t, dir, "init") //nolint

	// Write custom content.
	policyPath := filepath.Join(dir, ".tr", "policy.yaml")
	custom := []byte("# my custom policy\n")
	os.WriteFile(policyPath, custom, 0o644)

	// Re-init without --force.
	runCmd(t, dir, "init") //nolint

	// Custom content must be preserved.
	got, _ := os.ReadFile(policyPath)
	if string(got) != string(custom) {
		t.Errorf("policy was overwritten without --force\nwant: %s\ngot: %s", custom, got)
	}
}

// ---------------------------------------------------------------------------
// relic policy init
// ---------------------------------------------------------------------------

func TestPolicyInit_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".tr"), 0o755)

	runCmd(t, dir, "policy", "init") //nolint

	policyPath := filepath.Join(dir, ".tr", "policy.yaml")
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		t.Error(".tr/policy.yaml not created by 'policy init'")
	}
}

func TestPolicyInit_DoesNotOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".tr"), 0o755)
	policyPath := filepath.Join(dir, ".tr", "policy.yaml")

	custom := []byte("# custom\n")
	os.WriteFile(policyPath, custom, 0o644)

	runCmd(t, dir, "policy", "init") //nolint

	got, _ := os.ReadFile(policyPath)
	if string(got) != string(custom) {
		t.Error("policy was overwritten without --force")
	}
}

func TestPolicyInit_ForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".tr"), 0o755)
	policyPath := filepath.Join(dir, ".tr", "policy.yaml")

	os.WriteFile(policyPath, []byte("corrupted"), 0o644)
	runCmd(t, dir, "policy", "init", "--force") //nolint

	// Should now be valid.
	stdout, _, err := runCmd(t, dir, "policy", "validate", "--policy", policyPath)
	if err != nil {
		t.Fatalf("policy invalid after force: %v", err)
	}
	if !strings.Contains(stdout, "Policy valid") {
		t.Errorf("expected 'Policy valid', got: %s", stdout)
	}
}

// ---------------------------------------------------------------------------
// relic policy validate
// ---------------------------------------------------------------------------

func TestPolicyValidate_ValidPolicy(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyPath, []byte(`
version: "1"
agent:
  name: "my-agent"
mode: enforce
default: deny
rules:
  - id: allow-web
    protocol: mcp
    method: tool_call
    target: "web_search"
    action: allow
`), 0o644)

	stdout, _, err := runCmd(t, dir, "policy", "validate", "--policy", policyPath)
	if err != nil {
		t.Fatalf("valid policy failed validation: %v", err)
	}
	if !strings.Contains(stdout, "Policy valid") {
		t.Errorf("expected 'Policy valid', got: %q", stdout)
	}
}

func TestPolicyValidate_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyPath, []byte("invalid yaml {{{{"), 0o644)

	_, _, err := runCmd(t, dir, "policy", "validate", "--policy", policyPath)
	if err == nil {
		t.Error("expected validation error for invalid YAML, got nil")
	}
}

func TestPolicyValidate_MissingRuleID(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyPath, []byte(`
version: "1"
agent:
  name: "a"
mode: enforce
default: deny
rules:
  - protocol: mcp
    method: tool_call
    target: "web_search"
    action: allow
`), 0o644)

	_, stderr, err := runCmd(t, dir, "policy", "validate", "--policy", policyPath)
	if err == nil {
		t.Error("expected error for missing rule id")
	}
	if !strings.Contains(stderr, "id") {
		t.Errorf("expected error to mention 'id', got: %q", stderr)
	}
}

func TestPolicyValidate_InvalidMode(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyPath, []byte(`
version: "1"
agent:
  name: "a"
mode: superenforce
default: deny
rules: []
`), 0o644)

	_, stderr, err := runCmd(t, dir, "policy", "validate", "--policy", policyPath)
	if err == nil {
		t.Error("expected error for invalid mode")
	}
	if !strings.Contains(stderr, "mode") {
		t.Errorf("stderr should mention 'mode', got: %q", stderr)
	}
}

func TestPolicyValidate_StrictWarn_DefaultAllow_EnforceMode(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyPath, []byte(`
version: "1"
agent:
  name: "a"
mode: enforce
default: allow
rules: []
`), 0o644)

	_, stderr, err := runCmd(t, dir, "policy", "validate", "--policy", policyPath, "--strict")
	if err == nil {
		t.Error("expected strict validation error for default:allow+mode:enforce")
	}
	if !strings.Contains(stderr, "insecure") {
		t.Errorf("expected 'insecure' in strict output, got: %q", stderr)
	}
}

func TestPolicyValidate_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runCmd(t, dir, "policy", "validate", "--policy", "/nonexistent/policy.yaml")
	if err == nil {
		t.Error("expected error for missing policy file")
	}
}

func TestPolicyValidate_DuplicateRuleID(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyPath, []byte(`
version: "1"
agent:
  name: "a"
mode: enforce
default: deny
rules:
  - id: same-id
    protocol: mcp
    method: tool_call
    target: "web_search"
    action: allow
  - id: same-id
    protocol: mcp
    method: tool_call
    target: "web_fetch"
    action: allow
`), 0o644)

	_, stderr, err := runCmd(t, dir, "policy", "validate", "--policy", policyPath)
	if err == nil {
		t.Error("expected error for duplicate rule ID")
	}
	if !strings.Contains(stderr, "duplicate") {
		t.Errorf("expected 'duplicate' in error, got: %q", stderr)
	}
}
