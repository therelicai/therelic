package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/therelicai/therelic/internal/policy"
)

func TestHarden_AllIssues(t *testing.T) {
	p := &policy.Policy{
		Version: "1",
		Agent:   policy.AgentIdentity{Name: "test"},
		Mode:    "permissive",
		Default: "allow",
	}

	report := evaluate(p, ".tr/policy.yaml")

	if report.Passed != 0 {
		t.Errorf("expected 0 checks passed, got %d", report.Passed)
	}
	if len(report.Issues) != len(hardenChecks) {
		t.Errorf("expected %d issues, got %d", len(hardenChecks), len(report.Issues))
	}
}

func TestHarden_FullyHardened(t *testing.T) {
	p := &policy.Policy{
		Version:           "1",
		Agent:             policy.AgentIdentity{Name: "test"},
		Mode:              "enforce",
		Default:           "deny",
		SignatureRequired: true,
		Rules: []policy.Rule{
			{ID: "r1", Protocol: "mcp", Method: "tool_call", Target: "web_search", Action: "allow"},
		},
		Constraints: policy.Constraints{MaxActions: 100, MaxDurationSeconds: 600},
		Filesystem:  policy.FilesystemConfig{Enabled: true, Mounts: []policy.FilesystemMount{{Source: ".", Target: "data", Mode: "ro"}}},
		Network:     policy.NetworkConfig{DNSAllow: []string{"api.example.com"}},
		Exfiltration: policy.ExfiltrationConfig{Enabled: true},
		Sequences: policy.SequenceConfig{
			Window: 10,
			Rules:  []policy.SequenceRule{{ID: "s1", Pattern: []string{"a", "b"}, Action: "deny"}},
		},
	}

	report := evaluate(p, ".tr/policy.yaml")

	if len(report.Issues) != 0 {
		for _, issue := range report.Issues {
			t.Errorf("unexpected issue: [%s] %s", issue.ID, issue.Description)
		}
	}
	if report.Passed != report.Total {
		t.Errorf("expected %d/%d passed, got %d/%d", report.Total, report.Total, report.Passed, report.Total)
	}
}

func TestHarden_PermissiveModeIsCritical(t *testing.T) {
	p := &policy.Policy{
		Version: "1",
		Agent:   policy.AgentIdentity{Name: "test"},
		Mode:    "permissive",
		Default: "deny",
	}

	report := evaluate(p, ".tr/policy.yaml")

	found := false
	for _, issue := range report.Issues {
		if issue.ID == "permissive-mode" {
			found = true
			if issue.Severity != "critical" {
				t.Errorf("permissive-mode should be critical, got %s", issue.Severity)
			}
		}
	}
	if !found {
		t.Error("permissive-mode check did not fire")
	}
}

func TestHarden_DefaultAllowIsCritical(t *testing.T) {
	p := &policy.Policy{
		Version: "1",
		Agent:   policy.AgentIdentity{Name: "test"},
		Mode:    "enforce",
		Default: "allow",
	}

	report := evaluate(p, ".tr/policy.yaml")

	found := false
	for _, issue := range report.Issues {
		if issue.ID == "default-allow" {
			found = true
			if issue.Severity != "critical" {
				t.Errorf("default-allow should be critical, got %s", issue.Severity)
			}
		}
	}
	if !found {
		t.Error("default-allow check did not fire")
	}
}

func TestHarden_MissingNetworkPolicyIsWarning(t *testing.T) {
	p := &policy.Policy{
		Version: "1",
		Agent:   policy.AgentIdentity{Name: "test"},
		Mode:    "enforce",
		Default: "deny",
	}

	report := evaluate(p, ".tr/policy.yaml")

	found := false
	for _, issue := range report.Issues {
		if issue.ID == "no-network-policy" {
			found = true
			if issue.Severity != "warning" {
				t.Errorf("no-network-policy should be warning, got %s", issue.Severity)
			}
		}
	}
	if !found {
		t.Error("no-network-policy check did not fire")
	}
}

func TestHarden_JSONOutput(t *testing.T) {
	p := &policy.Policy{
		Version: "1",
		Agent:   policy.AgentIdentity{Name: "test"},
		Mode:    "audit",
		Default: "deny",
	}

	report := evaluate(p, ".tr/policy.yaml")

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		t.Fatalf("json encode: %v", err)
	}

	var decoded hardenReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json decode: %v", err)
	}

	if decoded.Mode != "audit" {
		t.Errorf("expected mode 'audit', got %q", decoded.Mode)
	}
	if decoded.Default != "deny" {
		t.Errorf("expected default 'deny', got %q", decoded.Default)
	}
	if decoded.Total != len(hardenChecks) {
		t.Errorf("expected total %d, got %d", len(hardenChecks), decoded.Total)
	}
}

func TestHarden_ExitCode1OnCritical(t *testing.T) {
	p := &policy.Policy{
		Version: "1",
		Agent:   policy.AgentIdentity{Name: "test"},
		Mode:    "permissive",
		Default: "deny",
	}

	report := evaluate(p, ".tr/policy.yaml")
	hasCritical := false
	for _, issue := range report.Issues {
		if issue.Severity == "critical" {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Error("expected critical issue for permissive mode")
	}
}

func TestHarden_ExitCode0NoCritical(t *testing.T) {
	p := &policy.Policy{
		Version:           "1",
		Agent:             policy.AgentIdentity{Name: "test"},
		Mode:              "enforce",
		Default:           "deny",
		SignatureRequired: true,
		Rules:             []policy.Rule{{ID: "r1", Protocol: "mcp", Method: "tool_call", Target: "x", Action: "allow"}},
		Constraints:       policy.Constraints{MaxActions: 100, MaxDurationSeconds: 600},
		Filesystem:        policy.FilesystemConfig{Enabled: true, Mounts: []policy.FilesystemMount{{Source: ".", Target: "d", Mode: "ro"}}},
		Network:           policy.NetworkConfig{DNSAllow: []string{"example.com"}},
		Exfiltration:      policy.ExfiltrationConfig{Enabled: true},
		Sequences:         policy.SequenceConfig{Window: 10, Rules: []policy.SequenceRule{{ID: "s1", Pattern: []string{"a", "b"}, Action: "deny"}}},
	}

	report := evaluate(p, ".tr/policy.yaml")
	for _, issue := range report.Issues {
		if issue.Severity == "critical" {
			t.Errorf("unexpected critical issue: %s", issue.ID)
		}
	}
}

func TestHarden_PrintReport_ContainsSections(t *testing.T) {
	p := &policy.Policy{
		Version: "1",
		Agent:   policy.AgentIdentity{Name: "test"},
		Mode:    "permissive",
		Default: "allow",
	}

	report := evaluate(p, ".tr/policy.yaml")

	var buf bytes.Buffer
	printReport(&buf, report)
	output := buf.String()

	for _, want := range []string{
		"relic harden",
		"Security Analysis",
		"[CRITICAL]",
		"[WARNING]",
		"[INFO]",
		"Score:",
		"permissive-mode",
		"default-allow",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, output)
		}
	}
}

func TestHarden_PrintReport_NoIssues(t *testing.T) {
	report := hardenReport{
		Policy:  ".tr/policy.yaml",
		Mode:    "enforce",
		Default: "deny",
		Passed:  9,
		Total:   9,
	}

	var buf bytes.Buffer
	printReport(&buf, report)
	output := buf.String()

	if !strings.Contains(output, "No issues found") {
		t.Errorf("expected 'No issues found' in output, got:\n%s", output)
	}
	if !strings.Contains(output, "9/9") {
		t.Errorf("expected '9/9' in score, got:\n%s", output)
	}
}

func TestHarden_CLIIntegration_CriticalExitCode(t *testing.T) {
	dir := t.TempDir()

	// Write a permissive policy.
	policyYAML := `version: "1"
agent:
  name: "test"
mode: permissive
default: allow
rules: []
`
	writePolicyFile(t, dir, policyYAML)

	_, _, err := runCmd(t, dir, "harden", "--policy", dir+"/.tr/policy.yaml")
	if err == nil {
		t.Error("expected non-zero exit for critical issues")
	}
}

func TestHarden_CLIIntegration_CleanExitCode(t *testing.T) {
	dir := t.TempDir()

	policyYAML := `version: "1"
agent:
  name: "test"
mode: enforce
default: deny
signature_required: true
rules:
  - id: r1
    protocol: mcp
    method: tool_call
    target: "web_search"
    action: allow
constraints:
  max_actions: 100
  max_duration_seconds: 600
filesystem:
  enabled: true
  mounts:
    - source: ./data
      target: data
      mode: ro
network:
  dns_allow:
    - "api.example.com"
exfiltration:
  enabled: true
sequences:
  window: 10
  rules:
    - id: s1
      pattern: ["a", "b"]
      reason: "test"
      action: deny
`
	writePolicyFile(t, dir, policyYAML)

	stdout, _, err := runCmd(t, dir, "harden", "--policy", dir+"/.tr/policy.yaml")
	if err != nil {
		t.Fatalf("expected clean exit, got error: %v\nstdout: %s", err, stdout)
	}
}

func TestHarden_CLIIntegration_JSONFlag(t *testing.T) {
	dir := t.TempDir()

	policyYAML := `version: "1"
agent:
  name: "test"
mode: audit
default: deny
rules: []
`
	writePolicyFile(t, dir, policyYAML)

	stdout, _, _ := runCmd(t, dir, "harden", "--policy", dir+"/.tr/policy.yaml", "--json")

	var report hardenReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("failed to parse JSON output: %v\nraw: %s", err, stdout)
	}
	if report.Mode != "audit" {
		t.Errorf("expected mode 'audit' in JSON, got %q", report.Mode)
	}
}

func writePolicyFile(t *testing.T, dir, content string) {
	t.Helper()
	trDir := dir + "/.tr"
	if err := os.MkdirAll(trDir, 0o755); err != nil {
		t.Fatalf("mkdir .tr: %v", err)
	}
	if err := os.WriteFile(trDir+"/policy.yaml", []byte(content), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
}
