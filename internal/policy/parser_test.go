package policy

import (
	"strings"
	"testing"
)

// validPolicy returns a minimal valid policy YAML.
func validPolicyYAML() []byte {
	return []byte(`
version: "1"
agent:
  name: "test-agent"
  version: "1.0.0"
mode: enforce
default: deny
rules:
  - id: allow-web
    protocol: mcp
    method: tool_call
    target: "web_search"
    action: allow
  - id: deny-shell
    protocol: mcp
    method: tool_call
    target: "shell_exec"
    action: deny
`)
}

func TestParse_ValidPolicy(t *testing.T) {
	p, err := Parse(validPolicyYAML())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Version != "1" {
		t.Errorf("Version = %q, want \"1\"", p.Version)
	}
	if p.Agent.Name != "test-agent" {
		t.Errorf("Agent.Name = %q, want \"test-agent\"", p.Agent.Name)
	}
	if p.Mode != "enforce" {
		t.Errorf("Mode = %q", p.Mode)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("len(Rules) = %d, want 2", len(p.Rules))
	}
	if p.Rules[0].ID != "allow-web" {
		t.Errorf("Rules[0].ID = %q", p.Rules[0].ID)
	}
	if p.Rules[1].Action != "deny" {
		t.Errorf("Rules[1].Action = %q, want \"deny\"", p.Rules[1].Action)
	}
}

func TestParse_InvalidYAML(t *testing.T) {
	_, err := Parse([]byte("invalid: yaml: {{{{"))
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestParse_RedactionConfig(t *testing.T) {
	yaml := `
version: "1"
agent:
  name: "a"
mode: permissive
default: deny
redaction:
  keys: ["password", "token"]
  headers: ["Authorization"]
rules: []
`
	p, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Redaction.Keys) != 2 {
		t.Errorf("Redaction.Keys len = %d, want 2", len(p.Redaction.Keys))
	}
	if len(p.Redaction.Headers) != 1 {
		t.Errorf("Redaction.Headers len = %d, want 1", len(p.Redaction.Headers))
	}
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

func TestValidate_ValidPolicy(t *testing.T) {
	p, _ := Parse(validPolicyYAML())
	errs := Validate(p, false)
	if len(errs) != 0 {
		t.Errorf("expected no errors for valid policy, got: %v", errs)
	}
}

func TestValidate_MissingVersion(t *testing.T) {
	p, _ := Parse(validPolicyYAML())
	p.Version = ""
	errs := Validate(p, false)
	assertHasField(t, errs, "version")
}

func TestValidate_WrongVersion(t *testing.T) {
	p, _ := Parse(validPolicyYAML())
	p.Version = "2"
	errs := Validate(p, false)
	assertHasField(t, errs, "version")
}

func TestValidate_MissingAgentName(t *testing.T) {
	p, _ := Parse(validPolicyYAML())
	p.Agent.Name = ""
	errs := Validate(p, false)
	assertHasField(t, errs, "agent.name")
}

func TestValidate_InvalidMode(t *testing.T) {
	p, _ := Parse(validPolicyYAML())
	p.Mode = "badmode"
	errs := Validate(p, false)
	assertHasField(t, errs, "mode")
}

func TestValidate_InvalidDefault(t *testing.T) {
	p, _ := Parse(validPolicyYAML())
	p.Default = "maybe"
	errs := Validate(p, false)
	assertHasField(t, errs, "default")
}

func TestValidate_MissingRuleID(t *testing.T) {
	p, _ := Parse(validPolicyYAML())
	p.Rules[0].ID = ""
	errs := Validate(p, false)
	assertHasField(t, errs, "rules[0].id")
}

func TestValidate_DuplicateRuleID(t *testing.T) {
	p, _ := Parse(validPolicyYAML())
	p.Rules[1].ID = p.Rules[0].ID // duplicate
	errs := Validate(p, false)
	assertContains(t, errs, "duplicate id")
}

func TestValidate_InvalidRuleAction(t *testing.T) {
	p, _ := Parse(validPolicyYAML())
	p.Rules[0].Action = "maybe"
	errs := Validate(p, false)
	assertHasField(t, errs, "rules[0].action")
}

func TestValidate_MissingRuleFields(t *testing.T) {
	p, _ := Parse(validPolicyYAML())
	p.Rules[0].Protocol = ""
	p.Rules[0].Method = ""
	p.Rules[0].Target = ""
	errs := Validate(p, false)

	assertHasField(t, errs, "rules[0].protocol")
	assertHasField(t, errs, "rules[0].method")
	assertHasField(t, errs, "rules[0].target")
}

func TestValidate_Strict_DefaultAllow_EnforceMode(t *testing.T) {
	p, _ := Parse(validPolicyYAML())
	p.Mode = "enforce"
	p.Default = "allow"
	errs := Validate(p, true)
	assertContains(t, errs, "insecure")
}

func TestValidate_Strict_DefaultAllow_PermissiveMode_NoWarn(t *testing.T) {
	// strict warning only fires for enforce+allow, not permissive+allow
	p, _ := Parse(validPolicyYAML())
	p.Mode = "permissive"
	p.Default = "allow"
	errs := Validate(p, true)
	for _, e := range errs {
		if strings.Contains(e.Message, "insecure") {
			t.Errorf("unexpected strict warning for permissive mode: %v", e)
		}
	}
}

func TestValidate_EmptyRules_Valid(t *testing.T) {
	p, _ := Parse(validPolicyYAML())
	p.Rules = nil
	errs := Validate(p, false)
	if len(errs) != 0 {
		t.Errorf("empty rules list should be valid, got: %v", errs)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func assertHasField(t *testing.T, errs []ValidationError, field string) {
	t.Helper()
	for _, e := range errs {
		if e.Field == field {
			return
		}
	}
	t.Errorf("expected validation error for field %q, got: %v", field, errs)
}

func assertContains(t *testing.T, errs []ValidationError, substring string) {
	t.Helper()
	for _, e := range errs {
		if strings.Contains(e.Message, substring) {
			return
		}
	}
	t.Errorf("expected validation error containing %q, got: %v", substring, errs)
}
