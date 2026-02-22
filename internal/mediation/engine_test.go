package mediation

import (
	"context"
	"testing"

	"github.com/therelicai/therelic/internal/policy"
)

// ---------------------------------------------------------------------------
// Helpers (mirror the style in internal/policy/engine_test.go)
// ---------------------------------------------------------------------------

func makePolicy(mode, defaultAction string, rules ...policy.Rule) *policy.Policy {
	return &policy.Policy{
		Version: "1",
		Agent:   policy.AgentIdentity{Name: "test-agent"},
		Mode:    mode,
		Default: defaultAction,
		Rules:   rules,
	}
}

func rule(id, proto, method, target, action string) policy.Rule {
	return policy.Rule{ID: id, Protocol: proto, Method: method, Target: target, Action: action}
}

var noState = policy.RunState{}

// ---------------------------------------------------------------------------
// MediationEngine – nil policy engine (permissive)
// ---------------------------------------------------------------------------

func TestMediate_NilPolicyEngine_Allows(t *testing.T) {
	eng := NewMediationEngine(nil, "run-1")

	result := eng.Mediate(ActionIntent{
		Protocol: "mcp",
		Method:   "tool_call",
		Target:   "any_tool",
	}, noState)

	if !result.Allowed {
		t.Fatal("expected Allowed=true with nil policy engine")
	}
	if result.Decision.Decision != "allow" {
		t.Errorf("Decision = %q, want %q", result.Decision.Decision, "allow")
	}
	if result.Decision.RuleID != "default" {
		t.Errorf("RuleID = %q, want %q", result.Decision.RuleID, "default")
	}
}

// ---------------------------------------------------------------------------
// MediationEngine – real policy engine (allow)
// ---------------------------------------------------------------------------

func TestMediate_PolicyEngineAllow(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("r1", "mcp", "tool_call", "safe_tool", "allow"),
	)
	eng := NewMediationEngine(policy.NewEngine(p), "run-2")

	result := eng.Mediate(ActionIntent{
		Protocol: "mcp",
		Method:   "tool_call",
		Target:   "safe_tool",
	}, noState)

	if !result.Allowed {
		t.Fatal("expected Allowed=true for allowed tool")
	}
	if result.Decision.Decision != "allow" {
		t.Errorf("Decision = %q, want %q", result.Decision.Decision, "allow")
	}
	if result.Decision.RuleID != "r1" {
		t.Errorf("RuleID = %q, want %q", result.Decision.RuleID, "r1")
	}
}

// ---------------------------------------------------------------------------
// MediationEngine – real policy engine (deny)
// ---------------------------------------------------------------------------

func TestMediate_PolicyEngineDeny(t *testing.T) {
	p := makePolicy("enforce", "deny")
	eng := NewMediationEngine(policy.NewEngine(p), "run-3")

	result := eng.Mediate(ActionIntent{
		Protocol: "mcp",
		Method:   "tool_call",
		Target:   "blocked_tool",
	}, noState)

	if result.Allowed {
		t.Fatal("expected Allowed=false for denied tool")
	}
	if result.Decision.Decision != "deny" {
		t.Errorf("Decision = %q, want %q", result.Decision.Decision, "deny")
	}
}

// ---------------------------------------------------------------------------
// MediationResult.Allowed reflects decision
// ---------------------------------------------------------------------------

func TestMediationResult_AllowedReflectsDecision(t *testing.T) {
	cases := []struct {
		decision string
		allowed  bool
	}{
		{"allow", true},
		{"deny", false},
		{"audit_deny", true},
		{"would_deny", true},
	}
	for _, tc := range cases {
		t.Run(tc.decision, func(t *testing.T) {
			d := policy.AuthDecision{Decision: tc.decision}
			r := MediationResult{Decision: d, Allowed: d.IsAllowed()}
			if r.Allowed != tc.allowed {
				t.Errorf("Allowed = %v for %q, want %v", r.Allowed, tc.decision, tc.allowed)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// MCPBinding and HTTPBinding implement TransportBinding
// ---------------------------------------------------------------------------

func TestMCPBinding_ImplementsTransportBinding(t *testing.T) {
	var b TransportBinding = NewMCPBinding("mcp-stdio")
	if b.Name() != "mcp-stdio" {
		t.Errorf("Name() = %q, want %q", b.Name(), "mcp-stdio")
	}
	if err := b.Serve(context.Background(), nil); err != nil {
		t.Errorf("Serve() returned unexpected error: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Errorf("Close() returned unexpected error: %v", err)
	}
}

func TestHTTPBinding_ImplementsTransportBinding(t *testing.T) {
	var b TransportBinding = NewHTTPBinding("http-proxy")
	if b.Name() != "http-proxy" {
		t.Errorf("Name() = %q, want %q", b.Name(), "http-proxy")
	}
	if err := b.Serve(context.Background(), nil); err != nil {
		t.Errorf("Serve() returned unexpected error: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Errorf("Close() returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Mock transport binding works with engine
// ---------------------------------------------------------------------------

type mockBinding struct {
	served bool
	closed bool
}

func (m *mockBinding) Name() string { return "mock" }
func (m *mockBinding) Serve(_ context.Context, _ *MediationEngine) error {
	m.served = true
	return nil
}
func (m *mockBinding) Close() error {
	m.closed = true
	return nil
}

func TestMockBinding_WorksWithEngine(t *testing.T) {
	eng := NewMediationEngine(nil, "run-mock")
	b := &mockBinding{}

	if err := b.Serve(context.Background(), eng); err != nil {
		t.Fatalf("Serve() error: %v", err)
	}
	if !b.served {
		t.Error("expected served=true after Serve()")
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	if !b.closed {
		t.Error("expected closed=true after Close()")
	}
}
