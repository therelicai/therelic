package delegation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/therelicai/therelic/internal/policy"
)

// ---------------------------------------------------------------------------
// Helpers
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

func intent(proto, method, target string) policy.ActionIntent {
	return policy.ActionIntent{Protocol: proto, Method: method, Target: target}
}

var noState = policy.RunState{}

// ---------------------------------------------------------------------------
// Graph structure tests
// ---------------------------------------------------------------------------

func TestNewGraph_EmptyGraph(t *testing.T) {
	g := NewGraph("root-1")
	if g.Root != "root-1" {
		t.Errorf("Root = %q, want %q", g.Root, "root-1")
	}
	if len(g.Nodes) != 0 {
		t.Errorf("Nodes = %d, want 0", len(g.Nodes))
	}
	if len(g.Edges) != 0 {
		t.Errorf("Edges = %d, want 0", len(g.Edges))
	}
}

func TestGraph_AddNode(t *testing.T) {
	g := NewGraph("root-1")
	g.AddNode(&DelegationNode{RunID: "root-1", AgentName: "home", Depth: 0, RootRunID: "root-1"})
	g.AddNode(&DelegationNode{RunID: "child-1", AgentName: "worker", Depth: 1, RootRunID: "root-1"})

	if len(g.Nodes) != 2 {
		t.Fatalf("Nodes = %d, want 2", len(g.Nodes))
	}
	if g.Nodes["child-1"].AgentName != "worker" {
		t.Errorf("child AgentName = %q, want %q", g.Nodes["child-1"].AgentName, "worker")
	}
}

func TestGraph_AddEdge(t *testing.T) {
	g := NewGraph("root-1")
	g.AddEdge("root-1", "child-1")
	g.AddEdge("root-1", "child-2")

	if len(g.Edges) != 2 {
		t.Fatalf("Edges = %d, want 2", len(g.Edges))
	}
}

// ---------------------------------------------------------------------------
// AncestorChain tests
// ---------------------------------------------------------------------------

func TestAncestorChain_Root_Empty(t *testing.T) {
	g := NewGraph("root-1")
	g.AddNode(&DelegationNode{RunID: "root-1"})

	chain := g.AncestorChain("root-1")
	if len(chain) != 0 {
		t.Errorf("root should have no ancestors, got %v", chain)
	}
}

func TestAncestorChain_OneLevel(t *testing.T) {
	g := NewGraph("root-1")
	g.AddNode(&DelegationNode{RunID: "root-1"})
	g.AddNode(&DelegationNode{RunID: "child-1"})
	g.AddEdge("root-1", "child-1")

	chain := g.AncestorChain("child-1")
	if len(chain) != 1 || chain[0] != "root-1" {
		t.Errorf("AncestorChain = %v, want [root-1]", chain)
	}
}

func TestAncestorChain_ThreeLevels(t *testing.T) {
	g := NewGraph("root")
	g.AddNode(&DelegationNode{RunID: "root"})
	g.AddNode(&DelegationNode{RunID: "mid"})
	g.AddNode(&DelegationNode{RunID: "leaf"})
	g.AddEdge("root", "mid")
	g.AddEdge("mid", "leaf")

	chain := g.AncestorChain("leaf")
	if len(chain) != 2 {
		t.Fatalf("AncestorChain length = %d, want 2", len(chain))
	}
	if chain[0] != "root" || chain[1] != "mid" {
		t.Errorf("AncestorChain = %v, want [root, mid]", chain)
	}
}

func TestAncestorChain_FanOut_ChildrenIndependent(t *testing.T) {
	g := NewGraph("root")
	g.AddEdge("root", "child-A")
	g.AddEdge("root", "child-B")
	g.AddEdge("root", "child-C")

	for _, child := range []string{"child-A", "child-B", "child-C"} {
		chain := g.AncestorChain(child)
		if len(chain) != 1 || chain[0] != "root" {
			t.Errorf("AncestorChain(%s) = %v, want [root]", child, chain)
		}
	}
}

func TestAncestorChain_UnknownNode_Empty(t *testing.T) {
	g := NewGraph("root")
	g.AddEdge("root", "child-1")

	chain := g.AncestorChain("unknown")
	if len(chain) != 0 {
		t.Errorf("AncestorChain(unknown) = %v, want empty", chain)
	}
}

// ---------------------------------------------------------------------------
// EvaluateWithDelegation tests
// ---------------------------------------------------------------------------

func TestEvaluateWithDelegation_RootSession_NormalEvaluation(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-web", "mcp", "tool_call", "web_search", "allow"),
	)

	result := EvaluateWithDelegation(
		intent("mcp", "tool_call", "web_search"),
		p,
		nil, // no ancestors — root session
		noState,
	)
	if result.Decision != "allow" {
		t.Errorf("Decision = %q, want %q", result.Decision, "allow")
	}
}

func TestEvaluateWithDelegation_RootSession_DefaultDeny(t *testing.T) {
	p := makePolicy("enforce", "deny")

	result := EvaluateWithDelegation(
		intent("mcp", "tool_call", "unknown"),
		p,
		nil,
		noState,
	)
	if result.Decision != "deny" {
		t.Errorf("Decision = %q, want %q", result.Decision, "deny")
	}
}

func TestEvaluateWithDelegation_ChildSession_Intersection(t *testing.T) {
	// Parent allows A and B
	parentPolicy := makePolicy("enforce", "deny",
		rule("allow-A", "mcp", "tool_call", "tool_A", "allow"),
		rule("allow-B", "mcp", "tool_call", "tool_B", "allow"),
	)
	// Child allows B and C
	childPolicy := makePolicy("enforce", "deny",
		rule("allow-B", "mcp", "tool_call", "tool_B", "allow"),
		rule("allow-C", "mcp", "tool_call", "tool_C", "allow"),
	)

	ancestors := []*policy.Policy{parentPolicy}

	// tool_A: parent allows, child denies → denied by child policy
	result := EvaluateWithDelegation(intent("mcp", "tool_call", "tool_A"), childPolicy, ancestors, noState)
	if result.Decision != "deny" {
		t.Errorf("tool_A: Decision = %q, want deny", result.Decision)
	}

	// tool_B: both allow → allowed
	result = EvaluateWithDelegation(intent("mcp", "tool_call", "tool_B"), childPolicy, ancestors, noState)
	if result.Decision != "allow" {
		t.Errorf("tool_B: Decision = %q, want allow", result.Decision)
	}

	// tool_C: parent denies, child allows → denied by ancestor
	result = EvaluateWithDelegation(intent("mcp", "tool_call", "tool_C"), childPolicy, ancestors, noState)
	if result.Decision != "deny" {
		t.Errorf("tool_C: Decision = %q, want deny", result.Decision)
	}
	if result.Reason == "" {
		t.Error("tool_C: expected reason to mention ancestor policy")
	}
}

func TestEvaluateWithDelegation_ThreeLevel_NarrowsAtEachLevel(t *testing.T) {
	// Root: allows A, B, C
	rootPolicy := makePolicy("enforce", "deny",
		rule("allow-A", "mcp", "tool_call", "tool_A", "allow"),
		rule("allow-B", "mcp", "tool_call", "tool_B", "allow"),
		rule("allow-C", "mcp", "tool_call", "tool_C", "allow"),
	)
	// Mid: allows B, C (drops A)
	midPolicy := makePolicy("enforce", "deny",
		rule("allow-B", "mcp", "tool_call", "tool_B", "allow"),
		rule("allow-C", "mcp", "tool_call", "tool_C", "allow"),
	)
	// Leaf: allows B only (drops C)
	leafPolicy := makePolicy("enforce", "deny",
		rule("allow-B", "mcp", "tool_call", "tool_B", "allow"),
	)

	ancestors := []*policy.Policy{rootPolicy, midPolicy}

	// tool_A: root allows, mid denies → denied
	result := EvaluateWithDelegation(intent("mcp", "tool_call", "tool_A"), leafPolicy, ancestors, noState)
	if result.Decision != "deny" {
		t.Errorf("tool_A: Decision = %q, want deny", result.Decision)
	}

	// tool_B: all three allow → allowed
	result = EvaluateWithDelegation(intent("mcp", "tool_call", "tool_B"), leafPolicy, ancestors, noState)
	if result.Decision != "allow" {
		t.Errorf("tool_B: Decision = %q, want allow", result.Decision)
	}

	// tool_C: root and mid allow, leaf denies → denied
	result = EvaluateWithDelegation(intent("mcp", "tool_call", "tool_C"), leafPolicy, ancestors, noState)
	if result.Decision != "deny" {
		t.Errorf("tool_C: Decision = %q, want deny", result.Decision)
	}
}

func TestEvaluateWithDelegation_FanOut_DifferentPolicies(t *testing.T) {
	parentPolicy := makePolicy("enforce", "deny",
		rule("allow-A", "mcp", "tool_call", "tool_A", "allow"),
		rule("allow-B", "mcp", "tool_call", "tool_B", "allow"),
		rule("allow-C", "mcp", "tool_call", "tool_C", "allow"),
	)
	ancestors := []*policy.Policy{parentPolicy}

	// Child 1: only has A
	child1 := makePolicy("enforce", "deny",
		rule("allow-A", "mcp", "tool_call", "tool_A", "allow"),
	)
	// Child 2: only has B
	child2 := makePolicy("enforce", "deny",
		rule("allow-B", "mcp", "tool_call", "tool_B", "allow"),
	)
	// Child 3: only has C
	child3 := makePolicy("enforce", "deny",
		rule("allow-C", "mcp", "tool_call", "tool_C", "allow"),
	)

	// Child 1 can use A but not B or C
	r := EvaluateWithDelegation(intent("mcp", "tool_call", "tool_A"), child1, ancestors, noState)
	if r.Decision != "allow" {
		t.Errorf("child1/tool_A: Decision = %q, want allow", r.Decision)
	}
	r = EvaluateWithDelegation(intent("mcp", "tool_call", "tool_B"), child1, ancestors, noState)
	if r.Decision != "deny" {
		t.Errorf("child1/tool_B: Decision = %q, want deny", r.Decision)
	}

	// Child 2 can use B but not A or C
	r = EvaluateWithDelegation(intent("mcp", "tool_call", "tool_B"), child2, ancestors, noState)
	if r.Decision != "allow" {
		t.Errorf("child2/tool_B: Decision = %q, want allow", r.Decision)
	}
	r = EvaluateWithDelegation(intent("mcp", "tool_call", "tool_A"), child2, ancestors, noState)
	if r.Decision != "deny" {
		t.Errorf("child2/tool_A: Decision = %q, want deny", r.Decision)
	}

	// Child 3 can use C but not A or B
	r = EvaluateWithDelegation(intent("mcp", "tool_call", "tool_C"), child3, ancestors, noState)
	if r.Decision != "allow" {
		t.Errorf("child3/tool_C: Decision = %q, want allow", r.Decision)
	}
	r = EvaluateWithDelegation(intent("mcp", "tool_call", "tool_A"), child3, ancestors, noState)
	if r.Decision != "deny" {
		t.Errorf("child3/tool_A: Decision = %q, want deny", r.Decision)
	}
}

func TestEvaluateWithDelegation_AncestorDeny_IncludesReasonPrefix(t *testing.T) {
	parentPolicy := makePolicy("enforce", "deny") // denies everything
	childPolicy := makePolicy("enforce", "allow")  // allows everything

	result := EvaluateWithDelegation(
		intent("mcp", "tool_call", "tool_X"),
		childPolicy,
		[]*policy.Policy{parentPolicy},
		noState,
	)
	if result.Decision != "deny" {
		t.Fatalf("Decision = %q, want deny", result.Decision)
	}
	if result.Reason == "" {
		t.Fatal("Reason should be non-empty")
	}
	// Should mention ancestor
	want := "denied by ancestor policy:"
	if len(result.Reason) < len(want) || result.Reason[:len(want)] != want {
		t.Errorf("Reason = %q, should start with %q", result.Reason, want)
	}
}

func TestEvaluateWithDelegation_EmptyAncestors_SameAsPlainEvaluate(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-web", "mcp", "tool_call", "web_search", "allow"),
	)
	i := intent("mcp", "tool_call", "web_search")

	delegated := EvaluateWithDelegation(i, p, []*policy.Policy{}, noState)
	plain := policy.Evaluate(i, p, noState)

	if delegated.Decision != plain.Decision {
		t.Errorf("Delegated=%q, Plain=%q — should match", delegated.Decision, plain.Decision)
	}
	if delegated.RuleID != plain.RuleID {
		t.Errorf("Delegated RuleID=%q, Plain RuleID=%q — should match", delegated.RuleID, plain.RuleID)
	}
}

// ---------------------------------------------------------------------------
// DetectParentSession tests
// ---------------------------------------------------------------------------

func clearDelegationEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{EnvRunID, EnvParentRunID, EnvParentPolicy, EnvDelegationDepth, EnvDelegationRoot} {
		os.Unsetenv(key)
	}
}

func TestDetectParentSession_NoEnvVars_NotChild(t *testing.T) {
	clearDelegationEnv(t)

	_, _, _, _, isChild := DetectParentSession()
	if isChild {
		t.Error("expected isChild=false when no env vars are set")
	}
}

func TestDetectParentSession_OnlyRunID_IsChild(t *testing.T) {
	clearDelegationEnv(t)
	t.Setenv(EnvRunID, "parent-run-123")

	parentRunID, _, _, _, isChild := DetectParentSession()
	if !isChild {
		t.Fatal("expected isChild=true when RELIC_RUN_ID is set")
	}
	if parentRunID != "parent-run-123" {
		t.Errorf("parentRunID = %q, want %q", parentRunID, "parent-run-123")
	}
}

func TestDetectParentSession_ParentRunID_TakesPrecedence(t *testing.T) {
	clearDelegationEnv(t)
	t.Setenv(EnvRunID, "my-own-run")
	t.Setenv(EnvParentRunID, "actual-parent")

	parentRunID, _, _, _, isChild := DetectParentSession()
	if !isChild {
		t.Fatal("expected isChild=true")
	}
	if parentRunID != "actual-parent" {
		t.Errorf("parentRunID = %q, want %q", parentRunID, "actual-parent")
	}
}

func TestDetectParentSession_AllVars(t *testing.T) {
	clearDelegationEnv(t)
	t.Setenv(EnvParentRunID, "parent-42")
	t.Setenv(EnvParentPolicy, "/path/to/policy.yaml")
	t.Setenv(EnvDelegationDepth, "3")
	t.Setenv(EnvDelegationRoot, "root-1")

	parentRunID, parentPolicy, delegRoot, depth, isChild := DetectParentSession()
	if !isChild {
		t.Fatal("expected isChild=true")
	}
	if parentRunID != "parent-42" {
		t.Errorf("parentRunID = %q", parentRunID)
	}
	if parentPolicy != "/path/to/policy.yaml" {
		t.Errorf("parentPolicy = %q", parentPolicy)
	}
	if delegRoot != "root-1" {
		t.Errorf("delegationRoot = %q", delegRoot)
	}
	if depth != 3 {
		t.Errorf("depth = %d, want 3", depth)
	}
}

func TestDetectParentSession_NoRoot_FallsBackToParentRunID(t *testing.T) {
	clearDelegationEnv(t)
	t.Setenv(EnvParentRunID, "parent-99")
	// RELIC_DELEGATION_ROOT not set

	_, _, delegRoot, _, isChild := DetectParentSession()
	if !isChild {
		t.Fatal("expected isChild=true")
	}
	if delegRoot != "parent-99" {
		t.Errorf("delegationRoot = %q, want %q (should fall back to parentRunID)", delegRoot, "parent-99")
	}
}

func TestDetectParentSession_InvalidDepth_DefaultsToZero(t *testing.T) {
	clearDelegationEnv(t)
	t.Setenv(EnvParentRunID, "p-1")
	t.Setenv(EnvDelegationDepth, "not-a-number")

	_, _, _, depth, isChild := DetectParentSession()
	if !isChild {
		t.Fatal("expected isChild=true")
	}
	if depth != 0 {
		t.Errorf("depth = %d, want 0 for invalid input", depth)
	}
}

// ---------------------------------------------------------------------------
// CachePolicy / LoadCachedPolicy tests
// ---------------------------------------------------------------------------

func TestCachePolicy_WritesAndLoads(t *testing.T) {
	dir := t.TempDir()
	policiesDir := filepath.Join(dir, "policies")

	yamlData := []byte(`version: "1"
agent:
  name: cached-agent
mode: enforce
default: deny
rules:
  - id: allow-web
    protocol: mcp
    method: tool_call
    target: web_search
    action: allow
`)

	path, err := CachePolicy(policiesDir, yamlData, "abc123")
	if err != nil {
		t.Fatalf("CachePolicy: %v", err)
	}

	expected := filepath.Join(policiesDir, "abc123.yaml")
	if path != expected {
		t.Errorf("path = %q, want %q", path, expected)
	}

	p, err := LoadCachedPolicy(path)
	if err != nil {
		t.Fatalf("LoadCachedPolicy: %v", err)
	}
	if p.Agent.Name != "cached-agent" {
		t.Errorf("Agent.Name = %q, want %q", p.Agent.Name, "cached-agent")
	}
	if len(p.Rules) != 1 {
		t.Errorf("Rules = %d, want 1", len(p.Rules))
	}
}

func TestCachePolicy_CreatesDirIfMissing(t *testing.T) {
	dir := t.TempDir()
	policiesDir := filepath.Join(dir, "deep", "nested", "policies")

	_, err := CachePolicy(policiesDir, []byte("version: \"1\""), "hash1")
	if err != nil {
		t.Fatalf("CachePolicy: %v", err)
	}

	if _, err := os.Stat(policiesDir); os.IsNotExist(err) {
		t.Error("expected policiesDir to be created")
	}
}

// ---------------------------------------------------------------------------
// SetChildEnv tests
// ---------------------------------------------------------------------------

func TestSetChildEnv_ContainsDelegationVars(t *testing.T) {
	env := SetChildEnv(nil, "run-42", "/tmp/policy.yaml", "root-1", 2)

	envMap := make(map[string]string)
	for _, e := range env {
		for i := 0; i < len(e); i++ {
			if e[i] == '=' {
				envMap[e[:i]] = e[i+1:]
				break
			}
		}
	}

	if envMap[EnvRunID] != "run-42" {
		t.Errorf("%s = %q, want %q", EnvRunID, envMap[EnvRunID], "run-42")
	}
	if envMap[EnvParentRunID] != "run-42" {
		t.Errorf("%s = %q, want %q", EnvParentRunID, envMap[EnvParentRunID], "run-42")
	}
	if envMap[EnvParentPolicy] != "/tmp/policy.yaml" {
		t.Errorf("%s = %q, want %q", EnvParentPolicy, envMap[EnvParentPolicy], "/tmp/policy.yaml")
	}
	if envMap[EnvDelegationDepth] != "3" {
		t.Errorf("%s = %q, want %q", EnvDelegationDepth, envMap[EnvDelegationDepth], "3")
	}
	if envMap[EnvDelegationRoot] != "root-1" {
		t.Errorf("%s = %q, want %q", EnvDelegationRoot, envMap[EnvDelegationRoot], "root-1")
	}
}
