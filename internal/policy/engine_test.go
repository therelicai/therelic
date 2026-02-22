package policy

import (
	"encoding/json"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makePolicy builds a minimal Policy for testing.
func makePolicy(mode, defaultAction string, rules ...Rule) *Policy {
	return &Policy{
		Version: "1",
		Agent:   AgentIdentity{Name: "test-agent"},
		Mode:    mode,
		Default: defaultAction,
		Rules:   rules,
	}
}

func rule(id, proto, method, target, action string) Rule {
	return Rule{ID: id, Protocol: proto, Method: method, Target: target, Action: action}
}

func ruleWithParams(id, proto, method, target, action string, params map[string]string) Rule {
	return Rule{ID: id, Protocol: proto, Method: method, Target: target, Action: action, Params: params}
}

func intent(proto, method, target string) ActionIntent {
	return ActionIntent{Protocol: proto, Method: method, Target: target}
}

func intentWithParams(proto, method, target string, params json.RawMessage) ActionIntent {
	return ActionIntent{Protocol: proto, Method: method, Target: target, Params: params}
}

var noState = RunState{} // zero state — no constraints triggered

// assertDecision fails the test if the AuthDecision's Decision field ≠ want.
func assertDecision(t *testing.T, got AuthDecision, want string) {
	t.Helper()
	if got.Decision != want {
		t.Errorf("Decision = %q, want %q  (RuleID=%q Reason=%q)",
			got.Decision, want, got.RuleID, got.Reason)
	}
}

func assertRuleID(t *testing.T, got AuthDecision, want string) {
	t.Helper()
	if got.RuleID != want {
		t.Errorf("RuleID = %q, want %q", got.RuleID, want)
	}
}

// ---------------------------------------------------------------------------
// Category 1: Exact matching
// ---------------------------------------------------------------------------

func TestExactMatch_Allow(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-web", "mcp", "tool_call", "web_search", "allow"),
	)
	got := Evaluate(intent("mcp", "tool_call", "web_search"), p, noState)
	assertDecision(t, got, "allow")
	assertRuleID(t, got, "allow-web")
}

func TestExactMatch_Deny(t *testing.T) {
	p := makePolicy("enforce", "allow",
		rule("deny-shell", "mcp", "tool_call", "shell_exec", "deny"),
	)
	got := Evaluate(intent("mcp", "tool_call", "shell_exec"), p, noState)
	assertDecision(t, got, "deny")
	assertRuleID(t, got, "deny-shell")
}

func TestExactMatch_HTTP(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-get", "http", "GET", "api.example.com", "allow"),
	)
	got := Evaluate(intent("http", "GET", "api.example.com"), p, noState)
	assertDecision(t, got, "allow")
}

// ---------------------------------------------------------------------------
// Category 2: Default (no matching rule)
// ---------------------------------------------------------------------------

func TestDefaultDeny_NoMatchingRule(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-web", "mcp", "tool_call", "web_search", "allow"),
	)
	got := Evaluate(intent("mcp", "tool_call", "shell_exec"), p, noState)
	assertDecision(t, got, "deny")
	assertRuleID(t, got, "default")
}

func TestDefaultAllow_NoMatchingRule(t *testing.T) {
	p := makePolicy("enforce", "allow",
		rule("deny-shell", "mcp", "tool_call", "shell_exec", "deny"),
	)
	got := Evaluate(intent("mcp", "tool_call", "web_search"), p, noState)
	assertDecision(t, got, "allow")
	assertRuleID(t, got, "default")
}

func TestDefaultDeny_EmptyRules(t *testing.T) {
	p := makePolicy("enforce", "deny")
	got := Evaluate(intent("mcp", "tool_call", "anything"), p, noState)
	assertDecision(t, got, "deny")
}

func TestDefaultAllow_EmptyRules(t *testing.T) {
	p := makePolicy("enforce", "allow")
	got := Evaluate(intent("mcp", "tool_call", "anything"), p, noState)
	assertDecision(t, got, "allow")
}

// ---------------------------------------------------------------------------
// Category 3: Glob matching — wildcards
// ---------------------------------------------------------------------------

func TestGlobMatch_StarProtocol_MatchesMCP(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-all", "*", "tool_call", "web_search", "allow"),
	)
	got := Evaluate(intent("mcp", "tool_call", "web_search"), p, noState)
	assertDecision(t, got, "allow")
}

func TestGlobMatch_StarProtocol_MatchesHTTP(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-all", "*", "GET", "api.example.com", "allow"),
	)
	got := Evaluate(intent("http", "GET", "api.example.com"), p, noState)
	assertDecision(t, got, "allow")
}

func TestGlobMatch_StarMethod_MatchesAnyMethod(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-all-methods", "mcp", "*", "web_search", "allow"),
	)
	for _, method := range []string{"tool_call", "resource_read", "prompt_get"} {
		got := Evaluate(intent("mcp", method, "web_search"), p, noState)
		assertDecision(t, got, "allow")
	}
}

func TestGlobMatch_StarTarget_MatchesAnyTarget(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-all-mcp", "mcp", "tool_call", "*", "allow"),
	)
	for _, target := range []string{"web_search", "shell_exec", "read_file"} {
		got := Evaluate(intent("mcp", "tool_call", target), p, noState)
		assertDecision(t, got, "allow")
	}
}

func TestGlobMatch_StarSuffix_CalendarTools(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-calendar", "mcp", "tool_call", "calendar_*", "allow"),
	)
	for _, target := range []string{"calendar_read", "calendar_write", "calendar_list"} {
		got := Evaluate(intent("mcp", "tool_call", target), p, noState)
		if got.Decision != "allow" {
			t.Errorf("target=%q: Decision=%q, want allow", target, got.Decision)
		}
	}
	// Should NOT match non-calendar tool
	got := Evaluate(intent("mcp", "tool_call", "web_search"), p, noState)
	assertDecision(t, got, "deny")
}

func TestGlobMatch_DoubleStar_PathSegments(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-api", "http", "GET", "api.example.com/**", "allow"),
	)
	for _, target := range []string{
		"api.example.com/v1/users",
		"api.example.com/v2/items/123",
		"api.example.com/health",
	} {
		got := Evaluate(intent("http", "GET", target), p, noState)
		if got.Decision != "allow" {
			t.Errorf("target=%q: Decision=%q, want allow", target, got.Decision)
		}
	}
	// Different host should not match
	got := Evaluate(intent("http", "GET", "other.example.com/v1"), p, noState)
	assertDecision(t, got, "deny")
}

func TestGlobMatch_SingleStar_NoPathCross(t *testing.T) {
	// Single star matches within one segment only (no '/')
	p := makePolicy("enforce", "deny",
		rule("allow-one-segment", "http", "GET", "api.example.com/*", "allow"),
	)
	// One path segment — should match
	got := Evaluate(intent("http", "GET", "api.example.com/health"), p, noState)
	assertDecision(t, got, "allow")

	// Two path segments — single star should NOT match
	got = Evaluate(intent("http", "GET", "api.example.com/v1/users"), p, noState)
	assertDecision(t, got, "deny")
}

func TestGlobMatch_QuestionMark_SingleChar(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-v1-or-v2", "http", "GET", "api.example.com/v?/data", "allow"),
	)
	got := Evaluate(intent("http", "GET", "api.example.com/v1/data"), p, noState)
	assertDecision(t, got, "allow")
	got = Evaluate(intent("http", "GET", "api.example.com/v2/data"), p, noState)
	assertDecision(t, got, "allow")
	// Two characters — should not match
	got = Evaluate(intent("http", "GET", "api.example.com/v10/data"), p, noState)
	assertDecision(t, got, "deny")
}

func TestGlobMatch_Alternatives_Method(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("deny-writes", "http", "{POST,PUT,DELETE,PATCH}", "**", "deny"),
	)
	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		got := Evaluate(intent("http", method, "api.example.com"), p, noState)
		if got.Decision != "deny" {
			t.Errorf("method=%q: Decision=%q, want deny", method, got.Decision)
		}
	}
	// GET should not match
	got := Evaluate(intent("http", "GET", "api.example.com"), p, noState)
	assertDecision(t, got, "deny") // default is deny, but different rule
	assertRuleID(t, got, "default")
}

func TestGlobMatch_Alternatives_Target(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-search", "mcp", "tool_call", "{web_search,web_fetch,web_browse}", "allow"),
	)
	for _, target := range []string{"web_search", "web_fetch", "web_browse"} {
		got := Evaluate(intent("mcp", "tool_call", target), p, noState)
		if got.Decision != "allow" {
			t.Errorf("target=%q: Decision=%q, want allow", target, got.Decision)
		}
	}
	got := Evaluate(intent("mcp", "tool_call", "web_scrape"), p, noState)
	assertDecision(t, got, "deny")
}

func TestGlobMatch_DeleteStar(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("deny-deletes", "mcp", "tool_call", "delete_*", "deny"),
	)
	for _, target := range []string{"delete_file", "delete_directory", "delete_item"} {
		got := Evaluate(intent("mcp", "tool_call", target), p, noState)
		if got.Decision != "deny" {
			t.Errorf("target=%q: Decision=%q, want deny", target, got.Decision)
		}
	}
}

// ---------------------------------------------------------------------------
// Category 4: Document order — first match wins
// ---------------------------------------------------------------------------

func TestDocumentOrder_AllowBeforeDeny_Wins(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-web", "mcp", "tool_call", "web_search", "allow"),
		rule("deny-all-mcp", "mcp", "*", "*", "deny"),
	)
	// web_search matches the allow rule first
	got := Evaluate(intent("mcp", "tool_call", "web_search"), p, noState)
	assertDecision(t, got, "allow")
	assertRuleID(t, got, "allow-web")
}

func TestDocumentOrder_DenyBeforeAllow_Wins(t *testing.T) {
	p := makePolicy("enforce", "allow",
		rule("deny-shell", "mcp", "tool_call", "shell_exec", "deny"),
		rule("allow-all-mcp", "mcp", "*", "*", "allow"),
	)
	// shell_exec matches the deny rule first
	got := Evaluate(intent("mcp", "tool_call", "shell_exec"), p, noState)
	assertDecision(t, got, "deny")
	assertRuleID(t, got, "deny-shell")
}

func TestDocumentOrder_ThirdRuleMatches(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-web", "mcp", "tool_call", "web_search", "allow"),
		rule("allow-fetch", "mcp", "tool_call", "web_fetch", "allow"),
		rule("allow-browse", "mcp", "tool_call", "web_browse", "allow"),
	)
	got := Evaluate(intent("mcp", "tool_call", "web_browse"), p, noState)
	assertDecision(t, got, "allow")
	assertRuleID(t, got, "allow-browse")
}

func TestDocumentOrder_RuleIDPopulated(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("my-rule-id", "mcp", "tool_call", "web_search", "allow"),
	)
	got := Evaluate(intent("mcp", "tool_call", "web_search"), p, noState)
	assertRuleID(t, got, "my-rule-id")
}

// ---------------------------------------------------------------------------
// Category 5: Protocol / method / target mismatches
// ---------------------------------------------------------------------------

func TestNoMatch_ProtocolMismatch(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-mcp", "mcp", "tool_call", "web_search", "allow"),
	)
	// http does not match mcp rule
	got := Evaluate(intent("http", "tool_call", "web_search"), p, noState)
	assertDecision(t, got, "deny")
	assertRuleID(t, got, "default")
}

func TestNoMatch_MethodMismatch(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-tool-call", "mcp", "tool_call", "web_search", "allow"),
	)
	got := Evaluate(intent("mcp", "resource_read", "web_search"), p, noState)
	assertDecision(t, got, "deny")
	assertRuleID(t, got, "default")
}

func TestNoMatch_TargetMismatch(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-web", "mcp", "tool_call", "web_search", "allow"),
	)
	got := Evaluate(intent("mcp", "tool_call", "shell_exec"), p, noState)
	assertDecision(t, got, "deny")
	assertRuleID(t, got, "default")
}

// ---------------------------------------------------------------------------
// Category 6: Constraints
// ---------------------------------------------------------------------------

func TestConstraint_MaxActions_Exceeded(t *testing.T) {
	p := makePolicy("enforce", "allow") // default allow so we know constraint fires
	p.Constraints.MaxActions = 10
	state := RunState{ActionCount: 10} // at limit

	got := Evaluate(intent("mcp", "tool_call", "web_search"), p, state)
	assertDecision(t, got, "deny")
	assertRuleID(t, got, "constraint:max_actions")
}

func TestConstraint_MaxActions_AtBoundary_Denied(t *testing.T) {
	p := makePolicy("enforce", "allow")
	p.Constraints.MaxActions = 5
	got := Evaluate(intent("mcp", "tool_call", "anything"), p, RunState{ActionCount: 5})
	assertDecision(t, got, "deny")
}

func TestConstraint_MaxActions_BelowLimit_Allowed(t *testing.T) {
	p := makePolicy("enforce", "allow")
	p.Constraints.MaxActions = 5
	got := Evaluate(intent("mcp", "tool_call", "anything"), p, RunState{ActionCount: 4})
	assertDecision(t, got, "allow")
}

func TestConstraint_MaxActions_Zero_Disabled(t *testing.T) {
	p := makePolicy("enforce", "deny")
	p.Constraints.MaxActions = 0 // disabled
	got := Evaluate(intent("mcp", "tool_call", "anything"), p, RunState{ActionCount: 999999})
	// Constraint disabled; falls through to default deny
	assertRuleID(t, got, "default")
}

func TestConstraint_MaxDuration_Exceeded(t *testing.T) {
	p := makePolicy("enforce", "allow")
	p.Constraints.MaxDurationSeconds = 300
	got := Evaluate(intent("mcp", "tool_call", "anything"), p, RunState{ElapsedSeconds: 300})
	assertDecision(t, got, "deny")
	assertRuleID(t, got, "constraint:max_duration")
}

func TestConstraint_MaxDuration_BelowLimit_Allowed(t *testing.T) {
	p := makePolicy("enforce", "allow")
	p.Constraints.MaxDurationSeconds = 300
	got := Evaluate(intent("mcp", "tool_call", "anything"), p, RunState{ElapsedSeconds: 299})
	assertDecision(t, got, "allow")
}

func TestConstraint_MaxDuration_Zero_Disabled(t *testing.T) {
	p := makePolicy("enforce", "deny")
	p.Constraints.MaxDurationSeconds = 0
	got := Evaluate(intent("mcp", "tool_call", "anything"), p, RunState{ElapsedSeconds: 999999})
	assertRuleID(t, got, "default") // constraint disabled; default applies
}

func TestConstraint_HardDeny_InPermissiveMode(t *testing.T) {
	// Constraints are hard limits even in permissive mode — they are never
	// converted to "would_deny".
	p := makePolicy("permissive", "allow")
	p.Constraints.MaxActions = 1
	got := Evaluate(intent("mcp", "tool_call", "anything"), p, RunState{ActionCount: 1})
	assertDecision(t, got, "deny") // NOT "would_deny"
	assertRuleID(t, got, "constraint:max_actions")
}

func TestConstraint_HardDeny_InAuditMode(t *testing.T) {
	p := makePolicy("audit", "allow")
	p.Constraints.MaxActions = 1
	got := Evaluate(intent("mcp", "tool_call", "anything"), p, RunState{ActionCount: 1})
	assertDecision(t, got, "deny") // NOT "audit_deny"
}

func TestConstraint_MaxActions_CheckedBeforeRules(t *testing.T) {
	// Even if a rule would allow, the constraint fires first.
	p := makePolicy("enforce", "allow",
		rule("allow-web", "mcp", "tool_call", "web_search", "allow"),
	)
	p.Constraints.MaxActions = 3
	got := Evaluate(intent("mcp", "tool_call", "web_search"), p, RunState{ActionCount: 3})
	assertDecision(t, got, "deny")
	assertRuleID(t, got, "constraint:max_actions")
}

// ---------------------------------------------------------------------------
// Category 7: Policy modes
// ---------------------------------------------------------------------------

func TestEnforceMode_Allow(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-web", "mcp", "tool_call", "web_search", "allow"),
	)
	got := Evaluate(intent("mcp", "tool_call", "web_search"), p, noState)
	assertDecision(t, got, "allow")
	if !got.IsAllowed() {
		t.Error("IsAllowed() should be true")
	}
}

func TestEnforceMode_Deny(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("deny-shell", "mcp", "tool_call", "shell_exec", "deny"),
	)
	got := Evaluate(intent("mcp", "tool_call", "shell_exec"), p, noState)
	assertDecision(t, got, "deny")
	if !got.IsDenied() {
		t.Error("IsDenied() should be true")
	}
	if got.IsAllowed() {
		t.Error("IsAllowed() should be false for deny")
	}
}

func TestAuditMode_DenyBecomesAuditDeny(t *testing.T) {
	p := makePolicy("audit", "deny",
		rule("deny-shell", "mcp", "tool_call", "shell_exec", "deny"),
	)
	got := Evaluate(intent("mcp", "tool_call", "shell_exec"), p, noState)
	assertDecision(t, got, "audit_deny")
	if !got.IsAllowed() {
		t.Error("audit_deny IsAllowed() should be true (action proceeds)")
	}
	if got.IsDenied() {
		t.Error("audit_deny IsDenied() should be false")
	}
}

func TestAuditMode_AllowStaysAllow(t *testing.T) {
	p := makePolicy("audit", "deny",
		rule("allow-web", "mcp", "tool_call", "web_search", "allow"),
	)
	got := Evaluate(intent("mcp", "tool_call", "web_search"), p, noState)
	assertDecision(t, got, "allow")
}

func TestAuditMode_DefaultDenyBecomesAuditDeny(t *testing.T) {
	p := makePolicy("audit", "deny") // empty rules
	got := Evaluate(intent("mcp", "tool_call", "anything"), p, noState)
	assertDecision(t, got, "audit_deny")
	assertRuleID(t, got, "default")
}

func TestPermissiveMode_DenyBecomesWouldDeny(t *testing.T) {
	p := makePolicy("permissive", "deny",
		rule("deny-shell", "mcp", "tool_call", "shell_exec", "deny"),
	)
	got := Evaluate(intent("mcp", "tool_call", "shell_exec"), p, noState)
	assertDecision(t, got, "would_deny")
	if !got.IsAllowed() {
		t.Error("would_deny IsAllowed() should be true")
	}
}

func TestPermissiveMode_AllowStaysAllow(t *testing.T) {
	p := makePolicy("permissive", "deny",
		rule("allow-web", "mcp", "tool_call", "web_search", "allow"),
	)
	got := Evaluate(intent("mcp", "tool_call", "web_search"), p, noState)
	assertDecision(t, got, "allow")
}

func TestPermissiveMode_DefaultDenyBecomesWouldDeny(t *testing.T) {
	p := makePolicy("permissive", "deny") // empty rules
	got := Evaluate(intent("mcp", "tool_call", "unrecognized_tool"), p, noState)
	assertDecision(t, got, "would_deny")
	assertRuleID(t, got, "default")
}

// ---------------------------------------------------------------------------
// Category 8: Engine struct wrapper
// ---------------------------------------------------------------------------

func TestEngine_EvaluateDelegates(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-web", "mcp", "tool_call", "web_search", "allow"),
	)
	eng := NewEngine(p)
	got := eng.Evaluate(intent("mcp", "tool_call", "web_search"), noState)
	assertDecision(t, got, "allow")
}

// ---------------------------------------------------------------------------
// Category 9: Full OpenClaw-style policy integration
// ---------------------------------------------------------------------------

func TestOpenClawPolicy_CompleteRuleSet(t *testing.T) {
	p := &Policy{
		Version: "1",
		Agent:   AgentIdentity{Name: "openclaw-home"},
		Mode:    "enforce",
		Default: "deny",
		Rules: []Rule{
			{ID: "allow-calendar", Protocol: "mcp", Method: "tool_call", Target: "calendar_*", Action: "allow"},
			{ID: "allow-search", Protocol: "mcp", Method: "tool_call", Target: "{web_search,web_fetch,web_browse}", Action: "allow"},
			{ID: "allow-fs-read", Protocol: "mcp", Method: "tool_call", Target: "read_file", Action: "allow"},
			{ID: "deny-fs-write", Protocol: "mcp", Method: "tool_call", Target: "{write_file,create_directory,move_file,delete_*}", Action: "deny"},
			{ID: "deny-shell", Protocol: "mcp", Method: "tool_call", Target: "{shell,execute_command,run_script}", Action: "deny"},
			{ID: "allow-msg-work", Protocol: "mcp", Method: "tool_call", Target: "agent_message", Action: "allow"},
			{ID: "deny-browser", Protocol: "mcp", Method: "tool_call", Target: "{browser_*,navigate,click,type_text}", Action: "deny"},
		},
	}

	cases := []struct {
		target   string
		wantDec  string
		wantRule string
	}{
		{"calendar_read", "allow", "allow-calendar"},
		{"calendar_write", "allow", "allow-calendar"},
		{"web_search", "allow", "allow-search"},
		{"web_fetch", "allow", "allow-search"},
		{"read_file", "allow", "allow-fs-read"},
		{"write_file", "deny", "deny-fs-write"},
		{"create_directory", "deny", "deny-fs-write"},
		{"delete_file", "deny", "deny-fs-write"},
		{"shell", "deny", "deny-shell"},
		{"execute_command", "deny", "deny-shell"},
		{"agent_message", "allow", "allow-msg-work"},
		{"browser_open", "deny", "deny-browser"},
		{"navigate", "deny", "deny-browser"},
		{"unknown_tool", "deny", "default"},
	}

	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			got := Evaluate(intent("mcp", "tool_call", tc.target), p, noState)
			if got.Decision != tc.wantDec {
				t.Errorf("Decision=%q want %q (RuleID=%q)", got.Decision, tc.wantDec, got.RuleID)
			}
			if got.RuleID != tc.wantRule {
				t.Errorf("RuleID=%q want %q", got.RuleID, tc.wantRule)
			}
		})
	}
}

func TestAuthDecision_IsAllowed_AllVariants(t *testing.T) {
	cases := []struct {
		decision  string
		isAllowed bool
		isDenied  bool
	}{
		{"allow", true, false},
		{"deny", false, true},
		{"audit_deny", true, false},
		{"would_deny", true, false},
	}
	for _, tc := range cases {
		d := AuthDecision{Decision: tc.decision}
		if got := d.IsAllowed(); got != tc.isAllowed {
			t.Errorf("[%s] IsAllowed()=%v want %v", tc.decision, got, tc.isAllowed)
		}
		if got := d.IsDenied(); got != tc.isDenied {
			t.Errorf("[%s] IsDenied()=%v want %v", tc.decision, got, tc.isDenied)
		}
	}
}

func TestReason_IsPopulated(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-web", "mcp", "tool_call", "web_search", "allow"),
	)
	got := Evaluate(intent("mcp", "tool_call", "web_search"), p, noState)
	if got.Reason == "" {
		t.Error("Reason should be non-empty")
	}
}

func TestReason_ConstraintIncludesNumbers(t *testing.T) {
	p := makePolicy("enforce", "allow")
	p.Constraints.MaxActions = 100
	got := Evaluate(intent("mcp", "tool_call", "anything"), p, RunState{ActionCount: 100})
	if got.Reason == "" {
		t.Error("constraint denial Reason should explain the limit")
	}
}

// ---------------------------------------------------------------------------
// Category 10: Behavioral contracts — parameter-level rules
// ---------------------------------------------------------------------------

func TestParams_NoParamsField_BackwardCompat(t *testing.T) {
	p := makePolicy("enforce", "deny",
		rule("allow-web", "mcp", "tool_call", "web_search", "allow"),
	)
	got := Evaluate(intent("mcp", "tool_call", "web_search"), p, noState)
	assertDecision(t, got, "allow")
	assertRuleID(t, got, "allow-web")
}

func TestParams_NilParamsMap_MatchesAnyIntent(t *testing.T) {
	r := Rule{ID: "r1", Protocol: "mcp", Method: "tool_call", Target: "web_search", Action: "allow"}
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "web_search", json.RawMessage(`{"q":"hello"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
}

func TestParams_EmptyParamsMap_MatchesAnyIntent(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "web_search", "allow", map[string]string{})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "web_search", json.RawMessage(`{"q":"hello"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
}

func TestParams_EmptyParamsMap_MatchesIntentWithNoParams(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "web_search", "allow", map[string]string{})
	p := makePolicy("enforce", "deny", r)
	got := Evaluate(intent("mcp", "tool_call", "web_search"), p, noState)
	assertDecision(t, got, "allow")
}

func TestParams_ExactMatch_SingleParam(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "web_search", "allow",
		map[string]string{"engine": "google"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "web_search", json.RawMessage(`{"engine":"google"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
	assertRuleID(t, got, "r1")
}

func TestParams_ExactMatch_Mismatch(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "web_search", "allow",
		map[string]string{"engine": "google"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "web_search", json.RawMessage(`{"engine":"bing"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "deny")
	assertRuleID(t, got, "default")
}

func TestParams_GlobPattern_Star(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "read_file", "allow",
		map[string]string{"path": "/home/user/*"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "read_file", json.RawMessage(`{"path":"/home/user/notes.txt"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
}

func TestParams_GlobPattern_Star_NoMatchSubdir(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "read_file", "allow",
		map[string]string{"path": "/home/user/*"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "read_file", json.RawMessage(`{"path":"/home/user/docs/secret.txt"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "deny")
}

func TestParams_GlobPattern_DoubleStar(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "read_file", "allow",
		map[string]string{"path": "/home/user/**"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "read_file", json.RawMessage(`{"path":"/home/user/docs/secret.txt"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
}

func TestParams_GlobPattern_Alternatives(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "web_search", "allow",
		map[string]string{"engine": "{google,duckduckgo}"})
	p := makePolicy("enforce", "deny", r)

	for _, eng := range []string{"google", "duckduckgo"} {
		ai := intentWithParams("mcp", "tool_call", "web_search",
			json.RawMessage(`{"engine":"`+eng+`"}`))
		got := Evaluate(ai, p, noState)
		if got.Decision != "allow" {
			t.Errorf("engine=%q: Decision=%q, want allow", eng, got.Decision)
		}
	}
	ai := intentWithParams("mcp", "tool_call", "web_search", json.RawMessage(`{"engine":"bing"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "deny")
}

func TestParams_GlobPattern_QuestionMark(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "read_file", "allow",
		map[string]string{"ext": "*.tx?"})
	p := makePolicy("enforce", "deny", r)
	for _, ext := range []string{"*.txt", "*.txs"} {
		ai := intentWithParams("mcp", "tool_call", "read_file",
			json.RawMessage(`{"ext":"`+ext+`"}`))
		got := Evaluate(ai, p, noState)
		if got.Decision != "allow" {
			t.Errorf("ext=%q: Decision=%q, want allow", ext, got.Decision)
		}
	}
}

func TestParams_MultipleParams_AllMatch(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "write_file", "allow",
		map[string]string{"path": "/tmp/*", "mode": "append"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "write_file",
		json.RawMessage(`{"path":"/tmp/log.txt","mode":"append"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
}

func TestParams_MultipleParams_OneDoesNotMatch(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "write_file", "allow",
		map[string]string{"path": "/tmp/*", "mode": "append"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "write_file",
		json.RawMessage(`{"path":"/tmp/log.txt","mode":"overwrite"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "deny")
}

func TestParams_MultipleParams_OneMissing(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "write_file", "allow",
		map[string]string{"path": "/tmp/*", "mode": "append"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "write_file",
		json.RawMessage(`{"path":"/tmp/log.txt"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "deny")
}

func TestParams_KeyNotPresentInIntent(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "web_search", "allow",
		map[string]string{"engine": "google"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "web_search",
		json.RawMessage(`{"query":"test"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "deny")
}

func TestParams_IntentNoParams_RuleHasParams(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "web_search", "allow",
		map[string]string{"engine": "google"})
	p := makePolicy("enforce", "deny", r)
	got := Evaluate(intent("mcp", "tool_call", "web_search"), p, noState)
	assertDecision(t, got, "deny")
	assertRuleID(t, got, "default")
}

func TestParams_IntentEmptyJSON_RuleHasParams(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "web_search", "allow",
		map[string]string{"engine": "google"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "web_search", json.RawMessage(`{}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "deny")
}

func TestParams_IntentNullJSON_RuleHasParams(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "web_search", "allow",
		map[string]string{"engine": "google"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "web_search", json.RawMessage(`null`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "deny")
}

func TestParams_IntentInvalidJSON_RuleHasParams(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "web_search", "allow",
		map[string]string{"engine": "google"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "web_search", json.RawMessage(`not-json`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "deny")
}

func TestParams_NumericValue_MatchesStringRepresentation(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "set_limit", "allow",
		map[string]string{"count": "42"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "set_limit",
		json.RawMessage(`{"count":42}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
}

func TestParams_BoolValue_MatchesStringRepresentation(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "toggle", "allow",
		map[string]string{"enabled": "true"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "toggle",
		json.RawMessage(`{"enabled":true}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
}

func TestParams_BoolFalse_MatchesStringRepresentation(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "toggle", "allow",
		map[string]string{"enabled": "false"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "toggle",
		json.RawMessage(`{"enabled":false}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
}

func TestParams_NestedObject_MatchesMapStringRepresentation(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "update", "allow",
		map[string]string{"opts": "map*"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "update",
		json.RawMessage(`{"opts":{"key":"value"}}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
}

func TestParams_ArrayValue_MatchesStringRepresentation(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "batch", "allow",
		map[string]string{"ids": "*1 2 3*"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "batch",
		json.RawMessage(`{"ids":[1,2,3]}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
}

func TestParams_FallsThroughToNextRule(t *testing.T) {
	r1 := ruleWithParams("deny-unsafe-path", "mcp", "tool_call", "read_file", "deny",
		map[string]string{"path": "/etc/**"})
	r2 := rule("allow-read", "mcp", "tool_call", "read_file", "allow")
	p := makePolicy("enforce", "deny", r1, r2)

	// /etc path hits the deny rule
	ai1 := intentWithParams("mcp", "tool_call", "read_file",
		json.RawMessage(`{"path":"/etc/passwd"}`))
	got := Evaluate(ai1, p, noState)
	assertDecision(t, got, "deny")
	assertRuleID(t, got, "deny-unsafe-path")

	// /home path does not match deny params → falls through to allow
	ai2 := intentWithParams("mcp", "tool_call", "read_file",
		json.RawMessage(`{"path":"/home/user/notes.txt"}`))
	got = Evaluate(ai2, p, noState)
	assertDecision(t, got, "allow")
	assertRuleID(t, got, "allow-read")
}

func TestParams_FallsThroughToDefault(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "web_search", "allow",
		map[string]string{"engine": "google"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "web_search",
		json.RawMessage(`{"engine":"bing"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "deny")
	assertRuleID(t, got, "default")
}

func TestParams_RuleWithoutParams_MatchesIntentWithParams(t *testing.T) {
	r := rule("allow-web", "mcp", "tool_call", "web_search", "allow")
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "web_search",
		json.RawMessage(`{"engine":"google","query":"hello"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
	assertRuleID(t, got, "allow-web")
}

func TestParams_WildcardParamValue(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "web_search", "allow",
		map[string]string{"engine": "*"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "web_search",
		json.RawMessage(`{"engine":"anything"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
}

func TestParams_WildcardParamValue_StillRequiresKey(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "web_search", "allow",
		map[string]string{"engine": "*"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "web_search",
		json.RawMessage(`{"query":"hello"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "deny")
}

func TestParams_IntentHasExtraParams_StillMatches(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "write_file", "allow",
		map[string]string{"path": "/tmp/*"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "write_file",
		json.RawMessage(`{"path":"/tmp/x.txt","content":"hello","mode":"overwrite"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
}

func TestParams_DenyWithParams_ThenAllowCatchAll(t *testing.T) {
	rules := []Rule{
		ruleWithParams("deny-etc", "mcp", "tool_call", "read_file", "deny",
			map[string]string{"path": "/etc/**"}),
		ruleWithParams("deny-var", "mcp", "tool_call", "read_file", "deny",
			map[string]string{"path": "/var/**"}),
		rule("allow-read", "mcp", "tool_call", "read_file", "allow"),
	}
	p := makePolicy("enforce", "deny", rules...)

	cases := []struct {
		path     string
		wantDec  string
		wantRule string
	}{
		{"/etc/shadow", "deny", "deny-etc"},
		{"/var/log/syslog", "deny", "deny-var"},
		{"/home/user/file.txt", "allow", "allow-read"},
	}
	for _, tc := range cases {
		ai := intentWithParams("mcp", "tool_call", "read_file",
			json.RawMessage(`{"path":"`+tc.path+`"}`))
		got := Evaluate(ai, p, noState)
		if got.Decision != tc.wantDec {
			t.Errorf("path=%q: Decision=%q, want %q", tc.path, got.Decision, tc.wantDec)
		}
		if got.RuleID != tc.wantRule {
			t.Errorf("path=%q: RuleID=%q, want %q", tc.path, got.RuleID, tc.wantRule)
		}
	}
}

func TestParams_AuditMode_ParamDeny(t *testing.T) {
	r := ruleWithParams("deny-unsafe", "mcp", "tool_call", "read_file", "deny",
		map[string]string{"path": "/etc/**"})
	p := makePolicy("audit", "allow", r)
	ai := intentWithParams("mcp", "tool_call", "read_file",
		json.RawMessage(`{"path":"/etc/passwd"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "audit_deny")
}

func TestParams_PermissiveMode_ParamDeny(t *testing.T) {
	r := ruleWithParams("deny-unsafe", "mcp", "tool_call", "read_file", "deny",
		map[string]string{"path": "/etc/**"})
	p := makePolicy("permissive", "allow", r)
	ai := intentWithParams("mcp", "tool_call", "read_file",
		json.RawMessage(`{"path":"/etc/passwd"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "would_deny")
}

func TestParams_ConstraintStillFiresBeforeParamRules(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "web_search", "allow",
		map[string]string{"engine": "google"})
	p := makePolicy("enforce", "deny", r)
	p.Constraints.MaxActions = 5
	ai := intentWithParams("mcp", "tool_call", "web_search",
		json.RawMessage(`{"engine":"google"}`))
	got := Evaluate(ai, p, RunState{ActionCount: 5})
	assertDecision(t, got, "deny")
	assertRuleID(t, got, "constraint:max_actions")
}

func TestParams_PrefixGlob_URL(t *testing.T) {
	r := ruleWithParams("r1", "http", "POST", "api.example.com/v1/chat", "allow",
		map[string]string{"model": "gpt-*"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("http", "POST", "api.example.com/v1/chat",
		json.RawMessage(`{"model":"gpt-4o"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")

	ai2 := intentWithParams("http", "POST", "api.example.com/v1/chat",
		json.RawMessage(`{"model":"claude-3"}`))
	got2 := Evaluate(ai2, p, noState)
	assertDecision(t, got2, "deny")
}

func TestParams_EmptyStringValue(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "web_search", "allow",
		map[string]string{"query": ""})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "web_search",
		json.RawMessage(`{"query":""}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
}

func TestParams_EmptyStringPattern_NoMatchNonEmpty(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "web_search", "allow",
		map[string]string{"query": ""})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "web_search",
		json.RawMessage(`{"query":"hello"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "deny")
}

func TestParams_FloatValue_MatchesStringRepresentation(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "set_temp", "allow",
		map[string]string{"temperature": "0.7"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "set_temp",
		json.RawMessage(`{"temperature":0.7}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
}

func TestParams_NullJSONValue_MatchesStringNil(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "tool", "allow",
		map[string]string{"opt": "<nil>"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "tool",
		json.RawMessage(`{"opt":null}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
}

func TestParams_ThreeParams_AllMatch(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "deploy", "allow",
		map[string]string{"env": "staging", "region": "us-*", "dry_run": "true"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "deploy",
		json.RawMessage(`{"env":"staging","region":"us-east-1","dry_run":true}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
}

func TestParams_ThreeParams_ThirdFails(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "deploy", "allow",
		map[string]string{"env": "staging", "region": "us-*", "dry_run": "true"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "deploy",
		json.RawMessage(`{"env":"staging","region":"us-east-1","dry_run":false}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "deny")
}

func TestParams_JSONArray_TopLevel(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "tool", "allow",
		map[string]string{"key": "val"})
	p := makePolicy("enforce", "deny", r)
	ai := intentWithParams("mcp", "tool_call", "tool",
		json.RawMessage(`[1,2,3]`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "deny")
}

func TestParams_EngineWrapper_WithParams(t *testing.T) {
	r := ruleWithParams("r1", "mcp", "tool_call", "web_search", "allow",
		map[string]string{"engine": "google"})
	p := makePolicy("enforce", "deny", r)
	eng := NewEngine(p)
	ai := intentWithParams("mcp", "tool_call", "web_search",
		json.RawMessage(`{"engine":"google"}`))
	got := eng.Evaluate(ai, noState)
	assertDecision(t, got, "allow")
	assertRuleID(t, got, "r1")
}

func TestParams_MultipleRules_FirstWithParamsMisses_SecondWithoutParamsHits(t *testing.T) {
	r1 := ruleWithParams("specific", "mcp", "tool_call", "web_search", "deny",
		map[string]string{"engine": "dangerous"})
	r2 := rule("general", "mcp", "tool_call", "web_search", "allow")
	p := makePolicy("enforce", "deny", r1, r2)

	ai := intentWithParams("mcp", "tool_call", "web_search",
		json.RawMessage(`{"engine":"google"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
	assertRuleID(t, got, "general")
}

func TestParams_MultipleRules_FirstWithParamsHits(t *testing.T) {
	r1 := ruleWithParams("specific", "mcp", "tool_call", "web_search", "deny",
		map[string]string{"engine": "dangerous"})
	r2 := rule("general", "mcp", "tool_call", "web_search", "allow")
	p := makePolicy("enforce", "deny", r1, r2)

	ai := intentWithParams("mcp", "tool_call", "web_search",
		json.RawMessage(`{"engine":"dangerous"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "deny")
	assertRuleID(t, got, "specific")
}

func TestParams_YAML_RoundTrip(t *testing.T) {
	yaml := `
version: "1"
agent:
  name: test
mode: enforce
default: deny
rules:
  - id: allow-safe-read
    protocol: mcp
    method: tool_call
    target: read_file
    action: allow
    params:
      path: "/home/**"
  - id: deny-all-read
    protocol: mcp
    method: tool_call
    target: read_file
    action: deny
`
	p, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(p.Rules))
	}
	if p.Rules[0].Params["path"] != "/home/**" {
		t.Errorf("Params[path]=%q, want /home/**", p.Rules[0].Params["path"])
	}
	if len(p.Rules[1].Params) != 0 {
		t.Errorf("second rule should have no params, got %v", p.Rules[1].Params)
	}

	ai := intentWithParams("mcp", "tool_call", "read_file",
		json.RawMessage(`{"path":"/home/user/notes.txt"}`))
	got := Evaluate(ai, p, noState)
	assertDecision(t, got, "allow")
	assertRuleID(t, got, "allow-safe-read")

	ai2 := intentWithParams("mcp", "tool_call", "read_file",
		json.RawMessage(`{"path":"/etc/passwd"}`))
	got2 := Evaluate(ai2, p, noState)
	assertDecision(t, got2, "deny")
	assertRuleID(t, got2, "deny-all-read")
}
