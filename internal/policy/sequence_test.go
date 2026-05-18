package policy

import (
	"testing"
)

func seqCfg(window int, rules ...SequenceRule) SequenceConfig {
	return SequenceConfig{Rules: rules, Window: window}
}

func seqRule(id string, pattern []string, action string) SequenceRule {
	return SequenceRule{ID: id, Pattern: pattern, Reason: "test: " + id, Action: action}
}

// ---------------------------------------------------------------------------
// Basic detection
// ---------------------------------------------------------------------------

func TestSequence_Simple2Step_Detected(t *testing.T) {
	cfg := seqCfg(10, seqRule("exfil", []string{"web_fetch", "send_email"}, "deny"))
	d := NewSequenceDetector(cfg)

	if m := d.Record("web_fetch"); m != nil {
		t.Fatalf("unexpected match after first tool: %+v", m)
	}
	m := d.Record("send_email")
	if m == nil {
		t.Fatal("expected match after send_email")
	}
	if m.RuleID != "exfil" {
		t.Errorf("RuleID = %q, want exfil", m.RuleID)
	}
	if m.Action != "deny" {
		t.Errorf("Action = %q, want deny", m.Action)
	}
	if len(m.Chain) != 2 || m.Chain[0] != "web_fetch" || m.Chain[1] != "send_email" {
		t.Errorf("Chain = %v, want [web_fetch send_email]", m.Chain)
	}
}

func TestSequence_3Step_WithAlternatives(t *testing.T) {
	cfg := seqCfg(10, seqRule("exfil-3",
		[]string{"web_fetch", "read_file|list_directory", "send_email|send_message"}, "deny"))
	d := NewSequenceDetector(cfg)

	d.Record("web_fetch")
	d.Record("list_directory") // matches "read_file|list_directory"
	m := d.Record("send_message") // matches "send_email|send_message"
	if m == nil {
		t.Fatal("expected match for 3-step pattern with alternatives")
	}
	if m.RuleID != "exfil-3" {
		t.Errorf("RuleID = %q", m.RuleID)
	}
	if len(m.Chain) != 3 {
		t.Errorf("Chain len = %d, want 3", len(m.Chain))
	}
	if m.Chain[1] != "list_directory" {
		t.Errorf("Chain[1] = %q, want list_directory", m.Chain[1])
	}
	if m.Chain[2] != "send_message" {
		t.Errorf("Chain[2] = %q, want send_message", m.Chain[2])
	}
}

func TestSequence_WrongOrder_NoMatch(t *testing.T) {
	cfg := seqCfg(10, seqRule("exfil", []string{"web_fetch", "send_email"}, "deny"))
	d := NewSequenceDetector(cfg)

	d.Record("send_email")
	m := d.Record("web_fetch")
	if m != nil {
		t.Errorf("expected no match when tools in wrong order, got %+v", m)
	}
}

func TestSequence_MissingStep_NoMatch(t *testing.T) {
	cfg := seqCfg(10, seqRule("exfil-3",
		[]string{"web_fetch", "read_file", "send_email"}, "deny"))
	d := NewSequenceDetector(cfg)

	d.Record("web_fetch")
	m := d.Record("send_email") // skipped read_file
	if m != nil {
		t.Errorf("expected no match when middle step missing, got %+v", m)
	}
}

// ---------------------------------------------------------------------------
// Window size
// ---------------------------------------------------------------------------

func TestSequence_Window_OldToolsExpired(t *testing.T) {
	cfg := seqCfg(3, seqRule("exfil", []string{"web_fetch", "send_email"}, "deny"))
	d := NewSequenceDetector(cfg)

	d.Record("web_fetch")
	d.Record("noop_1")
	d.Record("noop_2")
	// Window is 3, so web_fetch is now the oldest. One more push evicts it.
	d.Record("noop_3")
	m := d.Record("send_email")
	if m != nil {
		t.Errorf("expected no match after web_fetch evicted from window, got %+v", m)
	}
}

func TestSequence_Window_StillInWindow(t *testing.T) {
	cfg := seqCfg(4, seqRule("exfil", []string{"web_fetch", "send_email"}, "deny"))
	d := NewSequenceDetector(cfg)

	d.Record("web_fetch")
	d.Record("noop_1")
	d.Record("noop_2")
	m := d.Record("send_email") // window=[web_fetch, noop_1, noop_2, send_email]
	if m == nil {
		t.Fatal("expected match — web_fetch still in window")
	}
}

// ---------------------------------------------------------------------------
// Non-consecutive (subsequence) matching
// ---------------------------------------------------------------------------

func TestSequence_NonConsecutive_Match(t *testing.T) {
	cfg := seqCfg(10, seqRule("exfil",
		[]string{"web_fetch", "read_file", "send_email"}, "deny"))
	d := NewSequenceDetector(cfg)

	d.Record("web_fetch")
	d.Record("other_tool")
	d.Record("read_file")
	d.Record("another_tool")
	m := d.Record("send_email")
	if m == nil {
		t.Fatal("expected subsequence match with intervening tools")
	}
	if len(m.Chain) != 3 {
		t.Errorf("Chain len = %d, want 3", len(m.Chain))
	}
}

// ---------------------------------------------------------------------------
// Glob matching in patterns
// ---------------------------------------------------------------------------

func TestSequence_GlobStar_InPattern(t *testing.T) {
	cfg := seqCfg(10, seqRule("exfil",
		[]string{"web_*", "send_*"}, "deny"))
	d := NewSequenceDetector(cfg)

	d.Record("web_fetch")
	m := d.Record("send_message")
	if m == nil {
		t.Fatal("expected glob match for web_* and send_*")
	}
	if m.Chain[0] != "web_fetch" || m.Chain[1] != "send_message" {
		t.Errorf("Chain = %v", m.Chain)
	}
}

// ---------------------------------------------------------------------------
// Multiple rules — first match wins
// ---------------------------------------------------------------------------

func TestSequence_MultipleRules_FirstMatchWins(t *testing.T) {
	cfg := seqCfg(10,
		seqRule("narrow", []string{"web_fetch", "send_email"}, "deny"),
		seqRule("broad", []string{"web_*", "send_*"}, "audit"),
	)
	d := NewSequenceDetector(cfg)

	d.Record("web_fetch")
	m := d.Record("send_email")
	if m == nil {
		t.Fatal("expected match")
	}
	if m.RuleID != "narrow" {
		t.Errorf("RuleID = %q, want narrow (first match wins)", m.RuleID)
	}
}

func TestSequence_MultipleRules_SecondRuleMatches(t *testing.T) {
	cfg := seqCfg(10,
		seqRule("narrow", []string{"web_fetch", "send_email"}, "deny"),
		seqRule("broad", []string{"web_*", "send_*"}, "audit"),
	)
	d := NewSequenceDetector(cfg)

	d.Record("web_browse")
	m := d.Record("send_message")
	if m == nil {
		t.Fatal("expected match from broad rule")
	}
	if m.RuleID != "broad" {
		t.Errorf("RuleID = %q, want broad", m.RuleID)
	}
	if m.Action != "audit" {
		t.Errorf("Action = %q, want audit", m.Action)
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestSequence_EmptyHistory_NoMatch(t *testing.T) {
	cfg := seqCfg(10, seqRule("exfil", []string{"web_fetch", "send_email"}, "deny"))
	d := NewSequenceDetector(cfg)
	// Record a single tool that doesn't complete the pattern.
	m := d.Record("unrelated_tool")
	if m != nil {
		t.Errorf("expected nil for non-matching single tool, got %+v", m)
	}
}

func TestSequence_NoRules_NeverMatches(t *testing.T) {
	cfg := seqCfg(10)
	d := NewSequenceDetector(cfg)
	d.Record("web_fetch")
	m := d.Record("send_email")
	if m != nil {
		t.Errorf("expected nil when no rules defined, got %+v", m)
	}
}

func TestSequence_NonMatchingTools_NoTrigger(t *testing.T) {
	cfg := seqCfg(10, seqRule("exfil", []string{"web_fetch", "send_email"}, "deny"))
	d := NewSequenceDetector(cfg)

	for _, tool := range []string{"read_file", "write_file", "list_directory", "search"} {
		if m := d.Record(tool); m != nil {
			t.Errorf("unexpected match for tool %q: %+v", tool, m)
		}
	}
}

func TestSequence_AuditAction(t *testing.T) {
	cfg := seqCfg(10, seqRule("recon", []string{"list_directory", "read_file"}, "audit"))
	d := NewSequenceDetector(cfg)

	d.Record("list_directory")
	m := d.Record("read_file")
	if m == nil {
		t.Fatal("expected match")
	}
	if m.Action != "audit" {
		t.Errorf("Action = %q, want audit", m.Action)
	}
}

func TestSequence_DefaultWindow(t *testing.T) {
	cfg := SequenceConfig{
		Rules:  []SequenceRule{seqRule("exfil", []string{"web_fetch", "send_email"}, "deny")},
		Window: 0, // should default to 10
	}
	d := NewSequenceDetector(cfg)
	if d.window != 10 {
		t.Errorf("window = %d, want 10 (default)", d.window)
	}
}

func TestSequence_ReasonPropagated(t *testing.T) {
	r := SequenceRule{
		ID:      "exfil",
		Pattern: []string{"web_fetch", "send_email"},
		Reason:  "possible data exfiltration",
		Action:  "deny",
	}
	cfg := seqCfg(10, r)
	d := NewSequenceDetector(cfg)

	d.Record("web_fetch")
	m := d.Record("send_email")
	if m == nil {
		t.Fatal("expected match")
	}
	if m.Reason != "possible data exfiltration" {
		t.Errorf("Reason = %q", m.Reason)
	}
}

func TestSequence_WindowSize2_Minimal(t *testing.T) {
	cfg := seqCfg(2, seqRule("exfil", []string{"web_fetch", "send_email"}, "deny"))
	d := NewSequenceDetector(cfg)

	d.Record("web_fetch")
	m := d.Record("send_email")
	if m == nil {
		t.Fatal("expected match with window=2 and 2-step pattern")
	}
}

func TestSequence_PatternLongerThanWindow_NeverMatches(t *testing.T) {
	cfg := seqCfg(2, seqRule("long",
		[]string{"step1", "step2", "step3"}, "deny"))
	d := NewSequenceDetector(cfg)

	d.Record("step1")
	d.Record("step2")
	m := d.Record("step3")
	if m != nil {
		t.Errorf("expected no match when pattern longer than window, got %+v", m)
	}
}

func TestSequence_RepeatedPattern_MatchesOnSecondOccurrence(t *testing.T) {
	cfg := seqCfg(10, seqRule("exfil", []string{"web_fetch", "send_email"}, "deny"))
	d := NewSequenceDetector(cfg)

	d.Record("web_fetch")
	m1 := d.Record("send_email")
	if m1 == nil {
		t.Fatal("expected first match")
	}

	// Pattern is already in history; adding a new send_email with web_fetch
	// still in window should match again.
	m2 := d.Record("send_email")
	if m2 == nil {
		t.Fatal("expected second match — web_fetch still in window")
	}
}
