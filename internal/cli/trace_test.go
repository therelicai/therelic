package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeTraceFile writes a .trtrace file in a temp .tr/traces directory and
// returns the directory path.
func makeTraceFile(t *testing.T, runID string, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	tracesDir := filepath.Join(dir, ".tr", "traces")
	if err := os.MkdirAll(tracesDir, 0o755); err != nil {
		t.Fatalf("makeTraceFile mkdir: %v", err)
	}
	content := strings.Join(lines, "\n") + "\n"
	path := filepath.Join(tracesDir, runID+".trtrace")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("makeTraceFile write: %v", err)
	}
	return dir
}

// runView executes `relic trace view <runID>` with extra flags, captures stdout,
// and returns it as a string.
func runView(t *testing.T, projectDir, runID string, extraFlags ...string) string {
	t.Helper()
	root := NewRootCmd("test")

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)

	tracesDir := filepath.Join(projectDir, ".tr", "traces")
	args := append([]string{"trace", "view", runID, "--dir", tracesDir}, extraFlags...)
	root.SetArgs(args)

	if err := root.Execute(); err != nil {
		t.Logf("runView output: %s", buf.String())
		t.Fatalf("command failed: %v", err)
	}
	return buf.String()
}

const (
	testRunStart    = `{"v":1,"t":"run","ts":"2026-02-17T14:00:00Z","run":"TEST01","agent":"test-agent","agent_v":"1.0.0","policy":"abc","env":"local","status":"start"}`
	testActionAllow = `{"v":1,"t":"action","ts":"2026-02-17T14:00:01Z","run":"TEST01","seq":1,"proto":"mcp","method":"tool_call","target":"web_search","auth":"allow","rule":"allow-web"}`
	testActionDeny  = `{"v":1,"t":"action","ts":"2026-02-17T14:00:02Z","run":"TEST01","seq":2,"proto":"mcp","method":"tool_call","target":"shell_exec","auth":"deny","rule":"default"}`
	testRunEnd      = `{"v":1,"t":"run","ts":"2026-02-17T14:00:03Z","run":"TEST01","status":"end","exit":0,"ms":3000,"actions_total":2,"actions_allowed":1,"actions_denied":1}`
)

func TestTraceView_FormattedOutput(t *testing.T) {
	dir := makeTraceFile(t, "TEST01",
		testRunStart, testActionAllow, testActionDeny, testRunEnd)

	out := runView(t, dir, "TEST01")

	// Run start line
	if !strings.Contains(out, "RUN START") {
		t.Error("output missing RUN START")
	}
	if !strings.Contains(out, "agent=test-agent") {
		t.Error("output missing agent name")
	}
	if !strings.Contains(out, "env=local") {
		t.Error("output missing env")
	}

	// Allow action
	if !strings.Contains(out, "ALLOW") {
		t.Error("output missing ALLOW label")
	}
	if !strings.Contains(out, "web_search") {
		t.Error("output missing web_search target")
	}

	// Deny action
	if !strings.Contains(out, "DENY") {
		t.Error("output missing DENY label")
	}
	if !strings.Contains(out, "shell_exec") {
		t.Error("output missing shell_exec target")
	}

	// Run end line
	if !strings.Contains(out, "RUN END") {
		t.Error("output missing RUN END")
	}
	if !strings.Contains(out, "actions=2") {
		t.Error("output missing actions count")
	}
	if !strings.Contains(out, "allowed=1") {
		t.Error("output missing allowed count")
	}
	if !strings.Contains(out, "denied=1") {
		t.Error("output missing denied count")
	}
}

func TestTraceView_DeniedFlag(t *testing.T) {
	dir := makeTraceFile(t, "TEST01",
		testRunStart, testActionAllow, testActionDeny, testRunEnd)

	out := runView(t, dir, "TEST01", "--denied")

	// Should include the deny action
	if !strings.Contains(out, "shell_exec") {
		t.Error("--denied output missing shell_exec")
	}

	// Should NOT include the allow action
	if strings.Contains(out, "web_search") {
		t.Error("--denied output should not include allowed action web_search")
	}

	// Run events are not filtered by --denied
	// (only action events are filtered)
}

func TestTraceView_JSONFlag(t *testing.T) {
	dir := makeTraceFile(t, "TEST01",
		testRunStart, testActionAllow, testActionDeny, testRunEnd)

	out := runView(t, dir, "TEST01", "--json")

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 {
		t.Errorf("--json output: expected 4 lines, got %d", len(lines))
	}

	// Each line should contain the raw JSON fields
	if !strings.Contains(lines[0], `"run":"TEST01"`) {
		t.Errorf("line[0] missing run field: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"target":"web_search"`) {
		t.Errorf("line[1] missing target: %s", lines[1])
	}
	if !strings.Contains(lines[2], `"target":"shell_exec"`) {
		t.Errorf("line[2] missing target: %s", lines[2])
	}
}

func TestTraceView_RunNotFound(t *testing.T) {
	dir := t.TempDir()
	tracesDir := filepath.Join(dir, ".tr", "traces")
	os.MkdirAll(tracesDir, 0o755)

	root := NewRootCmd("test")
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"trace", "view", "NOSUCHRUN", "--dir", tracesDir})

	err := root.Execute()
	if err == nil {
		t.Error("expected error for missing run, got nil")
	}
}

func TestTraceView_TimestampFormatting(t *testing.T) {
	dir := makeTraceFile(t, "TEST01", testRunStart, testActionAllow, testRunEnd)
	out := runView(t, dir, "TEST01")

	// Timestamp should be formatted as HH:MM:SS, not the raw ISO string
	if strings.Contains(out, "2026-02-17T") {
		t.Error("output contains raw ISO timestamp; expected HH:MM:SS format")
	}
	if !strings.Contains(out, "14:00:00") {
		t.Error("output missing expected time 14:00:00")
	}
}

func TestTraceView_AllowAndDenyPresent(t *testing.T) {
	dir := makeTraceFile(t, "TEST01",
		testRunStart, testActionAllow, testActionDeny, testRunEnd)

	out := runView(t, dir, "TEST01")

	allowIdx := strings.Index(out, "ALLOW")
	denyIdx := strings.Index(out, "DENY")

	if allowIdx < 0 {
		t.Error("ALLOW not found in output")
	}
	if denyIdx < 0 {
		t.Error("DENY not found in output")
	}
	// ALLOW should appear before DENY (seq 1 before seq 2)
	if allowIdx > denyIdx {
		t.Error("ALLOW appears after DENY; expected order seq=1 (allow) then seq=2 (deny)")
	}
}

func TestTraceView_AuditDenyLabel(t *testing.T) {
	auditDeny := `{"v":1,"t":"action","ts":"2026-02-17T14:00:01Z","run":"AUDIT01","seq":1,"proto":"mcp","method":"tool_call","target":"dangerous_tool","auth":"audit_deny","rule":"deny-danger"}`
	dir := makeTraceFile(t, "AUDIT01", testRunStart, auditDeny, testRunEnd)

	// Re-make with the right run ID
	tracesDir := filepath.Join(dir, ".tr", "traces")
	auditStart := `{"v":1,"t":"run","ts":"2026-02-17T14:00:00Z","run":"AUDIT01","agent":"test","agent_v":"1.0.0","policy":"abc","env":"ci","status":"start"}`
	auditEnd := `{"v":1,"t":"run","ts":"2026-02-17T14:00:03Z","run":"AUDIT01","status":"end","exit":0,"ms":1000,"actions_total":1,"actions_allowed":0,"actions_denied":1}`
	content := strings.Join([]string{auditStart, auditDeny, auditEnd}, "\n") + "\n"
	os.WriteFile(filepath.Join(tracesDir, "AUDIT01.trtrace"), []byte(content), 0o644)

	root := NewRootCmd("test")
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"trace", "view", "AUDIT01", "--dir", tracesDir})
	root.Execute()

	out := buf.String()
	if !strings.Contains(out, "A_DENY") {
		t.Error("output missing A_DENY label for audit_deny action")
	}
}

func TestTraceView_RuleFieldShown(t *testing.T) {
	dir := makeTraceFile(t, "TEST01",
		testRunStart, testActionAllow, testActionDeny, testRunEnd)

	out := runView(t, dir, "TEST01")

	if !strings.Contains(out, "rule=allow-web") {
		t.Error("output missing rule=allow-web for allowed action")
	}
	if !strings.Contains(out, "rule=default") {
		t.Error("output missing rule=default for denied action")
	}
}
