package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/therelicai/therelic/internal/trace"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// runSearch executes `relic trace search` with given flags and returns stdout.
func runSearch(t *testing.T, projectDir string, extraFlags ...string) string {
	t.Helper()
	root := NewRootCmd("test")
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)

	tracesDir := filepath.Join(projectDir, ".tr", "traces")
	args := append([]string{"trace", "search", "--dir", tracesDir}, extraFlags...)
	root.SetArgs(args)

	if err := root.Execute(); err != nil {
		t.Logf("runSearch output: %s", buf.String())
		t.Fatalf("command failed: %v", err)
	}
	return buf.String()
}

// makeActionEvent constructs a minimal trace.TraceEvent for filter unit tests.
func makeActionEvent(proto, method, target, auth string) trace.TraceEvent {
	return trace.TraceEvent{
		T:      "action",
		Proto:  proto,
		Method: method,
		Target: target,
		Auth:   auth,
	}
}

// ---------------------------------------------------------------------------
// Basic search — no filters (all action events)
// ---------------------------------------------------------------------------

func TestTraceSearch_NoFilters_ReturnsAllActions(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runSearch(t, dir)

	// All action targets should appear.
	for _, target := range []string{"web_search", "web_fetch", "shell_exec", "api.example.com"} {
		if !strings.Contains(out, target) {
			t.Errorf("output missing target %q\n%s", target, out)
		}
	}
}

func TestTraceSearch_NoFilters_ShowsRunContext(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runSearch(t, dir)

	// Run separators should include run IDs.
	for _, id := range []string{runAID, runBID, runCID} {
		if !strings.Contains(out, id) {
			t.Errorf("output missing run ID %s in context", id)
		}
	}
}

// ---------------------------------------------------------------------------
// --auth filter
// ---------------------------------------------------------------------------

func TestTraceSearch_AuthDeny_OnlyDeniedActions(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runSearch(t, dir, "--auth", "deny")

	// shell_exec is the only denied action.
	if !strings.Contains(out, "shell_exec") {
		t.Error("output missing shell_exec (the denied action)")
	}
	// web_search and web_fetch are allowed.
	if strings.Contains(out, "web_search") {
		t.Error("output should not contain web_search (allowed)")
	}
	if strings.Contains(out, "web_fetch") {
		t.Error("output should not contain web_fetch (allowed)")
	}
}

func TestTraceSearch_AuthAllow_OnlyAllowedActions(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runSearch(t, dir, "--auth", "allow")

	if strings.Contains(out, "shell_exec") {
		t.Error("output should not contain shell_exec (denied)")
	}
	if !strings.Contains(out, "web_search") {
		t.Error("output missing web_search (allowed)")
	}
}

func TestTraceSearch_AuthDeny_CrossesRuns(t *testing.T) {
	// Add a second denial in a different run.
	dir := t.TempDir()
	tracesDir := filepath.Join(dir, ".tr", "traces")
	os.MkdirAll(tracesDir, 0o755)

	deny2 := `{"v":1,"t":"action","ts":"2026-02-17T10:00:01Z","run":"RUNA","seq":1,"proto":"mcp","method":"tool_call","target":"delete_file","auth":"deny","rule":"default"}`
	deny3 := `{"v":1,"t":"action","ts":"2026-02-17T11:00:01Z","run":"RUNB","seq":1,"proto":"mcp","method":"tool_call","target":"exec_shell","auth":"deny","rule":"default"}`

	writeFile := func(id, start, event, end string) {
		content := strings.Join([]string{start, event, end}, "\n") + "\n"
		os.WriteFile(filepath.Join(tracesDir, id+".trtrace"), []byte(content), 0o644)
	}
	startA := `{"v":1,"t":"run","ts":"2026-02-17T10:00:00Z","run":"RUNA","agent":"ag","status":"start"}`
	startB := `{"v":1,"t":"run","ts":"2026-02-17T11:00:00Z","run":"RUNB","agent":"ag","status":"start"}`
	endA := `{"v":1,"t":"run","ts":"2026-02-17T10:00:02Z","run":"RUNA","status":"end","ms":1,"actions_total":1,"actions_allowed":0,"actions_denied":1}`
	endB := `{"v":1,"t":"run","ts":"2026-02-17T11:00:02Z","run":"RUNB","status":"end","ms":1,"actions_total":1,"actions_allowed":0,"actions_denied":1}`
	writeFile("RUNA", startA, deny2, endA)
	writeFile("RUNB", startB, deny3, endB)

	out := runSearch(t, dir, "--auth", "deny")

	if !strings.Contains(out, "delete_file") {
		t.Error("output missing delete_file denial from RUNA")
	}
	if !strings.Contains(out, "exec_shell") {
		t.Error("output missing exec_shell denial from RUNB")
	}
}

// ---------------------------------------------------------------------------
// --target filter (glob)
// ---------------------------------------------------------------------------

func TestTraceSearch_TargetExact(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runSearch(t, dir, "--target", "web_search")

	if !strings.Contains(out, "web_search") {
		t.Error("output missing web_search")
	}
	if strings.Contains(out, "web_fetch") {
		t.Error("output should not contain web_fetch")
	}
}

func TestTraceSearch_TargetGlob_WildcardSuffix(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runSearch(t, dir, "--target", "web_*")

	if !strings.Contains(out, "web_search") {
		t.Error("web_* should match web_search")
	}
	if !strings.Contains(out, "web_fetch") {
		t.Error("web_* should match web_fetch")
	}
	if strings.Contains(out, "shell_exec") {
		t.Error("web_* should not match shell_exec")
	}
}

func TestTraceSearch_TargetGlob_URLPattern(t *testing.T) {
	dir := makeMultiTraceDir(t)
	// HTTP target is "http://api.example.com/v1"
	out := runSearch(t, dir, "--target", "http://**")

	if !strings.Contains(out, "api.example.com") {
		t.Error("http://** should match http://api.example.com/v1")
	}
}

func TestTraceSearch_TargetGlob_NoMatch(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runSearch(t, dir, "--target", "nonexistent_*")

	if strings.Contains(out, "web_search") || strings.Contains(out, "shell_exec") {
		t.Error("nonexistent_* should not match any target")
	}
	if !strings.Contains(out, "No matching events") {
		t.Error("expected 'No matching events' message")
	}
}

// ---------------------------------------------------------------------------
// --proto filter
// ---------------------------------------------------------------------------

func TestTraceSearch_Proto_MCP(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runSearch(t, dir, "--proto", "mcp")

	if !strings.Contains(out, "web_search") {
		t.Error("mcp filter should include web_search")
	}
	if strings.Contains(out, "api.example.com") {
		t.Error("mcp filter should not include HTTP action")
	}
}

func TestTraceSearch_Proto_HTTP(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runSearch(t, dir, "--proto", "http")

	if !strings.Contains(out, "api.example.com") {
		t.Error("http filter should include api.example.com action")
	}
	if strings.Contains(out, "web_search") {
		t.Error("http filter should not include web_search (mcp)")
	}
}

// ---------------------------------------------------------------------------
// Combined filters
// ---------------------------------------------------------------------------

func TestTraceSearch_ProtoAndAuth(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runSearch(t, dir, "--proto", "mcp", "--auth", "deny")

	if !strings.Contains(out, "shell_exec") {
		t.Error("mcp+deny should show shell_exec")
	}
	if strings.Contains(out, "web_search") || strings.Contains(out, "web_fetch") {
		t.Error("mcp+deny should not show allowed mcp actions")
	}
}

func TestTraceSearch_ProtoAndTarget(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runSearch(t, dir, "--proto", "mcp", "--target", "web_*")

	if !strings.Contains(out, "web_search") {
		t.Error("mcp+web_* should include web_search")
	}
	if !strings.Contains(out, "web_fetch") {
		t.Error("mcp+web_* should include web_fetch")
	}
	if strings.Contains(out, "shell_exec") {
		t.Error("mcp+web_* should not include shell_exec")
	}
}

// ---------------------------------------------------------------------------
// --limit flag
// ---------------------------------------------------------------------------

func TestTraceSearch_Limit(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runSearch(t, dir, "--limit", "2")

	targets := []string{"web_search", "web_fetch", "shell_exec", "api.example.com"}
	count := 0
	for _, tgt := range targets {
		if strings.Contains(out, tgt) {
			count++
		}
	}
	if count > 2 {
		t.Errorf("--limit 2 should show at most 2 distinct targets, found %d", count)
	}
}

// ---------------------------------------------------------------------------
// Empty directory
// ---------------------------------------------------------------------------

func TestTraceSearch_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	tracesDir := filepath.Join(dir, ".tr", "traces")
	os.MkdirAll(tracesDir, 0o755)

	out := runSearch(t, dir)
	if !strings.Contains(out, "No matching events") {
		t.Errorf("expected 'No matching events' for empty dir, got: %s", out)
	}
}

// ---------------------------------------------------------------------------
// searchTraces helper (unit tests)
// ---------------------------------------------------------------------------

func TestSearchTraces_ReturnsAllActions(t *testing.T) {
	dir := makeMultiTraceDir(t)
	tracesDir := filepath.Join(dir, ".tr", "traces")

	matches, err := searchTraces(tracesDir, "", "", "")
	if err != nil {
		t.Fatalf("searchTraces: %v", err)
	}
	// 4 action events total (web_search, web_fetch, shell_exec, GET api.example.com)
	if len(matches) != 4 {
		t.Errorf("expected 4 matches (all actions), got %d", len(matches))
	}
}

func TestSearchTraces_AuthFilter(t *testing.T) {
	dir := makeMultiTraceDir(t)
	tracesDir := filepath.Join(dir, ".tr", "traces")

	matches, err := searchTraces(tracesDir, "", "", "deny")
	if err != nil {
		t.Fatalf("searchTraces: %v", err)
	}
	if len(matches) != 1 {
		t.Errorf("expected 1 denied action, got %d", len(matches))
	}
	if matches[0].Event.Target != "shell_exec" {
		t.Errorf("denied target=%q want shell_exec", matches[0].Event.Target)
	}
}

func TestSearchTraces_GlobFilter(t *testing.T) {
	dir := makeMultiTraceDir(t)
	tracesDir := filepath.Join(dir, ".tr", "traces")

	matches, err := searchTraces(tracesDir, "web_*", "", "")
	if err != nil {
		t.Fatalf("searchTraces: %v", err)
	}
	if len(matches) != 2 {
		t.Errorf("expected 2 matches for web_*, got %d", len(matches))
	}
}

func TestSearchTraces_AgentInMatch(t *testing.T) {
	dir := makeMultiTraceDir(t)
	tracesDir := filepath.Join(dir, ".tr", "traces")

	matches, err := searchTraces(tracesDir, "", "mcp", "deny")
	if err != nil {
		t.Fatalf("searchTraces: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Agent != "agent-beta" {
		t.Errorf("Agent=%q want agent-beta", matches[0].Agent)
	}
	if matches[0].RunID != runBID {
		t.Errorf("RunID=%q want %s", matches[0].RunID, runBID)
	}
}

// ---------------------------------------------------------------------------
// matchesFilter unit tests
// ---------------------------------------------------------------------------

func TestMatchesFilter_EmptyFilters_AlwaysTrue(t *testing.T) {
	ev := makeActionEvent("mcp", "tool_call", "web_search", "allow")
	if !matchesFilter(ev, "", "", "") {
		t.Error("empty filters should match all events")
	}
}

func TestMatchesFilter_AuthMatch(t *testing.T) {
	ev := makeActionEvent("mcp", "tool_call", "web_search", "deny")
	if !matchesFilter(ev, "", "", "deny") {
		t.Error("auth=deny should match deny event")
	}
	if matchesFilter(ev, "", "", "allow") {
		t.Error("auth=allow should not match deny event")
	}
}

func TestMatchesFilter_ProtoMatch(t *testing.T) {
	ev := makeActionEvent("http", "GET", "http://example.com", "allow")
	if !matchesFilter(ev, "", "http", "") {
		t.Error("proto=http should match http event")
	}
	if matchesFilter(ev, "", "mcp", "") {
		t.Error("proto=mcp should not match http event")
	}
}

func TestMatchesFilter_GlobMatch(t *testing.T) {
	ev := makeActionEvent("mcp", "tool_call", "web_search", "allow")
	if !matchesFilter(ev, "web_*", "", "") {
		t.Error("web_* should match web_search")
	}
	if matchesFilter(ev, "shell_*", "", "") {
		t.Error("shell_* should not match web_search")
	}
}

func TestMatchesFilter_InvalidGlob_NoMatch(t *testing.T) {
	ev := makeActionEvent("mcp", "tool_call", "web_search", "allow")
	// An invalid glob pattern should not match.
	if matchesFilter(ev, "[invalid", "", "") {
		t.Error("invalid glob should not match")
	}
}

func TestMatchesFilter_AllFiltersAndCondition(t *testing.T) {
	ev := makeActionEvent("mcp", "tool_call", "web_search", "deny")
	// All three match → true
	if !matchesFilter(ev, "web_*", "mcp", "deny") {
		t.Error("all-matching filters should return true")
	}
	// One mismatch → false
	if matchesFilter(ev, "web_*", "http", "deny") {
		t.Error("proto mismatch should return false")
	}
	if matchesFilter(ev, "shell_*", "mcp", "deny") {
		t.Error("target mismatch should return false")
	}
}
