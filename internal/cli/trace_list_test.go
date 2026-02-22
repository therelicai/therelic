package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test data — three distinct runs
// ---------------------------------------------------------------------------

// run A: agent-alpha, no denials, ended normally
const (
	runAID    = "01AALPHA0000000000000000AA"
	runAStart = `{"v":1,"t":"run","ts":"2026-02-17T10:00:00Z","run":"01AALPHA0000000000000000AA","agent":"agent-alpha","agent_v":"1.0","policy":"","env":"local","status":"start"}`
	runAAllow = `{"v":1,"t":"action","ts":"2026-02-17T10:00:01Z","run":"01AALPHA0000000000000000AA","seq":1,"proto":"mcp","method":"tool_call","target":"web_search","auth":"allow","rule":"allow-web"}`
	runAEnd   = `{"v":1,"t":"run","ts":"2026-02-17T10:00:02Z","run":"01AALPHA0000000000000000AA","status":"end","exit":0,"ms":2000,"actions_total":1,"actions_allowed":1,"actions_denied":0}`
)

// run B: agent-beta, has a denial
const (
	runBID    = "01BBETA00000000000000000BB"
	runBStart = `{"v":1,"t":"run","ts":"2026-02-17T11:00:00Z","run":"01BBETA00000000000000000BB","agent":"agent-beta","agent_v":"2.0","policy":"","env":"staging","status":"start"}`
	runBAllow = `{"v":1,"t":"action","ts":"2026-02-17T11:00:01Z","run":"01BBETA00000000000000000BB","seq":1,"proto":"mcp","method":"tool_call","target":"web_fetch","auth":"allow","rule":"allow-fetch"}`
	runBDeny  = `{"v":1,"t":"action","ts":"2026-02-17T11:00:02Z","run":"01BBETA00000000000000000BB","seq":2,"proto":"mcp","method":"tool_call","target":"shell_exec","auth":"deny","rule":"default"}`
	runBEnd   = `{"v":1,"t":"run","ts":"2026-02-17T11:00:03Z","run":"01BBETA00000000000000000BB","status":"end","exit":0,"ms":3000,"actions_total":2,"actions_allowed":1,"actions_denied":1}`
)

// run C: agent-alpha (same agent as A but newer), HTTP action
const (
	runCID    = "01CGAMMA0000000000000000CC"
	runCStart = `{"v":1,"t":"run","ts":"2026-02-17T12:00:00Z","run":"01CGAMMA0000000000000000CC","agent":"agent-alpha","agent_v":"1.1","policy":"","env":"local","status":"start"}`
	runCHTTP  = `{"v":1,"t":"action","ts":"2026-02-17T12:00:01Z","run":"01CGAMMA0000000000000000CC","seq":1,"proto":"http","method":"GET","target":"http://api.example.com/v1","auth":"allow","rule":"allow-http"}`
	runCEnd   = `{"v":1,"t":"run","ts":"2026-02-17T12:00:02Z","run":"01CGAMMA0000000000000000CC","status":"end","exit":0,"ms":2000,"actions_total":1,"actions_allowed":1,"actions_denied":0}`
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeMultiTraceDir creates a temp directory with three .trtrace files.
func makeMultiTraceDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	tracesDir := filepath.Join(dir, ".tr", "traces")
	if err := os.MkdirAll(tracesDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	writeTrace := func(id string, lines ...string) {
		content := strings.Join(lines, "\n") + "\n"
		path := filepath.Join(tracesDir, id+".trtrace")
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write trace %s: %v", id, err)
		}
	}

	writeTrace(runAID, runAStart, runAAllow, runAEnd)
	writeTrace(runBID, runBStart, runBAllow, runBDeny, runBEnd)
	writeTrace(runCID, runCStart, runCHTTP, runCEnd)
	return dir
}

// runList executes `relic trace list` with given extra flags and returns stdout.
func runList(t *testing.T, projectDir string, extraFlags ...string) string {
	t.Helper()
	root := NewRootCmd("test")
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)

	tracesDir := filepath.Join(projectDir, ".tr", "traces")
	args := append([]string{"trace", "list", "--dir", tracesDir}, extraFlags...)
	root.SetArgs(args)

	if err := root.Execute(); err != nil {
		t.Logf("runList output: %s", buf.String())
		t.Fatalf("command failed: %v", err)
	}
	return buf.String()
}

// ---------------------------------------------------------------------------
// relic trace list — basic output
// ---------------------------------------------------------------------------

func TestTraceList_ShowsAllRuns(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runList(t, dir)

	// All three run IDs should appear.
	for _, id := range []string{runAID, runBID, runCID} {
		if !strings.Contains(out, id) {
			t.Errorf("output missing run ID %s\n%s", id, out)
		}
	}
}

func TestTraceList_ShowsAgentNames(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runList(t, dir)

	if !strings.Contains(out, "agent-alpha") {
		t.Error("output missing agent-alpha")
	}
	if !strings.Contains(out, "agent-beta") {
		t.Error("output missing agent-beta")
	}
}

func TestTraceList_ShowsActionCounts(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runList(t, dir)

	// Run B has 2 total, 1 allowed, 1 denied.
	if !strings.Contains(out, "1 denied") {
		t.Error("output missing denial count for run B")
	}
}

func TestTraceList_MostRecentFirst(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runList(t, dir)

	idxA := strings.Index(out, runAID)
	idxB := strings.Index(out, runBID)
	idxC := strings.Index(out, runCID)

	if idxA < 0 || idxB < 0 || idxC < 0 {
		t.Fatal("not all run IDs present in output")
	}
	// C (12:00) > B (11:00) > A (10:00) → C should appear first.
	if !(idxC < idxB && idxB < idxA) {
		t.Errorf("runs not sorted most-recent-first: idxA=%d idxB=%d idxC=%d", idxA, idxB, idxC)
	}
}

func TestTraceList_HasHeader(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runList(t, dir)

	if !strings.Contains(out, "RUN ID") {
		t.Error("output missing RUN ID header")
	}
	if !strings.Contains(out, "AGENT") {
		t.Error("output missing AGENT header")
	}
}

// ---------------------------------------------------------------------------
// relic trace list --agent filter
// ---------------------------------------------------------------------------

func TestTraceList_AgentFilter_MatchesSubstring(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runList(t, dir, "--agent", "alpha")

	// Only runs A and C have agent-alpha.
	if !strings.Contains(out, runAID) {
		t.Error("run A (agent-alpha) should appear with --agent alpha")
	}
	if !strings.Contains(out, runCID) {
		t.Error("run C (agent-alpha) should appear with --agent alpha")
	}
	if strings.Contains(out, runBID) {
		t.Error("run B (agent-beta) should NOT appear with --agent alpha")
	}
}

func TestTraceList_AgentFilter_CaseInsensitive(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runList(t, dir, "--agent", "BETA")

	if !strings.Contains(out, runBID) {
		t.Error("run B should appear with case-insensitive --agent BETA")
	}
}

func TestTraceList_AgentFilter_NoMatch(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runList(t, dir, "--agent", "nonexistent-agent")

	if strings.Contains(out, runAID) || strings.Contains(out, runBID) || strings.Contains(out, runCID) {
		t.Error("no runs should appear for nonexistent agent")
	}
	if !strings.Contains(out, "No runs found") {
		t.Error("expected 'No runs found' message")
	}
}

// ---------------------------------------------------------------------------
// relic trace list --has-denials filter
// ---------------------------------------------------------------------------

func TestTraceList_HasDenials_OnlyDeniedRuns(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runList(t, dir, "--has-denials")

	// Only run B has a denial.
	if !strings.Contains(out, runBID) {
		t.Error("run B should appear with --has-denials")
	}
	if strings.Contains(out, runAID) {
		t.Error("run A (no denials) should NOT appear with --has-denials")
	}
	if strings.Contains(out, runCID) {
		t.Error("run C (no denials) should NOT appear with --has-denials")
	}
}

func TestTraceList_HasDenials_NoMatch(t *testing.T) {
	// Create a directory with only no-denial runs.
	dir := t.TempDir()
	tracesDir := filepath.Join(dir, ".tr", "traces")
	os.MkdirAll(tracesDir, 0o755)

	content := strings.Join([]string{runAStart, runAAllow, runAEnd}, "\n") + "\n"
	os.WriteFile(filepath.Join(tracesDir, runAID+".trtrace"), []byte(content), 0o644)

	out := runList(t, dir, "--has-denials")
	if !strings.Contains(out, "No runs found") {
		t.Error("expected 'No runs found' when no runs have denials")
	}
}

// ---------------------------------------------------------------------------
// relic trace list — edge cases
// ---------------------------------------------------------------------------

func TestTraceList_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	tracesDir := filepath.Join(dir, ".tr", "traces")
	os.MkdirAll(tracesDir, 0o755)

	out := runList(t, dir)
	if !strings.Contains(out, "No runs found") {
		t.Errorf("expected 'No runs found' for empty dir, got: %s", out)
	}
}

func TestTraceList_InterruptedRun_NoEnd(t *testing.T) {
	// A run file with only a run_start (no run_end) should still appear.
	dir := t.TempDir()
	tracesDir := filepath.Join(dir, ".tr", "traces")
	os.MkdirAll(tracesDir, 0o755)

	content := runAStart + "\n"
	os.WriteFile(filepath.Join(tracesDir, runAID+".trtrace"), []byte(content), 0o644)

	out := runList(t, dir)
	if !strings.Contains(out, runAID) {
		t.Error("interrupted run should still appear in list")
	}
	if !strings.Contains(out, "running") {
		t.Error("interrupted run should be marked as running")
	}
}

func TestTraceList_Limit(t *testing.T) {
	dir := makeMultiTraceDir(t)
	out := runList(t, dir, "--limit", "1")

	lines := strings.Split(strings.TrimSpace(out), "\n")
	// Header line + separator + 1 run = 3 lines minimum.
	// Ensure we don't have all 3 runs' IDs.
	count := 0
	for _, id := range []string{runAID, runBID, runCID} {
		if strings.Contains(out, id) {
			count++
		}
	}
	if count > 1 {
		t.Errorf("--limit 1 should show at most 1 run, found %d run IDs in: %s", count, out)
	}
	_ = lines
}

// ---------------------------------------------------------------------------
// scanTraces helper (unit tests)
// ---------------------------------------------------------------------------

func TestScanTraces_ReturnsRunsInOrder(t *testing.T) {
	dir := makeMultiTraceDir(t)
	tracesDir := filepath.Join(dir, ".tr", "traces")

	runs, err := scanTraces(tracesDir)
	if err != nil {
		t.Fatalf("scanTraces: %v", err)
	}
	if len(runs) != 3 {
		t.Fatalf("expected 3 runs, got %d", len(runs))
	}
	// Most recent first: C, B, A.
	wantOrder := []string{runCID, runBID, runAID}
	for i, r := range runs {
		if r.RunID != wantOrder[i] {
			t.Errorf("runs[%d].RunID=%q want %q", i, r.RunID, wantOrder[i])
		}
	}
}

func TestScanTraces_ExtractsAgentAndCounts(t *testing.T) {
	dir := makeMultiTraceDir(t)
	tracesDir := filepath.Join(dir, ".tr", "traces")

	runs, err := scanTraces(tracesDir)
	if err != nil {
		t.Fatalf("scanTraces: %v", err)
	}

	// Find run B.
	var runB *runSummary
	for i := range runs {
		if runs[i].RunID == runBID {
			runB = &runs[i]
		}
	}
	if runB == nil {
		t.Fatal("run B not found")
	}
	if runB.Agent != "agent-beta" {
		t.Errorf("Agent=%q want agent-beta", runB.Agent)
	}
	if runB.Total != 2 {
		t.Errorf("Total=%d want 2", runB.Total)
	}
	if runB.Allowed != 1 {
		t.Errorf("Allowed=%d want 1", runB.Allowed)
	}
	if runB.Denied != 1 {
		t.Errorf("Denied=%d want 1", runB.Denied)
	}
	if runB.DurationMs != 3000 {
		t.Errorf("DurationMs=%d want 3000", runB.DurationMs)
	}
}

func TestScanTraces_SkipsMalformedFiles(t *testing.T) {
	dir := t.TempDir()
	tracesDir := filepath.Join(dir, ".tr", "traces")
	os.MkdirAll(tracesDir, 0o755)

	// One valid and one malformed.
	os.WriteFile(filepath.Join(tracesDir, runAID+".trtrace"),
		[]byte(runAStart+"\n"+runAAllow+"\n"+runAEnd+"\n"), 0o644)
	os.WriteFile(filepath.Join(tracesDir, "BROKEN.trtrace"),
		[]byte("not json at all\n"), 0o644)

	runs, err := scanTraces(tracesDir)
	if err != nil {
		t.Fatalf("scanTraces: %v", err)
	}
	if len(runs) != 1 {
		t.Errorf("expected 1 valid run, got %d", len(runs))
	}
}
