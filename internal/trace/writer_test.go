package trace

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// traceDir creates a temp directory for a test and returns its path plus a
// cleanup function.
func traceDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "trtrace-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// readLines reads the .trtrace file for runID in dir and returns each line as a
// raw JSON message.
func readLines(t *testing.T, dir, runID string) []json.RawMessage {
	t.Helper()
	path := filepath.Join(dir, runID+".trtrace")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open trace file: %v", err)
	}
	defer f.Close()

	var lines []json.RawMessage
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var msg json.RawMessage = make([]byte, len(raw))
		copy(msg, raw)
		lines = append(lines, msg)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return lines
}

// unmarshal decodes a raw JSON line into a map for field-level assertions.
func unmarshal(t *testing.T, raw json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v (raw: %s)", err, raw)
	}
	return m
}

// stringField extracts a string field from a decoded map.
func stringField(t *testing.T, m map[string]json.RawMessage, key string) string {
	t.Helper()
	raw, ok := m[key]
	if !ok {
		t.Fatalf("field %q not found in %v", key, keys(m))
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("field %q: %v", key, err)
	}
	return s
}

func intField(t *testing.T, m map[string]json.RawMessage, key string) int {
	t.Helper()
	raw, ok := m[key]
	if !ok {
		t.Fatalf("field %q not found", key)
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		t.Fatalf("field %q: %v", key, err)
	}
	return n
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// newWriter is a test helper that creates a TraceWriter and registers cleanup.
func newWriter(t *testing.T, dir, runID string) *TraceWriter {
	t.Helper()
	tw, err := NewTraceWriter(dir, runID)
	if err != nil {
		t.Fatalf("NewTraceWriter: %v", err)
	}
	t.Cleanup(func() { tw.Close() })
	return tw
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

func TestWriteRunStart_ValidNDJSON(t *testing.T) {
	dir := traceDir(t)
	tw := newWriter(t, dir, "run-001")

	if err := tw.WriteRunStart("run-001", "test-agent", "1.0.0", "abc123", "local"); err != nil {
		t.Fatalf("WriteRunStart: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := readLines(t, dir, "run-001")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	m := unmarshal(t, lines[0])

	if got := intField(t, m, "v"); got != 1 {
		t.Errorf("v = %d, want 1", got)
	}
	if got := stringField(t, m, "t"); got != "run" {
		t.Errorf("t = %q, want \"run\"", got)
	}
	if got := stringField(t, m, "run"); got != "run-001" {
		t.Errorf("run = %q, want \"run-001\"", got)
	}
	if got := stringField(t, m, "agent"); got != "test-agent" {
		t.Errorf("agent = %q, want \"test-agent\"", got)
	}
	if got := stringField(t, m, "agent_v"); got != "1.0.0" {
		t.Errorf("agent_v = %q, want \"1.0.0\"", got)
	}
	if got := stringField(t, m, "policy"); got != "abc123" {
		t.Errorf("policy = %q, want \"abc123\"", got)
	}
	if got := stringField(t, m, "env"); got != "local" {
		t.Errorf("env = %q, want \"local\"", got)
	}
	if got := stringField(t, m, "status"); got != "start" {
		t.Errorf("status = %q, want \"start\"", got)
	}
	if _, ok := m["ts"]; !ok {
		t.Error("ts field missing")
	}
}

func TestWriteAction_ValidNDJSON(t *testing.T) {
	dir := traceDir(t)
	tw := newWriter(t, dir, "run-002")

	event := ActionEvent{
		Run:    "run-002",
		Seq:    1,
		Proto:  "mcp",
		Method: "tool_call",
		Target: "web_search",
		Params: map[string]string{"query": "golang testing"},
		Auth:   "allow",
		Rule:   "allow-web-search",
	}
	if err := tw.WriteAction(event); err != nil {
		t.Fatalf("WriteAction: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := readLines(t, dir, "run-002")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	m := unmarshal(t, lines[0])

	if got := stringField(t, m, "t"); got != "action" {
		t.Errorf("t = %q, want \"action\"", got)
	}
	if got := intField(t, m, "v"); got != 1 {
		t.Errorf("v = %d, want 1", got)
	}
	if got := stringField(t, m, "proto"); got != "mcp" {
		t.Errorf("proto = %q, want \"mcp\"", got)
	}
	if got := stringField(t, m, "method"); got != "tool_call" {
		t.Errorf("method = %q, want \"tool_call\"", got)
	}
	if got := stringField(t, m, "target"); got != "web_search" {
		t.Errorf("target = %q, want \"web_search\"", got)
	}
	if got := stringField(t, m, "auth"); got != "allow" {
		t.Errorf("auth = %q, want \"allow\"", got)
	}
	if got := stringField(t, m, "rule"); got != "allow-web-search" {
		t.Errorf("rule = %q, want \"allow-web-search\"", got)
	}
	if got := intField(t, m, "seq"); got != 1 {
		t.Errorf("seq = %d, want 1", got)
	}
}

func TestWriteRunEnd_ValidNDJSON(t *testing.T) {
	dir := traceDir(t)
	tw := newWriter(t, dir, "run-003")

	if err := tw.WriteRunEnd("run-003", 0, 1500, 10, 8, 2); err != nil {
		t.Fatalf("WriteRunEnd: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := readLines(t, dir, "run-003")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	m := unmarshal(t, lines[0])

	if got := stringField(t, m, "status"); got != "end" {
		t.Errorf("status = %q, want \"end\"", got)
	}
	if got := intField(t, m, "exit"); got != 0 {
		t.Errorf("exit = %d, want 0", got)
	}
	if got := intField(t, m, "ms"); got != 1500 {
		t.Errorf("ms = %d, want 1500", got)
	}
	if got := intField(t, m, "actions_total"); got != 10 {
		t.Errorf("actions_total = %d, want 10", got)
	}
	if got := intField(t, m, "actions_allowed"); got != 8 {
		t.Errorf("actions_allowed = %d, want 8", got)
	}
	if got := intField(t, m, "actions_denied"); got != 2 {
		t.Errorf("actions_denied = %d, want 2", got)
	}
}

func TestExactLineCount(t *testing.T) {
	dir := traceDir(t)
	tw := newWriter(t, dir, "run-004")

	if err := tw.WriteRunStart("run-004", "agent", "1.0", "hash", "local"); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if err := tw.WriteAction(ActionEvent{
			Run: "run-004", Seq: i,
			Proto: "mcp", Method: "tool_call", Target: "tool",
			Auth: "allow", Rule: "default",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.WriteRunEnd("run-004", 0, 100, 5, 5, 0); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	lines := readLines(t, dir, "run-004")
	// 1 run-start + 5 actions + 1 run-end = 7
	if len(lines) != 7 {
		t.Errorf("expected 7 lines, got %d", len(lines))
	}
}

func TestAllLinesValidJSON(t *testing.T) {
	dir := traceDir(t)
	tw := newWriter(t, dir, "run-005")

	tw.WriteRunStart("run-005", "agent", "1.0", "hash", "ci")
	tw.WriteAction(ActionEvent{
		Run: "run-005", Seq: 1,
		Proto: "http", Method: "GET", Target: "api.example.com",
		Auth: "allow", Rule: "allow-api",
	})
	tw.WriteRunEnd("run-005", 1, 500, 1, 1, 0)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	lines := readLines(t, dir, "run-005")
	for i, line := range lines {
		var v any
		if err := json.Unmarshal(line, &v); err != nil {
			t.Errorf("line %d is not valid JSON: %v (raw: %s)", i, err, line)
		}
	}
}

func TestOptionalFieldsOmitted(t *testing.T) {
	dir := traceDir(t)
	tw := newWriter(t, dir, "run-006")

	// Single-agent run — multi-agent fields must be absent
	tw.WriteRunStart("run-006", "agent", "1.0", "hash", "local")
	tw.WriteAction(ActionEvent{
		Run: "run-006", Seq: 1,
		Proto: "mcp", Method: "tool_call", Target: "web_search",
		Auth: "allow", Rule: "allow-web",
		// ToAgent, Corr intentionally left empty
	})
	tw.WriteRunEnd("run-006", 0, 200, 1, 1, 0)
	tw.Close()

	lines := readLines(t, dir, "run-006")

	// Check run-start line
	runStart := unmarshal(t, lines[0])
	for _, field := range []string{"corr", "from_agent", "from_run"} {
		if _, ok := runStart[field]; ok {
			t.Errorf("run-start: field %q should be omitted for single-agent run", field)
		}
	}

	// Check action line
	action := unmarshal(t, lines[1])
	for _, field := range []string{"to_agent", "corr", "response"} {
		if _, ok := action[field]; ok {
			t.Errorf("action: field %q should be omitted when empty", field)
		}
	}

	// Check run-end line: start-only fields should be omitted
	runEnd := unmarshal(t, lines[2])
	for _, field := range []string{"agent", "agent_v", "policy", "env"} {
		if _, ok := runEnd[field]; ok {
			t.Errorf("run-end: field %q should be omitted (not set on end event)", field)
		}
	}
}

func TestMultiAgentFieldsPresent(t *testing.T) {
	dir := traceDir(t)
	tw := newWriter(t, dir, "run-007")

	// Simulate an agent that is a child in a multi-agent run
	if err := tw.WriteEvent(RunEvent{
		V:         1,
		T:         "run",
		TS:        now(),
		Run:       "run-007",
		Agent:     "work-agent",
		AgentV:    "1.0.0",
		Policy:    "hash",
		Env:       "local",
		Status:    "start",
		Corr:      "corr-abc",
		FromAgent: "home-agent",
		FromRun:   "run-006",
	}); err != nil {
		t.Fatal(err)
	}

	// Action with to_agent and corr set
	if err := tw.WriteAction(ActionEvent{
		Run:     "run-007",
		Seq:     1,
		Proto:   "mcp",
		Method:  "tool_call",
		Target:  "agent_message",
		Auth:    "allow",
		Rule:    "allow-msg-work",
		ToAgent: "work-agent",
		Corr:    "corr-abc",
	}); err != nil {
		t.Fatal(err)
	}

	tw.Close()

	lines := readLines(t, dir, "run-007")

	runStart := unmarshal(t, lines[0])
	if got := stringField(t, runStart, "corr"); got != "corr-abc" {
		t.Errorf("corr = %q, want \"corr-abc\"", got)
	}
	if got := stringField(t, runStart, "from_agent"); got != "home-agent" {
		t.Errorf("from_agent = %q, want \"home-agent\"", got)
	}
	if got := stringField(t, runStart, "from_run"); got != "run-006" {
		t.Errorf("from_run = %q, want \"run-006\"", got)
	}

	action := unmarshal(t, lines[1])
	if got := stringField(t, action, "to_agent"); got != "work-agent" {
		t.Errorf("to_agent = %q, want \"work-agent\"", got)
	}
	if got := stringField(t, action, "corr"); got != "corr-abc" {
		t.Errorf("action corr = %q, want \"corr-abc\"", got)
	}
}

func TestWriterCreatesDirectory(t *testing.T) {
	base := t.TempDir()
	nested := filepath.Join(base, "a", "b", "traces")
	tw, err := NewTraceWriter(nested, "run-nested")
	if err != nil {
		t.Fatalf("NewTraceWriter with nested dir: %v", err)
	}
	tw.Close()

	if _, err := os.Stat(nested); os.IsNotExist(err) {
		t.Error("expected nested directory to be created")
	}
}

func TestFlushOnClose(t *testing.T) {
	dir := traceDir(t)
	tw := newWriter(t, dir, "run-flush")

	tw.WriteRunStart("run-flush", "agent", "1.0", "hash", "local")

	// Close immediately — data must be on disk before the periodic flush fires.
	if err := tw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := readLines(t, dir, "run-flush")
	if len(lines) != 1 {
		t.Errorf("expected 1 line after immediate Close, got %d", len(lines))
	}
}

func TestTSIsRFC3339(t *testing.T) {
	dir := traceDir(t)
	tw := newWriter(t, dir, "run-ts")
	tw.WriteRunStart("run-ts", "agent", "1.0", "hash", "local")
	tw.Close()

	lines := readLines(t, dir, "run-ts")
	m := unmarshal(t, lines[0])
	ts := stringField(t, m, "ts")

	if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
		t.Errorf("ts %q is not RFC3339Nano: %v", ts, err)
	}
}
