package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/therelicai/therelic/internal/trace"
)

// execRun runs `relic run --trace-dir <dir> [extraArgs...] -- <cmd> [cmdArgs...]`
// and returns (stderr output, error). Stdout from the child process goes to
// os.Stdout (visible in -v mode).
func execRun(t *testing.T, traceDir string, relicFlags []string, cmd string, cmdArgs ...string) (string, error) {
	t.Helper()

	root := NewRootCmd("test")
	root.SilenceErrors = true

	var errBuf bytes.Buffer
	root.SetErr(&errBuf)

	args := []string{"run", "--trace-dir", traceDir, "--quiet"}
	args = append(args, relicFlags...)
	args = append(args, "--")
	args = append(args, cmd)
	args = append(args, cmdArgs...)

	root.SetArgs(args)
	err := root.Execute()
	return errBuf.String(), err
}

// traceEvents reads all events from the sole .trtrace file in dir.
func traceEvents(t *testing.T, traceDir string) []trace.TraceEvent {
	t.Helper()
	entries, err := os.ReadDir(traceDir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", traceDir, err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 trace file in %s, got %d", traceDir, len(entries))
	}
	path := filepath.Join(traceDir, entries[0].Name())
	events, err := trace.ReadTrace(path)
	if err != nil {
		t.Fatalf("ReadTrace %s: %v", path, err)
	}
	return events
}

// ---------------------------------------------------------------------------

func TestRun_EchoHello_ExitZero(t *testing.T) {
	dir := t.TempDir()
	_, err := execRun(t, dir, nil, "echo", "hello")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}

	events := traceEvents(t, dir)
	if len(events) != 2 {
		t.Fatalf("expected 2 trace events (run-start + run-end), got %d", len(events))
	}
}

func TestRun_TraceFileIsValidNDJSON(t *testing.T) {
	dir := t.TempDir()
	execRun(t, dir, nil, "echo", "validate") //nolint

	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected 1 trace file, got %d", len(entries))
	}

	// Read raw bytes and verify each line is valid JSON.
	path := filepath.Join(dir, entries[0].Name())
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read trace: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Errorf("expected exactly 2 lines in trace file, got %d", len(lines))
	}
	for i, line := range lines {
		if !strings.HasPrefix(line, "{") || !strings.HasSuffix(line, "}") {
			t.Errorf("line %d does not look like JSON: %s", i, line)
		}
	}
}

func TestRun_RunStartEvent(t *testing.T) {
	dir := t.TempDir()
	execRun(t, dir, []string{"--env", "ci"}, "echo", "start-test") //nolint

	events := traceEvents(t, dir)
	start := events[0]

	if start.T != "run" {
		t.Errorf("events[0].T = %q, want \"run\"", start.T)
	}
	if start.Status != "start" {
		t.Errorf("events[0].Status = %q, want \"start\"", start.Status)
	}
	if start.Env != "ci" {
		t.Errorf("events[0].Env = %q, want \"ci\"", start.Env)
	}
	if start.Run == "" {
		t.Error("events[0].Run (ULID) is empty")
	}
	if start.Agent != "echo" {
		t.Errorf("events[0].Agent = %q, want \"echo\"", start.Agent)
	}
	if start.TS == "" {
		t.Error("events[0].TS is empty")
	}
}

func TestRun_RunEndEvent_ExitZero(t *testing.T) {
	dir := t.TempDir()
	execRun(t, dir, nil, "echo", "end-test") //nolint

	events := traceEvents(t, dir)
	end := events[1]

	if end.T != "run" {
		t.Errorf("events[1].T = %q, want \"run\"", end.T)
	}
	if end.Status != "end" {
		t.Errorf("events[1].Status = %q, want \"end\"", end.Status)
	}
	if end.Exit == nil || *end.Exit != 0 {
		t.Errorf("events[1].Exit = %v, want 0", end.Exit)
	}
	if end.DurationMs == nil {
		t.Error("events[1].DurationMs is nil")
	}
	if end.ActionsTotal == nil || *end.ActionsTotal != 0 {
		t.Errorf("events[1].ActionsTotal = %v, want 0", end.ActionsTotal)
	}
}

func TestRun_FalseCommand_ExitOne(t *testing.T) {
	dir := t.TempDir()
	_, err := execRun(t, dir, nil, "false")

	if err == nil {
		t.Fatal("expected non-zero exit from 'false', got nil error")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if exitErr.Code != 1 {
		t.Errorf("exit code = %d, want 1", exitErr.Code)
	}

	// Trace file must still be written even on non-zero exit.
	events := traceEvents(t, dir)
	if len(events) != 2 {
		t.Fatalf("expected 2 trace events even on exit 1, got %d", len(events))
	}
	if end := events[1]; end.Exit == nil || *end.Exit != 1 {
		t.Errorf("run-end exit = %v, want 1", end.Exit)
	}
}

func TestRun_Duration_IsPositive(t *testing.T) {
	dir := t.TempDir()
	// sleep 0.1 runs for at least 100ms.
	execRun(t, dir, nil, "sleep", "0.1") //nolint

	events := traceEvents(t, dir)
	end := events[1]

	if end.DurationMs == nil {
		t.Fatal("DurationMs is nil")
	}
	if *end.DurationMs <= 0 {
		t.Errorf("DurationMs = %d, want > 0", *end.DurationMs)
	}
}

func TestRun_RunIDIsULID(t *testing.T) {
	dir := t.TempDir()
	execRun(t, dir, nil, "echo", "ulid-test") //nolint

	events := traceEvents(t, dir)

	// ULID is 26 uppercase base32 characters.
	runID := events[0].Run
	if len(runID) != 26 {
		t.Errorf("run ID %q has length %d, want 26 (ULID)", runID, len(runID))
	}
	for _, c := range runID {
		if !strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", c) {
			t.Errorf("run ID %q contains invalid ULID character %q", runID, c)
			break
		}
	}
}

func TestRun_StartAndEndHaveSameRunID(t *testing.T) {
	dir := t.TempDir()
	execRun(t, dir, nil, "echo", "same-id") //nolint

	events := traceEvents(t, dir)
	if events[0].Run != events[1].Run {
		t.Errorf("run IDs differ: start=%q end=%q", events[0].Run, events[1].Run)
	}
}

func TestRun_TraceFileNameMatchesRunID(t *testing.T) {
	dir := t.TempDir()
	execRun(t, dir, nil, "echo", "filename") //nolint

	events := traceEvents(t, dir)
	runID := events[0].Run

	expected := runID + ".trtrace"
	entries, _ := os.ReadDir(dir)
	if entries[0].Name() != expected {
		t.Errorf("trace file name = %q, want %q", entries[0].Name(), expected)
	}
}

func TestRun_AWRunIDEnvPassedToChild(t *testing.T) {
	base := t.TempDir()
	traceDir := filepath.Join(base, "traces")
	outFile := filepath.Join(base, "env.txt")

	// Use sh -c to capture the RELIC_RUN_ID env var to a file.
	execRun(t, traceDir, nil, "sh", "-c", "echo $RELIC_RUN_ID > "+outFile) //nolint

	events := traceEvents(t, traceDir)
	runID := events[0].Run

	envOut, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read env output file: %v", err)
	}
	if got := strings.TrimSpace(string(envOut)); got != runID {
		t.Errorf("child RELIC_RUN_ID = %q, want %q", got, runID)
	}
}

func TestRun_NoCommand_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	root := NewRootCmd("test")
	root.SilenceErrors = true
	root.SetArgs([]string{"run", "--trace-dir", dir})
	err := root.Execute()
	if err == nil {
		t.Error("expected error when no command specified, got nil")
	}
}

func TestRun_SummaryLine_DefaultEnv(t *testing.T) {
	dir := t.TempDir()

	root := NewRootCmd("test")
	root.SilenceErrors = true
	var errBuf bytes.Buffer
	root.SetErr(&errBuf)
	root.SetArgs([]string{"run", "--trace-dir", dir, "--", "echo", "summary"})
	root.Execute() //nolint

	summary := errBuf.String()
	if !strings.Contains(summary, "The Relic:") {
		t.Errorf("summary missing 'The Relic:' prefix: %q", summary)
	}
	if !strings.Contains(summary, "0 actions") {
		t.Errorf("summary missing '0 actions': %q", summary)
	}
	if !strings.Contains(summary, ".trtrace") {
		t.Errorf("summary missing trace file path: %q", summary)
	}
}

func TestRun_QuietFlag_SuppressesSummary(t *testing.T) {
	dir := t.TempDir()

	root := NewRootCmd("test")
	root.SilenceErrors = true
	var errBuf bytes.Buffer
	root.SetErr(&errBuf)
	root.SetArgs([]string{"run", "--trace-dir", dir, "--quiet", "--", "echo", "quiet"})
	root.Execute() //nolint

	// The only stderr output should be nothing (or at most the relic version banner
	// which comes from main.go, not the command itself).
	if strings.Contains(errBuf.String(), "The Relic:") {
		t.Errorf("--quiet should suppress summary, but found it in stderr: %q", errBuf.String())
	}
}

func TestRun_Timing_SleepIsAtLeast100ms(t *testing.T) {
	dir := t.TempDir()
	before := time.Now()
	execRun(t, dir, nil, "sleep", "0.1") //nolint
	elapsed := time.Since(before)

	if elapsed < 80*time.Millisecond {
		t.Errorf("sleep 0.1 completed in %v, expected >= 80ms", elapsed)
	}

	events := traceEvents(t, dir)
	if *events[1].DurationMs < 80 {
		t.Errorf("trace DurationMs = %d, expected >= 80", *events[1].DurationMs)
	}
}
