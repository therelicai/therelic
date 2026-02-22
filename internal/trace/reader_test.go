package trace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixture writes a .trtrace file to dir with the given NDJSON lines and
// returns its path.
func fixture(t *testing.T, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "TEST01.trtrace")
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return path
}

var (
	lineRunStart  = `{"v":1,"t":"run","ts":"2026-02-17T14:00:00Z","run":"TEST01","agent":"test","agent_v":"1.0.0","policy":"abc","env":"local","status":"start"}`
	lineActionAllow = `{"v":1,"t":"action","ts":"2026-02-17T14:00:01Z","run":"TEST01","seq":1,"proto":"mcp","method":"tool_call","target":"web_search","auth":"allow","rule":"allow-web"}`
	lineActionDeny  = `{"v":1,"t":"action","ts":"2026-02-17T14:00:02Z","run":"TEST01","seq":2,"proto":"mcp","method":"tool_call","target":"shell_exec","auth":"deny","rule":"default"}`
	lineRunEnd    = `{"v":1,"t":"run","ts":"2026-02-17T14:00:03Z","run":"TEST01","status":"end","exit":0,"ms":3000,"actions_total":2,"actions_allowed":1,"actions_denied":1}`
)

func TestReadTrace_ParsesAllEvents(t *testing.T) {
	path := fixture(t, lineRunStart, lineActionAllow, lineActionDeny, lineRunEnd)

	events, err := ReadTrace(path)
	if err != nil {
		t.Fatalf("ReadTrace: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}

	// First event: run start
	if events[0].T != "run" {
		t.Errorf("[0] T = %q, want \"run\"", events[0].T)
	}
	if events[0].Status != "start" {
		t.Errorf("[0] Status = %q, want \"start\"", events[0].Status)
	}
	if events[0].Agent != "test" {
		t.Errorf("[0] Agent = %q, want \"test\"", events[0].Agent)
	}
	if events[0].Run != "TEST01" {
		t.Errorf("[0] Run = %q, want \"TEST01\"", events[0].Run)
	}

	// Second event: allow action
	if events[1].T != "action" {
		t.Errorf("[1] T = %q, want \"action\"", events[1].T)
	}
	if events[1].Target != "web_search" {
		t.Errorf("[1] Target = %q, want \"web_search\"", events[1].Target)
	}
	if events[1].Auth != "allow" {
		t.Errorf("[1] Auth = %q, want \"allow\"", events[1].Auth)
	}
	if events[1].Seq != 1 {
		t.Errorf("[1] Seq = %d, want 1", events[1].Seq)
	}

	// Third event: deny action
	if events[2].Auth != "deny" {
		t.Errorf("[2] Auth = %q, want \"deny\"", events[2].Auth)
	}
	if events[2].Target != "shell_exec" {
		t.Errorf("[2] Target = %q, want \"shell_exec\"", events[2].Target)
	}
	if events[2].Rule != "default" {
		t.Errorf("[2] Rule = %q, want \"default\"", events[2].Rule)
	}

	// Fourth event: run end
	if events[3].Status != "end" {
		t.Errorf("[3] Status = %q, want \"end\"", events[3].Status)
	}
	if events[3].ActionsTotal == nil || *events[3].ActionsTotal != 2 {
		t.Errorf("[3] ActionsTotal = %v, want 2", events[3].ActionsTotal)
	}
	if events[3].ActionsAllowed == nil || *events[3].ActionsAllowed != 1 {
		t.Errorf("[3] ActionsAllowed = %v, want 1", events[3].ActionsAllowed)
	}
	if events[3].ActionsDenied == nil || *events[3].ActionsDenied != 1 {
		t.Errorf("[3] ActionsDenied = %v, want 1", events[3].ActionsDenied)
	}
}

func TestReadTrace_DeniedFilter(t *testing.T) {
	path := fixture(t, lineRunStart, lineActionAllow, lineActionDeny, lineRunEnd)

	events, err := ReadTrace(path)
	if err != nil {
		t.Fatalf("ReadTrace: %v", err)
	}

	var denied []TraceEvent
	for _, ev := range events {
		if ev.IsDenied() {
			denied = append(denied, ev)
		}
	}

	if len(denied) != 1 {
		t.Fatalf("expected 1 denied event, got %d", len(denied))
	}
	if denied[0].Target != "shell_exec" {
		t.Errorf("denied[0].Target = %q, want \"shell_exec\"", denied[0].Target)
	}
}

func TestReadTrace_RawFieldPreserved(t *testing.T) {
	path := fixture(t, lineActionAllow)
	events, err := ReadTrace(path)
	if err != nil {
		t.Fatalf("ReadTrace: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if len(events[0].Raw) == 0 {
		t.Error("Raw field is empty; expected original JSON line")
	}
	if string(events[0].Raw) != lineActionAllow {
		t.Errorf("Raw = %s, want %s", events[0].Raw, lineActionAllow)
	}
}

func TestReadTrace_SkipsMalformedLines(t *testing.T) {
	path := fixture(t,
		lineRunStart,
		`not valid json`,
		``,
		lineActionAllow,
		`{"broken":`,
		lineRunEnd,
	)

	events, err := ReadTrace(path)
	if err != nil {
		t.Fatalf("ReadTrace: %v", err)
	}
	// Only 3 valid lines
	if len(events) != 3 {
		t.Errorf("expected 3 events (skipping 3 bad lines), got %d", len(events))
	}
}

func TestReadTrace_IsDenied_Variants(t *testing.T) {
	cases := []struct {
		auth string
		want bool
	}{
		{"allow", false},
		{"deny", true},
		{"audit_deny", true},
		{"would_deny", true},
		{"", false},
	}
	for _, tc := range cases {
		ev := TraceEvent{Auth: tc.auth}
		if got := ev.IsDenied(); got != tc.want {
			t.Errorf("IsDenied(%q) = %v, want %v", tc.auth, got, tc.want)
		}
	}
}

func TestReadTraceStream_AllEvents(t *testing.T) {
	path := fixture(t, lineRunStart, lineActionAllow, lineActionDeny, lineRunEnd)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch := ReadTraceStream(ctx, path, false)

	var events []TraceEvent
	for r := range ch {
		if r.Err != nil {
			t.Fatalf("stream error: %v", r.Err)
		}
		events = append(events, r.Event)
	}

	if len(events) != 4 {
		t.Fatalf("expected 4 events from stream, got %d", len(events))
	}
	if events[0].Status != "start" {
		t.Errorf("events[0].Status = %q, want \"start\"", events[0].Status)
	}
	if events[3].Status != "end" {
		t.Errorf("events[3].Status = %q, want \"end\"", events[3].Status)
	}
}

func TestReadTraceStream_Follow_PicksUpNewLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "follow.trtrace")

	// Write initial content.
	initial := lineRunStart + "\n" + lineActionAllow + "\n"
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch := ReadTraceStream(ctx, path, true)

	// Collect the initial 2 events, then append more and collect them.
	collected := make(chan TraceEvent, 10)
	go func() {
		for r := range ch {
			if r.Err == nil {
				collected <- r.Event
			}
		}
		close(collected)
	}()

	// Wait a bit for the first 2 events to arrive.
	time.Sleep(150 * time.Millisecond)

	// Append 2 more lines to the file.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(lineActionDeny + "\n")
	f.WriteString(lineRunEnd + "\n")
	f.Close()

	// Wait for the new lines to be picked up.
	time.Sleep(400 * time.Millisecond)
	cancel()

	// Drain channel.
	var events []TraceEvent
	for ev := range collected {
		events = append(events, ev)
	}

	if len(events) < 4 {
		t.Errorf("expected >=4 events after follow, got %d", len(events))
	}
}

func TestReadTrace_EmptyFile(t *testing.T) {
	path := fixture(t)
	events, err := ReadTrace(path)
	if err != nil {
		t.Fatalf("ReadTrace on empty file: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events for empty file, got %d", len(events))
	}
}

func TestReadTrace_FileNotFound(t *testing.T) {
	_, err := ReadTrace("/nonexistent/path/run.trtrace")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}
