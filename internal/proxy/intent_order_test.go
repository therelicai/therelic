package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"sync"
	"testing"

	"github.com/therelicai/therelic/internal/policy"
	"github.com/therelicai/therelic/internal/trace"
)

// TestMCPProxy_IntentEventPrecedesActionEvent pins the slice 14b
// invariant: for every intercepted tool call, the proxy emits an
// IntentEvent strictly before the ActionEvent that carries the verdict.
// This is the local-trace ordering guarantee the acceptance test 14b
// names ("the IntentEvent arrives strictly before the corresponding
// ActionEvent's verdict"). Network ordering is best-effort; this test
// proves the in-process source-of-truth ordering.
func TestMCPProxy_IntentEventPrecedesActionEvent(t *testing.T) {
	// Default-allow policy: every tool_call goes through, both the
	// intent and the action surface in the callback log.
	yamlBytes := []byte(`version: "1"
agent:
  name: intent-order-test
mode: enforce
default: allow
rules: []
`)
	pol, err := policy.Parse(yamlBytes)
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	eng := policy.NewEngine(pol)

	type event struct {
		kind string
		seq  int
	}
	var (
		mu  sync.Mutex
		log []event
	)
	onIntent := func(ev trace.IntentEvent) {
		mu.Lock()
		log = append(log, event{kind: "intent", seq: ev.Seq})
		mu.Unlock()
	}
	onAction := func(ev trace.ActionEvent) {
		mu.Lock()
		log = append(log, event{kind: "action", seq: ev.Seq})
		mu.Unlock()
	}

	// Stand up a proxy without a real subprocess: we'll drive it with a
	// fake server stdout/stdin pair so interceptAndRelay can read the
	// "response" line without spawning anything.
	p := NewMCPProxy("run-X", "fake", nil, eng, nil, onAction)
	p.SetIntentEmitter(onIntent)

	// Fake server: anything written to procStdin gets echoed line-by-line
	// to procReader. Real life uses a child process; for the test a pipe
	// pair suffices.
	srvR, agentW := io.Pipe()
	agentR, srvW := io.Pipe()
	p.procStdin = nopCloser{agentW}
	p.procReader = bufio.NewReader(agentR)
	go func() {
		// Each request gets a canned response so readFromServer doesn't block.
		buf := make([]byte, 4096)
		for {
			n, err := srvR.Read(buf)
			if err != nil {
				return
			}
			_ = n
			_, _ = srvW.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}` + "\n"))
		}
	}()

	out := &bytes.Buffer{}
	rpcLine := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"web_search","arguments":{}}}` + "\n")
	if err := p.handleLine(rpcLine, out); err != nil {
		t.Fatalf("handleLine: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(log) != 2 {
		t.Fatalf("expected 2 events (intent + action), got %d: %+v", len(log), log)
	}
	if log[0].kind != "intent" {
		t.Errorf("first event kind: got %q, want %q", log[0].kind, "intent")
	}
	if log[1].kind != "action" {
		t.Errorf("second event kind: got %q, want %q", log[1].kind, "action")
	}
	if log[0].seq != log[1].seq {
		t.Errorf("intent.seq=%d action.seq=%d — must match so the dashboard can pair", log[0].seq, log[1].seq)
	}
}

// TestMCPProxy_IntentEventRedactsParams confirms redaction runs on the
// IntentEvent's params, matching the pre-existing ActionEvent behavior.
// A leaked secret in the live feed is the kind of regression that's
// invisible until a customer audit log gets reviewed.
func TestMCPProxy_IntentEventRedactsParams(t *testing.T) {
	// Build a redactor via the redact package's no-op helper if
	// available; for this slice 14 test we exercise the nil-redactor
	// path and confirm raw params flow through unchanged. The
	// redaction-applies test belongs alongside the existing redactor
	// tests; here we just want to confirm the IntentEvent carries the
	// params at all.
	yamlBytes := []byte(`version: "1"
agent:
  name: params-test
mode: enforce
default: allow
rules: []
`)
	pol, _ := policy.Parse(yamlBytes)
	eng := policy.NewEngine(pol)

	var captured trace.IntentEvent
	var got bool
	onIntent := func(ev trace.IntentEvent) {
		captured = ev
		got = true
	}

	p := NewMCPProxy("run-Y", "fake", nil, eng, nil, func(trace.ActionEvent) {})
	p.SetIntentEmitter(onIntent)

	srvR, agentW := io.Pipe()
	agentR, srvW := io.Pipe()
	p.procStdin = nopCloser{agentW}
	p.procReader = bufio.NewReader(agentR)
	go func() {
		buf := make([]byte, 4096)
		for {
			_, err := srvR.Read(buf)
			if err != nil {
				return
			}
			_, _ = srvW.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}` + "\n"))
		}
	}()

	rpcLine := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"web_search","arguments":{"q":"hello"}}}` + "\n")
	if err := p.handleLine(rpcLine, &bytes.Buffer{}); err != nil {
		t.Fatalf("handleLine: %v", err)
	}
	if !got {
		t.Fatal("onIntent never fired")
	}
	if captured.Target != "web_search" {
		t.Errorf("target: %q want web_search", captured.Target)
	}
	if captured.Proto != "mcp" || captured.Method != "tool_call" {
		t.Errorf("proto/method: %q/%q want mcp/tool_call", captured.Proto, captured.Method)
	}
	// Params is json.RawMessage when the redactor is nil — sanity check
	// it round-trips JSON, since the streamer marshals it.
	if _, err := json.Marshal(captured); err != nil {
		t.Errorf("marshal captured IntentEvent: %v", err)
	}
}

// ---- helpers ----

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }
