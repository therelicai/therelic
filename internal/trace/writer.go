package trace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RunEvent is emitted at the start and end of every agent run.
// Short field names reduce file size per the v2.1 spec.
type RunEvent struct {
	V          int    `json:"v"`
	T          string `json:"t"`
	TS         string `json:"ts"`
	Run        string `json:"run"`
	Agent      string `json:"agent,omitempty"`
	AgentV     string `json:"agent_v,omitempty"`
	Policy     string `json:"policy,omitempty"`
	Env        string `json:"env,omitempty"`
	Status     string `json:"status"`
	Exit       *int   `json:"exit,omitempty"`
	DurationMs *int   `json:"ms,omitempty"`

	// Run summary — present on status:"end" only
	ActionsTotal   *int `json:"actions_total,omitempty"`
	ActionsAllowed *int `json:"actions_allowed,omitempty"`
	ActionsDenied  *int `json:"actions_denied,omitempty"`

	// Multi-agent correlation — omitted for single-agent runs
	Corr      string `json:"corr,omitempty"`
	FromAgent string `json:"from_agent,omitempty"`
	FromRun   string `json:"from_run,omitempty"`

	// Delegation chain — omitted for root sessions
	DelegationDepth *int   `json:"delegation_depth,omitempty"`
	DelegationRoot  string `json:"delegation_root,omitempty"`
}

// ActionEvent is emitted for every intercepted tool call, resource read, or
// prompt get. It is self-contained: intent + authorization + result in one line.
type ActionEvent struct {
	V      int    `json:"v"`
	T      string `json:"t"`
	TS     string `json:"ts"`
	Run    string `json:"run"`
	Seq    int    `json:"seq"`
	Proto  string `json:"proto"`
	Method string `json:"method"`
	Target string `json:"target"`

	// Params holds the (redacted) input parameters for the action.
	Params any `json:"params,omitempty"`

	// Auth is the authorization decision: "allow", "deny", "audit_deny", "would_deny".
	Auth string `json:"auth"`
	// Rule is the ID of the matched policy rule, or "default".
	Rule string `json:"rule"`
	// Ctx holds optional tool-call provenance extracted from _context in arguments.
	Ctx any `json:"ctx,omitempty"`

	// Response is the tool result — captured only when --capture-responses is set.
	Response any `json:"response,omitempty"`

	// Multi-agent fields — omitted for single-agent runs.
	ToAgent string `json:"to_agent,omitempty"`
	Corr    string `json:"corr,omitempty"`
}

// PolicyReloadEvent is emitted when the policy watcher detects a file change.
type PolicyReloadEvent struct {
	V      int    `json:"v"`
	T      string `json:"t"`                // "policy_reload"
	TS     string `json:"ts"`
	Run    string `json:"run"`
	Policy string `json:"policy,omitempty"` // file path or hash
	Status string `json:"status"`           // "ok" | "error"
	Error  string `json:"error,omitempty"`
}

// TraceWriter appends NDJSON events to an append-only .trtrace file.
// Writes are buffered and fsynced on a 100ms interval or on Close().
//
// When a chain is attached (NewTraceWriterWithKey or SetIntegrityKey),
// every emitted event is sealed with an HMAC that covers the event
// bytes plus the previous event's HMAC. Tampering with, inserting, or
// removing any sealed event breaks the chain for every subsequent
// event — making the trace tamper-evident.
type TraceWriter struct {
	mu       sync.Mutex
	f        *os.File
	buf      [][]byte
	done     chan struct{}
	closed   bool
	flushErr error
	chain    *IntegrityChain
}

// NewTraceWriter creates or opens the .trtrace file at
// <traceDir>/<runID>.trtrace and starts the background flush loop.
// Events written through this writer are NOT sealed; use
// NewTraceWriterWithKey for tamper-evident traces.
func NewTraceWriter(traceDir, runID string) (*TraceWriter, error) {
	return newTraceWriter(traceDir, runID, nil)
}

// NewTraceWriterWithKey behaves like NewTraceWriter but seals every
// emitted event with an HMAC chain keyed by chainKey. chainKey is
// typically derived from a master secret + runID via GenerateChainKey,
// so the platform can recompute it during upload verification without
// the runtime needing to ship the raw key over the wire.
//
// Passing a nil or empty chainKey is treated as "no sealing" so the
// caller can wire this in without conditional branching.
func NewTraceWriterWithKey(traceDir, runID string, chainKey []byte) (*TraceWriter, error) {
	var chain *IntegrityChain
	if len(chainKey) > 0 {
		chain = NewIntegrityChain(chainKey)
	}
	return newTraceWriter(traceDir, runID, chain)
}

func newTraceWriter(traceDir, runID string, chain *IntegrityChain) (*TraceWriter, error) {
	if err := os.MkdirAll(traceDir, 0o755); err != nil {
		return nil, fmt.Errorf("trace: mkdir %s: %w", traceDir, err)
	}

	path := filepath.Join(traceDir, runID+".trtrace")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("trace: open %s: %w", path, err)
	}

	tw := &TraceWriter{
		f:     f,
		buf:   make([][]byte, 0, 64),
		done:  make(chan struct{}),
		chain: chain,
	}
	go tw.flushLoop()
	return tw, nil
}

// WriteEvent serializes v to JSON and enqueues it for writing.
// The caller must ensure v is one of RunEvent or ActionEvent.
//
// When a chain is attached, the JSON is rewritten in place to splice
// an "hmac":"<hex>" field at the end of the event object. The hmac
// covers the canonical event bytes (without the hmac field) plus the
// previous event's hmac. Splicing rather than re-marshalling preserves
// field ordering and avoids a second round trip through encoding/json.
func (tw *TraceWriter) WriteEvent(event any) error {
	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("trace: marshal: %w", err)
	}

	tw.mu.Lock()
	defer tw.mu.Unlock()
	if tw.closed {
		return fmt.Errorf("trace: writer is closed")
	}
	if tw.chain != nil {
		sealed, err := sealEventLine(tw.chain, line)
		if err != nil {
			return fmt.Errorf("trace: seal: %w", err)
		}
		line = sealed
	}
	tw.buf = append(tw.buf, line)
	return nil
}

// sealEventLine computes the chain HMAC over the unsealed event bytes
// and returns the same JSON object with an `hmac` field appended.
// The input MUST be a JSON object ending in '}' — all of our typed
// events satisfy that. We never re-parse the bytes so the field order
// the runtime emits is preserved exactly.
func sealEventLine(chain *IntegrityChain, line []byte) ([]byte, error) {
	if len(line) < 2 || line[len(line)-1] != '}' {
		return nil, fmt.Errorf("event is not a JSON object")
	}
	mac := chain.Seal(line)
	// Empty object {"hmac":"…"} vs. populated {"a":1,"hmac":"…"} — the
	// only difference is a leading comma for the populated case.
	out := make([]byte, 0, len(line)+80)
	out = append(out, line[:len(line)-1]...)
	if len(line) > 2 {
		out = append(out, ',')
	}
	out = append(out, '"', 'h', 'm', 'a', 'c', '"', ':', '"')
	out = append(out, mac...)
	out = append(out, '"', '}')
	return out, nil
}

// WriteRunStart emits a run-start event.
func (tw *TraceWriter) WriteRunStart(runID, agent, version, policyHash, env string) error {
	return tw.WriteEvent(RunEvent{
		V:      1,
		T:      "run",
		TS:     now(),
		Run:    runID,
		Agent:  agent,
		AgentV: version,
		Policy: policyHash,
		Env:    env,
		Status: "start",
	})
}

// WriteRunEnd emits a run-end event with summary counts.
func (tw *TraceWriter) WriteRunEnd(runID string, exitCode, durationMs, total, allowed, denied int) error {
	return tw.WriteEvent(RunEvent{
		V:              1,
		T:              "run",
		TS:             now(),
		Run:            runID,
		Status:         "end",
		Exit:           &exitCode,
		DurationMs:     &durationMs,
		ActionsTotal:   &total,
		ActionsAllowed: &allowed,
		ActionsDenied:  &denied,
	})
}

// WriteAction emits an action event. The caller is responsible for populating
// all required fields (Run, Seq, Proto, Method, Target, Auth, Rule).
func (tw *TraceWriter) WriteAction(event ActionEvent) error {
	event.V = 1
	event.T = "action"
	if event.TS == "" {
		event.TS = now()
	}
	return tw.WriteEvent(event)
}

// WritePolicyReload emits a policy_reload event.
func (tw *TraceWriter) WritePolicyReload(runID, policyPath, status, errMsg string) error {
	ev := PolicyReloadEvent{
		V:      1,
		T:      "policy_reload",
		TS:     now(),
		Run:    runID,
		Policy: policyPath,
		Status: status,
	}
	if errMsg != "" {
		ev.Error = errMsg
	}
	return tw.WriteEvent(ev)
}

// Close flushes any buffered events, syncs the file, and closes it.
func (tw *TraceWriter) Close() error {
	tw.mu.Lock()
	if tw.closed {
		tw.mu.Unlock()
		return nil
	}
	tw.closed = true
	tw.mu.Unlock()

	close(tw.done)

	tw.mu.Lock()
	err := tw.flush()
	tw.mu.Unlock()

	if closeErr := tw.f.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	return err
}

// flushLoop batches writes every 100ms.
func (tw *TraceWriter) flushLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			tw.mu.Lock()
			tw.flushErr = tw.flush()
			tw.mu.Unlock()
		case <-tw.done:
			return
		}
	}
}

// flush writes all buffered lines to disk. Must be called with mu held.
func (tw *TraceWriter) flush() error {
	if len(tw.buf) == 0 {
		return nil
	}
	for _, line := range tw.buf {
		if _, err := tw.f.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("trace: write: %w", err)
		}
	}
	if err := tw.f.Sync(); err != nil {
		return fmt.Errorf("trace: sync: %w", err)
	}
	tw.buf = tw.buf[:0]
	return nil
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
