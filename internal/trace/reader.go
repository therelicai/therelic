package trace

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// TraceEvent is a unified, flat representation of both run and action events.
// Fields not applicable to a given event type are zero-valued / nil.
// It uses the same short JSON field names as the writer so json.Unmarshal
// works directly without any transformation.
type TraceEvent struct {
	// Common fields
	V   int    `json:"v"`
	T   string `json:"t"`   // "run" | "action"
	TS  string `json:"ts"`
	Run string `json:"run"`

	// Run-event fields (T == "run")
	Agent          string `json:"agent,omitempty"`
	AgentV         string `json:"agent_v,omitempty"`
	Policy         string `json:"policy,omitempty"`
	Env            string `json:"env,omitempty"`
	Status         string `json:"status,omitempty"` // "start" | "end"
	Exit           *int   `json:"exit,omitempty"`
	DurationMs     *int   `json:"ms,omitempty"`
	ActionsTotal   *int   `json:"actions_total,omitempty"`
	ActionsAllowed *int   `json:"actions_allowed,omitempty"`
	ActionsDenied  *int   `json:"actions_denied,omitempty"`

	// Action-event fields (T == "action")
	Seq      int             `json:"seq,omitempty"`
	Proto    string          `json:"proto,omitempty"`
	Method   string          `json:"method,omitempty"`
	Target   string          `json:"target,omitempty"`
	Params   json.RawMessage `json:"params,omitempty"`
	Auth     string          `json:"auth,omitempty"` // "allow" | "deny" | "audit_deny" | "would_deny"
	Rule     string          `json:"rule,omitempty"`
	Ctx      json.RawMessage `json:"ctx,omitempty"`
	Response json.RawMessage `json:"response,omitempty"`

	// Multi-agent fields (optional on both event types)
	Corr      string `json:"corr,omitempty"`
	ToAgent   string `json:"to_agent,omitempty"`
	FromAgent string `json:"from_agent,omitempty"`
	FromRun   string `json:"from_run,omitempty"`

	// Delegation chain — omitted for root sessions
	DelegationDepth *int   `json:"delegation_depth,omitempty"`
	DelegationRoot  string `json:"delegation_root,omitempty"`

	// Raw holds the original JSON line for --json pass-through. Not serialized.
	Raw json.RawMessage `json:"-"`
}

// IsDenied returns true for any auth decision that represents a denial,
// whether enforced, audit-mode, or permissive-mode.
func (e TraceEvent) IsDenied() bool {
	return e.Auth == "deny" || e.Auth == "audit_deny" || e.Auth == "would_deny"
}

// ReadTrace reads all events from a .trtrace file and returns them in order.
// Blank lines and unparseable lines are silently skipped.
func ReadTrace(path string) ([]TraceEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("trace: open %s: %w", path, err)
	}
	defer f.Close()
	return parseReader(f)
}

// parseReader reads NDJSON events from r until EOF.
func parseReader(r io.Reader) ([]TraceEvent, error) {
	var events []TraceEvent
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		ev, ok := parseLine(scanner.Bytes())
		if ok {
			events = append(events, ev)
		}
	}
	return events, scanner.Err()
}

// parseLine parses a single NDJSON line. Returns (event, true) on success.
func parseLine(line []byte) (TraceEvent, bool) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return TraceEvent{}, false
	}
	var ev TraceEvent
	if err := json.Unmarshal(line, &ev); err != nil {
		return TraceEvent{}, false
	}
	raw := make([]byte, len(line))
	copy(raw, line)
	ev.Raw = raw
	return ev, true
}

// StreamResult is a single item emitted by ReadTraceStream.
type StreamResult struct {
	Event TraceEvent
	Err   error
}

// ReadTraceStream reads a .trtrace file and streams events on the returned
// channel. When follow is true the file is tailed: lines appended after EOF
// are emitted as they arrive. The stream ends when ctx is cancelled or, for
// follow=false, after all existing lines are consumed.
//
// Implementation uses byte-offset tracking so the file descriptor's position
// is never confused by internal buffering, making follow mode safe regardless
// of OS or filesystem.
func ReadTraceStream(ctx context.Context, path string, follow bool) <-chan StreamResult {
	ch := make(chan StreamResult, 32)

	go func() {
		defer close(ch)

		f, err := os.Open(path)
		if err != nil {
			send(ctx, ch, StreamResult{Err: fmt.Errorf("trace: open %s: %w", path, err)})
			return
		}
		defer f.Close()

		var offset int64
		var pending []byte // incomplete line fragment carried across reads

		emit := func(data []byte) bool {
			// data may contain multiple lines. Split on newlines, carry incomplete
			// lines in pending for the next read.
			data = append(pending, data...)
			pending = nil

			for {
				idx := bytes.IndexByte(data, '\n')
				if idx < 0 {
					// No complete line yet — buffer remainder.
					pending = append(pending[:0], data...)
					return true
				}
				line := data[:idx]
				data = data[idx+1:]
				ev, ok := parseLine(line)
				if !ok {
					continue
				}
				if !send(ctx, ch, StreamResult{Event: ev}) {
					return false
				}
			}
		}

		poll := func() bool {
			f.Seek(offset, io.SeekStart) //nolint:errcheck
			buf := make([]byte, 32*1024)
			for {
				n, err := f.Read(buf)
				if n > 0 {
					offset += int64(n)
					if !emit(buf[:n]) {
						return false
					}
				}
				if err == io.EOF {
					return true
				}
				if err != nil {
					send(ctx, ch, StreamResult{Err: fmt.Errorf("trace: read: %w", err)})
					return false
				}
			}
		}

		// Initial read.
		if !poll() {
			return
		}
		if !follow {
			return
		}

		// Tail loop: poll every 100 ms until ctx is cancelled.
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !poll() {
					return
				}
			}
		}
	}()

	return ch
}

// send delivers a result to ch, returning false if ctx is cancelled first.
func send(ctx context.Context, ch chan<- StreamResult, r StreamResult) bool {
	select {
	case ch <- r:
		return true
	case <-ctx.Done():
		return false
	}
}
