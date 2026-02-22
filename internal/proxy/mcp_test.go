package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/therelicai/therelic/internal/policy"
	"github.com/therelicai/therelic/internal/redact"
	"github.com/therelicai/therelic/internal/trace"
)

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

const testServerBin = "../../test/fixtures/mcp-test-server"

// checkTestServer skips the test if the mcp-test-server binary is missing.
// It also attempts to build it if 'go' is available.
func checkTestServer(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(testServerBin); err == nil {
		return // already built
	}
	// Try to build it automatically.
	out, buildErr := exec.Command("go", "build", "-o", testServerBin, "../../test/fixtures/").CombinedOutput()
	if buildErr != nil {
		t.Skipf("mcp-test-server not found and build failed (%v): %s\n"+
			"Run: go build -o test/fixtures/mcp-test-server ./test/fixtures/", buildErr, out)
	}
}

// proxySession is a helper that starts a proxy and returns a function to send
// one JSON-RPC request and read back the response line.
type proxySession struct {
	t         *testing.T
	proxy     *MCPProxy
	events    []trace.ActionEvent
	agentOut  *io.PipeWriter // agent writes here (proxy reads)
	agentIn   *io.PipeReader // agent reads here (proxy writes)
	enc       *json.Encoder
	scanner   *bufio.Scanner
	done      chan error
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// newSession starts a proxy with no policy engine and no redactor (permissive).
func newSession(t *testing.T, serverBin string, serverArgs ...string) *proxySession {
	return newSessionWith(t, nil, nil, serverBin, serverArgs...)
}

// newSessionWithEngine starts a proxy with an explicit policy engine and no redactor.
func newSessionWithEngine(t *testing.T, eng *policy.Engine, serverBin string, serverArgs ...string) *proxySession {
	return newSessionWith(t, eng, nil, serverBin, serverArgs...)
}

// newSessionWith starts a proxy with the given engine and redactor.
func newSessionWith(t *testing.T, eng *policy.Engine, red *redact.Redactor, serverBin string, serverArgs ...string) *proxySession {
	t.Helper()

	// Build the session first so the onAction closure can append directly
	// to s.events rather than a separate local variable (which would not
	// be reflected in s.events after append reallocates the backing array).
	s := &proxySession{t: t}

	p := NewMCPProxy("test-run-1", serverBin, serverArgs, eng, red, func(ev trace.ActionEvent) {
		s.events = append(s.events, ev)
	})
	s.proxy = p

	if err := p.Start(); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	// Pipes connecting the test harness (acting as the agent) to the proxy.
	agentOutR, agentOutW := io.Pipe() // test writes → proxy reads
	agentInR, agentInW := io.Pipe()   // proxy writes → test reads

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- p.ServeStdio(ctx, agentOutR, agentInW)
		agentInW.Close()
	}()

	s.agentOut = agentOutW
	s.agentIn = agentInR
	s.enc = json.NewEncoder(agentOutW)
	s.scanner = bufio.NewScanner(agentInR)
	s.done = done
	s.cancel = cancel
	s.scanner.Buffer(make([]byte, 1<<20), 1<<20)
	t.Cleanup(s.close)
	return s
}

// eventsPtr returns a pointer to the events slice, useful for assertions after close.
func (s *proxySession) eventsPtr() *[]trace.ActionEvent {
	return &s.events
}

func (s *proxySession) close() {
	s.closeOnce.Do(func() {
		s.agentOut.Close() // signal EOF → ServeStdio scanner unblocks
		s.cancel()
		<-s.done
		s.proxy.Close()
	})
}

// send encodes req and writes it to the proxy input.
func (s *proxySession) send(req any) {
	s.t.Helper()
	if err := s.enc.Encode(req); err != nil {
		s.t.Fatalf("send: %v", err)
	}
}

// recv reads and returns the next response as a parsed map.
func (s *proxySession) recv() map[string]any {
	s.t.Helper()
	if !s.scanner.Scan() {
		s.t.Fatalf("recv: no more data (scanner error: %v)", s.scanner.Err())
	}
	var m map[string]any
	if err := json.Unmarshal(s.scanner.Bytes(), &m); err != nil {
		s.t.Fatalf("recv: unmarshal: %v (raw: %s)", err, s.scanner.Bytes())
	}
	return m
}

// request is a convenience RPC request builder.
func rpc(id any, method string, params any) map[string]any {
	m := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if params != nil {
		m["params"] = params
	}
	return m
}

// ---------------------------------------------------------------------------
// Tests: non-intercepted methods (no ActionEvent created)
// ---------------------------------------------------------------------------

func TestProxy_Initialize_RelayedNoActionEvent(t *testing.T) {
	checkTestServer(t)
	s := newSession(t, testServerBin)

	s.send(rpc(1, "initialize", map[string]any{}))
	resp := s.recv()

	if resp["error"] != nil {
		t.Fatalf("expected no error, got: %v", resp["error"])
	}
	result, _ := resp["result"].(map[string]any)
	if result == nil {
		t.Fatal("expected result map")
	}
	if result["protocolVersion"] != "2024-11-05" {
		t.Errorf("protocolVersion = %v", result["protocolVersion"])
	}

	s.close()
	if len(s.events) != 0 {
		t.Errorf("expected 0 action events for initialize, got %d", len(s.events))
	}
}

func TestProxy_ToolsList_RelayedNoActionEvent(t *testing.T) {
	checkTestServer(t)
	s := newSession(t, testServerBin)

	s.send(rpc(2, "tools/list", map[string]any{}))
	resp := s.recv()

	if resp["error"] != nil {
		t.Fatalf("expected no error: %v", resp["error"])
	}
	result := resp["result"].(map[string]any)
	tools := result["tools"].([]any)
	if len(tools) != 3 {
		t.Errorf("expected 3 tools, got %d", len(tools))
	}

	s.close()
	if len(s.events) != 0 {
		t.Errorf("expected 0 action events for tools/list, got %d", len(s.events))
	}
}

// ---------------------------------------------------------------------------
// Tests: tools/call — intercepted, ActionEvent created
// ---------------------------------------------------------------------------

func TestProxy_ToolCall_Echo_CreatesActionEvent(t *testing.T) {
	checkTestServer(t)
	s := newSession(t, testServerBin)

	s.send(rpc(3, "tools/call", map[string]any{
		"name":      "echo",
		"arguments": map[string]any{"message": "hello proxy"},
	}))
	resp := s.recv()

	if resp["error"] != nil {
		t.Fatalf("unexpected error: %v", resp["error"])
	}

	// Verify tool result forwarded faithfully.
	content := toolContent(t, resp)
	if content != "hello proxy" {
		t.Errorf("echo returned %q, want %q", content, "hello proxy")
	}

	s.close()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 action event, got %d", len(s.events))
	}
	ev := s.events[0]
	if ev.Proto != "mcp" {
		t.Errorf("Proto=%q want mcp", ev.Proto)
	}
	if ev.Method != "tool_call" {
		t.Errorf("Method=%q want tool_call", ev.Method)
	}
	if ev.Target != "echo" {
		t.Errorf("Target=%q want echo", ev.Target)
	}
	if ev.Auth != "allow" {
		t.Errorf("Auth=%q want allow", ev.Auth)
	}
	if ev.Rule != "default" {
		t.Errorf("Rule=%q want default", ev.Rule)
	}
	if ev.Run != "test-run-1" {
		t.Errorf("Run=%q want test-run-1", ev.Run)
	}
	if ev.Seq != 1 {
		t.Errorf("Seq=%d want 1", ev.Seq)
	}
}

func TestProxy_ToolCall_Add_ResultForwarded(t *testing.T) {
	checkTestServer(t)
	s := newSession(t, testServerBin)

	s.send(rpc(4, "tools/call", map[string]any{
		"name":      "add",
		"arguments": map[string]any{"a": 7, "b": 8},
	}))
	resp := s.recv()

	if resp["error"] != nil {
		t.Fatalf("unexpected error: %v", resp["error"])
	}
	content := toolContent(t, resp)
	if content != "15" {
		t.Errorf("add returned %q, want %q", content, "15")
	}

	s.close()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	if s.events[0].Target != "add" {
		t.Errorf("Target=%q want add", s.events[0].Target)
	}
}

func TestProxy_ToolCall_Secret_ActionEventParamsPopulated(t *testing.T) {
	checkTestServer(t)
	s := newSession(t, testServerBin)

	s.send(rpc(5, "tools/call", map[string]any{
		"name":      "secret",
		"arguments": map[string]any{"password": "s3cr3t"},
	}))
	resp := s.recv()

	if resp["error"] != nil {
		t.Fatalf("unexpected error: %v", resp["error"])
	}
	content := toolContent(t, resp)
	if content != "ok" {
		t.Errorf("secret returned %q, want ok", content)
	}

	s.close()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	// Params should be captured (redaction comes in a later step).
	ev := s.events[0]
	if ev.Target != "secret" {
		t.Errorf("Target=%q want secret", ev.Target)
	}
	if ev.Params == nil {
		t.Error("Params should be non-nil")
	}
}

func TestProxy_ToolCall_UnknownTool_ErrorForwardedToAgent(t *testing.T) {
	checkTestServer(t)
	s := newSession(t, testServerBin)

	s.send(rpc(6, "tools/call", map[string]any{
		"name":      "nonexistent",
		"arguments": map[string]any{},
	}))
	resp := s.recv()

	// The server returns a JSON-RPC error; the proxy must forward it unchanged.
	if resp["error"] == nil {
		t.Fatalf("expected error response for unknown tool, got: %v", resp)
	}
	errObj := resp["error"].(map[string]any)
	msg := errObj["message"].(string)
	if !strings.Contains(msg, "nonexistent") {
		t.Errorf("error message %q should mention the unknown tool", msg)
	}

	// An ActionEvent is still created (the attempt was intercepted).
	s.close()
	if len(s.events) != 1 {
		t.Errorf("expected 1 event even for unknown tool, got %d", len(s.events))
	}
}

// ---------------------------------------------------------------------------
// Tests: sequence numbers and multiple requests
// ---------------------------------------------------------------------------

func TestProxy_MultipleRequests_SeqIncremental(t *testing.T) {
	checkTestServer(t)
	s := newSession(t, testServerBin)

	// tools/list — no ActionEvent
	s.send(rpc(1, "tools/list", map[string]any{}))
	s.recv()

	// echo — ActionEvent seq=1
	s.send(rpc(2, "tools/call", map[string]any{
		"name": "echo", "arguments": map[string]any{"message": "a"},
	}))
	s.recv()

	// add — ActionEvent seq=2
	s.send(rpc(3, "tools/call", map[string]any{
		"name": "add", "arguments": map[string]any{"a": 1, "b": 2},
	}))
	s.recv()

	// echo again — ActionEvent seq=3
	s.send(rpc(4, "tools/call", map[string]any{
		"name": "echo", "arguments": map[string]any{"message": "b"},
	}))
	s.recv()

	s.close()
	if len(s.events) != 3 {
		t.Fatalf("expected 3 action events, got %d", len(s.events))
	}
	if s.events[0].Seq != 1 {
		t.Errorf("first event Seq=%d want 1", s.events[0].Seq)
	}
	if s.events[1].Seq != 2 {
		t.Errorf("second event Seq=%d want 2", s.events[1].Seq)
	}
	if s.events[2].Seq != 3 {
		t.Errorf("third event Seq=%d want 3", s.events[2].Seq)
	}
}

func TestProxy_ResponseIDMatchesRequest(t *testing.T) {
	checkTestServer(t)
	s := newSession(t, testServerBin)

	s.send(rpc(42, "tools/call", map[string]any{
		"name": "echo", "arguments": map[string]any{"message": "id-check"},
	}))
	resp := s.recv()

	// The JSON-RPC id should be preserved exactly.
	if id, ok := resp["id"].(float64); !ok || int(id) != 42 {
		t.Errorf("response id = %v, want 42", resp["id"])
	}
}

// ---------------------------------------------------------------------------
// Tests: notification handling (no response expected)
// ---------------------------------------------------------------------------

func TestProxy_Notification_NoHang(t *testing.T) {
	checkTestServer(t)
	s := newSession(t, testServerBin)

	// Send a notification (no id) then a request to verify normal flow continues.
	notif := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	if err := s.enc.Encode(notif); err != nil {
		t.Fatalf("send notification: %v", err)
	}

	// The proxy should not read a response for the notification; subsequent
	// requests must still work.
	s.send(rpc(99, "tools/list", map[string]any{}))
	resp := s.recv()
	if resp["result"] == nil {
		t.Errorf("tools/list after notification failed: %v", resp)
	}

	s.close()
	if len(s.events) != 0 {
		t.Errorf("notification + tools/list should produce 0 events, got %d", len(s.events))
	}
}

// ---------------------------------------------------------------------------
// Tests: ActionEvent fields
// ---------------------------------------------------------------------------

func TestProxy_ActionEvent_RunIDEmbedded(t *testing.T) {
	checkTestServer(t)

	var events []trace.ActionEvent
	p := NewMCPProxy("my-run-id", testServerBin, nil, nil, nil, func(ev trace.ActionEvent) {
		events = append(events, ev)
	})
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { p.Close() })

	agentOutR, agentOutW := io.Pipe()
	agentInR, agentInW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- p.ServeStdio(ctx, agentOutR, agentInW)
		agentInW.Close()
	}()

	enc := json.NewEncoder(agentOutW)
	sc := bufio.NewScanner(agentInR)
	enc.Encode(rpc(1, "tools/call", map[string]any{
		"name": "echo", "arguments": map[string]any{"message": "run-id-test"},
	}))
	sc.Scan()

	agentOutW.Close()
	cancel()
	<-done

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Run != "my-run-id" {
		t.Errorf("Run=%q want my-run-id", events[0].Run)
	}
}

// ---------------------------------------------------------------------------
// Tests: LoadMCPConfig integration (sanity check; proxy reads YAML correctly)
// ---------------------------------------------------------------------------

func TestProxy_NewMCPProxy_NilCallbackNoActionEvent(t *testing.T) {
	checkTestServer(t)
	// When onAction is nil, the proxy must not panic.
	p := NewMCPProxy("run-no-cb", testServerBin, nil, nil, nil, nil)
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	agentOutR, agentOutW := io.Pipe()
	agentInR, agentInW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- p.ServeStdio(ctx, agentOutR, agentInW)
		agentInW.Close()
	}()

	enc := json.NewEncoder(agentOutW)
	sc := bufio.NewScanner(agentInR)
	if err := enc.Encode(rpc(1, "tools/call", map[string]any{
		"name": "echo", "arguments": map[string]any{"message": "no-panic"},
	})); err != nil {
		t.Fatal(err)
	}
	sc.Scan()

	agentOutW.Close()
	cancel()
	<-done
}

// ---------------------------------------------------------------------------
// Tests: malformed input resilience
// ---------------------------------------------------------------------------

func TestProxy_MalformedLine_DoesNotCrash(t *testing.T) {
	checkTestServer(t)
	s := newSession(t, testServerBin)

	// Write garbage to the proxy.
	_, _ = s.agentOut.Write([]byte("this is not json\n"))

	// Proxy should log the error and keep serving.
	s.send(rpc(1, "tools/list", map[string]any{}))
	resp := s.recv()
	if resp["result"] == nil {
		t.Errorf("tools/list after malformed line failed: %v", resp)
	}
}

// ---------------------------------------------------------------------------
// Tests: config integration
// ---------------------------------------------------------------------------

// TestProxy_Start_InvalidCommand verifies that Start() returns an error when
// the server binary does not exist.
func TestProxy_Start_InvalidCommand(t *testing.T) {
	p := NewMCPProxy("run-x", "/nonexistent/binary", nil, nil, nil, nil)
	if err := p.Start(); err == nil {
		p.Close()
		t.Error("expected Start() error for non-existent binary")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// toolContent extracts the first content text from a tools/call response map.
func toolContent(t *testing.T, resp map[string]any) string {
	t.Helper()
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in response: %v", resp)
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("empty content in result: %v", result)
	}
	first := content[0].(map[string]any)
	return first["text"].(string)
}

// captureEvents starts a proxy session with an event buffer, sends requests via
// the given encoded bytes, and returns all collected events.
// Used for integration-style assertions.
func captureEvents(t *testing.T, serverBin string, requests [][]byte) []trace.ActionEvent {
	t.Helper()
	checkTestServer(t)

	var events []trace.ActionEvent
	p := NewMCPProxy("capture-run", serverBin, nil, nil, nil, func(ev trace.ActionEvent) {
		events = append(events, ev)
	})
	if err := p.Start(); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	defer p.Close()

	var agentInput bytes.Buffer
	for _, r := range requests {
		agentInput.Write(r)
		agentInput.WriteByte('\n')
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentOutR := bytes.NewReader(agentInput.Bytes())
	var agentInBuf bytes.Buffer

	_ = p.ServeStdio(ctx, agentOutR, &agentInBuf) // blocks until EOF
	return events
}

// ---------------------------------------------------------------------------
// Policy helpers
// ---------------------------------------------------------------------------

// makeEngine creates an Engine from a simple list of allowed tool names
// and a policy mode.  Everything else is denied by default.
func makeEngine(mode string, allowedTools ...string) *policy.Engine {
	rules := make([]policy.Rule, len(allowedTools))
	for i, name := range allowedTools {
		rules[i] = policy.Rule{
			ID:       "allow-" + name,
			Protocol: "mcp",
			Method:   "tool_call",
			Target:   name,
			Action:   "allow",
		}
	}
	p := &policy.Policy{
		Version: "1",
		Agent:   policy.AgentIdentity{Name: "test"},
		Mode:    mode,
		Default: "deny",
		Rules:   rules,
	}
	return policy.NewEngine(p)
}

// ---------------------------------------------------------------------------
// Policy: enforce mode
// ---------------------------------------------------------------------------

// TestProxy_Enforce_AllowedActionForwarded verifies that an allowed action
// reaches the real server and the trace event carries auth="allow".
func TestProxy_Enforce_AllowedActionForwarded(t *testing.T) {
	checkTestServer(t)
	eng := makeEngine("enforce", "echo")
	s := newSessionWithEngine(t, eng, testServerBin)

	s.send(rpc(1, "tools/call", map[string]any{
		"name": "echo", "arguments": map[string]any{"message": "hello-allowed"},
	}))
	resp := s.recv()

	if resp["error"] != nil {
		t.Fatalf("expected success, got error: %v", resp["error"])
	}
	got := toolContent(t, resp)
	if got != "hello-allowed" {
		t.Errorf("echo content=%q want hello-allowed", got)
	}

	s.close()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	ev := s.events[0]
	if ev.Auth != "allow" {
		t.Errorf("Auth=%q want allow", ev.Auth)
	}
	if ev.Rule != "allow-echo" {
		t.Errorf("Rule=%q want allow-echo", ev.Rule)
	}
}

// TestProxy_Enforce_DeniedActionBlocked verifies that a denied action is NOT
// forwarded to the server and the agent receives a JSON-RPC error.
func TestProxy_Enforce_DeniedActionBlocked(t *testing.T) {
	checkTestServer(t)
	eng := makeEngine("enforce", "echo") // "add" is not in the allow list
	s := newSessionWithEngine(t, eng, testServerBin)

	s.send(rpc(2, "tools/call", map[string]any{
		"name": "add", "arguments": map[string]any{"a": 1, "b": 2},
	}))
	resp := s.recv()

	errField, hasErr := resp["error"]
	if !hasErr || errField == nil {
		t.Fatalf("expected JSON-RPC error for denied action, got: %v", resp)
	}
	errMap := errField.(map[string]any)
	if code := errMap["code"]; code != float64(-32600) {
		t.Errorf("error.code=%v want -32600", code)
	}
	if msg := errMap["message"]; msg != "Action denied by policy" {
		t.Errorf("error.message=%q want 'Action denied by policy'", msg)
	}
	data := errMap["data"].(map[string]any)
	if data["target"] != "add" {
		t.Errorf("error.data.target=%q want add", data["target"])
	}

	s.close()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event for denied action, got %d", len(s.events))
	}
	ev := s.events[0]
	if ev.Auth != "deny" {
		t.Errorf("Auth=%q want deny", ev.Auth)
	}
	if ev.Target != "add" {
		t.Errorf("Target=%q want add", ev.Target)
	}
}

// TestProxy_Enforce_DeniedAction_ServerNeverSees verifies that the server did
// NOT receive the denied call by sending an allowed call afterward and
// checking that the server only saw the one allowed call.
func TestProxy_Enforce_DeniedAction_ServerNeverSees(t *testing.T) {
	checkTestServer(t)
	eng := makeEngine("enforce", "echo")
	s := newSessionWithEngine(t, eng, testServerBin)

	// Send denied call ("add" not allowed).
	s.send(rpc(1, "tools/call", map[string]any{
		"name": "add", "arguments": map[string]any{"a": 1, "b": 2},
	}))
	resp := s.recv()
	if resp["error"] == nil {
		t.Fatal("expected error for denied add call")
	}

	// Send allowed call; server should respond normally (not confused by missing denied req).
	s.send(rpc(2, "tools/call", map[string]any{
		"name": "echo", "arguments": map[string]any{"message": "only-me"},
	}))
	resp = s.recv()
	if resp["error"] != nil {
		t.Fatalf("echo after denied add got error: %v", resp["error"])
	}
	if got := toolContent(t, resp); got != "only-me" {
		t.Errorf("echo content=%q want only-me", got)
	}

	s.close()
	// 2 events: 1 denied add + 1 allowed echo.
	if len(s.events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(s.events))
	}
	if s.events[0].Auth != "deny" {
		t.Errorf("events[0].Auth=%q want deny", s.events[0].Auth)
	}
	if s.events[1].Auth != "allow" {
		t.Errorf("events[1].Auth=%q want allow", s.events[1].Auth)
	}
}

// TestProxy_Enforce_DefaultDeny_NoRules verifies that with no rules and
// default=deny, all actions are blocked.
func TestProxy_Enforce_DefaultDeny_NoRules(t *testing.T) {
	checkTestServer(t)
	eng := makeEngine("enforce") // no allowed tools
	s := newSessionWithEngine(t, eng, testServerBin)

	s.send(rpc(1, "tools/call", map[string]any{
		"name": "echo", "arguments": map[string]any{"message": "blocked"},
	}))
	resp := s.recv()
	if resp["error"] == nil {
		t.Fatal("expected error with no-rules enforce policy")
	}

	s.close()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	if s.events[0].Auth != "deny" {
		t.Errorf("Auth=%q want deny", s.events[0].Auth)
	}
	if s.events[0].Rule != "default" {
		t.Errorf("Rule=%q want default", s.events[0].Rule)
	}
}

// ---------------------------------------------------------------------------
// Policy: audit mode
// ---------------------------------------------------------------------------

// TestProxy_Audit_DeniedActionStillForwarded verifies that in audit mode,
// a "would-deny" action is still forwarded and trace shows auth="audit_deny".
func TestProxy_Audit_DeniedActionStillForwarded(t *testing.T) {
	checkTestServer(t)
	eng := makeEngine("audit", "echo") // "add" would be denied
	s := newSessionWithEngine(t, eng, testServerBin)

	s.send(rpc(1, "tools/call", map[string]any{
		"name": "add", "arguments": map[string]any{"a": 3, "b": 4},
	}))
	resp := s.recv()

	// In audit mode, the action proceeds — no error.
	if resp["error"] != nil {
		t.Fatalf("audit mode should allow action, got error: %v", resp["error"])
	}
	got := toolContent(t, resp)
	if got != "7" {
		t.Errorf("add result=%q want 7", got)
	}

	s.close()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	ev := s.events[0]
	if ev.Auth != "audit_deny" {
		t.Errorf("Auth=%q want audit_deny", ev.Auth)
	}
}

// TestProxy_Audit_AllowedAction verifies that an explicitly allowed action
// in audit mode records auth="allow".
func TestProxy_Audit_AllowedAction(t *testing.T) {
	checkTestServer(t)
	eng := makeEngine("audit", "echo")
	s := newSessionWithEngine(t, eng, testServerBin)

	s.send(rpc(1, "tools/call", map[string]any{
		"name": "echo", "arguments": map[string]any{"message": "audit-ok"},
	}))
	resp := s.recv()

	if resp["error"] != nil {
		t.Fatalf("unexpected error: %v", resp["error"])
	}

	s.close()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	if s.events[0].Auth != "allow" {
		t.Errorf("Auth=%q want allow", s.events[0].Auth)
	}
}

// ---------------------------------------------------------------------------
// Policy: permissive mode
// ---------------------------------------------------------------------------

// TestProxy_Permissive_AllActionsForwarded verifies that in permissive mode
// denied actions are forwarded and trace shows auth="would_deny".
func TestProxy_Permissive_AllActionsForwarded(t *testing.T) {
	checkTestServer(t)
	eng := makeEngine("permissive", "echo") // "add" would be denied
	s := newSessionWithEngine(t, eng, testServerBin)

	s.send(rpc(1, "tools/call", map[string]any{
		"name": "add", "arguments": map[string]any{"a": 10, "b": 10},
	}))
	resp := s.recv()

	if resp["error"] != nil {
		t.Fatalf("permissive mode should forward all, got error: %v", resp["error"])
	}
	got := toolContent(t, resp)
	if got != "20" {
		t.Errorf("add result=%q want 20", got)
	}

	s.close()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	ev := s.events[0]
	if ev.Auth != "would_deny" {
		t.Errorf("Auth=%q want would_deny", ev.Auth)
	}
}

// ---------------------------------------------------------------------------
// Policy: nil engine (no policy — permissive default)
// ---------------------------------------------------------------------------

// TestProxy_NilEngine_AllActionsAllowed verifies that with no engine, all
// actions are forwarded and traced as auth="allow".
func TestProxy_NilEngine_AllActionsAllowed(t *testing.T) {
	checkTestServer(t)
	s := newSession(t, testServerBin) // nil engine

	s.send(rpc(1, "tools/call", map[string]any{
		"name": "add", "arguments": map[string]any{"a": 5, "b": 5},
	}))
	resp := s.recv()
	if resp["error"] != nil {
		t.Fatalf("unexpected error with nil engine: %v", resp["error"])
	}

	s.close()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	if s.events[0].Auth != "allow" {
		t.Errorf("Auth=%q want allow", s.events[0].Auth)
	}
}

// ---------------------------------------------------------------------------
// Policy: error response structure
// ---------------------------------------------------------------------------

// TestProxy_DenialResponse_ContainsRuleAndTarget verifies the full JSON-RPC
// error shape returned for a denied action.
func TestProxy_DenialResponse_ContainsRuleAndTarget(t *testing.T) {
	checkTestServer(t)
	eng := makeEngine("enforce") // deny everything
	s := newSessionWithEngine(t, eng, testServerBin)

	s.send(rpc(42, "tools/call", map[string]any{
		"name": "secret", "arguments": map[string]any{"password": "pw"},
	}))
	resp := s.recv()

	if resp["error"] == nil {
		t.Fatal("expected error")
	}
	// id must be preserved.
	if resp["id"] != float64(42) {
		t.Errorf("response id=%v want 42", resp["id"])
	}
	errMap := resp["error"].(map[string]any)
	data := errMap["data"].(map[string]any)
	if data["target"] != "secret" {
		t.Errorf("data.target=%q want secret", data["target"])
	}
	if data["rule"] != "default" {
		t.Errorf("data.rule=%q want default", data["rule"])
	}
}

// ---------------------------------------------------------------------------
// Redaction via proxy
// ---------------------------------------------------------------------------

// TestProxy_Redaction_PasswordRedactedInTrace verifies that a parameter key
// matching the redaction list is replaced in the trace event params.
func TestProxy_Redaction_PasswordRedactedInTrace(t *testing.T) {
	checkTestServer(t)

	red := redact.NewRedactor(policy.RedactionConfig{Keys: []string{"password"}})
	s := newSessionWith(t, nil, red, testServerBin)

	s.send(rpc(1, "tools/call", map[string]any{
		"name": "secret", "arguments": map[string]any{"password": "super-secret"},
	}))
	s.recv() // response forwarded to agent

	s.close()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}

	// Verify that the raw params in the trace contain [REDACTED] not the secret.
	ev := s.events[0]
	paramsJSON, err := json.Marshal(ev.Params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	if strings.Contains(string(paramsJSON), "super-secret") {
		t.Errorf("secret value should not appear in trace params: %s", paramsJSON)
	}
	if !strings.Contains(string(paramsJSON), "[REDACTED]") {
		t.Errorf("trace params should contain [REDACTED]: %s", paramsJSON)
	}
}

// TestProxy_Redaction_NonMatchingKey_Untouched verifies that non-matching keys
// are preserved in the trace event.
func TestProxy_Redaction_NonMatchingKey_Untouched(t *testing.T) {
	checkTestServer(t)

	red := redact.NewRedactor(policy.RedactionConfig{Keys: []string{"password"}})
	s := newSessionWith(t, nil, red, testServerBin)

	s.send(rpc(1, "tools/call", map[string]any{
		"name": "echo", "arguments": map[string]any{"message": "hello-world"},
	}))
	s.recv()

	s.close()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}

	paramsJSON, _ := json.Marshal(s.events[0].Params)
	if !strings.Contains(string(paramsJSON), "hello-world") {
		t.Errorf("non-matching key should appear in trace: %s", paramsJSON)
	}
}

// TestProxy_Redaction_NilRedactor_ParamsPassedThrough verifies that with no
// redactor the params are written to the trace unchanged.
func TestProxy_Redaction_NilRedactor_ParamsPassedThrough(t *testing.T) {
	checkTestServer(t)

	s := newSession(t, testServerBin) // nil redactor

	s.send(rpc(1, "tools/call", map[string]any{
		"name": "secret", "arguments": map[string]any{"password": "visible"},
	}))
	s.recv()

	s.close()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}

	paramsJSON, _ := json.Marshal(s.events[0].Params)
	if !strings.Contains(string(paramsJSON), "visible") {
		t.Errorf("with nil redactor, params should be visible in trace: %s", paramsJSON)
	}
}

// TestProxy_Redaction_DeniedAction_ParamsRedactedInTrace verifies that even for
// denied actions, the trace event has redacted params.
func TestProxy_Redaction_DeniedAction_ParamsRedactedInTrace(t *testing.T) {
	checkTestServer(t)

	eng := makeEngine("enforce") // deny everything
	red := redact.NewRedactor(policy.RedactionConfig{Keys: []string{"password"}})
	s := newSessionWith(t, eng, red, testServerBin)

	s.send(rpc(1, "tools/call", map[string]any{
		"name": "secret", "arguments": map[string]any{"password": "should-not-appear"},
	}))
	resp := s.recv()
	if resp["error"] == nil {
		t.Fatal("expected denial error")
	}

	s.close()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}

	paramsJSON, _ := json.Marshal(s.events[0].Params)
	if strings.Contains(string(paramsJSON), "should-not-appear") {
		t.Errorf("secret should not appear in denied trace event: %s", paramsJSON)
	}
	if !strings.Contains(string(paramsJSON), "[REDACTED]") {
		t.Errorf("denied trace event should contain [REDACTED]: %s", paramsJSON)
	}
}

// ---------------------------------------------------------------------------
// Tests: tool call provenance (_context extraction)
// ---------------------------------------------------------------------------

// TestProxy_ToolCall_WithoutContext_NoCtxInTrace verifies that a normal tool
// call without _context produces no ctx field in the trace event and the
// forwarded message is unchanged.
func TestProxy_ToolCall_WithoutContext_NoCtxInTrace(t *testing.T) {
	checkTestServer(t)
	s := newSession(t, testServerBin)

	s.send(rpc(1, "tools/call", map[string]any{
		"name":      "echo",
		"arguments": map[string]any{"message": "no-context"},
	}))
	resp := s.recv()

	if resp["error"] != nil {
		t.Fatalf("unexpected error: %v", resp["error"])
	}
	if got := toolContent(t, resp); got != "no-context" {
		t.Errorf("echo returned %q, want %q", got, "no-context")
	}

	s.close()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	if s.events[0].Ctx != nil {
		t.Errorf("Ctx should be nil when no _context, got %v", s.events[0].Ctx)
	}
}

// TestProxy_ToolCall_WithContext_CtxInTraceAndStripped verifies that _context
// is extracted into the trace event's Ctx field and stripped from the arguments
// before forwarding to the server.
func TestProxy_ToolCall_WithContext_CtxInTraceAndStripped(t *testing.T) {
	checkTestServer(t)
	s := newSession(t, testServerBin)

	s.send(rpc(1, "tools/call", map[string]any{
		"name": "echo",
		"arguments": map[string]any{
			"message":  "with-context",
			"_context": map[string]any{"source": "test-agent", "purpose": "testing"},
		},
	}))
	resp := s.recv()

	if resp["error"] != nil {
		t.Fatalf("unexpected error: %v", resp["error"])
	}
	if got := toolContent(t, resp); got != "with-context" {
		t.Errorf("echo returned %q, want %q", got, "with-context")
	}

	s.close()
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	ev := s.events[0]

	// Ctx should be populated with the _context value.
	if ev.Ctx == nil {
		t.Fatal("Ctx should be non-nil when _context is present")
	}
	ctxJSON, err := json.Marshal(ev.Ctx)
	if err != nil {
		t.Fatalf("marshal Ctx: %v", err)
	}
	if !strings.Contains(string(ctxJSON), "test-agent") {
		t.Errorf("Ctx should contain source value: %s", ctxJSON)
	}

	// Trace params should NOT contain _context.
	paramsJSON, _ := json.Marshal(ev.Params)
	if strings.Contains(string(paramsJSON), "_context") {
		t.Errorf("trace params should not contain _context: %s", paramsJSON)
	}
	if !strings.Contains(string(paramsJSON), "with-context") {
		t.Errorf("trace params should still contain message value: %s", paramsJSON)
	}
}

// TestProxy_CaptureMultipleToolCalls verifies the full round-trip for several
// tool calls in one session, checking both the responses and ActionEvents.
func TestProxy_CaptureMultipleToolCalls(t *testing.T) {
	checkTestServer(t)

	req1, _ := json.Marshal(rpc(1, "tools/call", map[string]any{
		"name": "echo", "arguments": map[string]any{"message": "first"},
	}))
	req2, _ := json.Marshal(rpc(2, "tools/call", map[string]any{
		"name": "add", "arguments": map[string]any{"a": 10, "b": 5},
	}))
	req3, _ := json.Marshal(rpc(3, "tools/list", map[string]any{}))
	req4, _ := json.Marshal(rpc(4, "tools/call", map[string]any{
		"name": "secret", "arguments": map[string]any{"password": "pw"},
	}))

	events := captureEvents(t, testServerBin, [][]byte{req1, req2, req3, req4})

	// 3 tool calls → 3 events; tools/list → no event.
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	wantTargets := []string{"echo", "add", "secret"}
	for i, ev := range events {
		if ev.Target != wantTargets[i] {
			t.Errorf("events[%d].Target=%q want %q", i, ev.Target, wantTargets[i])
		}
		if ev.Proto != "mcp" {
			t.Errorf("events[%d].Proto=%q want mcp", i, ev.Proto)
		}
		if ev.Method != "tool_call" {
			t.Errorf("events[%d].Method=%q want tool_call", i, ev.Method)
		}
		if ev.Auth != "allow" {
			t.Errorf("events[%d].Auth=%q want allow", i, ev.Auth)
		}
	}
}
