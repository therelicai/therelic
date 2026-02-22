package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/therelicai/therelic/internal/policy"
	"github.com/therelicai/therelic/internal/redact"
	"github.com/therelicai/therelic/internal/trace"
)

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

// httpSession manages a started HTTPLogger for a single test.
type httpSession struct {
	logger *HTTPLogger
	events []trace.ActionEvent
	port   int
}

func newHTTPSession(t *testing.T, eng *policy.Engine, red *redact.Redactor) *httpSession {
	t.Helper()
	s := &httpSession{}
	s.logger = NewHTTPLogger("http-test-run", eng, red, func(ev trace.ActionEvent) {
		s.events = append(s.events, ev)
	})
	port, err := s.logger.Start()
	if err != nil {
		t.Fatalf("HTTPLogger.Start: %v", err)
	}
	s.port = port
	t.Cleanup(func() { s.logger.Close() })
	return s
}

// proxyClient returns an http.Client configured to use the HTTPLogger as proxy.
func (s *httpSession) proxyClient() *http.Client {
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", s.port))
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
}

// allowAllEngine creates an engine that allows all HTTP/HTTPS actions.
func allowAllEngine(mode string) *policy.Engine {
	p := &policy.Policy{
		Version: "1",
		Agent:   policy.AgentIdentity{Name: "test"},
		Mode:    mode,
		Default: "allow",
	}
	return policy.NewEngine(p)
}

// denyAllEngine creates an engine that denies all HTTP/HTTPS actions.
func denyAllEngine(mode string) *policy.Engine {
	p := &policy.Policy{
		Version: "1",
		Agent:   policy.AgentIdentity{Name: "test"},
		Mode:    mode,
		Default: "deny",
	}
	return policy.NewEngine(p)
}

// allowHTTPEngine allows a specific HTTP method+host combination, denies rest.
func allowHTTPEngine(proto, method, target string) *policy.Engine {
	p := &policy.Policy{
		Version: "1",
		Agent:   policy.AgentIdentity{Name: "test"},
		Mode:    "enforce",
		Default: "deny",
		Rules: []policy.Rule{
			{ID: "allow-target", Protocol: proto, Method: method, Target: target, Action: "allow"},
		},
	}
	return policy.NewEngine(p)
}

// ---------------------------------------------------------------------------
// HTTPLogger lifecycle
// ---------------------------------------------------------------------------

func TestHTTPLogger_StartStop(t *testing.T) {
	logger := NewHTTPLogger("run-1", nil, nil, nil)
	port, err := logger.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if port == 0 {
		t.Error("expected non-zero port")
	}
	addr := logger.Addr()
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Errorf("Addr=%q want 127.0.0.1:<port>", addr)
	}
	if err := logger.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestHTTPLogger_Close_BeforeStart_NoError(t *testing.T) {
	logger := NewHTTPLogger("run-1", nil, nil, nil)
	if err := logger.Close(); err != nil {
		t.Errorf("Close before Start: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Plaintext HTTP: allowed
// ---------------------------------------------------------------------------

func TestHTTPLogger_HTTP_AllowedRequest_Forwarded(t *testing.T) {
	// Real HTTP target
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "pong")
	}))
	defer target.Close()

	s := newHTTPSession(t, allowAllEngine("enforce"), nil)
	client := s.proxyClient()

	resp, err := client.Get(target.URL + "/ping")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "pong" {
		t.Errorf("body=%q want pong", body)
	}

	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	ev := s.events[0]
	if ev.Proto != "http" {
		t.Errorf("Proto=%q want http", ev.Proto)
	}
	if ev.Method != "GET" {
		t.Errorf("Method=%q want GET", ev.Method)
	}
	if ev.Auth != "allow" {
		t.Errorf("Auth=%q want allow", ev.Auth)
	}
	if !strings.Contains(ev.Target, "/ping") {
		t.Errorf("Target=%q want to contain /ping", ev.Target)
	}
}

// ---------------------------------------------------------------------------
// Plaintext HTTP: denied
// ---------------------------------------------------------------------------

func TestHTTPLogger_HTTP_DeniedRequest_Returns403(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	s := newHTTPSession(t, denyAllEngine("enforce"), nil)
	client := s.proxyClient()

	resp, err := client.Get(target.URL + "/secret")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status=%d want 403", resp.StatusCode)
	}

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck
	if body["error"] != "Action denied by The Relic policy" {
		t.Errorf("body.error=%q", body["error"])
	}

	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	if s.events[0].Auth != "deny" {
		t.Errorf("Auth=%q want deny", s.events[0].Auth)
	}
}

// ---------------------------------------------------------------------------
// Plaintext HTTP: audit mode
// ---------------------------------------------------------------------------

func TestHTTPLogger_HTTP_AuditMode_DeniedActionForwarded(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "audit-pong")
	}))
	defer target.Close()

	s := newHTTPSession(t, denyAllEngine("audit"), nil)
	client := s.proxyClient()

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	// In audit mode, the request proceeds.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d want 200 in audit mode", resp.StatusCode)
	}
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	if s.events[0].Auth != "audit_deny" {
		t.Errorf("Auth=%q want audit_deny", s.events[0].Auth)
	}
}

// ---------------------------------------------------------------------------
// Plaintext HTTP: permissive mode
// ---------------------------------------------------------------------------

func TestHTTPLogger_HTTP_PermissiveMode_WouldDeny(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	s := newHTTPSession(t, denyAllEngine("permissive"), nil)
	client := s.proxyClient()

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d want 200 in permissive mode", resp.StatusCode)
	}
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	if s.events[0].Auth != "would_deny" {
		t.Errorf("Auth=%q want would_deny", s.events[0].Auth)
	}
}

// ---------------------------------------------------------------------------
// Plaintext HTTP: nil engine (no policy)
// ---------------------------------------------------------------------------

func TestHTTPLogger_HTTP_NilEngine_AllAllowed(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	s := newHTTPSession(t, nil, nil) // nil engine
	client := s.proxyClient()

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d want 200", resp.StatusCode)
	}
	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	if s.events[0].Auth != "allow" {
		t.Errorf("Auth=%q want allow", s.events[0].Auth)
	}
}

// ---------------------------------------------------------------------------
// Plaintext HTTP: trace event fields
// ---------------------------------------------------------------------------

func TestHTTPLogger_HTTP_TraceEvent_RunIDEmbedded(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	logger := NewHTTPLogger("my-run-99", nil, nil, nil)
	var events []trace.ActionEvent
	logger.onAction = func(ev trace.ActionEvent) { events = append(events, ev) }
	_, err := logger.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer logger.Close()

	proxyURL, _ := url.Parse("http://" + logger.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Run != "my-run-99" {
		t.Errorf("Run=%q want my-run-99", events[0].Run)
	}
}

func TestHTTPLogger_HTTP_TraceEvent_SeqIncremental(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	s := newHTTPSession(t, nil, nil)
	client := s.proxyClient()

	for i := 0; i < 3; i++ {
		resp, err := client.Get(target.URL)
		if err != nil {
			t.Fatalf("GET #%d: %v", i, err)
		}
		resp.Body.Close()
	}

	if len(s.events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(s.events))
	}
	if s.events[0].Seq >= s.events[1].Seq || s.events[1].Seq >= s.events[2].Seq {
		t.Errorf("seq not incremental: %v %v %v", s.events[0].Seq, s.events[1].Seq, s.events[2].Seq)
	}
}

func TestHTTPLogger_HTTP_TraceEvent_ParamsContainHeaders(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	s := newHTTPSession(t, nil, nil)
	client := s.proxyClient()

	req, _ := http.NewRequest("GET", target.URL, nil)
	req.Header.Set("X-Custom-Header", "my-value")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	paramsJSON, _ := json.Marshal(s.events[0].Params)
	if !strings.Contains(string(paramsJSON), "X-Custom-Header") {
		t.Errorf("trace params should contain X-Custom-Header: %s", paramsJSON)
	}
}

// ---------------------------------------------------------------------------
// HTTPS CONNECT: allowed
// ---------------------------------------------------------------------------

func TestHTTPLogger_CONNECT_AllowedTunnel(t *testing.T) {
	// We test CONNECT by sending a raw HTTP/1.1 CONNECT request via TCP and
	// verifying the "200 Connection Established" response.
	s := newHTTPSession(t, allowAllEngine("enforce"), nil)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(line, "200") {
		t.Errorf("CONNECT response=%q want 200", strings.TrimSpace(line))
	}
}

// ---------------------------------------------------------------------------
// HTTPS CONNECT: denied
// ---------------------------------------------------------------------------

func TestHTTPLogger_CONNECT_DeniedRequest_Returns403(t *testing.T) {
	s := newHTTPSession(t, denyAllEngine("enforce"), nil)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT blocked.example.com:443 HTTP/1.1\r\nHost: blocked.example.com:443\r\n\r\n")

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(line, "403") {
		t.Errorf("CONNECT denied response=%q want 403", strings.TrimSpace(line))
	}

	// Give the goroutine time to call onAction.
	// (The event is emitted after the response is sent for denials.)
}

func TestHTTPLogger_CONNECT_DeniedRequest_TraceEventRecorded(t *testing.T) {
	s := newHTTPSession(t, denyAllEngine("enforce"), nil)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT secret.api.com:443 HTTP/1.1\r\nHost: secret.api.com:443\r\n\r\n")
	bufio.NewReader(conn).ReadString('\n') //nolint:errcheck

	// Wait briefly for the event to be recorded.
	deadline := make(chan struct{})
	go func() {
		// small busy-wait; acceptable in tests
		for i := 0; i < 50; i++ {
			if len(s.events) > 0 {
				break
			}
		}
		close(deadline)
	}()
	<-deadline

	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	ev := s.events[0]
	if ev.Proto != "https" {
		t.Errorf("Proto=%q want https", ev.Proto)
	}
	if ev.Method != "CONNECT" {
		t.Errorf("Method=%q want CONNECT", ev.Method)
	}
	if ev.Target != "secret.api.com:443" {
		t.Errorf("Target=%q want secret.api.com:443", ev.Target)
	}
	if ev.Auth != "deny" {
		t.Errorf("Auth=%q want deny", ev.Auth)
	}
}

// ---------------------------------------------------------------------------
// HTTP redaction
// ---------------------------------------------------------------------------

func TestHTTPLogger_HTTP_HeadersRedacted_InTrace(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	red := redact.NewRedactor(policy.RedactionConfig{Headers: []string{"Authorization"}})
	s := newHTTPSession(t, nil, red)
	client := s.proxyClient()

	req, _ := http.NewRequest("GET", target.URL, nil)
	req.Header.Set("Authorization", "Bearer super-secret-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if len(s.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.events))
	}
	paramsJSON, _ := json.Marshal(s.events[0].Params)
	if strings.Contains(string(paramsJSON), "super-secret-token") {
		t.Errorf("secret token should not appear in trace: %s", paramsJSON)
	}
	if !strings.Contains(string(paramsJSON), "[REDACTED]") {
		t.Errorf("trace should contain [REDACTED]: %s", paramsJSON)
	}
	if !strings.Contains(string(paramsJSON), "application/json") {
		t.Errorf("non-matching header should still appear: %s", paramsJSON)
	}
}
