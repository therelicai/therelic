package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/therelicai/therelic/internal/policy"
	"github.com/therelicai/therelic/internal/redact"
	"github.com/therelicai/therelic/internal/trace"
)

// httpProxyTransport is the RoundTripper used to forward plaintext HTTP
// requests upstream. Building a dedicated Transport (rather than reusing
// http.DefaultTransport) lets us bound dial, TLS handshake, response
// header, and idle timeouts, so a slow / hostile upstream can't pin the
// proxy goroutine indefinitely.
var httpProxyTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          50,
	MaxIdleConnsPerHost:   10,
	IdleConnTimeout:       60 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
}

// maxResponseBytes caps how much body we'll relay from an upstream HTTP
// response back to the agent. 50 MiB is enormous for any reasonable
// tool call response while still preventing OOM from a malicious or
// runaway upstream streaming forever.
const maxResponseBytes = 50 * 1024 * 1024

// HTTPLogger is a forward proxy that logs HTTP/HTTPS metadata for audit.
//
// Architecture §6.1:
//   - Plaintext HTTP: full request/response capture, policy checked on method+URL.
//   - HTTPS (CONNECT): blind tunnel; policy checked at host:port level only.
//
// Start() binds to a random port on 127.0.0.1. The caller sets HTTP_PROXY and
// HTTPS_PROXY environment variables on the child process to point at this address.
type HTTPLogger struct {
	runID    string
	engine   *policy.Engine
	redactor *redact.Redactor
	onAction func(trace.ActionEvent)

	server   *http.Server
	listener net.Listener

	dnsAllow []string
	dnsDeny  []string

	startTime   time.Time
	actionCount int32 // atomic — used for RunState constraint tracking
	seq         int32 // atomic — trace sequence numbers
}

// NewHTTPLogger creates an HTTPLogger. engine and redactor may be nil (permissive /
// no redaction). onAction is called synchronously for every intercepted request.
func NewHTTPLogger(runID string, engine *policy.Engine, red *redact.Redactor, onAction func(trace.ActionEvent)) *HTTPLogger {
	return &HTTPLogger{
		runID:     runID,
		engine:    engine,
		redactor:  red,
		onAction:  onAction,
		startTime: time.Now(),
	}
}

// SetNetworkPolicy configures DNS-level allow/deny lists for outbound connections.
// Deny list is checked first (takes precedence). If allow list is non-empty,
// host must match at least one allow pattern.
func (h *HTTPLogger) SetNetworkPolicy(dnsAllow, dnsDeny []string) {
	h.dnsAllow = dnsAllow
	h.dnsDeny = dnsDeny
}

// Start binds to an ephemeral port on 127.0.0.1 and begins serving.
// Returns the bound port so the caller can set HTTP_PROXY/HTTPS_PROXY.
func (h *HTTPLogger) Start() (port int, err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("http logger: listen: %w", err)
	}
	h.listener = ln
	h.server = &http.Server{
		Handler: h,
		// Bound the time we'll wait for an agent's request headers
		// before tearing the connection down. Without this, a stuck
		// agent connection holds a goroutine forever.
		ReadHeaderTimeout: 10 * time.Second,
	}
	go h.server.Serve(ln) //nolint:errcheck
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// Addr returns the listening address, e.g. "127.0.0.1:52341".
// Empty string before Start() is called.
func (h *HTTPLogger) Addr() string {
	if h.listener == nil {
		return ""
	}
	return h.listener.Addr().String()
}

// Close gracefully shuts down the proxy server.
func (h *HTTPLogger) Close() error {
	if h.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return h.server.Shutdown(ctx)
}

// ---------------------------------------------------------------------------
// http.Handler dispatch
// ---------------------------------------------------------------------------

// ServeHTTP dispatches CONNECT requests (HTTPS tunnels) to handleConnect and
// all other methods (plaintext HTTP) to handleHTTP.
func (h *HTTPLogger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
	} else {
		h.handleHTTP(w, r)
	}
}

// ---------------------------------------------------------------------------
// Plaintext HTTP
// ---------------------------------------------------------------------------

func (h *HTTPLogger) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host := extractHost(r.URL)
	if denyResult := h.checkNetworkPolicy(host); denyResult != nil {
		seq := int(atomic.AddInt32(&h.seq, 1))
		atomic.AddInt32(&h.actionCount, 1)
		h.emit(seq, "http", r.Method, r.URL.String(), json.RawMessage(`{}`), *denyResult)
		h.writeDeniedHTTP(w, *denyResult, r.URL.String())
		return
	}

	target := r.URL.String()

	// Build params: headers (redacted) + body size.
	rawHeaders := flattenHeaders(r.Header)
	if h.redactor != nil {
		rawHeaders = h.redactor.RedactHeaders(rawHeaders)
	}
	paramsMap := map[string]any{
		"headers":   rawHeaders,
		"body_size": r.ContentLength,
	}
	paramsJSON, _ := json.Marshal(paramsMap)
	// Also apply key-level redaction to the params object itself.
	if h.redactor != nil {
		paramsJSON = h.redactor.RedactParams(paramsJSON)
	}

	result := h.evaluate("http", r.Method, target)
	seq := int(atomic.AddInt32(&h.seq, 1))
	atomic.AddInt32(&h.actionCount, 1)

	if result.IsDenied() {
		h.emit(seq, "http", r.Method, target, paramsJSON, result)
		h.writeDeniedHTTP(w, result, target)
		return
	}

	// Forward the request to the real server.
	outReq := r.Clone(r.Context())
	outReq.RequestURI = "" // must be cleared for outbound requests
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authenticate")
	outReq.Header.Del("Proxy-Authorization")

	resp, err := httpProxyTransport.RoundTrip(outReq)
	if err != nil {
		// Don't leak the transport error to the agent — DNS failures,
		// internal IPs, and OS-level error strings all surface here
		// and an adversarial agent can use them for fingerprinting.
		// The detail is still recorded in the trace and proxy logs.
		http.Error(w, "bad gateway", http.StatusBadGateway)
		h.emit(seq, "http", r.Method, target, paramsJSON, result)
		return
	}
	defer resp.Body.Close()

	h.emit(seq, "http", r.Method, target, paramsJSON, result)

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// LimitReader caps the relayed body so an upstream that streams
	// forever (or an attacker's gzip bomb pre-expansion) can't exhaust
	// the proxy's memory.
	io.Copy(w, io.LimitReader(resp.Body, maxResponseBytes)) //nolint:errcheck
}

// ---------------------------------------------------------------------------
// HTTPS CONNECT tunnel
// ---------------------------------------------------------------------------

func (h *HTTPLogger) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host // "host:port"

	hostOnly := target
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		hostOnly = target[:idx]
	}
	if denyResult := h.checkNetworkPolicy(hostOnly); denyResult != nil {
		seq := int(atomic.AddInt32(&h.seq, 1))
		atomic.AddInt32(&h.actionCount, 1)
		h.emit(seq, "https", "CONNECT", target, json.RawMessage(`{}`), *denyResult)
		h.writeDeniedHTTP(w, *denyResult, target)
		return
	}

	result := h.evaluate("https", "CONNECT", target)
	seq := int(atomic.AddInt32(&h.seq, 1))
	atomic.AddInt32(&h.actionCount, 1)

	if result.IsDenied() {
		h.emit(seq, "https", "CONNECT", target, json.RawMessage(`{}`), result)
		h.writeDeniedHTTP(w, result, target)
		return
	}

	serverConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		// Same reasoning as the plaintext path — don't leak the
		// dial error message to the agent. Logging happens server-side.
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer serverConn.Close()

	// Hijack the client connection.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "server does not support hijacking", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	// Acknowledge the CONNECT and emit the trace event.
	fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	h.emit(seq, "https", "CONNECT", target, json.RawMessage(`{}`), result)

	// Tunnel bidirectionally until one side closes.
	done := make(chan struct{}, 1)
	go func() {
		io.Copy(serverConn, clientConn) //nolint:errcheck
		done <- struct{}{}
	}()
	io.Copy(clientConn, serverConn) //nolint:errcheck
	<-done
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// evaluate builds an ActionIntent and calls the policy engine.
func (h *HTTPLogger) evaluate(proto, method, target string) policy.AuthDecision {
	intent := policy.ActionIntent{
		Protocol: proto,
		Method:   method,
		Target:   target,
	}
	if h.engine != nil {
		state := policy.RunState{
			ActionCount:    int(atomic.LoadInt32(&h.actionCount)),
			ElapsedSeconds: int(time.Since(h.startTime).Seconds()),
		}
		return h.engine.Evaluate(intent, state)
	}
	return policy.AuthDecision{Decision: "allow", RuleID: "default", Reason: "no policy (permissive)"}
}

// emit dispatches an ActionEvent to the onAction callback.
func (h *HTTPLogger) emit(seq int, proto, method, target string, params json.RawMessage, result policy.AuthDecision) {
	if h.onAction == nil {
		return
	}
	h.onAction(trace.ActionEvent{
		Run:    h.runID,
		Seq:    seq,
		Proto:  proto,
		Method: method,
		Target: target,
		Params: params,
		Auth:   result.Decision,
		Rule:   result.RuleID,
	})
}

// writeDeniedHTTP writes a 403 JSON response per architecture Appendix C.
func (h *HTTPLogger) writeDeniedHTTP(w http.ResponseWriter, result policy.AuthDecision, target string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"error":  "Action denied by The Relic policy",
		"rule":   result.RuleID,
		"target": target,
	})
}

// checkNetworkPolicy evaluates the hostname against DNS allow/deny lists.
// Returns a non-nil AuthDecision if the host should be denied.
func (h *HTTPLogger) checkNetworkPolicy(host string) *policy.AuthDecision {
	if len(h.dnsDeny) == 0 && len(h.dnsAllow) == 0 {
		return nil
	}

	for _, pattern := range h.dnsDeny {
		if matched, _ := doublestar.Match(pattern, host); matched {
			return &policy.AuthDecision{
				Decision: "deny",
				RuleID:   "network:dns_deny",
				Reason:   fmt.Sprintf("host %q matches deny pattern %q", host, pattern),
			}
		}
	}

	if len(h.dnsAllow) > 0 {
		for _, pattern := range h.dnsAllow {
			if matched, _ := doublestar.Match(pattern, host); matched {
				return nil
			}
		}
		return &policy.AuthDecision{
			Decision: "deny",
			RuleID:   "network:dns_allow",
			Reason:   fmt.Sprintf("host %q not in allow list", host),
		}
	}

	return nil
}

// extractHost extracts the hostname from a URL, stripping port if present.
func extractHost(u *url.URL) string {
	host := u.Hostname()
	if host == "" {
		host = u.Host
	}
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host
}

// flattenHeaders collapses http.Header (map[string][]string) to map[string]string
// using the first value for each header name.
func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}
