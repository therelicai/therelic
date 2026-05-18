package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/therelicai/therelic/internal/policy"
	"github.com/therelicai/therelic/internal/redact"
	"github.com/therelicai/therelic/internal/trace"
)

// MCPGateway is a single-connection stdio MCP server that fans out
// to N upstream stdio MCP servers. The agent (Claude Code, etc.)
// speaks MCP to the gateway over its own stdio; the gateway forwards
// each request to the right upstream and records the tool call to a
// .trtrace.
//
// Tool-name namespacing: each upstream's tools are exposed to the
// client as "<upstream-name>__<original-tool-name>". This avoids
// collisions when two upstreams expose the same tool (both filesystem
// servers exposing `read_file`, for example) without requiring the
// upstreams themselves to change.
//
// The gateway is intentionally minimal: it implements just the
// subset of JSON-RPC over stdio that real MCP clients use today
// (initialize, tools/list, tools/call, plus notifications). More
// methods (resources/*, prompts/*) can be added the same way later.
type MCPGateway struct {
	upstreams []*gatewayUpstream
	traceDir  string
	logger    *slog.Logger
	engine    *policy.Engine
	redactor  *redact.Redactor

	runID  string
	writer *trace.TraceWriter
	seq    int
	mu     sync.Mutex
}

// GatewayConfig is the public constructor input.
type GatewayConfig struct {
	Upstreams  []GatewayUpstream
	TraceDir   string
	PolicyPath string
	Logger     *slog.Logger
}

// GatewayUpstream identifies a single MCP server to fan out to.
type GatewayUpstream struct {
	Name    string
	Command string
	Args    []string
}

// NewMCPGateway constructs (but does not yet start) a gateway.
func NewMCPGateway(cfg GatewayConfig) (*MCPGateway, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	pol, err := loadPolicy(cfg.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	gw := &MCPGateway{
		traceDir: cfg.TraceDir,
		logger:   cfg.Logger,
		engine:   policy.NewEngine(pol),
		redactor: redact.NewRedactor(pol.Redaction),
		runID:    ulid.Make().String(),
	}
	for _, u := range cfg.Upstreams {
		gw.upstreams = append(gw.upstreams, &gatewayUpstream{
			name:    u.Name,
			command: u.Command,
			args:    u.Args,
		})
	}
	return gw, nil
}

// Close terminates every upstream and finalizes the trace file.
func (g *MCPGateway) Close() error {
	for _, u := range g.upstreams {
		u.close()
	}
	if g.writer != nil {
		_ = g.writer.WriteRunEnd(g.runID, 0, 0, g.seq, g.seq, 0)
		_ = g.writer.Close()
	}
	return nil
}

// ServeStdio runs the gateway's main loop against the provided
// stdin/stdout pair. Blocks until ctx is cancelled or stdin closes.
func (g *MCPGateway) ServeStdio(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	// Spawn every upstream eagerly. Cheaper than lazy because every
	// agent's first action is tools/list, which needs every
	// upstream's tool catalog anyway.
	for _, u := range g.upstreams {
		if err := u.start(ctx, g.logger); err != nil {
			return fmt.Errorf("start upstream %q: %w", u.name, err)
		}
	}

	if err := os.MkdirAll(g.traceDir, 0o755); err != nil {
		return fmt.Errorf("mkdir trace dir: %w", err)
	}
	w, err := trace.NewTraceWriter(g.traceDir, g.runID)
	if err != nil {
		return fmt.Errorf("trace writer: %w", err)
	}
	g.writer = w
	_ = g.writer.WriteRunStart(g.runID, "relic-gateway", "", "", "local")

	reader := bufio.NewReader(stdin)
	encoder := json.NewEncoder(stdout)
	writeMu := sync.Mutex{}
	writeJSON := func(v any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return encoder.Encode(v)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read stdin: %w", err)
		}
		line = trimCR(line)
		if len(line) == 0 {
			continue
		}
		var msg jsonRPCMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			g.logger.Warn("invalid JSON from agent", "error", err)
			continue
		}
		go g.handleMessage(ctx, msg, writeJSON)
	}
}

// jsonRPCMessage is the union of JSON-RPC 2.0 request, response, and
// notification shapes. We decode permissively and dispatch on the
// presence of `id` and `method`.
type jsonRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

func (g *MCPGateway) handleMessage(ctx context.Context, msg jsonRPCMessage, writeJSON func(any) error) {
	// Notifications (no id) flow to every upstream and get no reply.
	if len(msg.ID) == 0 {
		for _, u := range g.upstreams {
			_ = u.send(msg)
		}
		return
	}

	switch msg.Method {
	case "initialize":
		// Initialize every upstream then return one canonical reply
		// to the agent. Pick the first upstream's protocolVersion
		// since they should all agree; if they don't, the first one's
		// is the wire contract.
		var firstInit json.RawMessage
		for _, u := range g.upstreams {
			r, err := u.call(ctx, "initialize", msg.Params, 5*time.Second)
			if err != nil {
				g.logger.Warn("upstream initialize failed", "upstream", u.name, "error", err)
				continue
			}
			if firstInit == nil {
				firstInit = r
			}
		}
		if firstInit == nil {
			_ = writeJSON(jsonRPCError(msg.ID, -32000, "no upstream MCP server responded to initialize"))
			return
		}
		// Patch serverInfo so the agent sees us as the server.
		patched := patchServerInfo(firstInit, "relic-gateway")
		_ = writeJSON(jsonRPCResult(msg.ID, patched))

	case "tools/list":
		// Aggregate tool catalogs across upstreams, prefixing each
		// tool's name with "<upstream>__" so the namespace is unique.
		aggregated := map[string]any{"tools": []any{}}
		for _, u := range g.upstreams {
			r, err := u.call(ctx, "tools/list", msg.Params, 10*time.Second)
			if err != nil {
				g.logger.Warn("upstream tools/list failed", "upstream", u.name, "error", err)
				continue
			}
			var body struct {
				Tools []map[string]any `json:"tools"`
			}
			if err := json.Unmarshal(r, &body); err != nil {
				continue
			}
			for _, t := range body.Tools {
				if n, ok := t["name"].(string); ok {
					t["name"] = u.name + "__" + n
				}
				aggregated["tools"] = append(aggregated["tools"].([]any), t)
			}
		}
		out, _ := json.Marshal(aggregated)
		_ = writeJSON(jsonRPCResult(msg.ID, out))

	case "tools/call":
		// Route the call by the "<upstream>__<tool>" prefix. Record
		// every call (allow / deny / etc.) to the trace.
		var call struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(msg.Params, &call); err != nil {
			_ = writeJSON(jsonRPCError(msg.ID, -32602, "invalid params"))
			return
		}
		u, originalName := g.routeTool(call.Name)
		if u == nil {
			_ = writeJSON(jsonRPCError(msg.ID, -32601,
				fmt.Sprintf("tool %q not found. expected `<upstream>__<tool>`, e.g. \"filesystem__read_file\".", call.Name)))
			return
		}

		// Policy decision (mode mostly drives audit-vs-enforce).
		decision := g.evaluate(u.name, originalName, call.Arguments)
		g.recordAction(u.name, originalName, call.Arguments, decision)
		if decision.Decision == "deny" {
			_ = writeJSON(jsonRPCError(msg.ID, -32603, fmt.Sprintf("denied by policy: %s", decision.Reason)))
			return
		}

		// Forward to the upstream with the original (unprefixed) name.
		forwarded := map[string]any{"name": originalName}
		if len(call.Arguments) > 0 {
			forwarded["arguments"] = call.Arguments
		}
		params, _ := json.Marshal(forwarded)
		r, err := u.call(ctx, "tools/call", params, 30*time.Second)
		if err != nil {
			_ = writeJSON(jsonRPCError(msg.ID, -32603, err.Error()))
			return
		}
		_ = writeJSON(jsonRPCResult(msg.ID, r))

	default:
		// Pass-through for anything else (resources/list, prompts/get,
		// future methods). Route to first upstream that doesn't error.
		// This is conservative; if a real-world client uses one of
		// these methods we may need per-method routing logic.
		for _, u := range g.upstreams {
			r, err := u.call(ctx, msg.Method, msg.Params, 30*time.Second)
			if err != nil {
				continue
			}
			_ = writeJSON(jsonRPCResult(msg.ID, r))
			return
		}
		_ = writeJSON(jsonRPCError(msg.ID, -32601, fmt.Sprintf("method %q not implemented by any upstream", msg.Method)))
	}
}

// routeTool splits a namespaced tool name back into its upstream +
// original name.
func (g *MCPGateway) routeTool(prefixed string) (*gatewayUpstream, string) {
	parts := strings.SplitN(prefixed, "__", 2)
	if len(parts) != 2 {
		return nil, ""
	}
	upstreamName, original := parts[0], parts[1]
	for _, u := range g.upstreams {
		if u.name == upstreamName {
			return u, original
		}
	}
	return nil, ""
}

// evaluate consults the policy engine. The current engine is intent-
// shaped around HTTP/MCP; we feed it an MCP-tool-call intent. We do
// the minimum work needed; a richer integration can pass auth context
// + redaction state via the same engine.
func (g *MCPGateway) evaluate(upstream, tool string, args json.RawMessage) policy.AuthDecision {
	target := tool
	intent := policy.ActionIntent{
		Protocol: "mcp",
		Method:   "tool_call",
		Target:   target,
	}
	return g.engine.Evaluate(intent, policy.RunState{})
}

func (g *MCPGateway) recordAction(upstream, tool string, args json.RawMessage, decision policy.AuthDecision) {
	g.mu.Lock()
	g.seq++
	seq := g.seq
	g.mu.Unlock()

	ev := trace.ActionEvent{
		V:      2,
		T:      "action",
		Run:    g.runID,
		Seq:    seq,
		TS:     time.Now().UTC().Format(time.RFC3339Nano),
		Proto:  "mcp",
		Method: "tool_call",
		Target: upstream + "__" + tool,
		Params: redactArgs(g.redactor, args),
		Auth:   decision.Decision,
		Rule:   decision.Reason,
	}
	if g.writer != nil {
		_ = g.writer.WriteAction(ev)
	}
}

// redactArgs applies the policy's RedactionConfig to MCP arguments
// before recording. Uses RedactParams which is what the existing
// HTTPLogger uses, keeping behavior consistent across surfaces.
func redactArgs(r *redact.Redactor, raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || r == nil {
		return raw
	}
	return r.RedactParams(raw)
}

func loadPolicy(path string) (*policy.Policy, error) {
	if path == "" {
		home, _ := os.UserHomeDir()
		candidate := filepath.Join(home, ".relic", "policy.yaml")
		if _, err := os.Stat(candidate); err == nil {
			path = candidate
		}
	}
	if path == "" {
		return &policy.Policy{
			Version: "1",
			Agent:   policy.AgentIdentity{Name: "relic-gateway", Version: "0"},
			Mode:    "permissive",
			Default: "allow",
		}, nil
	}
	return policy.Load(path)
}

func jsonRPCResult(id json.RawMessage, raw json.RawMessage) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"result":  raw,
	}
}

func jsonRPCError(id json.RawMessage, code int, msg string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"error": map[string]any{
			"code":    code,
			"message": msg,
		},
	}
}

func patchServerInfo(raw json.RawMessage, name string) json.RawMessage {
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	if info, ok := v["serverInfo"].(map[string]any); ok {
		info["name"] = name
	}
	out, _ := json.Marshal(v)
	return out
}

func trimCR(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// ----- upstream connection -----

// gatewayUpstream is a single proxied MCP server: a subprocess
// speaking JSON-RPC over its own stdio. We maintain a request/reply
// table keyed by id, then route incoming responses back to the
// caller waiting on that id.
type gatewayUpstream struct {
	name    string
	command string
	args    []string

	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	encoder *json.Encoder
	decoder *bufio.Reader

	mu       sync.Mutex
	nextID   int
	pending  map[string]chan jsonRPCMessage
	writeMu  sync.Mutex
	finished chan struct{}
}

func (u *gatewayUpstream) start(ctx context.Context, logger *slog.Logger) error {
	cmd := exec.CommandContext(ctx, u.command, u.args...)
	cmd.Env = os.Environ()
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", u.command, err)
	}
	u.cmd = cmd
	u.stdin = stdin
	u.stdout = stdout
	u.encoder = json.NewEncoder(stdin)
	u.decoder = bufio.NewReader(stdout)
	u.pending = map[string]chan jsonRPCMessage{}
	u.finished = make(chan struct{})

	go u.readLoop(logger)
	return nil
}

func (u *gatewayUpstream) readLoop(logger *slog.Logger) {
	defer close(u.finished)
	for {
		line, err := u.decoder.ReadBytes('\n')
		if err != nil {
			return
		}
		line = trimCR(line)
		if len(line) == 0 {
			continue
		}
		var msg jsonRPCMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			logger.Warn("upstream: bad json", "upstream", u.name, "error", err)
			continue
		}
		if len(msg.ID) == 0 {
			// Server notification; nothing to dispatch.
			continue
		}
		// msg.ID is the raw JSON bytes. For numeric ids we sent it
		// looks like `1` (no quotes); for string ids it'd look like
		// `"1"`. We index our pending map by the raw bytes either
		// way so the comparison is symmetric with how call() stored
		// the key.
		key := string(msg.ID)
		u.mu.Lock()
		ch, ok := u.pending[key]
		if ok {
			delete(u.pending, key)
		}
		u.mu.Unlock()
		if ok {
			ch <- msg
		}
	}
}

func (u *gatewayUpstream) call(ctx context.Context, method string, params json.RawMessage, timeout time.Duration) (json.RawMessage, error) {
	u.mu.Lock()
	u.nextID++
	// Use a numeric JSON-RPC id so the wire-form matches what the
	// pending-map key (the raw JSON bytes of the id) will look like
	// in the response. JSON-RPC permits both number and string ids;
	// numbers are simpler here because we don't have to think about
	// quoting.
	idNum := u.nextID
	id := fmt.Sprintf("%d", idNum) // map key: raw JSON, no quotes
	ch := make(chan jsonRPCMessage, 1)
	u.pending[id] = ch
	u.mu.Unlock()

	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      idNum,
		"method":  method,
	}
	if len(params) > 0 {
		req["params"] = json.RawMessage(params)
	}
	u.writeMu.Lock()
	err := u.encoder.Encode(req)
	u.writeMu.Unlock()
	if err != nil {
		u.mu.Lock()
		delete(u.pending, id)
		u.mu.Unlock()
		return nil, fmt.Errorf("write to %s: %w", u.name, err)
	}

	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case resp := <-ch:
		if len(resp.Error) > 0 {
			return nil, fmt.Errorf("upstream %s error: %s", u.name, string(resp.Error))
		}
		return resp.Result, nil
	case <-tctx.Done():
		u.mu.Lock()
		delete(u.pending, id)
		u.mu.Unlock()
		return nil, fmt.Errorf("upstream %s timed out after %s", u.name, timeout)
	case <-u.finished:
		return nil, fmt.Errorf("upstream %s exited", u.name)
	}
}

// send is fire-and-forget; for notifications (no id) that flow from
// the agent to every upstream.
func (u *gatewayUpstream) send(msg jsonRPCMessage) error {
	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	return u.encoder.Encode(msg)
}

func (u *gatewayUpstream) close() {
	if u.stdin != nil {
		_ = u.stdin.Close()
	}
	if u.cmd != nil && u.cmd.Process != nil {
		_ = u.cmd.Process.Kill()
	}
}
