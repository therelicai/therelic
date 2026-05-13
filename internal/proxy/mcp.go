// Package proxy contains the MCP and HTTP proxy implementations for The Relic.
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync/atomic"
	"time"

	"strings"

	"github.com/therelicai/therelic/internal/config"
	"github.com/therelicai/therelic/internal/exfiltration"
	"github.com/therelicai/therelic/internal/policy"
	"github.com/therelicai/therelic/internal/redact"
	"github.com/therelicai/therelic/internal/sandbox"
	"github.com/therelicai/therelic/internal/trace"
	"github.com/therelicai/therelic/internal/trust"
)

// ---------------------------------------------------------------------------
// JSON-RPC envelope (minimal — only fields we need)
// ---------------------------------------------------------------------------

// rpcMsg is used to peek at incoming JSON-RPC messages from the agent.
// Using json.RawMessage for variable-type fields avoids allocation overhead
// and preserves the original bytes for transparent forwarding.
type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`     // nil/absent ⟹ notification
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// ---------------------------------------------------------------------------
// Denial error response (Appendix C)
// ---------------------------------------------------------------------------

type denialData struct {
	Rule   string `json:"rule"`
	Target string `json:"target"`
	Reason string `json:"reason"`
}

type denialError struct {
	Code    int        `json:"code"`
	Message string     `json:"message"`
	Data    denialData `json:"data"`
}

type denialResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   denialError     `json:"error"`
}

// writeDenial encodes and writes a JSON-RPC denial error for a blocked action.
func writeDenial(out io.Writer, id json.RawMessage, result policy.AuthDecision, target string) error {
	resp := denialResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: denialError{
			Code:    -32600,
			Message: "Action denied by policy",
			Data: denialData{
				Rule:   result.RuleID,
				Target: target,
				Reason: result.Reason,
			},
		},
	}
	line, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	_, err = out.Write(line)
	return err
}

// ---------------------------------------------------------------------------
// MCPProxy
// ---------------------------------------------------------------------------

// MCPProxy sits between an agent and a single real MCP server.
// It evaluates every tools/call, resources/read, and prompts/get against the
// policy engine, blocks denied actions, and forwards allowed ones to the server.
//
// Usage:
//
//	eng := policy.NewEngine(p)
//	proxy := NewMCPProxy(runID, "npx", []string{"-y", "server"}, eng, onAction)
//	proxy.Start()
//	defer proxy.Close()
//	proxy.ServeStdio(ctx, agentReader, agentWriter)
type MCPProxy struct {
	runID      string
	serverCmd  string
	serverArgs []string
	engine     *policy.Engine         // nil → permissive (all actions allowed)
	redactor   *redact.Redactor       // nil → no redaction
	onAction   func(trace.ActionEvent) // called once per intercepted action
	// onIntent is called once per intercepted action *before* the policy
	// engine produces a verdict. nil → no intent emission (slice-13
	// behavior). The proxy fills Seq, Run, Proto, Method, Target, and
	// redacted Params; subscribers must not mutate the event.
	onIntent   func(trace.IntentEvent)
	sb         *sandbox.Sandbox       // nil → no filesystem sandbox
	exfilGuard  *exfiltration.Guard        // nil → no exfiltration guard
	seqDetector *policy.SequenceDetector  // nil → no sequence detection
	integrity   *config.MCPServerIntegrity // nil → skip integrity check

	proc       *exec.Cmd
	procStdin  io.WriteCloser
	procReader *bufio.Reader

	startTime   time.Time
	actionCount int32 // atomic; used for constraint evaluation
	seq         int32 // atomic; trace sequence numbers
}

// NewMCPProxy creates a proxy for the given MCP server command.
//
// engine controls authorization (nil → all actions allowed, logged as "allow").
// redactor is applied to params before the ActionEvent is emitted (nil → no redaction).
// onAction is called synchronously for every intercepted action; it must not block.
// runID is embedded in every ActionEvent.
func NewMCPProxy(runID, serverCmd string, serverArgs []string, engine *policy.Engine, redactor *redact.Redactor, onAction func(trace.ActionEvent)) *MCPProxy {
	return &MCPProxy{
		runID:      runID,
		serverCmd:  serverCmd,
		serverArgs: serverArgs,
		engine:     engine,
		redactor:   redactor,
		onAction:   onAction,
	}
}

// SetIntentEmitter attaches a callback that is invoked before policy
// evaluation for every intercepted action. Slice 14 wires this to the
// local trace's WriteIntent and the optional streaming flush. Kept as
// a setter (not a constructor arg) so existing call sites compile
// unchanged.
func (p *MCPProxy) SetIntentEmitter(fn func(trace.IntentEvent)) {
	p.onIntent = fn
}

// SetSandbox attaches a filesystem sandbox to the proxy. When set, file-related
// tool calls are validated against the sandbox policy before forwarding.
func (p *MCPProxy) SetSandbox(sb *sandbox.Sandbox) {
	p.sb = sb
}

// SetExfiltrationGuard attaches an exfiltration guard to the proxy. When set,
// outbound network tool calls are checked for data exfiltration attempts.
func (p *MCPProxy) SetExfiltrationGuard(g *exfiltration.Guard) {
	p.exfilGuard = g
}

// SetSequenceDetector attaches a sequence anomaly detector to the proxy. When
// set, tool calls are tracked and multi-step attack patterns are blocked.
func (p *MCPProxy) SetSequenceDetector(d *policy.SequenceDetector) {
	p.seqDetector = d
}

// SetIntegrity attaches server integrity verification config to the proxy.
// When set, Start() will verify the server executable before spawning it.
func (p *MCPProxy) SetIntegrity(i *config.MCPServerIntegrity) {
	p.integrity = i
}

// Start spawns the real MCP server subprocess and connects stdin/stdout pipes.
// Must be called before ServeStdio.
func (p *MCPProxy) Start() error {
	if p.integrity != nil {
		result := trust.VerifyServer(p.serverCmd, p.integrity)
		if !result.Verified {
			return fmt.Errorf("mcp proxy: server integrity check failed for %q: %s", p.serverCmd, result.Reason)
		}
		fmt.Fprintf(os.Stderr, "mcp proxy: server %q verified (sha256: %s)\n", p.serverCmd, result.Actual)
	}

	p.startTime = time.Now()
	p.proc = exec.Command(p.serverCmd, p.serverArgs...)

	stdin, err := p.proc.StdinPipe()
	if err != nil {
		return fmt.Errorf("mcp proxy: stdin pipe: %w", err)
	}
	p.procStdin = stdin

	stdout, err := p.proc.StdoutPipe()
	if err != nil {
		return fmt.Errorf("mcp proxy: stdout pipe: %w", err)
	}
	p.procReader = bufio.NewReader(stdout)

	// Server diagnostic output goes to relic's stderr, not the agent channel.
	p.proc.Stderr = os.Stderr

	if err := p.proc.Start(); err != nil {
		return fmt.Errorf("mcp proxy: start server %q: %w", p.serverCmd, err)
	}
	return nil
}

// ServeStdio reads JSON-RPC messages from in (agent side), proxies them to
// the real MCP server, and writes responses back to out (agent side).
// Returns when in reaches EOF or ctx is cancelled. ctx may be nil, in which
// case cancellation is disabled and the function returns on EOF only.
func (p *MCPProxy) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	const maxLine = 4 * 1024 * 1024
	scanner.Buffer(make([]byte, maxLine), maxLine)

	for scanner.Scan() {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		if err := p.handleLine(line, out); err != nil {
			// Log non-fatal per-message errors; keep serving.
			fmt.Fprintf(os.Stderr, "mcp proxy: message error: %v\n", err)
		}
	}
	return scanner.Err()
}

// Close terminates the MCP server subprocess and closes the stdin pipe.
func (p *MCPProxy) Close() error {
	if p.procStdin != nil {
		_ = p.procStdin.Close()
	}
	if p.proc != nil && p.proc.Process != nil {
		_ = p.proc.Process.Kill()
		_ = p.proc.Wait() // reap zombie; ignore "already finished" errors
	}
	return nil
}

// ---------------------------------------------------------------------------
// Internal message dispatch
// ---------------------------------------------------------------------------

// handleLine processes one JSON-RPC line from the agent.
func (p *MCPProxy) handleLine(line []byte, out io.Writer) error {
	var msg rpcMsg
	if err := json.Unmarshal(line, &msg); err != nil {
		return fmt.Errorf("parse agent message: %w", err)
	}

	// JSON-RPC 2.0: notifications have no "id" field.
	isNotification := len(msg.ID) == 0

	switch msg.Method {
	case "tools/call":
		if !isNotification {
			return p.interceptToolCall(line, msg, out)
		}
	case "resources/read":
		if !isNotification {
			return p.interceptResourceRead(line, msg, out)
		}
	case "prompts/get":
		if !isNotification {
			return p.interceptPromptGet(line, msg, out)
		}
	}

	// Everything else (initialize, tools/list, resources/list, prompts/list,
	// notifications): relay transparently.
	return p.relay(line, isNotification, out)
}

// ---------------------------------------------------------------------------
// Intercept helpers
// ---------------------------------------------------------------------------

func (p *MCPProxy) interceptToolCall(line []byte, msg rpcMsg, out io.Writer) error {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if len(msg.Params) > 0 {
		_ = json.Unmarshal(msg.Params, &params)
	}

	strippedArgs, ctx := extractAndStripContext(params.Arguments)

	// Filesystem sandbox enforcement for file-related tools.
	if p.sb != nil {
		if err := p.validateSandboxAccess(params.Name, strippedArgs, msg.ID, out); err != nil {
			return nil
		}
	}

	// Exfiltration guard: check outbound network tool calls for data leakage.
	if p.exfilGuard != nil {
		if r := p.exfilGuard.CheckParams(strippedArgs, params.Name); r != nil && r.Triggered {
			exfilResult := policy.AuthDecision{
				Decision: p.exfilGuard.Action(),
				RuleID:   r.RuleID,
				Reason:   r.Reason,
			}
			if exfilResult.IsDenied() {
				seq := int(atomic.AddInt32(&p.seq, 1))
				atomic.AddInt32(&p.actionCount, 1)
				p.emit(seq, "tool_call", params.Name, strippedArgs, exfilResult, ctx)
				return writeDenial(out, msg.ID, exfilResult, params.Name)
			}
		}
	}

	forwardLine := line
	if ctx != nil {
		var paramMap map[string]json.RawMessage
		if err := json.Unmarshal(msg.Params, &paramMap); err == nil {
			paramMap["arguments"] = strippedArgs
			if newParams, err := json.Marshal(paramMap); err == nil {
				rebuilt, err := json.Marshal(rpcMsg{
					JSONRPC: msg.JSONRPC,
					ID:      msg.ID,
					Method:  msg.Method,
					Params:  newParams,
				})
				if err == nil {
					forwardLine = rebuilt
				}
			}
		}
	}

	return p.interceptAndRelay(forwardLine, msg.ID, out, "tool_call", params.Name, strippedArgs, ctx)
}

func (p *MCPProxy) interceptResourceRead(line []byte, msg rpcMsg, out io.Writer) error {
	var params struct {
		URI string `json:"uri"`
	}
	if len(msg.Params) > 0 {
		_ = json.Unmarshal(msg.Params, &params)
	}
	return p.interceptAndRelay(line, msg.ID, out, "resource_read", params.URI, msg.Params, nil)
}

func (p *MCPProxy) interceptPromptGet(line []byte, msg rpcMsg, out io.Writer) error {
	var params struct {
		Name string `json:"name"`
	}
	if len(msg.Params) > 0 {
		_ = json.Unmarshal(msg.Params, &params)
	}
	return p.interceptAndRelay(line, msg.ID, out, "prompt_get", params.Name, msg.Params, nil)
}

// interceptAndRelay is the core authorization + relay function.
//
// Flow:
//  1. Build ActionIntent from proto/method/target/params.
//  2. Call policy engine → AuthDecision.
//  3. Increment actionCount regardless (constraint tracking).
//  4. If DENY: emit trace event + return JSON-RPC error. Server never sees it.
//  5. If ALLOW (or audit_deny / would_deny): forward to server, emit trace event.
func (p *MCPProxy) interceptAndRelay(
	line []byte,
	msgID json.RawMessage,
	out io.Writer,
	mcpMethod string,
	target string,
	params json.RawMessage,
	ctx json.RawMessage,
) error {
	// Build the ActionIntent.
	intent := policy.ActionIntent{
		Protocol: "mcp",
		Method:   mcpMethod,
		Target:   target,
		Params:   params,
	}

	// Assign the sequence number *before* evaluation so the IntentEvent
	// (emitted next) and the eventual ActionEvent share the same Seq.
	// The dashboard pairs them on (Run, Seq). actionCount is bumped
	// *after* Evaluate so the constraint check (state.ActionCount >=
	// MaxActions) keeps its slice-13 semantics.
	seq := int(atomic.AddInt32(&p.seq, 1))

	// Slice 14: emit the intent event before the engine produces a
	// verdict so streaming subscribers see "agent wants to do X"
	// before they see "X was {allowed|denied}". The local trace
	// writer ordering is what the acceptance test verifies; network
	// streaming ordering is best-effort.
	p.emitIntent(seq, mcpMethod, target, params)

	// Evaluate against the policy engine.
	var result policy.AuthDecision
	if p.engine != nil {
		state := policy.RunState{
			ActionCount:    int(atomic.LoadInt32(&p.actionCount)),
			ElapsedSeconds: int(time.Since(p.startTime).Seconds()),
		}
		result = p.engine.Evaluate(intent, state)
	} else {
		// No engine → permissive: everything allowed.
		result = policy.AuthDecision{Decision: "allow", RuleID: "default", Reason: "no policy (permissive)"}
	}

	// Count this action regardless of outcome (for constraint tracking).
	atomic.AddInt32(&p.actionCount, 1)

	if result.IsDenied() {
		// Emit a denial trace event.
		p.emit(seq, mcpMethod, target, params, result, ctx)
		// Return a JSON-RPC error to the agent — do NOT forward to server.
		return writeDenial(out, msgID, result, target)
	}

	// Sequence anomaly detection: record the tool call and check for
	// multi-step attack patterns before forwarding.
	if p.seqDetector != nil && mcpMethod == "tool_call" {
		if match := p.seqDetector.Record(target); match != nil {
			seqResult := policy.AuthDecision{
				RuleID: "sequence:" + match.RuleID,
				Reason: match.Reason + " [chain: " + strings.Join(match.Chain, " → ") + "]",
			}
			if match.Action == "deny" {
				seqResult.Decision = "deny"
				p.emit(seq, mcpMethod, target, params, seqResult, ctx)
				return writeDenial(out, msgID, seqResult, target)
			}
			// audit: emit a flagged trace event but still forward.
			seqResult.Decision = "audit_deny"
			p.emit(seq, mcpMethod, target, params, seqResult, ctx)
		}
	}

	// Action is allowed (possibly flagged as audit_deny or would_deny).
	// Forward to server.
	if err := p.writeToServer(line); err != nil {
		return err
	}
	responseLine, err := p.readFromServer()
	if err != nil {
		return err
	}

	// Emit trace event with the actual decision string.
	p.emit(seq, mcpMethod, target, params, result, ctx)

	// Forward server response to agent.
	_, err = out.Write(responseLine)
	return err
}

// emitIntent dispatches an IntentEvent to the onIntent callback when
// configured. Called *before* engine.Evaluate so streaming subscribers
// see "agent wants to do X" before the verdict. Redaction matches the
// rules emit() uses for the ActionEvent — the same params bytes flow
// through the same redactor.
func (p *MCPProxy) emitIntent(seq int, mcpMethod, target string, params json.RawMessage) {
	if p.onIntent == nil {
		return
	}
	var redactedParams any
	if p.redactor != nil && len(params) > 0 {
		redactedParams = p.redactor.RedactParams(params)
	} else if len(params) > 0 {
		redactedParams = params
	}
	p.onIntent(trace.IntentEvent{
		Run:    p.runID,
		Seq:    seq,
		Proto:  "mcp",
		Method: mcpMethod,
		Target: target,
		Params: redactedParams,
	})
}

// emit builds and dispatches an ActionEvent to the onAction callback.
// Redaction is applied to params before the event is emitted.
func (p *MCPProxy) emit(seq int, mcpMethod, target string, params json.RawMessage, result policy.AuthDecision, ctx json.RawMessage) {
	if p.onAction == nil {
		return
	}
	// Apply redaction before writing to trace (architecture §7.4).
	var redactedParams any
	if p.redactor != nil && len(params) > 0 {
		redactedParams = p.redactor.RedactParams(params)
	} else {
		redactedParams = params
	}
	// _context is agent-supplied metadata that travels with the tool
	// call (provenance, intent, etc). It's regular JSON from an
	// untrusted source and can hold the same kinds of secrets we
	// already redact from params (API tokens accidentally pasted into
	// "intent" fields, etc), so route it through the same redactor.
	var ctxVal any
	if len(ctx) > 0 {
		if p.redactor != nil {
			ctxVal = p.redactor.RedactParams(ctx)
		} else {
			ctxVal = ctx
		}
	}
	p.onAction(trace.ActionEvent{
		Run:    p.runID,
		Seq:    seq,
		Proto:  "mcp",
		Method: mcpMethod,
		Target: target,
		Params: redactedParams,
		Auth:   result.Decision,
		Rule:   result.RuleID,
		Ctx:    ctxVal,
	})
}

// extractAndStripContext removes the "_context" key from a JSON object (tool
// call arguments) and returns the stripped JSON plus the extracted value.
// If "_context" is absent or the input is not a JSON object, the original
// bytes are returned unchanged with a nil ctx.
func extractAndStripContext(params json.RawMessage) (stripped json.RawMessage, ctx json.RawMessage) {
	if len(params) == 0 {
		return params, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(params, &m); err != nil {
		return params, nil
	}
	ctxVal, hasCtx := m["_context"]
	if !hasCtx {
		return params, nil
	}
	delete(m, "_context")
	stripped, err := json.Marshal(m)
	if err != nil {
		return params, nil
	}
	return stripped, ctxVal
}

// fileToolOps maps MCP tool names to the sandbox operation they perform.
var fileToolOps = map[string]string{
	"read_file":          "read",
	"write_file":         "write",
	"edit_file":          "write",
	"create_file":        "write",
	"delete_file":        "delete",
	"move_file":          "write",
	"copy_file":          "read",
	"list_directory":     "list",
	"glob":               "read",
	"search_files":       "read",
	"read_multiple_files": "read",
	"list_allowed_directories": "list",
	"get_file_info":      "read",
	"create_directory":   "mkdir",
	"directory_tree":     "list",
	"file_search":        "read",
}

// validateSandboxAccess checks file paths in tool call arguments against the sandbox.
// Returns an error (to signal the caller to stop processing) if the access was denied.
func (p *MCPProxy) validateSandboxAccess(toolName string, args json.RawMessage, msgID json.RawMessage, out io.Writer) error {
	op, isFileTool := fileToolOps[toolName]
	if !isFileTool {
		return nil
	}

	paths := extractPaths(args)
	for _, path := range paths {
		if err := p.sb.ValidatePath(op, path); err != nil {
			result := policy.AuthDecision{
				Decision: "deny",
				RuleID:   "sandbox",
				Reason:   err.Error(),
			}
			seq := int(atomic.AddInt32(&p.seq, 1))
			atomic.AddInt32(&p.actionCount, 1)
			p.emit(seq, "tool_call", toolName, args, result, nil)
			writeDenial(out, msgID, result, toolName) //nolint:errcheck
			return err
		}
	}
	return nil
}

// extractPaths pulls file path values from tool call arguments by checking
// common parameter names used by MCP file tools.
func extractPaths(args json.RawMessage) []string {
	if len(args) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(args, &m); err != nil {
		return nil
	}

	pathKeys := []string{"path", "file", "filename", "file_path", "filepath",
		"directory", "dir", "source", "destination", "target", "old_path", "new_path"}

	var paths []string
	for _, key := range pathKeys {
		if raw, ok := m[key]; ok {
			var s string
			if json.Unmarshal(raw, &s) == nil && s != "" {
				paths = append(paths, s)
			}
		}
	}
	return paths
}

// relay forwards a message to the server. For requests (not notifications),
// it also reads and forwards the server's response to the agent.
func (p *MCPProxy) relay(line []byte, isNotification bool, out io.Writer) error {
	if err := p.writeToServer(line); err != nil {
		return err
	}
	if isNotification {
		return nil
	}
	responseLine, err := p.readFromServer()
	if err != nil {
		return err
	}
	_, err = out.Write(responseLine)
	return err
}

// ---------------------------------------------------------------------------
// Low-level server I/O
// ---------------------------------------------------------------------------

// writeToServer sends a JSON-RPC line to the server subprocess.
// Scanner strips the newline, so we add it back.
func (p *MCPProxy) writeToServer(line []byte) error {
	buf := make([]byte, len(line)+1)
	copy(buf, line)
	buf[len(line)] = '\n'
	_, err := p.procStdin.Write(buf)
	if err != nil {
		return fmt.Errorf("mcp proxy: write to server: %w", err)
	}
	return nil
}

// maxServerLineBytes caps how many bytes we read from the wrapped MCP
// server before a newline must appear. A misbehaving (or malicious)
// server can otherwise stream forever without a delimiter and exhaust
// memory. 4 MiB matches the agent-side scanner cap and is enough for
// the largest tool result we've ever observed in practice.
const maxServerLineBytes = 4 * 1024 * 1024

// readFromServer reads one complete JSON-RPC line from the server.
// The returned slice includes the trailing newline so it can be written
// directly to the agent's output. Lines longer than maxServerLineBytes
// abort the proxy — relaying garbage to the agent is strictly worse
// than terminating the session.
func (p *MCPProxy) readFromServer() ([]byte, error) {
	var buf []byte
	for {
		b, err := p.procReader.ReadByte()
		if err != nil {
			if len(buf) > 0 {
				return buf, nil
			}
			return nil, fmt.Errorf("mcp proxy: read from server: %w", err)
		}
		buf = append(buf, b)
		if b == '\n' {
			return buf, nil
		}
		if len(buf) > maxServerLineBytes {
			return nil, fmt.Errorf("mcp proxy: server line exceeded %d bytes (no newline) — refusing to forward", maxServerLineBytes)
		}
	}
}
