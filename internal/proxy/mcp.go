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

	"github.com/therelicai/therelic/internal/policy"
	"github.com/therelicai/therelic/internal/redact"
	"github.com/therelicai/therelic/internal/sandbox"
	"github.com/therelicai/therelic/internal/trace"
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
	sb         *sandbox.Sandbox       // nil → no filesystem sandbox

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

// SetSandbox attaches a filesystem sandbox to the proxy. When set, file-related
// tool calls are validated against the sandbox policy before forwarding.
func (p *MCPProxy) SetSandbox(sb *sandbox.Sandbox) {
	p.sb = sb
}

// Start spawns the real MCP server subprocess and connects stdin/stdout pipes.
// Must be called before ServeStdio.
func (p *MCPProxy) Start() error {
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
	seq := int(atomic.AddInt32(&p.seq, 1))

	if result.IsDenied() {
		// Emit a denial trace event.
		p.emit(seq, mcpMethod, target, params, result, ctx)
		// Return a JSON-RPC error to the agent — do NOT forward to server.
		return writeDenial(out, msgID, result, target)
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
	var ctxVal any
	if len(ctx) > 0 {
		ctxVal = ctx
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

// readFromServer reads one complete JSON-RPC line from the server.
// The returned slice includes the trailing newline so it can be written
// directly to the agent's output.
func (p *MCPProxy) readFromServer() ([]byte, error) {
	line, err := p.procReader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("mcp proxy: read from server: %w", err)
	}
	return line, nil
}
