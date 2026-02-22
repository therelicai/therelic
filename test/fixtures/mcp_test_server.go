// mcp_test_server is a minimal MCP (Model Context Protocol) server over stdio
// used exclusively as a test fixture. It is NOT part of the The Relic product.
//
// Build:
//
//	go build -o test/fixtures/mcp-test-server ./test/fixtures/
//
// It speaks JSON-RPC 2.0 over stdin/stdout, one request per line.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 envelope types
// ---------------------------------------------------------------------------

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Result  any    `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ---------------------------------------------------------------------------
// MCP schema types
// ---------------------------------------------------------------------------

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type capabilities struct {
	Tools     map[string]any `json:"tools"`
	Resources map[string]any `json:"resources"`
}

type initResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	ServerInfo      serverInfo   `json:"serverInfo"`
	Capabilities    capabilities `json:"capabilities"`
}

type toolInputSchema struct {
	Type       string         `json:"type"`
	Properties map[string]any `json:"properties"`
	Required   []string       `json:"required"`
}

type tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema toolInputSchema `json:"inputSchema"`
}

type toolsListResult struct {
	Tools []tool `json:"tools"`
}

type contentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolCallResult struct {
	Content []contentItem `json:"content"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// ---------------------------------------------------------------------------
// Tool list
// ---------------------------------------------------------------------------

var toolList = []tool{
	{
		Name:        "echo",
		Description: "Returns the provided message unchanged.",
		InputSchema: toolInputSchema{
			Type: "object",
			Properties: map[string]any{
				"message": map[string]any{"type": "string", "description": "The message to echo"},
			},
			Required: []string{"message"},
		},
	},
	{
		Name:        "add",
		Description: "Returns the sum of two numbers.",
		InputSchema: toolInputSchema{
			Type: "object",
			Properties: map[string]any{
				"a": map[string]any{"type": "number", "description": "First operand"},
				"b": map[string]any{"type": "number", "description": "Second operand"},
			},
			Required: []string{"a", "b"},
		},
	},
	{
		Name:        "secret",
		Description: "Accepts a password and returns ok. Used to test redaction.",
		InputSchema: toolInputSchema{
			Type: "object",
			Properties: map[string]any{
				"password": map[string]any{"type": "string", "description": "A secret value"},
			},
			Required: []string{"password"},
		},
	},
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

func handle(req request) response {
	switch req.Method {
	case "initialize":
		return ok(req.ID, initResult{
			ProtocolVersion: "2024-11-05",
			ServerInfo:      serverInfo{Name: "mcp-test-server", Version: "0.1.0"},
			Capabilities: capabilities{
				Tools:     map[string]any{"listChanged": false},
				Resources: map[string]any{},
			},
		})

	case "tools/list":
		return ok(req.ID, toolsListResult{Tools: toolList})

	case "tools/call":
		return handleToolCall(req)

	default:
		return errResp(req.ID, -32601, fmt.Sprintf("method not found: %s", req.Method))
	}
}

func handleToolCall(req request) response {
	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return errResp(req.ID, -32600, "invalid params: "+err.Error())
	}

	switch params.Name {
	case "echo":
		var args struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			return errResp(req.ID, -32600, "echo: invalid arguments: "+err.Error())
		}
		return ok(req.ID, toolCallResult{
			Content: []contentItem{{Type: "text", Text: args.Message}},
		})

	case "add":
		var args struct {
			A float64 `json:"a"`
			B float64 `json:"b"`
		}
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			return errResp(req.ID, -32600, "add: invalid arguments: "+err.Error())
		}
		sum := args.A + args.B
		// Return as integer string when the result is a whole number.
		var text string
		if sum == float64(int64(sum)) {
			text = fmt.Sprintf("%d", int64(sum))
		} else {
			text = fmt.Sprintf("%g", sum)
		}
		return ok(req.ID, toolCallResult{
			Content: []contentItem{{Type: "text", Text: text}},
		})

	case "secret":
		// Intentionally ignores the password value — just returns "ok".
		// The password parameter is used by The Relic redaction tests.
		return ok(req.ID, toolCallResult{
			Content: []contentItem{{Type: "text", Text: "ok"}},
		})

	default:
		return errResp(req.ID, -32602, fmt.Sprintf("unknown tool: %s", params.Name))
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func ok(id any, result any) response {
	return response{JSONRPC: "2.0", ID: id, Result: result}
}

func errResp(id any, code int, msg string) response {
	return response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

// ---------------------------------------------------------------------------
// Main — line-delimited JSON-RPC loop
// ---------------------------------------------------------------------------

func main() {
	enc := json.NewEncoder(os.Stdout)
	scanner := bufio.NewScanner(os.Stdin)

	// Allow large payloads (e.g. base64-encoded content in future tests).
	const maxLine = 4 * 1024 * 1024
	scanner.Buffer(make([]byte, maxLine), maxLine)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			// Best-effort error response with null id.
			resp := errResp(nil, -32700, "parse error: "+err.Error())
			_ = enc.Encode(resp)
			continue
		}

		// JSON-RPC 2.0: notifications have no "id" field. The Go JSON decoder
		// leaves req.ID as nil when the field is absent. Per spec, the server
		// must NOT send a response for notifications.
		if req.ID == nil {
			continue
		}

		resp := handle(req)
		if err := enc.Encode(resp); err != nil {
			fmt.Fprintf(os.Stderr, "mcp-test-server: encode error: %v\n", err)
			return
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "mcp-test-server: read error: %v\n", err)
		os.Exit(1)
	}
}
