package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/therelicai/therelic/internal/policy"
	"github.com/therelicai/therelic/internal/trace"
)

type infiniteResponseReader struct {
	line []byte
}

func (r *infiniteResponseReader) Read(p []byte) (int, error) {
	n := copy(p, r.line)
	return n, nil
}

func fakeServerReader() *bufio.Reader {
	line := []byte(`{"jsonrpc":"2.0","id":1,"result":{}}` + "\n")
	return bufio.NewReader(&infiniteResponseReader{line: line})
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

func FuzzHandleLine(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///tmp/test"}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"name":"my-prompt"}}`))
	f.Add([]byte(`not json at all`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":null,"method":"tools/call"}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":"string-id","method":"tools/call","params":{"name":"x"}}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}

		p := &MCPProxy{
			runID:  "fuzz-run",
			engine: nil,
			onAction: func(ev trace.ActionEvent) {
				if ev.Run != "fuzz-run" {
					t.Errorf("unexpected run ID: %q", ev.Run)
				}
			},
			procStdin:  nopWriteCloser{io.Discard},
			procReader: fakeServerReader(),
		}

		var out bytes.Buffer
		p.handleLine(data, &out) //nolint:errcheck
	})
}

func FuzzHandleLineWithPolicy(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"blocked","arguments":{"key":"val"}}}`))

	eng := policy.NewEngine(&policy.Policy{
		Version: "1",
		Agent:   policy.AgentIdentity{Name: "fuzz"},
		Mode:    "enforce",
		Default: "deny",
		Rules: []policy.Rule{
			{ID: "allow-echo", Protocol: "mcp", Method: "tool_call", Target: "echo", Action: "allow"},
		},
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}

		p := &MCPProxy{
			runID:  "fuzz-policy-run",
			engine: eng,
			onAction: func(ev trace.ActionEvent) {
				switch ev.Auth {
				case "allow", "deny", "audit_deny", "would_deny":
				default:
					t.Errorf("unexpected auth decision: %q", ev.Auth)
				}
			},
			procStdin:  nopWriteCloser{io.Discard},
			procReader: fakeServerReader(),
		}

		var out bytes.Buffer
		p.handleLine(data, &out) //nolint:errcheck
	})
}

func FuzzHTTPProxy(f *testing.F) {
	f.Add("GET", "/test", "")
	f.Add("POST", "/api/data", `{"key":"value"}`)
	f.Add("CONNECT", "example.com:443", "")
	f.Add("DELETE", "/resource/123", "")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, method, path, body string) {
		if len(method) > 100 || len(path) > 1000 || len(body) > 10000 {
			return
		}

		logger := NewHTTPLogger("fuzz-http-run", nil, nil, func(ev trace.ActionEvent) {})
		result := logger.evaluate("http", method, path)
		switch result.Decision {
		case "allow", "deny", "audit_deny", "would_deny":
		default:
			t.Errorf("unexpected decision: %q", result.Decision)
		}
	})
}

func BenchmarkMCPProxy_ToolCall(b *testing.B) {
	checkTestServerBench(b)

	eng := policy.NewEngine(&policy.Policy{
		Version: "1",
		Agent:   policy.AgentIdentity{Name: "bench"},
		Mode:    "enforce",
		Default: "deny",
		Rules: []policy.Rule{
			{ID: "allow-echo", Protocol: "mcp", Method: "tool_call", Target: "echo", Action: "allow"},
		},
	})

	p := NewMCPProxy("bench-run", testServerBin, nil, eng, nil, func(ev trace.ActionEvent) {})
	if err := p.Start(); err != nil {
		b.Skipf("Start: %v (test server may not be built)", err)
		return
	}
	defer p.Close()

	agentOutR, agentOutW := io.Pipe()
	agentInR, agentInW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		p.ServeStdio(ctx, agentOutR, agentInW) //nolint:errcheck
		agentInW.Close()
	}()

	enc := json.NewEncoder(agentOutW)
	scanner := bufio.NewScanner(agentInR)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc.Encode(rpc(i+1, "tools/call", map[string]any{ //nolint:errcheck
			"name":      "echo",
			"arguments": map[string]any{"message": "bench"},
		}))
		scanner.Scan()
	}
	b.StopTimer()
	agentOutW.Close()
}

func checkTestServerBench(b *testing.B) {
	b.Helper()
	t := &testing.T{}
	checkTestServer(t)
}
