package policy

import (
	"testing"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte(`
version: "1"
agent:
  name: test
mode: enforce
default: deny
rules:
  - id: r1
    protocol: mcp
    method: tool_call
    target: "echo"
    action: allow
`))
	f.Add([]byte(`version: "1"`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not yaml at all [][][][`))
	f.Add([]byte(``))
	f.Add([]byte(`
version: "1"
agent:
  name: ""
mode: invalid
default: maybe
constraints:
  max_actions: -1
  max_duration_seconds: 999999999
rules:
  - id: ""
    protocol: ""
    method: ""
    target: ""
    action: ""
`))
	f.Add([]byte(`
version: "1"
agent:
  name: fuzz
mode: enforce
default: deny
redaction:
  keys: ["password", "token", "secret"]
  headers: ["Authorization", "Cookie"]
rules:
  - id: glob-star
    protocol: "*"
    method: "*"
    target: "**"
    action: allow
  - id: alternatives
    protocol: mcp
    method: "{tool_call,resource_read}"
    target: "{web_*,api_*}"
    action: deny
`))

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			return
		}
		Validate(p, false)
		Validate(p, true)

		if p.Mode == "" || p.Default == "" {
			return
		}

		intent := ActionIntent{
			Protocol: "mcp",
			Method:   "tool_call",
			Target:   "test_target",
		}
		Evaluate(intent, p, RunState{})
		Evaluate(intent, p, RunState{ActionCount: 100, ElapsedSeconds: 100})
	})
}

func FuzzEvaluate(f *testing.F) {
	f.Add("mcp", "tool_call", "echo", "enforce", "deny", "echo")
	f.Add("http", "GET", "api.example.com/v1", "audit", "allow", "api.*")
	f.Add("https", "CONNECT", "example.com:443", "permissive", "deny", "**")
	f.Add("", "", "", "enforce", "deny", "*")
	f.Add("mcp", "tool_call", "calendar_read", "enforce", "deny", "calendar_*")
	f.Add("http", "POST", "evil.com", "enforce", "deny", "{evil,bad}*")

	f.Fuzz(func(t *testing.T, proto, method, target, mode, defaultAction, ruleTarget string) {
		switch mode {
		case "enforce", "audit", "permissive":
		default:
			return
		}
		switch defaultAction {
		case "allow", "deny":
		default:
			return
		}

		p := &Policy{
			Version: "1",
			Agent:   AgentIdentity{Name: "fuzz"},
			Mode:    mode,
			Default: defaultAction,
			Rules: []Rule{
				{ID: "fuzz-rule", Protocol: "mcp", Method: "tool_call", Target: ruleTarget, Action: "allow"},
			},
			Constraints: Constraints{MaxActions: 50},
		}
		intent := ActionIntent{Protocol: proto, Method: method, Target: target}

		result := Evaluate(intent, p, RunState{})
		switch result.Decision {
		case "allow", "deny", "audit_deny", "would_deny":
		default:
			t.Errorf("unexpected decision: %q", result.Decision)
		}
	})
}
