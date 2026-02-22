# The Relic Quickstart

This guide takes you from zero to a governed AI agent in about 10 minutes.

---

## Prerequisites

- Go 1.21+ **or** a pre-built `relic` binary
- An AI agent you want to govern (any MCP-capable agent)
- Your agent's MCP server(s) already working

---

## Step 1: Install

**Homebrew**

```bash
brew install therelic/tap/relic
```

**curl (Linux / macOS)**

```bash
curl -fsSL https://github.com/therelicai/therelic/releases/latest/download/relic_Linux_x86_64.tar.gz \
  | tar xz -C /usr/local/bin relic
```

**go install**

```bash
go install github.com/therelicai/therelic/cmd/relic@latest
```

Verify the install:

```bash
relic --version
# relic v0.2.0
```

---

## Step 2: Initialize your project

Run this in the directory where you launch your agent:

```bash
relic init
```

This creates:

```
.tr/
├── policy.yaml   # Starter policy (permissive mode — logs everything, blocks nothing)
├── mcp.yaml      # MCP server configuration
└── traces/       # Run traces are stored here (one file per run)
```

---

## Step 3: Configure MCP servers

Edit `.tr/mcp.yaml` to list the MCP servers your agent uses:

```yaml
servers:
  # stdio transport (most common — wraps a local subprocess)
  - name: filesystem
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]

  # HTTP+SSE transport
  - name: web-search
    transport: sse
    url: "http://localhost:3001/mcp"
```

> **Note:** If you use OpenClaw or Claude Desktop, skip this step. Use
> `relic run --from-openclaw` or `relic run --from-claude-config` instead — Agent
> Waze reads the server list from those tools' config files automatically.

---

## Step 4: First run — permissive mode

The starter policy uses `mode: permissive`. Nothing is blocked; every action is
logged with `auth=would_deny` or `auth=allow`.

```bash
relic run -- python my_agent.py
```

You'll see a summary when your agent exits:

```
The Relic: 12 actions, 12 allowed, 0 denied  [run=01ARZ3NDEKTSV4RRFFQ69G5FAV duration=4.2s trace=.tr/traces/01ARZ3NDEKTSV4RRFFQ69G5FAV.trtrace]
```

---

## Step 5: View the trace

```bash
relic trace list
```

```
RUN ID                      AGENT              ENV        STARTED              ACTIONS
──────────────────────────────────────────────────────────────────────────────────────────
01ARZ3NDEKTSV4RRFFQ69G5FAV  python             local      2025-01-15 09:03:12  12 actions (12 allowed)
```

```bash
relic trace view 01ARZ3NDEKTSV4RRFFQ69G5FAV
```

```
[09:03:12] ALLOW  #1  mcp  tool_call    web_search    rule=default
[09:03:13] ALLOW  #2  mcp  tool_call    read_file     rule=default
[09:03:14] ALLOW  #3  mcp  tool_call    write_file    rule=default
...
```

In permissive mode every action shows `ALLOW` even though the `default` is `deny`.
The trace tells you what your agent actually did — you use this to write your policy.

---

## Step 6: Write a policy

Now that you know what your agent does, lock it down.

```bash
relic policy init
```

Edit `.tr/policy.yaml`:

```yaml
version: "1"
agent:
  name: my-agent
  version: "1.0.0"

# Switch to enforce when you're ready to block actions.
# Use 'audit' to shadow-test your rules without blocking.
mode: enforce
default: deny

# Redact sensitive values before writing to trace files.
redaction:
  keys:
    - password
    - token
    - api_key
    - secret
  headers:
    - Authorization
    - X-Api-Key

rules:
  # Allow the tools your agent legitimately needs.
  - id: allow-web-search
    protocol: mcp
    method: tool_call
    target: "web_search"
    action: allow

  - id: allow-read-file
    protocol: mcp
    method: tool_call
    target: "read_file"
    action: allow

  # Explicitly deny dangerous tools even if they somehow match a wildcard.
  - id: deny-shell-exec
    protocol: mcp
    method: tool_call
    target: "{execute_command,run_script,shell,bash}"
    action: deny
```

Validate it:

```bash
relic policy validate
# Policy valid: 3 rules, mode=enforce, default=deny
```

---

## Step 7: Test in audit mode first

Before enforcing, shadow-test your rules with `mode: audit`. Denied actions are
logged as `audit_deny` but **not blocked**. Your agent runs normally while you
verify the rules are right.

```bash
relic run --mode audit -- python my_agent.py
relic trace view $(relic trace list --limit 1 | awk 'NR==3{print $1}')
```

Look for `A_DENY` events. If you see legitimate tools flagged, add allow rules for them.

---

## Step 8: Enforce

Change `mode: permissive` → `mode: enforce` in `policy.yaml` (or just use the
`--mode` flag temporarily):

```bash
relic run -- python my_agent.py
```

Denied actions now return a structured error to the agent instead of proceeding:

```json
{
  "error": {
    "code": -32600,
    "message": "Action denied by policy",
    "data": { "rule": "default", "target": "execute_command", "reason": "no matching rule; policy default: deny" }
  }
}
```

---

## Reference

### Useful flags for `relic run`

| Flag | Effect |
|------|--------|
| `--mode enforce\|audit\|permissive` | Override the mode from policy.yaml |
| `--policy path/to/policy.yaml` | Use a different policy file |
| `--env production` | Tag this run with an environment label |
| `--verbose` | Print each action as it happens |
| `--quiet` | Suppress the post-run summary |

### Searching traces

```bash
# All denied actions across all runs
relic trace search --auth deny

# Actions to any "db_*" tool
relic trace search --target "db_*"

# Only MCP actions
relic trace search --proto mcp

# Combined: denied MCP actions to filesystem tools
relic trace search --proto mcp --auth deny --target "write_*"

# Runs with at least one denial
relic trace list --has-denials
```

---

## Next Steps

- [OpenClaw Guide](quickstart-openclaw.md) — govern OpenClaw in 3 minutes
- [Policy Reference](policy-reference.md) — all fields, glob syntax, constraints, redaction
- [Architecture](ARCHITECTURE.md) — how The Relic works internally
