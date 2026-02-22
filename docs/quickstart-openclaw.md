# Govern Your OpenClaw Agent in 3 Minutes

The Relic intercepts all of OpenClaw's MCP tool calls and HTTP requests with
**zero changes** to OpenClaw. No plugins. No patches. A single command.

---

## Prerequisites

- OpenClaw installed and working (`openclaw gateway` launches successfully)
- `relic` installed ([install instructions](../README.md#install))
- `~/.openclaw/openclaw.json` configured with at least one MCP server

---

## Minute 1: Initialize

```bash
# In the directory where you run OpenClaw (usually your home dir or project)
relic init
```

This creates `.tr/policy.yaml` in **permissive mode** — all tools are allowed
and every action is logged. Nothing breaks. You're just observing.

---

## Minute 2: Start OpenClaw under governance

```bash
relic run --from-openclaw -- openclaw gateway
```

That's it. The Relic:

1. Reads `~/.openclaw/openclaw.json`
2. Rewrites each stdio MCP server entry to route through a proxy
3. Writes a modified config to a temp file and sets `OPENCLAW_CONFIG` for OpenClaw
4. Starts OpenClaw — which now sees the proxy endpoints instead of raw servers
5. Records every tool call to `.tr/traces/`

Use OpenClaw normally. When you're done:

```bash
relic trace list
```

```
RUN ID                      AGENT              ENV        STARTED              ACTIONS
──────────────────────────────────────────────────────────────────────────────────────────
01ARZ3NDEKTSV4RRFFQ69G5FAV  openclaw           local      2025-01-15 14:22:05  47 actions (47 allowed)
```

```bash
relic trace view 01ARZ3NDEKTSV4RRFFQ69G5FAV
```

```
[14:22:06] ALLOW  #1   mcp  tool_call    web_search      rule=default
[14:22:07] ALLOW  #2   mcp  tool_call    read_file       rule=default
[14:22:08] ALLOW  #3   http GET          https://api...  rule=default
[14:22:09] ALLOW  #4   mcp  tool_call    write_file      rule=default
[14:22:10] ALLOW  #5   mcp  tool_call    execute_command rule=default  ← 😬
```

---

## Minute 3: Write a policy

You can see what OpenClaw actually did. Now decide what it should be allowed to do.

```bash
relic policy init
```

Edit `.tr/policy.yaml`. Here's a production-ready starting point:

```yaml
version: "1"
agent:
  name: "openclaw"
  version: "1.0.0"

# Start with 'audit' to verify your rules don't block legitimate tools.
# Switch to 'enforce' when you're confident.
mode: audit
default: deny

redaction:
  keys:
    - password
    - token
    - api_key
    - secret
    - access_token
  headers:
    - Authorization
    - X-Api-Key
    - Cookie

rules:
  # Web browsing and search — usually safe
  - id: allow-web-search
    protocol: mcp
    method: tool_call
    target: "{web_search,web_fetch,browser_navigate}"
    action: allow

  # File reads — allow, but watch for sensitive paths
  - id: allow-file-reads
    protocol: mcp
    method: tool_call
    target: "{read_file,list_directory,get_file_info}"
    action: allow

  # File writes — allow with caution
  - id: allow-file-writes
    protocol: mcp
    method: tool_call
    target: "{write_file,create_directory}"
    action: allow

  # Outbound HTTP GET — allow reads
  - id: allow-http-get
    protocol: http
    method: GET
    target: "**"
    action: allow

  # Deny shell execution — always
  - id: deny-shell
    protocol: mcp
    method: tool_call
    target: "{execute_command,run_script,shell,bash,terminal}"
    action: deny

  # Deny email and calendar by default — high-risk
  - id: deny-email
    protocol: mcp
    method: tool_call
    target: "{send_email,send_message,email_*}"
    action: deny

  - id: deny-calendar-writes
    protocol: mcp
    method: tool_call
    target: "{create_event,delete_event,calendar_write_*}"
    action: deny

constraints:
  max_actions: 200
  max_duration_seconds: 1800
```

Validate:

```bash
relic policy validate
# Policy valid: 8 rules, mode=audit, default=deny
```

Run in audit mode:

```bash
relic run --from-openclaw -- openclaw gateway
```

Check for `A_DENY` events to find any legitimate tools you need to allow:

```bash
relic trace search --auth audit_deny
```

When you're happy with the rules, switch to `enforce`:

```bash
sed -i 's/mode: audit/mode: enforce/' .tr/policy.yaml
relic run --from-openclaw -- openclaw gateway
```

---

## Multi-agent setup

If you use OpenClaw's multi-agent feature, you can govern each agent separately:

```bash
# Govern only the "home" agent
relic run --from-openclaw --openclaw-agent home -- openclaw gateway

# Use a per-agent policy
relic run --from-openclaw --openclaw-agent work --policy .tr/policy-work.yaml -- openclaw gateway
```

---

## Custom openclaw.json path

```bash
relic run --openclaw-config ~/work/.openclaw/openclaw.json -- openclaw gateway
```

---

## How the interception works

The Relic generates a modified `openclaw.json` where each stdio MCP server
entry is replaced with:

```json
{
  "filesystem": {
    "command": "/usr/local/bin/relic",
    "args": ["proxy-stdio", "--run-id", "01ARZ...", "--", "npx", "-y", "@mcp/server-filesystem"]
  }
}
```

OpenClaw spawns these `relic proxy-stdio` processes as its MCP backends. Each one
wraps the real server and enforces your policy. OpenClaw doesn't know the proxy
is there — it sees the same MCP protocol it always has.

The `OPENCLAW_CONFIG` environment variable is set to the modified config path.
The original `openclaw.json` is never modified.

---

## Troubleshooting

**OpenClaw can't find tools it used to have**

Check `relic trace search --auth deny` — a rule is probably blocking them. Add an
allow rule or switch to `mode: audit` temporarily.

**The trace is empty / shows no MCP actions**

Check that `~/.openclaw/openclaw.json` has `mcpServers` entries with `command`
fields (stdio transport). URL-based servers are passed through without proxying
in Stage 1.

**OpenClaw starts but ignores the proxy**

Check that `OPENCLAW_CONFIG` is respected by your OpenClaw version. You can
verify with:

```bash
relic run --from-openclaw --verbose -- openclaw gateway
```

The `--verbose` flag prints each intercepted action in real-time.

---

## Next steps

- [Policy Reference](policy-reference.md) — all rule fields, glob patterns, and constraints
- [Example policies](../examples/policies/) — ready-to-use policy files
- [`examples/policies/openclaw-production.yaml`](../examples/policies/openclaw-production.yaml) — recommended production policy
