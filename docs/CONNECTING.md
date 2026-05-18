# Connecting an agent to The Relic

This is the canonical guide for routing an agent's traffic through
The Relic so every action gets governed and recorded. Pick one of the
three patterns below depending on what your agent uses (MCP, HTTP,
or both).

The three patterns combine cleanly. A typical Claude Code setup uses
all three at once: `connect` wraps MCP servers, `daemon` runs the
HTTP proxy and ships traces to the platform, and (optionally)
`gateway` consolidates many MCP servers behind one entry.

---

## Quick decision

| Your agent talks to | Use |
|---|---|
| MCP tool servers (Claude Code, Cursor, Continue, Aider, Cline) | `relic connect <client>` or `relic gateway` |
| Model APIs / REST tools over HTTP(S) | `relic daemon` (HTTP proxy) |
| Both of the above | All three. They share the same trace directory. |

If you don't know yet, start with `relic connect claude-code` plus
`relic daemon`. Five-minute setup, full coverage.

---

## Pattern 1 · `relic connect <client>` (per-server wrap)

The lowest-friction way to instrument an existing agent client.
Rewrites the client's MCP server config so every entry gets wrapped
in `relic proxy-stdio`. The user keeps managing MCP servers the way
they always have; Relic just adds itself between client and server.

```bash
relic connect claude-code
```

What it does, step by step:

1. Reads `~/.claude.json`.
2. Finds every `mcpServers` block (top-level user-scope + per-project
   under `projects.<path>.mcpServers`).
3. For each entry, rewrites `command` + `args` so the new command is
   `relic proxy-stdio --agent-name=<server> --trace-dir=~/.relic/traces -- <original-command> <original-args>`.
4. Writes a timestamped backup to `~/.claude.json.relic-backup-YYYYMMDD-HHMMSS`.
5. Detects already-wrapped entries on re-run and leaves them alone.

### Flags

| Flag | Default | Use |
|---|---|---|
| `--trace-dir` | `~/.relic/traces` | Where the wrapped servers write `.trtrace` files. |
| `--policy` | none | Policy file applied by every wrapped server. |
| `--dry-run` | off | Print what would change without writing. |
| `--unwrap` | off | Reverse the wrap. Restores the original commands from the recorded marker. |

### Round-trip

```bash
relic connect claude-code             # wrap
relic connect claude-code             # idempotent: "Already up to date"
relic connect claude-code --unwrap    # restore originals
```

### Supported clients

| Client | Config path | Status |
|---|---|---|
| Claude Code | `~/.claude.json` | Supported |
| Cursor | `~/.cursor/mcp.json` | Planned |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) | Planned |

Each adapter follows the same pattern; adding a new client is one
function. File an issue with the client's config path if you want
yours next.

---

## Pattern 2 · `relic gateway` (consolidated MCP)

A single stdio MCP server that fans out to N upstream servers. The
client (Claude Code, Cursor, anything) adds **one** entry pointing at
`relic gateway`; the gateway reads its upstream list from
`~/.relic/gateway.yaml` and routes every tool call to the right
upstream.

```bash
# Configure once.
mkdir -p ~/.relic
cat > ~/.relic/gateway.yaml <<'EOF'
trace_dir: ~/.relic/traces
servers:
  - name: filesystem
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/Users/you/projects"]
  - name: git
    command: uvx
    args: ["mcp-server-git", "--repository", "."]
EOF

# Then wire one entry in Claude Code (or any other MCP client):
claude mcp add relic -- relic gateway
```

### Tool namespacing

Upstream tool names get prefixed with `<server-name>__` so two servers
exposing the same tool name don't collide. Claude Code sees
`filesystem__read_file` and `git__commit` rather than two ambiguous
`read_file` tools.

```
fs_a__list_directory   →  fs_a:list_directory
git__commit            →  git:commit
```

If your agent's prompts hard-code unqualified tool names, this might
confuse the model. Most agent frameworks handle the namespace
transparently because they discover tools at runtime.

### When to pick gateway over connect

| Use gateway when | Use connect when |
|---|---|
| You want one config entry, many tools | You want to keep your existing MCP entries managed by the client |
| You want to share an MCP server roster across multiple clients | You only use one client and editing its config is fine |
| You want a single trace per agent session covering all tool calls | You're OK with one trace per MCP server connection |

### Gateway config schema

```yaml
trace_dir: ~/.relic/traces        # optional; defaults to ~/.relic/traces
policy:    ~/.relic/policy.yaml   # optional; permissive default if missing
servers:                          # required; at least one
  - name: <unique-namespace>      # required; appears as <name>__ in tool names
    command: <executable>         # required; the MCP server to spawn
    args: [<arg1>, <arg2>, ...]   # optional
```

---

## Pattern 3 · `relic daemon` (HTTP proxy + trace pusher)

A long-running local process with two jobs:

1. **HTTP proxy** on an ephemeral local port. Set `HTTP_PROXY` and
   `HTTPS_PROXY` in any tool to route its traffic through Relic.
2. **Trace pusher.** Watches `~/.relic/traces/` and ships finished
   `.trtrace` files to the platform every 30 seconds (configurable).
   Pushed files are deleted from the local dir so it doesn't grow
   unbounded.

```bash
# Boot.
relic daemon &

# Read the proxy address from the daemon's first line of output, e.g.:
#   HTTP proxy started addr=127.0.0.1:52234

# Point any tool at it.
export HTTP_PROXY=http://127.0.0.1:52234
export HTTPS_PROXY=http://127.0.0.1:52234
```

The daemon is also useful **without the HTTP proxy** as a pure trace
pusher when you're using `relic connect` for MCP:

```bash
relic daemon --no-http --push-interval 10s &
```

### Flags

| Flag | Default | Use |
|---|---|---|
| `--trace-dir` | `~/.relic/traces` | Directory watched for `.trtrace` files. |
| `--policy` | `~/.relic/policy.yaml` if present | Policy applied by the HTTP proxy. |
| `--push-interval` | `30s` | How often the pusher runs. |
| `--no-http` | off | Skip the HTTP proxy (pusher only). |
| `--no-push` | off | Skip the pusher (HTTP proxy only). |

### Env vars

`relic daemon` honors the standard CLI env vars for talking to the
platform:

```bash
export RELIC_API_URL=http://localhost:8080/v1
export RELIC_API_KEY=rk_...
```

If `RELIC_API_KEY` is unset, the pusher logs a warning at boot and
the daemon runs as proxy-only. The HTTP proxy keeps working; traces
just accumulate locally.

---

## Combining patterns: a real Claude Code workflow

For a developer who uses Claude Code with several MCP servers AND
wants their model traffic captured too:

```bash
# One-time setup.
relic connect claude-code                  # wrap every MCP entry
mkdir -p ~/.relic && cat > ~/.relic/policy.yaml <<'EOF'
version: "1"
agent: { name: claude-code, version: "1" }
mode: audit
default: allow
EOF

# Then keep the daemon running in the background.
export RELIC_API_URL=http://localhost:8080/v1
export RELIC_API_KEY=rk_...
relic daemon &
```

Now:
- Every MCP tool call from Claude Code → `relic proxy-stdio` →
  written to `~/.relic/traces/<run-id>.trtrace` → daemon pushes →
  platform shows the run.
- (Optional) Set `HTTP_PROXY=$(daemon-addr)` in your shell to also
  capture HTTP/HTTPS your agent makes outside MCP.

The daemon, the wrapped MCP servers, and any HTTP proxy clients all
write into the **same** trace directory, so the push pipeline handles
everything uniformly.

---

## Trace flow at a glance

```
┌─────────────┐                            ┌──────────────────────┐
│ Claude Code │──── MCP stdio ────────────►│ relic proxy-stdio    │
└─────────────┘                            │ (per server)         │
                                           └──────────┬───────────┘
                                                      │
                                                      ▼
                                           ┌──────────────────────┐
┌─────────────┐                            │ ~/.relic/traces/     │
│  Any tool   │──── HTTP_PROXY ───────────►│ <run-id>.trtrace     │◄── relic gateway
│  with HTTP  │                            └──────────┬───────────┘    (one process,
└─────────────┘                                       │                 N upstreams)
                                                      │
                                                      ▼
                                           ┌──────────────────────┐
                                           │ relic daemon         │
                                           │ trace pusher         │
                                           └──────────┬───────────┘
                                                      │ HTTPS
                                                      ▼
                                           ┌──────────────────────┐
                                           │ therelic-platform    │
                                           │ /v1/traces           │
                                           └──────────────────────┘
```

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `relic connect claude-code` says "No MCP servers found" | You haven't added any MCP servers yet. Run `claude mcp add <name> -- <command>` first. |
| Claude Code shows tools but they hang | The wrapped command can't reach the original MCP server binary. Check `command` resolves in PATH inside the wrapped form; `which <name>` matches what's in `~/.claude.json`. |
| Daemon says "trace pusher disabled" | `RELIC_API_KEY` or `RELIC_API_URL` not set. Pure proxy mode still works; set them to enable push. |
| Gateway client says "tool X not found" | Tool names get namespaced. Use `<server>__<tool>` rather than the raw upstream name. |
| `relic trace push` says "no trace file found" | The pusher already shipped and deleted it. Check `relic trace list` on the platform side. |

---

## Reverting

Every modification is reversible.

- `relic connect <client> --unwrap` undoes any wrap on the client's
  config. The timestamped backups under `~/.claude.json.relic-backup-*`
  let you roll back to an earlier moment in time too.
- `relic gateway` and `relic daemon` are normal processes; `Ctrl-C`
  or `kill <pid>` stops them. Removing their config files
  (`~/.relic/gateway.yaml`, `~/.relic/daemon.yaml`) removes their
  state.
- The trace directory `~/.relic/traces/` is safe to delete; the
  platform retains pushed traces independently.

---

## Reference

- [therelic README](../README.md) - install and overview
- [therelic-platform RUNNING.md](../../therelic-platform/RUNNING.md) - five deployment paths for the control plane
- [policy reference](./policy-reference.md) - what the `policy:` file can do
