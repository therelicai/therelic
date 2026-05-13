# The Relic

**Authorization and audit for autonomous AI agents.**

The Relic sits between your AI agent and the tools it calls. It enforces authorization policies and captures a complete audit trail — without modifying your agent or MCP servers.

```
Agent ──> The Relic proxy ──> MCP servers / HTTP APIs
              │
              ├── enforce policy (allow / block / audit)
              ├── redact sensitive params from traces
              └── write .trtrace for every run
```

Works with **OpenClaw**, **Claude Desktop**, **LangChain**, and any agent that speaks MCP.

---

## Install

**Homebrew (macOS / Linux)**

```bash
brew install therelic/tap/relic
```

**curl (Linux / macOS)**

```bash
# Replace vX.Y.Z with the latest version from github.com/therelicai/therelic/releases
curl -fsSL https://github.com/therelicai/therelic/releases/latest/download/relic_Linux_x86_64.tar.gz \
  | tar xz -C /usr/local/bin relic
```

**go install**

```bash
go install github.com/therelicai/therelic/cmd/relic@latest
```

Verify:

```bash
relic --version
```

---

## 5-Minute Quickstart

### 1. Initialize your project

```bash
cd your-agent-project
relic init
```

Creates `.tr/` with a starter policy, MCP config, and an empty traces directory.

### 2. Configure your MCP servers

Edit `.tr/mcp.yaml`:

```yaml
servers:
  - name: filesystem
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
```

### 3. Run in permissive mode (log everything, block nothing)

```bash
relic run -- python my_agent.py
```

The Relic records every tool call in `.tr/traces/`. Nothing is blocked yet.

### 4. View what your agent did

```bash
relic trace list
relic trace view <run-id>
```

### 5. Write a policy

```bash
relic policy init      # generates a starter policy.yaml
```

Edit `.tr/policy.yaml` to allow only the tools your agent actually needs:

```yaml
version: "1"
agent:
  name: my-agent
  version: "1.0.0"
mode: enforce
default: deny
rules:
  - id: allow-web-search
    protocol: mcp
    method: tool_call
    target: "web_search"
    action: allow
  - id: allow-filesystem-reads
    protocol: mcp
    method: tool_call
    target: "read_file"
    action: allow
```

```bash
relic policy validate     # check for errors
relic run -- python my_agent.py   # now enforcing
```

### OpenClaw users

```bash
relic run --from-openclaw -- openclaw gateway
```

The Relic intercepts all MCP tool calls made by OpenClaw — no config changes to OpenClaw required.

See **[docs/quickstart-openclaw.md](docs/quickstart-openclaw.md)** for the full guide.

---

## How It Works

```
┌────────────────────────┐
│    Agent Process        │
│  (any framework/model) │
│                        │
│  Reasoning → Tool Call │
└──────────┬─────────────┘
           │ JSON-RPC (MCP)
    ┌──────▼──────────┐
    │  The Relic      │
    │                  │
    │  • Load policy   │
    │  • Check rules   │    ALLOW → forward to MCP server
    │  • DENY → error  │    DENY  → error back to agent
    │  • Write trace   │
    └──────────────────┘
```

**MCP proxy** — intercepts `tools/call`, `resources/read`, and `prompts/get` over stdio. Evaluates policy before forwarding. Returns a structured error to the agent for denied actions.

**HTTP logger** — transparent forward proxy. Sets `HTTP_PROXY` / `HTTPS_PROXY` on the agent process. Logs request metadata for all outbound HTTP calls.

**Policy engine** — evaluates rules in document order, first match wins. Three modes:
- `enforce` — block denied actions
- `audit` — allow but flag as `audit_deny`
- `permissive` — allow but flag as `would_deny`

**Trace files** — NDJSON, one file per run in `.tr/traces/`. Human-readable, grep-friendly, queryable with `relic trace search`.

**Intent events (slice 14)** — for every intercepted tool call, the runtime emits an `IntentEvent` *before* the policy engine produces a verdict, and the existing `ActionEvent` *after* the verdict. Both share the same `seq` so the platform's Live view can pair "agent wants to do X" with "X was {allowed|denied}". IntentEvents are additive — `ActionEvent` is unchanged — and extend the HMAC chain when `RELIC_TRACE_KEY` is set.

**Streaming flush** — when both `RELIC_API_URL` and `RELIC_API_KEY` are set, every sealed event line is POSTed to the platform's `/v1/intents` endpoint as it's written, in addition to landing in the local `.trtrace` file. The streamer uses a bounded per-process queue with drop-on-overflow semantics; the proxy's hot path is never blocked by network slowness.

**Standalone mode** — with `RELIC_API_KEY` (or `RELIC_API_URL`) unset, the streamer is a no-op. IntentEvents still land in the local trace; no network traffic is generated. The batch `relic trace push` at end-of-run remains the durable path for delivering completed runs to a control plane on reconnect.

**Universal policy hot-reload (slice 15)** — with `--watch` and a control plane configured (`RELIC_API_URL` + `RELIC_API_KEY`), the runtime subscribes to `GET /v1/agents/:name/policy_updates` on startup. Each notification triggers: pull policy → parse + validate → `eng.SwapPolicy` → `POST /v1/agents/:name/policy_applied`. Two invariants the runtime guarantees across every swap:

- **In-flight `Evaluate` calls complete under their starting policy.** The engine reads the policy pointer under an RWMutex; the swap publishes a new pointer atomically. Readers see the old or new pointer, never a torn mixture.
- **The per-run HMAC trace chain key is not rotated.** A run started under v1 keeps its chain key through any number of hot reloads; `relic trace verify` reads the trace end-to-end and confirms the chain is intact.

`--watch` without API credentials is a no-op with a stderr note — fsnotify-based local file watching was removed in slice 15 to keep the reload path single-source.

---

## Commands

| Command | Description |
|---------|-------------|
| `relic init` | Initialize `.tr/` in current directory |
| `relic run -- <cmd>` | Run agent under governance |
| `relic run --from-openclaw -- openclaw gateway` | Govern an OpenClaw agent |
| `relic run --mode audit -- <cmd>` | Audit mode (log denials, don't block) |
| `relic trace list` | List recent runs |
| `relic trace view <run-id>` | Show all events for a run |
| `relic trace search --auth deny` | Find all denied actions |
| `relic trace search --target "web_*"` | Search by tool name glob |
| `relic policy init` | Generate starter policy |
| `relic policy validate` | Check policy syntax |

---

## Documentation

- [Quickstart](docs/quickstart.md) — step-by-step for any agent
- [OpenClaw Guide](docs/quickstart-openclaw.md) — govern OpenClaw in 3 minutes
- [Policy Reference](docs/policy-reference.md) — all fields, all examples
- [Architecture](docs/ARCHITECTURE.md) — design decisions and internals
- [RELIC.md (cross-repo alignment)](https://github.com/therelicai/therelic-platform/blob/main/RELIC.md) — selector contract, event schemas, replay protocol. Authoritative for any cross-repo capability that involves the runtime + platform + app together.

---

## Pushing traces to a self-hosted control plane

`relic` is fully usable standalone — every trace lands in `.tr/traces/`
and `relic trace view`, `relic trace search`, and `relic trace verify`
work without a server. When you do want team visibility, point the CLI
at a self-hosted [therelic-platform](https://github.com/therelicai/therelic-platform)
instance:

```bash
# In therelic-platform/
docker compose up -d

# In your agent project
export RELIC_API_URL=http://localhost:8080
export RELIC_API_KEY=rk_...           # from `relic-api` `/v1/orgs/:id/api-keys`
export RELIC_TRACE_KEY=$(openssl rand -hex 32)  # same value the API has
relic run -- python my_agent.py
relic trace push
```

When `RELIC_TRACE_KEY` is set on both sides, every trace event is
HMAC-chained at write time and verified server-side on upload —
tampering anywhere on the path is detected at parse.

---

## Example Policies

| Policy | Description |
|--------|-------------|
| [`examples/policies/openclaw-permissive.yaml`](examples/policies/openclaw-permissive.yaml) | Audit mode — log everything, block nothing |
| [`examples/policies/openclaw-production.yaml`](examples/policies/openclaw-production.yaml) | Production-grade OpenClaw restrictions |
| [`examples/policies/claude-desktop.yaml`](examples/policies/claude-desktop.yaml) | Restrict Claude Desktop MCP tools |
| [`examples/policies/minimal-deny-all.yaml`](examples/policies/minimal-deny-all.yaml) | Deny everything except one tool |
| [`examples/policies/read-only.yaml`](examples/policies/read-only.yaml) | Allow reads, deny all writes |

---

## License

Apache License 2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE), and
[TRADEMARKS.md](TRADEMARKS.md) for the full terms and trademark policy.
