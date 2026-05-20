# The Relic

**An authorization and audit layer for AI agents.** Drop it between
your agent (Claude Code, Cursor, an OpenAI-Agents script, anything
that uses tools) and the tools it calls. Every action goes through
The Relic. Policies decide what's allowed. Every decision is recorded
as a signed, tamper-evident trace.

```
your agent  ──▶  The Relic  ──▶  the real MCP server / HTTP API
                  │
                  ├── policy decides: allow / deny / audit
                  ├── secrets are redacted from the recorded trace
                  └── every event written to .tr/traces/<run>.trtrace
```

Works with anything that speaks MCP (Claude Code, Claude Desktop,
Cursor) or HTTP (LangChain, OpenAI Agents SDK, custom scripts).

---

## Try it in 5 minutes

You'll need either Homebrew or Go.

```bash
# 1. Install
brew install therelicai/tap/relic
# or:  go install github.com/therelicai/therelic/cmd/relic@latest

# 2. Initialize a project
cd ~/path/to/your-agent-project
relic init                  # writes .tr/policy.yaml + .tr/mcp.yaml

# 3. Run your agent under Relic. Default mode is "audit": nothing
#    is blocked, but every action is recorded.
relic run -- python my_agent.py

# 4. See what happened
relic trace list
relic trace view <run-id>
```

That's the whole loop. Everything else (real policy, the hosted
dashboard, the MCP gateway, the HTTP proxy daemon) is optional and
documented in [docs/](docs/).

---

## Already using Claude Code?

One command wires every MCP server in your `~/.claude.json` to route
through Relic, with traces written to `~/.relic/traces/`:

```bash
relic connect claude-code
```

Reversible (`relic connect claude-code --unwrap`). Idempotent
(re-running is a no-op). See [docs/CONNECTING.md](docs/CONNECTING.md)
for Cursor, Claude Desktop, and the long-running gateway/daemon
patterns.

---

## What the commands do

| Command | What it does |
|---|---|
| `relic init` | Create `.tr/` with a starter policy and trace dir |
| `relic run -- <cmd>` | Run any command under Relic governance |
| `relic connect claude-code` | Wrap an existing Claude Code MCP config |
| `relic gateway` | Stdio MCP server multiplexing many upstreams (one config entry covers all) |
| `relic daemon` | Long-running HTTP proxy + trace pusher |
| `relic trace list` | List recent runs |
| `relic trace view <run-id>` | Pretty-print a run's events |
| `relic trace search --auth deny` | Find every denied action |
| `relic policy validate` | Check `.tr/policy.yaml` |
| `relic policy harden` | Suggest tightenings based on past runs |

`relic <cmd> --help` for the full flag set on any command.

---

## Pushing traces to a hosted dashboard (optional)

The Relic is fully usable standalone. When you want a team dashboard,
stand up [therelic-platform](https://github.com/therelicai/therelic-platform)
and point the CLI at it:

```bash
export RELIC_API_URL=http://localhost:8080/v1
export RELIC_API_KEY=rk_...   # generate in the dashboard
relic trace push
```

Traces are HMAC-chained at write time, so the platform verifies
integrity on upload. Tampering anywhere on the path is detected
when the dashboard parses the run.

---

## The four repos

| Repo | What it is |
|---|---|
| **therelic** (this repo) | The OSS runtime. CLI, MCP proxy, HTTP proxy, policy engine, trace writer. |
| [therelic-platform](https://github.com/therelicai/therelic-platform) | Self-hostable control plane that stores traces and runs governance. |
| [therelic-app](https://github.com/therelicai/therelic-app) | React dashboard that talks to the platform. |
| [therelic-website](https://github.com/therelicai/therelic-website) | Marketing site at [therelic.dev](https://therelic.dev). |

All four are Apache 2.0.

---

## Docs

- [Quickstart](docs/quickstart.md) — the long version of the
  5-minute setup above
- [Connecting agents](docs/CONNECTING.md) — `connect` / `gateway` /
  `daemon` patterns for Claude Code, Cursor, etc.
- [Policy reference](docs/policy-reference.md) — every field, every
  example
- [Architecture](docs/ARCHITECTURE.md) — design and internals
- [Example policies](examples/policies/) — starter policies for
  common setups (Claude Desktop, OpenClaw, read-only, deny-all)

---

## License

[Apache License 2.0](LICENSE). Trademarks reserved — see
[TRADEMARKS.md](TRADEMARKS.md).
