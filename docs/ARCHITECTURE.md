# The Relic — Technical Architecture v3.3

> **Revision 3.3** — Zero trust hardening: filesystem sandbox, Ed25519 policy signing, trace integrity chain, network policy, environment hardening.
>
> **Prior revisions:**
> - v3.2: Zero trust mediation architecture, agent identity primitives, delegation graph model.
> - v3.1: Advanced security features, licensing strategy, behavioral contracts.
> - v3.0: Mediation layer architecture, proactive skill.
> - v2.1: OpenClaw integration, multi-agent trace correlation.
> - v2.0: Simplified from v1.0. Removed HTTPS MITM, filesystem/subprocess monitors, SQLite indexing, priority-based rules, conditional policy evaluation from Stage 1. Compressed 32-week timeline to 16 weeks.
>
> **This revision (3.3):** Implements runtime zero trust hardening. Adds filesystem sandbox (mount-based isolation with deny patterns), Ed25519 policy signing (`relic keygen`, `relic policy sign/verify`, `--require-signature`), HMAC-SHA256 trace integrity chain (`relic trace verify`), DNS-level network policy on the HTTP proxy, and environment hardening (strips proxy overrides, TLS bypass, library injection, variable spoofing). Extends the policy model with `signature_required`, `filesystem`, and `network` configuration sections. Adds fuzz testing, concurrency stress testing, and a full CI pipeline with lint, vulncheck, and coverage.

---

**This document covers the open-source mediation layer (Sections 0–9).**

---

## Changes from v1.0 — Executive Summary

1. **Eliminated HTTPS MITM proxy from Stage 1.** TLS interception requires generating a local CA, injecting it into every possible runtime (Python, Node, Go, Java, system trust stores), and handling edge cases across operating systems. It is a multi-week effort by itself, it breaks in corporate environments with existing proxy configurations, and it is unnecessary. MCP is the primary interception surface. HTTP recording can begin as a passthrough logger on plaintext traffic and a connection-level metadata logger on TLS traffic. Full HTTPS inspection is a Stage 2 optimization.

2. **Removed Filesystem Monitor and Subprocess Monitor from Stage 1.** Agents primarily interact with the world through tool calls (MCP) and HTTP requests. Filesystem and subprocess monitoring are low-value, high-complexity, platform-specific, and can be added later without architectural changes.

3. **Removed priority field from policy rules.** Rules evaluate in document order, first match wins. This is how nginx, iptables, and every other rule-based system developers already understand works.

4. **Removed `RuleConditions` from Stage 1 policy engine.** Conditional policy evaluation (time-based, action-count-based, etc.) is a Stage 3 enterprise feature.

5. **Consolidated three separate trace events into one.** A single `action` event containing intent, authorization, and result is simpler, smaller, and faster to query.

6. **Removed the local Runtime API (Unix socket).** The CLI reads trace files directly. Live streaming uses file tailing. The trace file is the API.

7. **Replaced SQLite index with direct trace file queries for Stage 1.** NDJSON is grep-friendly. SQLite indexing is deferred to when trace querying performance actually matters.

8. **Local-first architecture.** Everything works offline. Hosted features are additive and documented separately.

---

## Table of Contents

- [0. Architectural Thesis](#0-architectural-thesis)

**Mediation Layer**

1. [System Overview](#1-system-overview)
2. [Architectural Principles](#2-architectural-principles)
3. [Component Architecture](#3-component-architecture)
4. [Data Models](#4-data-models)
5. [MCP Mediation Specification](#5-mcp-mediation-specification)
6. [HTTP Logger Specification](#6-http-logger-specification)
7. [Policy Engine](#7-policy-engine)
8. [Trace System](#8-trace-system)
9. [CLI Specification](#9-cli-specification)

**Reference**

10. [Technology Choices](#10-technology-choices)
11. [Appendices](#11-appendices)

---

## 0. Architectural Thesis

The Relic is not an agent. It is the runtime substrate that makes every agent deployable in production. The analogy is a service mesh for AI agents: Envoy doesn't care if the upstream microservice is Go, Java, or Python — it governs the traffic boundary. The Relic governs the action boundary.

Every AI agent in production is an untrusted principal in a high-risk distributed system. The agent performs inference (cognition) then acts on the world (execution). The Relic enforces a hard separation. Cognition is the agent's concern. Execution flows through the mediation layer, where every action is authenticated, authorized, traced, and policy-checked before anything executes.

### 0.1 Zero Trust Principles Mapping

| Zero Trust Principle | The Relic Implementation |
|---|---|
| Never trust, always verify | Every action evaluated regardless of agent identity or history |
| Enforce at the boundary | Mediation layer is the only path between intent and execution |
| Least privilege | Default deny + parameter-level behavioral contracts + filesystem sandbox |
| Assume breach | Immutable traces, capability fingerprinting, drift detection, HMAC-SHA256 trace integrity chain |
| No implicit trust from position | Delegation scope reduction across agent hierarchies |
| Cryptographic identity | Ed25519 policy signing, signed run manifests, verifiable provenance at startup |
| Environment isolation | Filesystem sandbox with mount-based access, environment variable hardening |
| Network boundary control | DNS-level allow/deny on HTTP proxy, outbound connection governance |

### 0.2 What The Relic Is Not

The Relic is not a peer agent. It is the platform; other agents are tenants. Every agent submits intent through the mediation layer before anything executes. The Relic validates, logs, enforces policy, scores behavior, escalates. Agents do the work; The Relic ensures they do it within bounds.

Inter-agent calls are themselves capability-gated, signed requests through mediation. No agent trusts another by default; trust is verified at runtime.

Enterprises keep their existing agent stack. No SDK, no plugin, no code change. The mediation layer is invisible to the agent and non-bypassable by it.

### 0.3 Open Substrate, Source-Available Platform

The Relic stack is split across two licenses on purpose:

| Repo | License | Why |
|---|---|---|
| `therelic` (this repo — runtime + CLI) | **Apache License 2.0** | Maximum adoption. The runtime is the wedge — every governed Claude / OpenClaw / LangChain agent has it on the host. OSI-approved, in `apt`/`brew`/`yum`, no procurement gates, no CLA. Patent grant + patent-retaliation + explicit trademark clause. |
| `therelic-website` (marketing) | **Apache License 2.0** | Same posture. Static site has no competitive moat; openness is the lower-friction default. |
| `therelic-platform` (control plane + governance worker) | **Business Source License 1.1** | Source-available, self-hostable for any purpose under the Additional Use Grant — including internal production use, embedding in non-competing products, and customer self-hosted deployments. The grant prohibits offering a competing hosted **Governance Service**. Each released file converts to Apache 2.0 four years after publication. |
| `therelic-app` (dashboard) | **Business Source License 1.1** | Same Additional Use Grant. Same Change Date / Change License. |

The business model does not depend on the runtime being closed; it depends
on the **hosted product** at `therelic.dev` plus **services revenue**
(implementation, management, AI-transformation consulting). The runtime
needs to be true open source for adoption to compound; the platform and
dashboard get BSL only to prevent a competing hosted clone.

What stays proprietary is the **operational substrate** (deployment
automation, secrets, customer-onboarding workflows) and the **brand**
(see TRADEMARKS.md, present in every repo). Forks are welcome; forks
named "The Relic" are not.

The trust network protocol — transport binding, identity verification,
`from_agent` policy field, trace correlation — belongs in this repo
(Apache 2.0) so any agent in any organization can speak it without asking
permission. The trust network *operations* — capability registry, trust
scoring, bilateral policy templates, marketplace UI, metered transactions
— belong in `therelic-platform` (BSL). The split is by concern; the
license follows the concern.

---

## 1. System Overview

### 1.1 What It Is

A zero trust mediation layer between AI agents and the tools they call. Enforces authorization policies, captures audit trails, provides the governance substrate enterprises require. Works with any agent framework and any model provider — operates on actions, not inference.

### 1.2 System Boundary

```
┌─────────────────────────────────┐
│          AGENT PROCESS          │
│  (OpenClaw, Claude Code,        │
│   LangChain, custom, any)       │
│                                 │
│   Reasoning ──> Tool Call       │
│                    │            │
└────────────────────┼────────────┘
                     │
             ┌───────▼───────┐
             │  THE RELIC   │
             │               │
             │  Mediation    │  ← Primary interception
             │  Layer        │
             │  Policy Engine│
             │  Identity     │  ← v3.2: new
             │  Verifier     │
             │  Trace Writer │
             └───────┬───────┘
                     │
             ┌───────▼───────┐
             │ EXTERNAL TOOLS│
             │               │
             │  MCP Servers  │
             │  REST APIs    │
             │  Databases    │
             │  (via MCP)    │
             └───────────────┘
```

### 1.3 Why MCP Is the Primary Surface

Most agent-tool interaction is converging on MCP. Anthropic, OpenAI, Google, and open-source frameworks are adopting it. MCP tool calls carry structured intent (tool name, typed parameters, typed responses) — making them ideal for authorization and audit. HTTP interception is valuable but secondary; many HTTP calls will also be reachable via MCP server wrappers.

Building the MCP mediation first means we govern the highest-value interaction surface with the lowest implementation complexity.

### 1.4 OpenClaw as Launch Integration

OpenClaw is the fastest-growing open-source agent framework (~175k GitHub stars) and the most immediate validation of The Relic's thesis. OpenClaw agents execute shell commands, manage filesystems, control browsers, send emails, and access calendars — all through a gateway architecture that routes tool calls. Enterprise security teams (including CrowdStrike) have flagged ungoverned OpenClaw deployments as a security risk, and third-party skills have already been caught performing data exfiltration.

The Relic interposes on OpenClaw's tool execution path. OpenClaw agents use MCP servers for capabilities. The Relic's MCP mediation sits between the OpenClaw gateway and those servers. No modification to OpenClaw is required — only a configuration change pointing MCP servers through The Relic.

OpenClaw also supports multi-agent routing: multiple isolated agents in a single gateway, with optional agent-to-agent messaging. The Relic governs inter-agent communication through the same MCP interception — agent-to-agent calls are tool invocations, and tool invocations pass through the mediation layer.

---

## 2. Architectural Principles

| Principle | Description |
|---|---|
| **P1: Actions, not models** | Never touch inference. Govern the execution boundary where agents act on the world. |
| **P2: Default deny** | Unlisted actions are blocked. Permissive mode exists for onboarding. |
| **P3: Zero agent modification** | The agent connects to `relic` as if it were the MCP server. No SDK, no plugin, no code change. |
| **P4: Trace file is the product** | The `.trtrace` file is the atomic deliverable. Everything downstream reads it. Design it once, design it right. |
| **P5: Local-first** | Everything works offline. Hosted features are additive. |
| **P6: Ship the smallest thing that governs** | Defer everything that doesn't directly contribute to: intercepting an action, checking authorization, and recording the result. |
| **P7: Untrusted principals** | Every agent is untrusted. Mediation enforces regardless of cooperation. |
| **P8: Cryptographic verifiability** | Identity, policy provenance, trace integrity are verifiable. |

---

## 3. Component Architecture

### 3.1 Layer 1 — Mediation Layer (Built)

| Component | What It Does | Status |
|---|---|---|
| `relic` CLI | Entry point. Spawns agent, starts mediation, writes traces. | Complete |
| Mediation Engine | Transport-agnostic interception, policy eval, trace emission. | Refactor |
| MCP Proxy | Intercepts all MCP tool calls. Enforces filesystem sandbox on file-related tools. | Complete |
| HTTP Logger | Logs HTTP request metadata (method, host, path, status). Enforces DNS-level network policy. | Complete |
| Policy Engine | Loads YAML policy, evaluates allow/deny on each action. Supports `filesystem`, `network`, `signature_required` config. | Complete |
| Trace Writer | Writes NDJSON events to `.trtrace` file. | Complete |
| Trace Integrity | Rolling HMAC-SHA256 chain over trace events. `relic trace verify` validates chain. | Complete |
| Redaction Engine | Strips sensitive values from trace params before writing. | Complete |
| Agent Identity | Signed manifests, verification at startup. | Pre-launch |
| Ed25519 Policy Signing | `relic keygen` generates keypair. `relic policy sign/verify` for policy file integrity. `--require-signature` on `relic run`. | Complete |
| Filesystem Sandbox | Mount-based isolation with ro/rw permissions and deny patterns. Enforced by MCP proxy on file-related tool calls. | Complete |
| Network Policy | DNS-level allow/deny lists on HTTP proxy. Glob matching on hostnames. | Complete |
| Environment Hardening | Strips dangerous env vars (proxy overrides, TLS bypass, library injection, `RELIC_` spoofing) from agent process. | Complete |
| OpenClaw Adapter | Reads `openclaw.json`, rewrites MCP routing through proxy. | Complete |
| OpenClaw Skill | Proactive SKILL.md: auto-reviews traces, surfaces anomalies, proposes policies. | Pre-launch |
| Policy Hot-Reload | `--watch` flag, fsnotify, atomic policy swap mid-session. | Pre-launch |

### 3.2 CLI Structure

```
relic
├── run              # Execute agent with governance proxy (supports --watch, --require-signature)
├── trace
│   ├── view         # Display trace events (supports --follow)
│   ├── list         # List recent runs
│   ├── search       # Search traces by protocol/target/decision
│   ├── verify       # v3.3: Verify HMAC-SHA256 integrity chain of a .trtrace file
│   └── push         # Upload traces to hosted API
├── policy
│   ├── init         # Generate starter policy
│   ├── validate     # Check policy syntax
│   ├── pull         # Pull authoritative policy from the control plane
│   ├── sign         # v3.3: Ed25519-sign a policy file
│   ├── verify       # v3.3: Verify Ed25519 signature of a policy file
│   └── history      # Show policy changelog
├── keygen           # v3.3: Generate Ed25519 keypair for policy signing
├── identity         # v3.2: Agent identity management
│   ├── init         # Generate identity manifest
│   ├── verify       # Verify identity manifest
│   └── show         # Display identity details
├── fingerprint      # Generate/compare capability manifest
├── init             # Initialize .tr/ directory in project
└── version
```

Subcommands like `trace diff`, `trace replay`, `policy test` are added in later stages. Do not build them now.

---

## 4. Data Models

### 4.1 Core Types

```
AgentIdentity {
    name:        string    // "data-pipeline-agent"
    version:     string    // "2.1.0"
    fingerprint: string    // SHA-256 of capabilities manifest (v3.2)
    signed_by:   string?   // Optional: identity of signing authority (v3.2)
}

Policy {
    version:            string          // Policy format version: "1"
    agent:              AgentIdentity
    mode:               enum { enforce, audit, permissive }
    default:            enum { deny, allow }
    redaction:          RedactionConfig
    rules:              []Rule          // Evaluated in order, first match wins
    constraints:        Constraints
    signature_required: bool?           // v3.3: Require Ed25519 signature verification
    filesystem:         FilesystemConfig? // v3.3: Sandbox configuration
    network:            NetworkConfig?    // v3.3: DNS-level network policy
}

FilesystemConfig {                      // v3.3
    mounts:  []FilesystemMount          // Host paths to expose in sandbox
    deny:    []string                   // Glob patterns to deny (e.g. "**/.env")
}

FilesystemMount {                       // v3.3
    host:   string                      // Host path to mount
    mode:   enum { ro, rw }            // Read-only or read-write
}

NetworkConfig {                         // v3.3
    dns_allow: []string                 // Allowed hostname globs (if set, only these pass)
    dns_deny:  []string                 // Denied hostname globs (checked first)
}

Rule {
    id:         string    // "allow-web-search"
    protocol:   string    // "mcp", "http", "*"
    method:     string    // "tool_call", "GET", "*"
    target:     string    // Glob: "web_search", "api.example.com/*"
    action:     enum { allow, deny }
    params:     map[string]string?  // Parameter constraints (glob match on values). See 7.3.
    from_agent: string?   // Match on calling agent identity (multi-agent scenarios)
}

Constraints {
    max_actions:          int?   // Max total actions per run
    max_duration_seconds: int?   // Max run wall time
}

RedactionConfig {
    keys:    []string   // Parameter names to redact: ["password", "token", "secret"]
    headers: []string   // HTTP headers to redact: ["Authorization", "X-Api-Key"]
}
```

Note what is absent versus v1.0: no `priority` field on rules, no `RuleCondition`, no `PolicyCondition` with time windows and human-approval triggers, no `DelegationContext`, no `ArtifactRef` as a separate type, no metadata maps. These are all Stage 3 features. Removing them from the data model cuts the implementation surface by roughly 40%.

### 4.2 Trace Event (Single Unified Event)

The trace contains two event types: `run` (start/end) and `action` (everything that happens during a run).

**Multi-agent trace correlation.** When one agent invokes another (e.g., OpenClaw agent-to-agent messaging, or any orchestrator-to-sub-agent call), the action event includes an optional `to_agent` field identifying the target agent, and both runs share a `corr` (correlation ID) that links them:

```json
{"v":1,"t":"run","ts":"2026-02-17T14:23:01Z","run":"01JMQ...","agent":"data-pipeline-agent","agent_v":"1.0.0","agent_fp":"sha256:...","policy":"sha256:...","status":"start"}
{"v":1,"t":"action","ts":"2026-02-17T14:23:01.12Z","run":"01JMQ...","seq":1,"proto":"mcp","method":"tool_call","target":"web_search","auth":"allow","rule":"allow-web-search"}
{"v":1,"t":"action","ts":"2026-02-17T14:23:02Z","run":"01JMQ...","seq":2,"proto":"mcp","method":"tool_call","target":"file_write","auth":"deny","rule":"default"}
{"v":1,"t":"run","ts":"2026-02-17T14:23:03Z","run":"01JMQ...","status":"end","exit":1,"ms":2000}
```

The receiving agent's run-start event includes the same correlation ID:

```json
{"v":1,"t":"action","ts":"...","run":"01JMQ...","seq":5,"proto":"mcp","method":"tool_call","target":"agent_message","auth":"allow","rule":"allow-msg-work","to_agent":"work-agent","corr":"01JMR..."}
{"v":1,"t":"run","ts":"...","run":"01JMR...","agent":"work-agent","agent_v":"1.0.0","policy":"sha256:...","status":"start","corr":"01JMR...","from_agent":"data-pipeline-agent","from_run":"01JMQ..."}
```

This links the traces without coupling them. Each agent's trace is a self-contained audit trail. The `corr` field enables cross-agent query reconstruction when needed. The `from_agent` and `from_run` fields on the child run establish the delegation chain.

These fields are optional. Single-agent runs omit them. No schema change — parsers already ignore unknown fields per the compatibility rule.

**v3.2:** Run start events include `agent_fp` (agent fingerprint). `identity_mismatch` is a new event type.

**Key changes from v1.0:**
- Short field names reduce file size by ~30%
- Single `action` event contains intent + auth + result (was three separate events)
- `response` field omitted by default (tool responses can be large); opt-in via `--capture-responses`
- Every line is self-contained: no cross-referencing needed to understand what happened

### 4.3 Agent Identity Manifest

```
AgentIdentityManifest {
    version:           "1"
    agent:             AgentIdentity
    created_at:        timestamp
    org:               string?          // Optional org identifier
    capabilities_hash: string           // SHA-256 of capabilities.json
    policy_hash:       string           // SHA-256 of policy
    signature:         string           // HMAC-SHA256 (local) or Ed25519 (hosted)
}
```

Written to `.tr/identity.json` at `relic init`. Verified at every `relic run`. Binds agent name + capability surface + policy. HMAC-SHA256 locally (using `.tr/identity.key`).

### 4.4 Delegation Graph

A directed acyclic graph (DAG) where each node is an `relic run` session. Effective policy at any node = intersection of all policies from root to that node.

```
DelegationNode {
    run_id:           string
    agent:            AgentIdentity
    policy_hash:      string
    parent_run_id:    string?     // null for root
    depth:            int
    effective_policy: Policy      // Computed intersection
}

DelegationEdge {
    parent_run_id:    string
    child_run_id:     string
    granted_at:       timestamp
    scope:            []string    // Delegated tool names
}
```

Handles fan-out orchestration (coordinator spawns N workers in parallel), dynamic delegation (A delegates to B delegates to C, narrowing at each level), and multi-root graphs (agent receives delegated authority from multiple external agents).

### 4.5 Trace File Specification

- **Format:** NDJSON (one JSON object per line)
- **Extension:** `.trtrace`
- **Encoding:** UTF-8
- **Location:** `.tr/traces/<run_id>.trtrace`
- **Compression:** gzip when uploading to hosted layer

Traces are append-only. The file is the audit trail. Consumers parse it line by line.

### 4.6 Policy File

```yaml
# .tr/policy.yaml
version: "1"
agent:
  name: "my-agent"
  version: "1.0.0"
mode: enforce        # enforce | audit | permissive
default: deny        # deny | allow

redaction:
  keys: ["password", "secret", "token", "api_key"]
  headers: ["Authorization", "X-Api-Key"]

# Rules evaluated top-to-bottom. First match wins.
rules:
  - id: allow-web-search
    protocol: mcp
    method: tool_call
    target: "web_search"
    action: allow

  - id: allow-web-fetch
    protocol: mcp
    method: tool_call
    target: "web_fetch"
    action: allow

  - id: allow-read-api
    protocol: http
    method: GET
    target: "api.example.com/**"
    action: allow

  - id: deny-all-writes
    protocol: http
    method: "{POST,PUT,DELETE,PATCH}"
    target: "**"
    action: deny

constraints:
  max_actions: 500
  max_duration_seconds: 300

# v3.3: Zero Trust Extensions (optional)

# Require Ed25519 signature verification before policy loads
# signature_required: true

# Filesystem sandbox: agent process runs in isolated workspace
# filesystem:
#   mounts:
#     - host: ./src
#       mode: ro
#     - host: ./output
#       mode: rw
#   deny:
#     - "**/.env"
#     - "**/*.key"
#     - "**/*.pem"

# DNS-level network policy applied to HTTP proxy
# network:
#   dns_allow:
#     - "api.example.com"
#     - "cdn.example.com"
#   dns_deny:
#     - "*.internal.corp"
#     - "metadata.google.internal"
```

**OpenClaw production policy example:**

```yaml
# .tr/policy.yaml — OpenClaw production agent
version: "1"
agent:
  name: "openclaw-home"
  version: "1.0.0"
mode: enforce
default: deny

redaction:
  keys: ["password", "secret", "token", "api_key", "authToken"]
  headers: ["Authorization", "X-Api-Key", "Cookie"]

rules:
  # Calendar and reminders — allow read/write
  - id: allow-calendar
    protocol: mcp
    method: tool_call
    target: "calendar_*"
    action: allow

  - id: allow-reminders
    protocol: mcp
    method: tool_call
    target: "reminders_*"
    action: allow

  # Web search — allow
  - id: allow-search
    protocol: mcp
    method: tool_call
    target: "{web_search,web_fetch,web_browse}"
    action: allow

  # Filesystem — read only, scoped to workspace
  - id: allow-fs-read
    protocol: mcp
    method: tool_call
    target: "read_file"
    action: allow

  - id: deny-fs-write
    protocol: mcp
    method: tool_call
    target: "{write_file,create_directory,move_file,delete_*}"
    action: deny

  # Shell — deny all execution
  - id: deny-shell
    protocol: mcp
    method: tool_call
    target: "{shell,execute_command,run_script}"
    action: deny

  # Agent-to-agent — allow messaging to work agent only
  - id: allow-msg-work
    protocol: mcp
    method: tool_call
    target: "agent_message"
    action: allow

  # Browser — deny (high risk surface)
  - id: deny-browser
    protocol: mcp
    method: tool_call
    target: "{browser_*,navigate,click,type_text}"
    action: deny

  # HTTP — allow only known API hosts
  - id: allow-known-apis
    protocol: https
    method: CONNECT
    target: "{api.anthropic.com,api.openai.com,api.google.com}:443"
    action: allow

constraints:
  max_actions: 1000
  max_duration_seconds: 600
```

This policy demonstrates the core value proposition: an OpenClaw agent that can manage your calendar and search the web, but cannot execute shell commands, write files outside its workspace, control the browser, or call unknown APIs. Every action is traced. An enterprise security team reviewing this deployment can read the policy and the trace and know exactly what the agent is authorized to do and what it actually did.

### 4.7 MCP Server Configuration

```yaml
# .tr/mcp.yaml
servers:
  - name: filesystem
    transport: stdio
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]

  - name: web-search
    transport: sse
    url: "http://localhost:3001/mcp"
```

This file is optional. If absent, the runtime reads MCP server config from the agent's own configuration (e.g., Claude Desktop's `claude_desktop_config.json`) and interposes transparently.

---

## 5. MCP Mediation Specification

This is the core of the product. Everything else supports it.

### 5.1 Mediation Abstraction

The core abstraction: receives action intent, evaluates against policy, records result, forwards or denies. MCP proxy, HTTP logger, and network endpoint are all transport bindings of the same engine.

```
MediationEngine {
    PolicyEngine
    IdentityVerifier
    TraceWriter
    DelegationGraph
}

Mediate(intent ActionIntent) -> Result:
    1. Verify agent identity
    2. Resolve effective policy (delegation-aware)
    3. Evaluate policy against intent
    4. Write trace event
    5. Forward (allow) or deny
```

**Transport bindings:**
- `MCPBinding` — stdio, HTTP+SSE
- `HTTPBinding` — forward proxy

**Payoff:** (1) Transport-agnostic engine is reusable across bindings, (2) testable against mocks.

### 5.2 Architecture

```
Agent           The Relic              Real MCP Servers
  │                  │                       │
  │── MCP connect ──>│                       │
  │                  │── spawn/connect ──────>│
  │                  │<── server ready ───────│
  │                  │                       │
  │── tools/list ───>│── tools/list ─────────>│
  │                  │<── tool list ──────────│
  │<── tool list ────│       (logged)         │
  │                  │                       │
  │── tools/call ───>│                       │
  │  {tool: web_search}   1. Normalize to ActionIntent
  │                  │   2. Evaluate policy  │
  │                  │   3a. ALLOW:          │
  │                  │── tools/call ─────────>│
  │                  │<── result ────────────│
  │<── result ───────│   4. Write trace event│
  │                  │                       │
  │                  │   3b. DENY:           │
  │<── error ────────│   4. Write trace event│
  │  {code: -32600}  │                       │
```

### 5.3 Implementation

The MCP proxy is a JSON-RPC router. It:

1. Listens for agent connections (stdio or HTTP+SSE)
2. Spawns or connects to real MCP servers per `mcp.yaml`
3. Forwards `list` requests transparently (logging only)
4. Intercepts `call` / `read` / `get` requests through the policy engine
5. **v3.3:** If a filesystem sandbox is attached, validates file paths in tool call parameters against sandbox boundaries before forwarding
6. Forwards allowed requests to the real server
7. Returns denial errors for blocked requests
8. Writes a trace event for every intercepted request

**v3.3: Filesystem Sandbox Enforcement.** When a `filesystem` section is present in the policy, `relic run` creates an isolated workspace with symlinks to explicitly mounted host paths. The sandbox is attached to the MCP proxy via `SetSandbox()`. For file-related tool calls (`read_file`, `write_file`, `create_directory`, `move_file`, `delete_file`, `list_directory`, `search_files`, `get_file_info`), the proxy extracts file paths from the tool parameters and calls `sandbox.ValidatePath()` before forwarding. Validation enforces mount boundaries, deny patterns, and write permissions (read-only mounts reject write operations). Symlink escape attacks are prevented by resolving real paths. If validation fails, the tool call is denied with a descriptive error before it reaches the MCP server.

**Policy hot-reload (`--watch`).** When the `--watch` flag is set, the proxy watches `.tr/policy.yaml` (or the path specified by `--policy`) using fsnotify. On file modification: re-parse the policy, validate it, and atomically swap the policy engine's reference. If the new policy is invalid, log a warning and keep the previous policy. This enables the agent (via the proactive skill) or the user to update policy mid-session without restarting the proxy. The swap is atomic — in-flight requests complete against the old policy; subsequent requests evaluate against the new one. A trace event of type `policy_reload` is emitted recording the old and new policy hashes.

**MCP server aggregation:** The proxy exposes a single MCP endpoint to the agent. It aggregates tools from all configured servers. Tool name collisions are prefixed with server name: `filesystem.read_file`, `database.query`. This is configurable; by default, tool names pass through unprefixed if unique across servers.

**Transport handling:**

| Agent-side Transport | Server-side Transport | Implementation |
|---|---|---|
| stdio | stdio | Pipe relay with interception |
| stdio | HTTP+SSE | stdio listener, HTTP client |
| HTTP+SSE | stdio | HTTP server, pipe client |
| HTTP+SSE | HTTP+SSE | HTTP relay with interception |

The proxy handles all four combinations. The most common is stdio-to-stdio (Claude Desktop, Claude Code) and HTTP+SSE-to-stdio.

### 5.4 MCP Interception Depth

| MCP Method | Action | Auth Check | Trace |
|---|---|---|---|
| `initialize` | Forward | No | Yes |
| `tools/list` | Forward | No | Yes (log available tools) |
| `tools/call` | Intercept | Yes | Yes (full params + result) |
| `resources/list` | Forward | No | Yes |
| `resources/read` | Intercept | Yes | Yes |
| `prompts/list` | Forward | No | Yes |
| `prompts/get` | Intercept | Yes | Yes |

### 5.5 Normalization

Every intercepted MCP request becomes:

```
ActionIntent {
    protocol: "mcp"
    method:   <MCP method>   // "tool_call", "resource_read", "prompt_get"
    target:   <name>         // Tool name, resource URI, prompt name
    params:   <input params> // Redacted per policy before trace writing
}
```

### 5.6 OpenClaw Gateway Integration

OpenClaw uses a gateway architecture where all tool execution is routed through a single control plane process. MCP servers are a primary tool surface. The integration is a configuration change, not a code change.

**How it works:**

```
OpenClaw Gateway     The Relic          MCP Servers / Skills
     │                   │                    │
     │── MCP tool_call ──>│                    │
     │  (via openclaw.json│── forward ────────>│
     │   mcpServers config)│<── result ────────│
     │<── result ─────────│                    │
     │                   │   (trace written)   │
```

OpenClaw's `openclaw.json` configures MCP servers under the `mcpServers` key. `relic run --from-openclaw` reads this configuration, starts The Relic's MCP proxy in front of each configured server, and rewrites the config to point OpenClaw at the proxy endpoints instead. OpenClaw sees the same MCP interface. It does not know The Relic is interposing.

**`relic run --from-openclaw` behavior:**

1. Read `~/.openclaw/openclaw.json` (or path specified by `--openclaw-config`)
2. Parse `mcpServers` entries (stdio commands and HTTP+SSE URLs)
3. For each MCP server: start an The Relic proxy instance
4. Generate a modified `openclaw.json` with MCP servers pointing to proxy endpoints
5. Start OpenClaw gateway with modified config (via `OPENCLAW_CONFIG` env var or temp file)
6. All tool calls now flow through The Relic

**Multi-agent integration:** OpenClaw supports multiple agents in a single gateway with optional agent-to-agent messaging. When this is enabled, inter-agent messages are tool calls (`agent_message` or similar tool name registered by OpenClaw). The Relic intercepts these like any other tool call:

- Policy can allow/deny agent-to-agent communication per agent pair
- Trace records which agent messaged which, with what content
- The `to_agent` and `corr` fields on trace events link the interaction chain

Each OpenClaw agent can have its own The Relic policy. In a multi-agent gateway, `relic` runs one proxy per agent, each with a separate policy file and trace file. Agent "home" might be permitted to message agent "work" but not vice versa. This mirrors OpenClaw's own `agentToAgent.allow` config but adds enforcement and audit.

**What this does NOT require:**
- No OpenClaw code changes or patches
- No OpenClaw plugin or skill to install
- No modification to existing OpenClaw skills
- No new component in The Relic — the existing MCP proxy handles it

The integration is a config adapter in the CLI, not an architectural addition.

### 5.7 OpenClaw Skill (Distribution + Proactive Governance)

The Relic ships an OpenClaw skill alongside the `relic` binary. The skill and the proxy serve different purposes and must not be confused:

**The proxy is enforcement.** It operates at the network/process layer. The agent cannot bypass it. Every tool call passes through it whether the agent cooperates or not.

**The skill is distribution, UX, and proactive governance.** It teaches the agent how to query its own audit trail, report activity to the user, help draft policies, and — critically — take initiative on governance without being asked. It operates at the prompt layer.

The skill enables five interactions:

**Self-installation.** User tells their OpenClaw agent "set up governance." The agent reads the skill instructions, installs `relic`, runs `relic init`, and rewrites MCP config to route through the proxy. The agent bootstraps its own governance layer.

**Trace reporting.** User asks "what did you do while I was asleep?" The agent runs `relic trace list` and `relic trace view`, parses the output, and summarizes: actions taken, tools used, what was blocked, and why.

**Policy authoring.** User says "lock down my agent." The agent runs `relic trace search` to discover what tools it has been using, proposes a `policy.yaml` that allows only approved tools, shows it to the user for approval, and writes it on confirmation.

**Proactive post-task review.** After completing any substantial task, the agent automatically reviews its most recent trace without being prompted. The SKILL.md instructs:

1. Run `relic trace view <current_run_id> --denied` to check for denials
2. If denials exist, inform the user: "I was denied N actions during this task. [summary of what was blocked and why]."
3. Run `relic trace list` to compare the current run's denial count against the last 5 runs
4. If denials are significantly higher than recent history (e.g., 3x or more), flag it as anomalous: "This run had unusually high denials compared to my recent history. This might indicate a policy gap or a behavior change."
5. If the same tool has been denied more than 3 times across recent runs, proactively offer: "The tool X has been denied N times recently. The denial parameters suggest [analysis]. Would you like me to propose a policy update?"

**Proactive policy proposals.** When the agent detects a pattern of denials that suggests a policy gap rather than correct enforcement, it proposes a specific policy change:

1. Run `relic trace search --auth deny` to gather recent denial data
2. Analyze the denied tool calls — group by tool name, examine parameters
3. Distinguish between "correct denial" (user probably wants this blocked) and "policy gap" (user probably wants this allowed but hasn't configured it yet) based on context
4. Draft a proposed rule with an explanation: "Based on the last 5 runs, you've been denied `npm_install` 12 times. These all appear to be package installation commands. Proposed rule: allow `npm_install` with id: `allow-npm`. Want me to add this to your policy?"
5. Show the full proposed policy diff before writing
6. Write only after explicit user approval
7. If `--watch` is enabled, the new policy takes effect immediately

The skill cannot modify policy without explicit user approval, cannot retry denied actions, and cannot disable or circumvent the proxy. These constraints are stated in the SKILL.md and reinforced by the fact that the proxy enforces independently of the skill.

**Skill file structure:**

```
dist/openclaw-skill/the-relic/
├── SKILL.md                        # Instructions + YAML frontmatter
└── references/
    ├── policy-reference.md         # Policy syntax reference (grounds the agent)
    └── trace-format.md             # Trace field definitions
```

Distribution: Published to ClawHub. Installable via `openclaw skills install the-relic` or by dropping the folder into `~/.openclaw/skills/`. The `relic` binary is declared as a dependency in the SKILL.md frontmatter; OpenClaw prompts the user to install it if missing.

---

## 6. HTTP Logger Specification

### 6.1 Stage 1: Metadata-Only Logging

The HTTP logger operates as a forward proxy set via `HTTP_PROXY` / `HTTPS_PROXY`. In Stage 1, it does **not** perform TLS interception.

- **For HTTP (plaintext):** Full request/response capture. Authorization checked against policy.
- **For HTTPS (TLS):** The proxy sees the `CONNECT` request. It logs the target host and port. It tunnels the connection without decrypting. Authorization is checked at the host/port level only (not path or body).

This means Stage 1 HTTP governance is coarse-grained: you can allow/deny by host, not by path. This is acceptable because:

- Most agent tool calls go through MCP, not raw HTTP
- Host-level control covers the majority of authorization needs ("this agent can talk to api.example.com but not admin.internal.com")
- Path-level HTTP authorization is a Stage 2 feature unlocked by TLS interception

**v3.3: DNS-Level Network Policy.** When a `network` section is present in the policy, `relic run` calls `SetNetworkPolicy()` on the HTTP logger to install hostname-based allow/deny lists. Both `handleHTTP()` and `handleConnect()` call `checkNetworkPolicy()` before forwarding:

1. Extract the hostname from the request (stripping port)
2. Check `dns_deny` patterns first — if any glob matches, return 403 Forbidden
3. If `dns_allow` is non-empty, check if the hostname matches any allow pattern — if not, return 403 Forbidden
4. If `dns_allow` is empty, all non-denied hosts pass through

Glob matching uses the `doublestar` library, consistent with policy rule matching. This provides defense-in-depth: even if an MCP server makes outbound HTTP calls that bypass the MCP proxy, the HTTP proxy enforces network boundaries at the connection level.

### 6.2 Stage 1 HTTP Normalization

```
# Plaintext HTTP
ActionIntent {
    protocol: "http"
    method:   "GET"
    target:   "http://api.example.com/v1/data"
    params:   { headers: {...}, body_size: 1024 }
}

# HTTPS (metadata only)
ActionIntent {
    protocol: "https"
    method:   "CONNECT"
    target:   "api.example.com:443"
    params:   {}
}
```

### 6.3 Stage 2: Full HTTPS Interception (Deferred)

When implemented, the HTTPS inspector:

- Generates a local CA at `relic init` time
- Performs MITM on HTTPS connections
- Injects CA cert via `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`
- Enables path-level HTTP authorization and full request/response capture
- Activated via `relic run --https-inspect`

This is deferred because it is complex, platform-specific, and not needed for the MCP-primary interception strategy.

---

## 7. Policy Engine

### 7.1 Evaluation

```
function evaluate(action, policy) -> {decision, rule_id}:
    // Check constraints
    if run.action_count >= policy.constraints.max_actions:
        return {deny, "constraint:max_actions"}
    if run.elapsed >= policy.constraints.max_duration_seconds:
        return {deny, "constraint:max_duration"}

    // Evaluate rules in document order. First match wins.
    for rule in policy.rules:
        if glob(action.protocol, rule.protocol)
        AND glob(action.method, rule.method)
        AND glob(action.target, rule.target):
            return {rule.action, rule.id}

    // No match: apply default
    return {policy.default, "default"}
```

That's the entire engine. No priority sorting. No condition evaluation. No recursive rule composition. Approximately 50 lines of Go.

### 7.2 Agent Identity Verification

Before policy evaluation, the mediation engine verifies the agent's identity manifest:

1. Load `.tr/identity.json`
2. Verify signature (HMAC-SHA256 local, Ed25519 hosted)
3. Compare `capabilities_hash` against current `capabilities.json`
4. Compare `policy_hash` against loaded policy
5. If mismatch: emit `identity_mismatch` trace event
6. **Enforce mode:** refuse to start
7. **Audit/permissive mode:** log warning, continue

Does not require PKI, CA, or external infrastructure. HMAC-SHA256 with local key (`.tr/identity.key`) is sufficient.

### 7.2.1 Ed25519 Policy Signing (v3.3)

Independent of agent identity verification, policy files can be cryptographically signed using Ed25519 to guarantee provenance and integrity. This prevents policy tampering — a signed policy can be verified by anyone with the public key, without access to the signing secret.

**Key generation:**

```bash
relic keygen                              # Generates .tr/keys/relic.key (private) and .tr/keys/relic.pub (public)
relic keygen --out-dir /path/to/keys      # Custom output directory
```

Keys are PEM-encoded. The private key stays with the policy author (team lead, security admin, CI pipeline). The public key is distributed to all agents.

**Signing and verification:**

```bash
relic policy sign                         # Sign .tr/policy.yaml with .tr/keys/relic.key → .tr/policy.yaml.sig
relic policy sign --policy custom.yaml --key /path/to/key
relic policy verify                       # Verify .tr/policy.yaml against .tr/policy.yaml.sig using .tr/keys/relic.pub
relic policy verify --pubkey /path/to/pub
```

**Runtime enforcement:**

When `relic run --require-signature` is set (or `signature_required: true` in the policy), the runtime verifies the policy signature before loading. If verification fails, the run refuses to start. This ensures agents can only execute under policies approved by the signing authority.

```bash
relic run --require-signature --pubkey .tr/keys/relic.pub -- python agent.py
```

**Design choice:** Ed25519 was chosen over HMAC-SHA256 for policy signing because policy signing is a multi-party verification problem — the signer and verifiers are different principals. HMAC requires sharing a secret key with every verifier, which undermines the security model. Ed25519 provides asymmetric verification: sign with the private key, verify with the public key, no secret sharing required.

### 7.3 Behavioral Contracts (Parameter-Level Constraints)

Rules can include a `params` field that constrains parameter values using glob matching. A rule with `params` only matches if ALL specified parameter constraints match the action's actual parameters.

```yaml
rules:
  # Allow shell_exec but ONLY for package installation
  - id: allow-npm-install
    protocol: mcp
    method: tool_call
    target: "shell_exec"
    action: allow
    params:
      command: "npm install *"

  # Allow shell_exec for pip install
  - id: allow-pip-install
    protocol: mcp
    method: tool_call
    target: "shell_exec"
    action: allow
    params:
      command: "pip install *"

  # Deny all other shell_exec (no params constraint = matches everything)
  - id: deny-shell
    protocol: mcp
    method: tool_call
    target: "shell_exec"
    action: deny

  # Allow file_write but only to the output directory
  - id: allow-write-output
    protocol: mcp
    method: tool_call
    target: "file_write"
    action: allow
    params:
      path: "/workspace/output/**"

  # Allow web_fetch but only to approved domains
  - id: allow-fetch-approved
    protocol: mcp
    method: tool_call
    target: "web_fetch"
    action: allow
    params:
      url: "https://{api.example.com,cdn.example.com}/**"
```

**Evaluation logic:**

```
function matchRule(action, rule) -> bool:
    if not glob(action.protocol, rule.protocol): return false
    if not glob(action.method, rule.method): return false
    if not glob(action.target, rule.target): return false

    // Parameter constraints
    if rule.params is not empty:
        for key, pattern in rule.params:
            actual_value = action.params[key]
            if actual_value is missing: return false
            if not glob(actual_value, pattern): return false

    return true
```

Rules without `params` behave exactly as before — they match on protocol/method/target only. The `params` field is additive and backward compatible. Existing policies are unaffected.

This is the adoption unlock. Without parameter constraints, developers must choose between "allow `shell_exec` entirely" (insecure) or "deny `shell_exec` entirely" (breaks their workflow). Behavioral contracts let them express the policy they actually want.

Glob matching is a stepping stone toward a proper capability model. Data model designed for evolution without breaking changes.

### 7.4 Glob Matching

- `*` matches within a segment (no separators)
- `**` matches across segments
- `{a,b}` matches alternatives
- `?` matches one character

Implementation: use the `doublestar` Go library. Do not write a custom glob engine.

### 7.5 Policy Modes

| Mode | Denied actions | Trace records denial |
|---|---|---|
| `enforce` | Blocked, error returned to agent | Yes |
| `audit` | Allowed to proceed | Yes (flagged as `audit_deny`) |
| `permissive` | Allowed to proceed | Yes (flagged as `would_deny`) |

`permissive` is the default when no policy file exists. This lets developers start using `relic run` immediately without writing a policy. The trace shows what would have been denied, educating them toward policy authorship.

### 7.6 Redaction

Before any action event is written to the trace:

1. Scan `params` keys against `redaction.keys` list. Replace matching values with `"[REDACTED]"`.
2. Scan HTTP headers against `redaction.headers` list. Replace matching values with `"[REDACTED]"`.
3. No regex patterns in Stage 1. Simple key-name matching only.

### 7.7 Capability Fingerprinting

On first run (or via `relic fingerprint`), The Relic profiles the agent's complete tool surface and records it as a capability manifest.

**How it works:**

1. During proxy startup, after connecting to each MCP server, the proxy sends `tools/list` (which it already does for tool aggregation)
2. The full tool catalog — tool names, descriptions, parameter schemas — is written to `.tr/capabilities.json`
3. On subsequent runs, the proxy compares the current tool list against the stored manifest
4. New tools that weren't in the previous manifest are flagged:
   - In `--verbose` mode: printed to stderr
   - In the trace: a `capability_change` event is emitted
   - The proactive skill uses this to alert the user: "A new tool `data_export` was detected on the filesystem server. It is not in your policy and will be denied by default."
5. Removed tools are also flagged (a tool the policy allows no longer exists — potential misconfiguration)

**v3.2:** Capabilities hash now included in agent identity manifest.

**Capability manifest format:**

```json
{
  "generated_at": "2026-02-17T14:23:01Z",
  "servers": {
    "filesystem": {
      "transport": "stdio",
      "tools": [
        {
          "name": "read_file",
          "description": "Read a file from the filesystem",
          "parameters": {
            "type": "object",
            "properties": {
              "path": { "type": "string", "description": "File path to read" }
            },
            "required": ["path"]
          }
        }
      ]
    }
  },
  "tool_count": 12,
  "hash": "sha256:a3f8..."
}
```

**CLI command:**

```bash
relic fingerprint             # Generate/update capabilities.json
relic fingerprint --diff      # Show changes since last fingerprint
relic fingerprint --json      # Output machine-readable diff
```

**Policy generation input.** The capability manifest is the input the proactive skill needs to propose a complete policy on first run. Instead of waiting for denials, the agent can say: "Your agent has access to 12 tools across 3 MCP servers. Here are the tools grouped by risk level. Which would you like to allow?"

### 7.8 Immutable Policy History

Every policy change is recorded in an append-only changelog at `.tr/policy.log`.

**Events recorded:**

```json
{"ts":"2026-02-17T14:00:00Z","type":"policy_init","hash":"a3f8...","actor":"user","source":"relic init"}
{"ts":"2026-02-17T15:30:00Z","type":"policy_change","old_hash":"a3f8...","new_hash":"b7c2...","diff":"...unified diff...","actor":"user","source":"manual edit"}
{"ts":"2026-02-17T16:00:00Z","type":"policy_reload","old_hash":"a3f8...","new_hash":"b7c2...","actor":"--watch"}
```

**How it works:**

1. `relic init` writes the initial `policy_init` entry to `.tr/policy.log`
2. When `--watch` detects a policy file change, it writes a `policy_change` entry with the full unified diff, old/new hashes, and the actor
3. When a policy change is applied programmatically, the actor and source are recorded
4. The log file is append-only. The CLI never modifies or truncates it.

**CLI command:**

```bash
relic policy history              # Show policy changelog
relic policy history --json       # Machine-readable output
relic policy history --since 7d   # Changes in last 7 days
```

Every compliance framework (SOC 2, HIPAA, SOX) requires audit trails for access control changes. Policy history is the audit trail for the audit trail. Without it, an organization can prove what an agent did but not who authorized the change in permissions that allowed it.

### 7.9 Tool Call Provenance

An optional `context` field on trace action events that captures the agent's stated reason for making a tool call.

**How it works:**

1. MCP tool call requests can include a `_context` field in their parameters (or in MCP request metadata, depending on framework conventions)
2. The proxy extracts `_context` if present, strips it from the parameters forwarded to the real tool server
3. The extracted context is recorded in the trace event as a `ctx` field:

```json
{"v":1,"t":"action","ts":"...","run":"01JMQ...","seq":3,"proto":"mcp","method":"tool_call","target":"file_write","auth":"allow","rule":"allow-write-output","ctx":"Writing analysis results from web search to output file"}
```

4. If `_context` is not present (most tool calls today), the field is omitted. Zero overhead, fully backward compatible.

**Why this matters now:** Debugging. When reviewing a trace, "file_write to /out/report.md" tells you what happened. "Writing analysis results from web search to output file" tells you why. Intent vs. behavior mismatch is a useful anomaly signal — an agent claiming "backing up data" while writing to an external endpoint is suspicious.

**Why this matters long-term:** Accountability in multi-agent scenarios. When Agent A calls Agent B's tool, both sides want to know not just what was called but the stated purpose.

### 7.10 Delegation Graph (Scope Reduction)

When an agent spawns a child agent (nested `relic run`), the child's effective permissions are the intersection of all policies from the root to the current node in the delegation graph. A child agent can never have more access than its parent.

**How it works:**

1. When `relic run` starts, it checks if `RELIC_RUN_ID` is already set in the environment (indicating it's running inside a parent `relic run` session)
2. If a parent session exists, the child reads the parent's policy hash from `RELIC_PARENT_POLICY` environment variable
3. The child loads both its own policy and the parent's policy (stored at `.tr/policies/<hash>.yaml` — the parent writes its policy to this location on startup)
4. The effective policy engine evaluates all policies in the delegation chain: an action is only allowed if ALL ancestor policies AND the child's own policy allow it

**Evaluation logic:**

```
function evaluate_with_delegation(action, child_policy, parent_policy, runState):
    parent_decision = evaluate(action, parent_policy, runState)
    if parent_decision.decision == "deny":
        return {deny, "delegation:" + parent_decision.rule_id,
                "Parent policy denies this action"}

    child_decision = evaluate(action, child_policy, runState)
    return child_decision
```

5. The trace records the delegation context:

```json
{"v":1,"t":"run","ts":"...","run":"01JMR...","agent":"sub-agent","agent_v":"1.0.0","policy":"sha256:...","status":"start","parent_run":"01JMQ...","parent_policy":"sha256:...","delegation_depth":1,"delegation_root":"01JMQ..."}
```

**Handles three scenarios the parent-child model could not:**

- **Fan-out orchestration:** Coordinator spawns 5 workers in parallel. Each worker's permissions = intersection of coordinator's policy and its own.
- **Dynamic delegation:** A delegates to B delegates to C. Permission boundary narrows at each level.
- **Multi-root graphs:** Agent receives delegated authority from multiple external agents.

**Environment variables (backward compatible):**

| Variable | Purpose |
|---|---|
| `RELIC_PARENT_RUN_ID` | The parent's run ID |
| `RELIC_PARENT_POLICY` | Path to the parent's cached policy file |
| `RELIC_DELEGATION_DEPTH` | Current depth in delegation graph |
| `RELIC_DELEGATION_ROOT` | Root run ID |

Without scope reduction, a coordinator agent with restricted permissions can delegate to a child agent with broader permissions, effectively escalating privileges. This is the same problem Unix solved with process capabilities. Scope reduction ensures the permission boundary holds across the delegation chain.

---

## 8. Trace System

### 8.1 Write Path

```
Action intercepted by proxy
         │
         ▼
Policy engine evaluates ──> auth decision
         │
         ▼
Redaction applied to params
         │
         ▼
Single JSON line constructed
         │
         ▼
Appended to .trtrace file (O_APPEND, fsync batched every 100ms)
```

No SQLite. No event bus. No Unix socket. The file is written and that's it.

### 8.2 Read Path

```
relic trace view <run_id>
    → Open .tr/traces/<run_id>.trtrace
    → Parse NDJSON line by line
    → Format and display

relic trace view --follow <run_id>
    → Tail the .trtrace file (inotify / FSEvents / polling)
    → Parse new lines as they appear
```

### 8.3 Search Path (Stage 1)

```
relic trace search --target "web_search" --auth deny
    → Scan all .trtrace files in .tr/traces/
    → Parse each line, filter by criteria
    → Display matching events
```

This is a linear scan. For a developer with dozens to hundreds of runs, it completes in milliseconds. When it becomes slow, add SQLite indexing. Not before.

### 8.4 Trace Integrity Chain (v3.3)

Trace files support an optional rolling HMAC-SHA256 integrity chain that makes tampering, insertion, or deletion of events detectable after the fact.

**How it works:**

1. At run start, the trace writer initializes an `IntegrityChain` with a secret key derived from the run ID (prefix: `relic-trace-chain-v1`)
2. Each trace event is sealed: `Seal(eventJSON)` computes `HMAC-SHA256(key, previousHMAC || eventJSON)` and appends an `hmac` field to the event
3. The HMAC chain is rolling — each event's HMAC depends on all preceding events. Modifying, inserting, or removing any event breaks the chain from that point forward
4. The final event's HMAC is a commitment over the entire trace

**Verification:**

```bash
relic trace verify <trace-file>         # Verify HMAC chain integrity
relic trace verify .tr/traces/01JMQ....trtrace
```

`VerifyChain()` re-computes the rolling HMAC for every event in the file and confirms each matches the stored `hmac` field. If any event has been tampered with, the verification reports the first broken link.

**Design choice:** HMAC-SHA256 (not Ed25519) is correct for trace integrity because it is a self-verification problem — the same runtime that writes the trace also verifies it. There is no multi-party verification requirement. HMAC is faster and does not require key management infrastructure. The chain structure (each HMAC depends on all previous) provides tamper evidence equivalent to a Merkle chain.

### 8.5 Storage

Traces live in `.tr/traces/`. One file per run. Files are never modified after the run ends. Total local disk usage is self-managing: add `relic trace prune --older-than 30d` as a convenience command.

---

## 9. CLI Specification

### 9.1 `relic run`

The primary command. Everything else is secondary.

```
relic run [flags] -- <command> [args...]
```

**Behavior:**

1. Load policy from `.tr/policy.yaml` (or `--policy <path>`)
2. **v3.3:** If `--require-signature` or policy `signature_required: true`, verify Ed25519 signature before proceeding
3. Load MCP config from `.tr/mcp.yaml` (or `--mcp <path>`)
4. Generate run ID (ULID)
5. **v3.3:** If policy includes `filesystem` config, create sandbox workspace with mounted paths
6. Start MCP proxy (bind to localhost, random port or `--mcp-port`); attach sandbox if created
7. Start HTTP logger (bind to localhost, random port or `--http-port`); apply `network` policy if configured
8. Write run start event to trace
9. **v3.3:** Sanitize environment (strip dangerous variables), then spawn agent command with:
   - `RELIC_MCP_URL=http://localhost:<mcp-port>/mcp` (or stdio pipe)
   - `HTTP_PROXY=http://localhost:<http-port>`
   - `HTTPS_PROXY=http://localhost:<http-port>`
   - `RELIC_RUN_ID=<run-id>`
   - `RELIC_GOVERNED=1`
10. Proxy runs until agent process exits
11. Write run end event to trace
12. **v3.3:** Clean up sandbox workspace if created
13. Print summary: total actions, allowed, denied, duration, trace file path

**Flags:**

| Flag | Description |
|---|---|
| `--policy <path>` | Policy file (default: `.tr/policy.yaml`) |
| `--mcp <path>` | MCP config file (default: `.tr/mcp.yaml`) |
| `--mode <mode>` | Override policy mode (`enforce\|audit\|permissive`) |
| `--env <name>` | Environment label (default: `local`) |
| `--capture-responses` | Include tool response bodies in trace (default: off) |
| `--watch` | Watch policy file for changes, hot-reload on modification |
| `--verbose` | Print actions to stdout in real-time |
| `--quiet` | Suppress all output except errors |
| `--require-signature` | v3.3: Verify Ed25519 policy signature before loading |
| `--pubkey <path>` | v3.3: Path to Ed25519 public key (default: `.tr/keys/relic.pub`) |

**Framework integration flags:**

| Flag | Description |
|---|---|
| `--from-claude-config` | Read MCP servers from Claude Desktop config |
| `--from-openclaw` | Read MCP servers from OpenClaw `openclaw.json` |
| `--openclaw-config <p>` | Path to `openclaw.json` (default: `~/.openclaw/openclaw.json`) |
| `--openclaw-agent <id>` | Govern a specific agent in multi-agent setup (default: all) |

**Integration examples:**

```bash
# Claude Desktop — interposes on all MCP servers
relic run --from-claude-config -- claude

# OpenClaw — interposes on all MCP servers for all agents
relic run --from-openclaw -- openclaw gateway

# OpenClaw — govern only the "home" agent in a multi-agent gateway
relic run --from-openclaw --openclaw-agent home -- openclaw gateway

# OpenClaw — per-agent policies
relic run --from-openclaw --openclaw-agent home --policy .tr/policy-home.yaml -- openclaw gateway

# Generic — provide your own MCP config
relic run --mcp ./my-mcp-servers.yaml -- python agent.py
```

### 9.2 `relic init`

```bash
relic init
```

Creates `.tr/` directory with:
- `policy.yaml` — starter policy in permissive mode with common redaction rules (includes commented zero-trust extension examples for `signature_required`, `filesystem`, `network`)
- `mcp.yaml` — empty server list with commented examples
- `traces/` — empty directory
- `identity.json` — agent identity manifest (v3.2)
- `identity.key` — HMAC-SHA256 key for local signing (v3.2)

### 9.3 `relic trace view`

```bash
relic trace view <run_id>              # Display all events
relic trace view <run_id> --denied     # Only denied actions
relic trace view <run_id> --follow     # Live tail during run
relic trace view <run_id> --json       # Raw NDJSON output
```

### 9.4 `relic trace list`

```bash
relic trace list                       # Recent runs
relic trace list --agent "my-agent"    # Filter by agent name
relic trace list --has-denials         # Only runs with denied actions
```

### 9.5 `relic trace search`

```bash
relic trace search --target "web_*"              # Actions matching target glob
relic trace search --auth deny                   # All denied actions across runs
relic trace search --proto mcp --target "db_*"   # MCP calls to db tools
```

### 9.6 `relic policy init` / `relic policy validate`

```bash
relic policy init                      # Generate starter policy
relic policy validate                  # Check syntax and consistency
relic policy validate --strict         # Also warn on overly permissive rules
```

### 9.6.1 `relic policy pull`

```bash
relic policy pull                                      # Pull policy for the agent in .tr/policy.yaml
relic policy pull --agent data-pipeline-agent          # Pull for an explicit agent
relic policy pull --dry-run                            # Print fetched policy without writing
relic policy pull --force                              # Overwrite local edits
relic policy pull --out ./custom-policy.yaml           # Write to a custom path
```

The control plane is the policy authority — agents pull from it, local files are a fallback when offline. `relic policy pull` calls `GET /v1/agents/:name/policy`, validates the returned YAML before touching disk, and refuses to overwrite a locally-modified file unless `--force` is set. Requires `RELIC_API_KEY`; override the endpoint with `RELIC_API_URL`.

### 9.7 `relic identity`

```bash
relic identity init                    # Generate identity manifest + key
relic identity verify                  # Verify current manifest against state
relic identity show                    # Display identity details
```

### 9.8 `relic keygen` (v3.3)

```bash
relic keygen                           # Generate Ed25519 keypair to .tr/keys/
relic keygen --out-dir /path/to/keys   # Custom output directory
```

Generates `relic.key` (Ed25519 private key, PEM-encoded) and `relic.pub` (public key, PEM-encoded). The private key is used for `relic policy sign`. The public key is distributed to agents for `relic policy verify` and `relic run --require-signature`.

### 9.9 `relic policy sign` / `relic policy verify` (v3.3)

```bash
relic policy sign                                    # Sign .tr/policy.yaml → .tr/policy.yaml.sig
relic policy sign --policy p.yaml --key /path/key    # Custom paths
relic policy verify                                  # Verify .tr/policy.yaml signature
relic policy verify --pubkey /path/to/relic.pub      # Custom public key path
```

### 9.10 `relic trace verify` (v3.3)

```bash
relic trace verify <trace-file>                      # Verify HMAC-SHA256 integrity chain
relic trace verify .tr/traces/01JMQ....trtrace       # Returns OK or first broken link
```

---

## 10. Technology Choices

| Component | Choice | Why |
|---|---|---|
| Language | Go | Single binary, fast compile, excellent net/io, cross-platform |
| CLI | `cobra` | Standard, well-documented |
| MCP protocol | Custom JSON-RPC | MCP is simple enough; no framework needed |
| Glob matching | `doublestar` | Battle-tested `**` support |
| YAML parsing | `gopkg.in/yaml.v3` | Standard |
| IDs | ULID (`oklog/ulid`) | Time-ordered, sortable, lexicographic |
| Trace format | NDJSON | Human-readable, grep-friendly, streamable |
| CI/CD | GitHub Actions + GoReleaser | Standard for Go projects |
| File watching | `fsnotify` | Cross-platform file system notifications for `--watch` |
| Agent identity (local) | HMAC-SHA256 | No external deps, sufficient locally |
| Policy signing | Ed25519 | Asymmetric verification, no secret sharing with verifiers |
| Trace integrity | HMAC-SHA256 rolling chain | Self-verification, fast, no key management |
| Filesystem sandbox | OS symlinks + temp workspace | No containerization overhead, works everywhere |
| Network policy matching | `doublestar` globs on hostnames | Consistent with policy rule matching |
| Linting | `golangci-lint` | errcheck, staticcheck, unused, govet |
| Vulnerability scanning | `govulncheck` | Go official vuln database |
| Code coverage | Codecov | Industry standard, free for OSS |
| Mediation abstraction | Go interface | Same pattern as `net.Listener` |

---

## 11. Appendices

### 11.1 File System Layout

```
<project>/.tr/
├── policy.yaml              # Authorization policy
├── policy.yaml.sig          # Ed25519 policy signature (v3.3, optional)
├── mcp.yaml                 # MCP server configuration
├── identity.json            # Agent identity manifest (v3.2)
├── identity.key             # HMAC-SHA256 signing key (v3.2)
├── capabilities.json        # Capability fingerprint
├── policy.log               # Immutable policy changelog
├── keys/                    # Ed25519 keypair for policy signing (v3.3)
│   ├── relic.key            # Private key (PEM-encoded, keep secret)
│   └── relic.pub            # Public key (PEM-encoded, distribute to agents)
├── policies/                # Cached parent policies for delegation
│   └── <hash>.yaml
└── traces/
    ├── 01JMQ....trtrace
    └── 01JMR....trtrace

dist/openclaw-skill/the-relic/    # Ships with relic binary
├── SKILL.md                       # Instructions + YAML frontmatter
└── references/
    ├── policy-reference.md        # Policy syntax reference
    └── trace-format.md            # Trace field definitions

# Installed by user or skill installer:
~/.openclaw/skills/the-relic/     # Same contents, copied here
```

No user-level config directory in Stage 1. Project-level only. User-level config (`~/.tr/`) added when there's a reason (hosted credentials in Stage 2).

### 11.2 Environment Variables

| Variable | Purpose | Set By |
|---|---|---|
| `RELIC_MCP_URL` | MCP proxy endpoint for agent | Runtime |
| `HTTP_PROXY` | HTTP logger endpoint | Runtime |
| `HTTPS_PROXY` | HTTPS logger endpoint | Runtime |
| `RELIC_RUN_ID` | Current run identifier | Runtime |
| `RELIC_PARENT_RUN_ID` | Parent's run ID (delegation) | Runtime |
| `RELIC_PARENT_POLICY` | Path to parent's cached policy | Runtime |
| `RELIC_DELEGATION_DEPTH` | Current depth in delegation graph | Runtime |
| `RELIC_DELEGATION_ROOT` | Root run ID in delegation graph | Runtime |
| `RELIC_POLICY_PATH` | Override policy location | User |
| `RELIC_MODE` | Override policy mode | User |
| `RELIC_ENV` | Environment label | User |
| `RELIC_API_KEY` | API key for hosted features | User |
| `RELIC_GOVERNED` | Set to `1` when agent runs under `relic run` (v3.3) | Runtime |

**v3.3: Environment Hardening.** Before spawning the agent process, `relic run` strips dangerous environment variables to prevent sandbox escape:

| Category | Variables Stripped |
|---|---|
| Proxy overrides | `http_proxy`, `HTTP_PROXY`, `https_proxy`, `HTTPS_PROXY`, `all_proxy`, `ALL_PROXY` (re-set to point at The Relic's proxies) |
| TLS bypass | `NODE_TLS_REJECT_UNAUTHORIZED`, `PYTHONHTTPSVERIFY`, `GIT_SSL_NO_VERIFY`, `CURL_CA_BUNDLE` |
| Library injection | `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `LD_LIBRARY_PATH` |
| Variable spoofing | Any variable starting with `RELIC_` not set by the runtime itself |

The `no_proxy` variable is also cleared to prevent agents from bypassing the HTTP proxy. `RELIC_GOVERNED=1` is injected so agents can detect they are running under governance.

### 11.3 Error Responses

**MCP denial (JSON-RPC error):**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32600,
    "message": "Action denied by policy",
    "data": {
      "rule": "default",
      "target": "file_write",
      "reason": "No matching allow rule. Default action: deny."
    }
  }
}
```

**HTTP denial (403 Forbidden):**

```json
{
  "error": "Action denied by The Relic policy",
  "rule": "deny-all-writes",
  "target": "api.example.com/v1/users"
}
```

### 11.4 Design Decisions Log

| Decision | Chose | Over | Why |
|---|---|---|---|
| **Framing** | Zero trust substrate | Governance proxy | Enterprise positioning, distributed systems model |
| **Identity timing** | Pre-platform | Deferred enterprise | Foundational to zero trust |
| **Local identity crypto** | HMAC-SHA256 | Ed25519 day 1 | No PKI needed for identity manifests locally |
| **Policy signing crypto** | Ed25519 | HMAC-SHA256 | Multi-party verification; signer ≠ verifier; no secret sharing |
| **Delegation** | DAG graph | Parent-child | Fan-out, dynamic, multi-root |
| **Abstraction** | Transport-agnostic | Proxy-per-protocol | Reuse locally + server-side + network |
| **Contracts** | Glob now, caps later | Full capability model | Ships fast, backward compat |
| Primary interception | MCP proxy | HTTP MITM | Lower complexity, higher value per action, aligns with ecosystem direction |
| Trace events | Single action event | Three separate events | Smaller files, simpler parsing, self-contained events |
| Rule ordering | Document order | Priority field | One ordering system, no ambiguity, matches developer intuition |
| Local storage | Flat NDJSON files | SQLite index | Simpler, sufficient for dev-scale, grep-friendly |
| Stage 1 HTTPS | Metadata logging | Full MITM | Weeks of implementation saved, CA injection complexity avoided |
| Stage 1 scope | MCP + HTTP | MCP + HTTP + FS + Subprocess | Two adapters ship faster than four; FS/subprocess add later |
| Policy conditions | Deferred to Stage 3 | Included in Stage 1 | Halves policy engine complexity; not needed for developer use case |
| Launch integration | OpenClaw first | Generic "any framework" | 175k+ star ecosystem with documented governance gap; sharpest adoption wedge |
| Multi-agent traces | Correlation ID field | Nested traces / shared trace files | Each agent's trace stays self-contained; correlation is query-time, not write-time |
| OpenClaw integration | Config adapter (CLI flag) | OpenClaw plugin/skill | Zero OpenClaw code changes; works with any version; no maintenance dependency |
| Agent-to-agent auth | Same policy engine, same rules | Separate delegation subsystem | Inter-agent calls are tool calls; governing them requires zero new components |
| OpenClaw skill | SKILL.md for distribution + UX | Skill as enforcement layer | Skills are prompt-layer (bypassable); proxy is network-layer (not bypassable) |
| Policy hot-reload | File watcher + atomic swap | Restart proxy on change | Mid-session updates critical for proactive skill |
| Proactive skill | Agent auto-reviews unprompted | Agent responds only when asked | Nobody asks "what did you do last run"; governance must be surfaced, not pulled |
| Behavioral contracts | Glob matching on params | Regex / custom DSL | Glob is already in the codebase; developers know it; regex is a security footgun |
| Capability fingerprinting | tools/list diffing | Static analysis of MCP servers | tools/list is already intercepted; diff is trivial; static analysis requires parsing arbitrary server code |
| Policy history | Append-only NDJSON log | Git-tracked policy file | Separate log captures actor and automated changes; git only captures manual edits |
| Provenance capture | Optional _context field extraction | Require all agents to annotate | Optional means zero adoption friction; mandatory breaks every existing agent |
| Delegation scope reduction | Policy intersection at runtime | Separate delegation permission system | Intersection uses the existing policy engine; no new evaluation model |
| Filesystem sandbox | Symlink-based temp workspace | Containers / chroot | No root required, cross-platform, zero dependencies |
| Sandbox enforcement point | MCP proxy (tool call interception) | OS-level filesystem monitor | Already intercepting all tool calls; FS monitor is complexity for marginal gain |
| Network policy level | DNS hostname globs | IP-level firewall rules | Hostnames are what policy authors understand; IP rules break on CDNs/dynamic IPs |
| Trace integrity | HMAC-SHA256 rolling chain | Digital signatures per event | Self-verification (same runtime writes+verifies); HMAC is 10x faster; no key distribution |
| Env hardening scope | Strip proxy/TLS/injection/spoofing vars | Full env whitelist | Whitelist breaks too many agent workflows; targeted stripping handles known attack vectors |
| CI quality gates | lint + test + vulncheck + coverage | Test only | Early adoption of quality gates prevents tech debt accumulation |
| Fuzz testing | Policy parser + proxy handlers | Skip fuzzing | Security-critical input parsing benefits disproportionately from fuzzing |
| Stack license | Apache 2.0 on runtime + website, BSL 1.1 on platform + app | All-Apache or all-BSL | Runtime needs maximum adoption (OSS-only procurement gates, distro packaging, no CLA); platform / app need protection from competing hosted clones. Apache 2.0 chosen for runtime over MIT for patent grant + retaliation + trademark clause. |
| Trust-network split | Mediation transport in `therelic` (Apache), registry + scoring + marketplace in `therelic-platform` (BSL) | Single repo or single license | Protocol must be open to become an interoperability standard; operations stay BSL so no competing hosted marketplace can clone the network effect |
| Policy authority direction | Agent pulls from control plane (`relic policy pull`) | Control plane pushes to agent | Agents are intermittently online; pull model works behind NAT/firewalls; same model as `git pull`, `apt update` |

### 11.5 Trace Format Version

| Version | Description |
|---|---|
| v1 | Initial: `run` and `action` event types, short field names, single-event-per-action. Optional multi-agent fields: `corr`, `to_agent`, `from_agent`, `from_run`. |
| v1 (additive) | `policy_reload` event type for hot-reload. `from_agent` field on policy rules. `agent_fp` on run start events. `identity_mismatch` event type. `capability_change` event type. No version bump per compatibility rule. |
| v1 (additive, v3.3) | Optional `hmac` field on all events (HMAC-SHA256 rolling integrity chain). Parsers that do not verify integrity ignore this field per compatibility rule. |

**Compatibility rule:** Parsers must ignore unknown fields. New fields can be added without version bump. New event types can be added without version bump. Structural changes to existing fields require version bump.

### 11.6 OpenClaw Config Parsing

The `--from-openclaw` flag reads OpenClaw's `openclaw.json` and extracts MCP server definitions. The relevant config structure:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
    },
    "web-search": {
      "url": "http://localhost:3001/mcp"
    }
  },
  "agents": {
    "list": [
      { "id": "home", "workspace": "~/.openclaw/workspace-home" },
      { "id": "work", "workspace": "~/.openclaw/workspace-work" }
    ]
  },
  "tools": {
    "agentToAgent": {
      "enabled": true,
      "allow": ["home", "work"]
    }
  }
}
```

The Relic reads `mcpServers` to determine what to proxy. It reads `agents.list` to support per-agent policies via `--openclaw-agent`. It reads `tools.agentToAgent` to identify inter-agent messaging tools for trace correlation.

The parser handles only these fields. All other OpenClaw configuration is passed through unmodified. The Relic does not depend on OpenClaw's internal schema beyond these entry points.
