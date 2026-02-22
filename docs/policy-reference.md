# Policy Reference

A complete reference for `.tr/policy.yaml`.

---

## File Structure

```yaml
version: "1"           # required — must be "1"

agent:                 # required — identifies the agent this policy governs
  name: "my-agent"
  version: "1.0.0"

mode: enforce          # required — enforce | audit | permissive
default: deny          # required — deny | allow

redaction:             # optional — values to scrub from trace files
  keys: []
  headers: []

rules: []              # optional — authorization rules (document order, first match wins)

constraints:           # optional — hard limits per run
  max_actions: 0
  max_duration_seconds: 0
```

---

## Fields

### `version`

**Required.** Must be `"1"`.

```yaml
version: "1"
```

---

### `agent`

**Required.** Identifies the agent this policy applies to. Used for display in
`relic trace list` and as metadata in trace files.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Agent name (free-form label) |
| `version` | string | no | Agent version (free-form label) |

```yaml
agent:
  name: "openclaw"
  version: "1.0.0"
```

---

### `mode`

**Required.** Controls how the policy engine handles denied actions.

| Value | Denied actions | Trace `auth` field |
|-------|---------------|-------------------|
| `enforce` | **Blocked** — agent receives a structured error | `deny` |
| `audit` | **Allowed** — action proceeds, flagged in trace | `audit_deny` |
| `permissive` | **Allowed** — action proceeds, flagged in trace | `would_deny` |

> **Workflow:** Start with `permissive` to discover what your agent does.
> Switch to `audit` to shadow-test rules. Switch to `enforce` when ready.

```yaml
mode: enforce
```

Override at run time without editing the file:

```bash
relic run --mode audit -- my_agent
```

---

### `default`

**Required.** The decision when no rule matches the action.

| Value | Effect |
|-------|--------|
| `deny` | Unmatched actions are denied (recommended) |
| `allow` | Unmatched actions are allowed (use with explicit deny rules) |

```yaml
default: deny
```

> **Security note:** `mode: enforce` + `default: allow` is flagged as a
> warning by `relic policy validate --strict` because any unrecognized action
> would be permitted.

---

### `redaction`

**Optional.** Lists parameter keys and HTTP header names to replace with
`"[REDACTED]"` before writing to the trace file. Matching is case-insensitive.
Redaction applies to all actions regardless of their auth outcome.

| Field | Type | Description |
|-------|------|-------------|
| `keys` | []string | JSON parameter key names to redact (recursive) |
| `headers` | []string | HTTP header names to redact |

```yaml
redaction:
  keys:
    - password
    - token
    - api_key
    - apikey
    - secret
    - access_token
    - refresh_token
    - private_key
    - client_secret
  headers:
    - Authorization
    - X-Api-Key
    - X-Auth-Token
    - Cookie
    - Set-Cookie
```

**Key redaction is recursive.** Given `keys: ["token"]`, both of these are
redacted:

```json
{ "token": "abc123" }
{ "auth": { "token": "abc123" } }
```

**Array elements are scanned.** An array of objects will have matching keys
redacted in each element.

---

### `rules`

**Optional.** An ordered list of authorization rules. Evaluation stops at the
first match. If no rule matches, `default` applies.

```yaml
rules:
  - id: allow-web-search
    protocol: mcp
    method: tool_call
    target: "web_search"
    action: allow
```

#### Rule fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique identifier for this rule. Appears in trace `rule` field and error messages. |
| `protocol` | string | yes | Protocol to match. `mcp`, `http`, `https`, or `*` |
| `method` | string | yes | Method to match. See methods table below. |
| `target` | string | yes | Target to match. Glob pattern. See glob syntax. |
| `action` | string | yes | `allow` or `deny` |

#### Protocols

| Value | Matches |
|-------|---------|
| `mcp` | MCP tool calls, resource reads, prompt gets |
| `http` | Plaintext HTTP requests |
| `https` | HTTPS CONNECT requests (connection-level metadata only in Stage 1) |
| `*` | Any protocol |

#### Methods

**MCP methods:**

| Value | Matches |
|-------|---------|
| `tool_call` | `tools/call` requests |
| `resource_read` | `resources/read` requests |
| `prompt_get` | `prompts/get` requests |
| `*` | Any MCP method |

**HTTP methods:**

| Value | Matches |
|-------|---------|
| `GET` | HTTP GET |
| `POST` | HTTP POST |
| `PUT` | HTTP PUT |
| `DELETE` | HTTP DELETE |
| `PATCH` | HTTP PATCH |
| `CONNECT` | HTTPS CONNECT (tunnel establishment) |
| `*` | Any HTTP method |

---

### `constraints`

**Optional.** Hard limits per run. Constraints are enforced regardless of
`mode` — they cannot be overridden by `audit` or `permissive` mode.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_actions` | int | 0 (disabled) | Maximum total actions in this run |
| `max_duration_seconds` | int | 0 (disabled) | Maximum wall-clock seconds for this run |

When a constraint is hit, the action is blocked with `auth=deny` and
`rule=constraint:max_actions` or `rule=constraint:max_duration`.

```yaml
constraints:
  max_actions: 500
  max_duration_seconds: 3600  # 1 hour
```

---

## Glob Syntax

Rule fields `protocol`, `method`, and `target` all support glob patterns using
[doublestar](https://github.com/bmatcuk/doublestar) semantics.

| Pattern | Matches |
|---------|---------|
| `*` | Any sequence of non-separator characters |
| `**` | Any sequence of characters including `/` |
| `?` | Any single non-separator character |
| `{a,b,c}` | Any of the alternatives |
| `[abc]` | Any character in the set |
| `[a-z]` | Any character in the range |

> The separator is `/`. For tool names (no `/`), `*` and `**` are equivalent.

### Examples

```yaml
# Match any tool name
target: "*"

# Match exactly one tool
target: "web_search"

# Match tools starting with "file_"
target: "file_*"

# Match any of several tools
target: "{web_search,web_fetch,browser_navigate}"

# Match tools on any sub-path
target: "filesystem/**"

# Match any URL on a specific domain
target: "api.example.com/**"

# Match any URL on any subdomain
target: "**.example.com/**"
```

---

## Auth Decision Values

The `auth` field in trace events (`relic trace view`) has these values:

| Value | Mode | Meaning |
|-------|------|---------|
| `allow` | any | Rule matched with `action: allow` (or `default: allow`) |
| `deny` | enforce | Action was blocked |
| `audit_deny` | audit | Would have been denied; allowed with flag |
| `would_deny` | permissive | Would have been denied; allowed with flag |

---

## Example Policies

### 1. Permissive observer (initial setup)

```yaml
version: "1"
agent:
  name: "my-agent"
  version: "1.0.0"
mode: permissive
default: deny
redaction:
  keys: [password, token, api_key, secret]
  headers: [Authorization, X-Api-Key]
rules: []
```

All actions are allowed and logged as `would_deny`. Use this to observe your
agent before writing rules.

---

### 2. Audit mode — shadow-test rules without blocking

```yaml
version: "1"
agent:
  name: "my-agent"
  version: "1.0.0"
mode: audit
default: deny
rules:
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
```

Rules are evaluated but denials are `audit_deny` — the action proceeds. Use
`relic trace search --auth audit_deny` to find legitimate tools that need allow rules.

---

### 3. Read-only agent

```yaml
version: "1"
agent:
  name: "read-only-agent"
  version: "1.0.0"
mode: enforce
default: deny
rules:
  - id: allow-reads
    protocol: mcp
    method: tool_call
    target: "{read_file,list_directory,get_file_info,search_files}"
    action: allow
  - id: allow-web-reads
    protocol: mcp
    method: tool_call
    target: "{web_search,web_fetch}"
    action: allow
  - id: allow-http-get
    protocol: http
    method: GET
    target: "**"
    action: allow
  - id: deny-http-writes
    protocol: http
    method: "{POST,PUT,DELETE,PATCH}"
    target: "**"
    action: deny
```

---

### 4. Deny everything except one tool

```yaml
version: "1"
agent:
  name: "single-purpose-agent"
  version: "1.0.0"
mode: enforce
default: deny
rules:
  - id: allow-only-echo
    protocol: mcp
    method: tool_call
    target: "echo"
    action: allow
```

---

### 5. Time-limited research agent

```yaml
version: "1"
agent:
  name: "research-agent"
  version: "1.0.0"
mode: enforce
default: deny
redaction:
  keys: [password, token, api_key]
  headers: [Authorization, Cookie]
rules:
  - id: allow-web-tools
    protocol: mcp
    method: tool_call
    target: "{web_search,web_fetch,browser_*}"
    action: allow
  - id: allow-read-only-fs
    protocol: mcp
    method: tool_call
    target: "{read_file,list_directory}"
    action: allow
  - id: allow-http-get
    protocol: http
    method: GET
    target: "**"
    action: allow
  - id: deny-all-writes
    protocol: mcp
    method: tool_call
    target: "{write_file,create_*,delete_*,execute_*,send_*}"
    action: deny
constraints:
  max_actions: 100
  max_duration_seconds: 900  # 15 minutes
```

---

## Validation

```bash
# Check for errors
relic policy validate

# Also warn on insecure configurations
relic policy validate --strict
```

**Validation checks:**
- `version` must be `"1"`
- `agent.name` must be present
- `mode` must be `enforce`, `audit`, or `permissive`
- `default` must be `deny` or `allow`
- Each rule must have `id`, `protocol`, `method`, `target`, `action`
- Rule IDs must be unique
- `action` must be `allow` or `deny`
- **Strict:** warns if `mode: enforce` + `default: allow` (allows all unmatched)

---

## CLI Reference

```bash
# Initialize a new policy (overwrites if --force)
relic policy init [--force]

# Validate the default policy file
relic policy validate

# Validate a specific file
relic policy validate --policy path/to/policy.yaml

# Strict mode (adds security warnings)
relic policy validate --strict

# Override mode at runtime without editing the file
relic run --mode audit -- my_agent
relic run --mode permissive -- my_agent

# Use a different policy file for this run
relic run --policy staging.yaml -- my_agent
```
