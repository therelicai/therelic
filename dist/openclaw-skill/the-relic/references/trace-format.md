# Trace File Format

The Relic writes one `.trtrace` file per run to `.tr/traces/<run_id>.trtrace`.
The format is **NDJSON** (newline-delimited JSON): one JSON object per line.
Files are append-only and never modified after the run ends.

---

## Event Types

Every line is one of two event types, identified by the `"t"` field:

| `t` value | Description |
|-----------|-------------|
| `"run"` | Lifecycle event: run started or ended |
| `"action"` | A single intercepted tool call, resource read, or HTTP request |

---

## Common Fields (all events)

| Field | Type | Description |
|-------|------|-------------|
| `v` | int | Schema version. Currently `1`. |
| `t` | string | Event type: `"run"` or `"action"` |
| `ts` | string | RFC3339Nano timestamp (UTC), e.g. `"2025-01-15T09:03:12.456789Z"` |
| `run` | string | ULID run identifier, e.g. `"01ARZ3NDEKTSV4RRFFQ69G5FAV"` |

---

## Run Event Fields (`t == "run"`)

Emitted at the start and end of every `relic run` invocation.

| Field | Type | When | Description |
|-------|------|------|-------------|
| `status` | string | always | `"start"` or `"end"` |
| `agent` | string | start | Agent command (argv[0]), e.g. `"openclaw"` |
| `agent_v` | string | start | Agent version, if known |
| `policy` | string | start | SHA of the loaded policy file |
| `env` | string | start | Environment label (`--env` flag), e.g. `"local"` |
| `exit` | int | end | Child process exit code |
| `ms` | int | end | Wall-clock duration in milliseconds |
| `actions_total` | int | end | Total intercepted actions in this run |
| `actions_allowed` | int | end | Actions with `auth == "allow"` or non-deny audit/permissive |
| `actions_denied` | int | end | Actions with `auth == "deny"` |
| `corr` | string | optional | Correlation ID for multi-agent runs |
| `from_agent` | string | optional | Parent agent ID (multi-agent) |
| `from_run` | string | optional | Parent run ID (multi-agent) |

### Example run-start event

```json
{"v":1,"t":"run","ts":"2025-01-15T09:03:12.123456Z","run":"01ARZ3NDEKTSV4RRFFQ69G5FAV","agent":"openclaw","agent_v":"","policy":"","env":"local","status":"start"}
```

### Example run-end event

```json
{"v":1,"t":"run","ts":"2025-01-15T09:07:44.987654Z","run":"01ARZ3NDEKTSV4RRFFQ69G5FAV","status":"end","exit":0,"ms":272864,"actions_total":47,"actions_allowed":45,"actions_denied":2}
```

---

## Action Event Fields (`t == "action"`)

Emitted for every intercepted action: MCP tool call, resource read, prompt get,
or HTTP request.

| Field | Type | Description |
|-------|------|-------------|
| `seq` | int | Sequential action number within this run (1-based) |
| `proto` | string | Protocol: `"mcp"`, `"http"`, or `"https"` |
| `method` | string | MCP method (`"tool_call"`, `"resource_read"`, `"prompt_get"`) or HTTP verb (`"GET"`, `"POST"`, `"CONNECT"`, …) |
| `target` | string | Tool name, resource URI, or URL |
| `params` | object | Input parameters (may contain `"[REDACTED]"` for sensitive fields) |
| `auth` | string | Authorization decision — see table below |
| `rule` | string | ID of the matched policy rule, or `"default"` |
| `response` | object | Tool response body — only present when `--capture-responses` is set |
| `to_agent` | string | Target agent ID for agent-to-agent calls (multi-agent) |
| `corr` | string | Correlation ID (multi-agent) |

### `auth` field values

| Value | Meaning |
|-------|---------|
| `"allow"` | Action was permitted by a matching allow rule (or `default: allow`) |
| `"deny"` | Action was **blocked** — agent received an error response |
| `"audit_deny"` | Would have been denied; allowed in `audit` mode |
| `"would_deny"` | Would have been denied; allowed in `permissive` mode |

### Example action events

```json
{"v":1,"t":"action","ts":"2025-01-15T09:03:13.000Z","run":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":1,"proto":"mcp","method":"tool_call","target":"web_search","params":{"query":"golang concurrency"},"auth":"allow","rule":"allow-web-search"}
```

```json
{"v":1,"t":"action","ts":"2025-01-15T09:03:14.000Z","run":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":2,"proto":"mcp","method":"tool_call","target":"execute_command","params":{"command":"rm -rf /tmp"},"auth":"deny","rule":"deny-shell"}
```

```json
{"v":1,"t":"action","ts":"2025-01-15T09:03:15.000Z","run":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":3,"proto":"mcp","method":"tool_call","target":"secret_tool","params":{"password":"[REDACTED]","user":"alice"},"auth":"allow","rule":"allow-secret"}
```

```json
{"v":1,"t":"action","ts":"2025-01-15T09:03:16.000Z","run":"01ARZ3NDEKTSV4RRFFQ69G5FAV","seq":4,"proto":"http","method":"GET","target":"https://api.example.com/data","params":{"headers":{"User-Agent":"curl/7.88"},"body_size":0},"auth":"allow","rule":"allow-http-get"}
```

---

## Complete Run Example

A minimal two-action run looks like this in the file:

```
{"v":1,"t":"run","ts":"2025-01-15T09:03:12Z","run":"01ARZ...","agent":"my-agent","env":"local","status":"start"}
{"v":1,"t":"action","ts":"2025-01-15T09:03:13Z","run":"01ARZ...","seq":1,"proto":"mcp","method":"tool_call","target":"web_search","params":{"query":"hello"},"auth":"allow","rule":"allow-web"}
{"v":1,"t":"action","ts":"2025-01-15T09:03:14Z","run":"01ARZ...","seq":2,"proto":"mcp","method":"tool_call","target":"execute_command","params":{"cmd":"whoami"},"auth":"deny","rule":"deny-shell"}
{"v":1,"t":"run","ts":"2025-01-15T09:03:15Z","run":"01ARZ...","status":"end","exit":0,"ms":3012,"actions_total":2,"actions_allowed":1,"actions_denied":1}
```

---

## Querying Traces

The `relic trace` commands parse `.trtrace` files for you:

```bash
# List all runs
relic trace list

# View one run (formatted)
relic trace view <run_id>

# View raw NDJSON
relic trace view <run_id> --json

# Filter to denied actions only
relic trace view <run_id> --denied

# Search across all runs
relic trace search --auth deny
relic trace search --target "web_*"
relic trace search --proto mcp --auth deny
```

You can also use `jq` directly on trace files:

```bash
# Count denials
jq -r 'select(.t == "action" and .auth == "deny") | .target' .tr/traces/*.trtrace | sort | uniq -c

# Get run summary
jq 'select(.t == "run" and .status == "end") | {run, ms, actions_total, actions_denied}' .tr/traces/*.trtrace

# Find all params containing redacted values
jq 'select(.t == "action") | select(.params | tostring | contains("REDACTED"))' .tr/traces/*.trtrace
```

---

## Notes for Summarizing Traces

When presenting trace data to a user:

- **Duration**: the `ms` field on the run-end event is milliseconds. Convert: `ms / 1000` = seconds.
- **Denied vs blocked**: `auth == "deny"` means the action was hard-blocked. `auth == "audit_deny"` or `auth == "would_deny"` means it was flagged but allowed through.
- **[REDACTED] values**: these were scrubbed by the redaction configuration before writing. Never attempt to guess or recover them.
- **Rule names**: the `rule` field tells you which policy rule matched. `"default"` means no rule matched and the policy default (`allow` or `deny`) was applied.
- **Sequence numbers**: `seq` is per-run and starts at 1. Gaps are not possible in normal operation.
