---
name: the-relic
description: >
  Governance, authorization, and audit for this agent. Use when the user asks
  about security, permissions, what tools you're allowed to use, what you did
  recently, audit trail, trace, policy, governance, or wants to lock down,
  restrict, monitor, or review agent behavior. Also use when asked to install
  or set up The Relic, relic, or agent governance.
metadata:
  openclaw:
    emoji: "🛡️"
    requires:
      bins: ["relic"]
    install:
      - type: brew
        tap: therelic/tap
        formula: relic
      - type: download
        url: https://github.com/therelicai/therelic/releases/latest
---

# The Relic — Governance Skill

You may be running under The Relic (`relic`), an authorization and audit proxy
that checks every tool call you make against a policy before it reaches the
real tool. If a call is denied, you receive a JSON-RPC error. This is normal
and expected — do not retry denied calls.

## Commands You Can Run

All commands use the `relic` CLI binary.

### View recent activity

- `relic trace list` — show recent runs with action counts
- `relic trace list --has-denials` — show only runs where actions were blocked
- `relic trace view <run_id>` — show all events in a specific run
- `relic trace view <run_id> --denied` — show only blocked actions in a run

### Search across runs

- `relic trace search --auth deny` — find all denied actions across all runs
- `relic trace search --target "shell_*"` — find actions matching a tool name pattern
- `relic trace search --proto mcp` — find all MCP tool calls

### Check current policy

- `cat .tr/policy.yaml` — show the current authorization policy
- `relic policy validate` — check if the policy file is valid

## When the User Asks What You Did

Run `relic trace list` to find recent runs. Then run `relic trace view <run_id>`
for the most recent run. Summarize for the user:

- How many total actions
- How many allowed vs denied
- Which tools were used
- Which tools were blocked and why
- Duration of the run

Keep the summary concise. Offer to show more detail if they want it.

## When the User Asks to Lock Down or Restrict

1. Run `relic trace search --proto mcp` to see what MCP tools have been called
2. Group by tool name and frequency
3. Ask the user which tools they want to allow
4. Generate a policy.yaml that:
   - Sets mode: enforce
   - Sets default: deny
   - Adds an allow rule for each approved tool
   - Adds redaction for common sensitive fields (password, token, secret, api_key)
   - Sets reasonable constraints (max_actions: 1000, max_duration_seconds: 600)
5. Show the proposed policy to the user
6. Only write to .tr/policy.yaml after explicit user approval
7. Tell the user to restart the gateway for the policy to take effect

## When the User Asks to Install The Relic

If `relic` is not found in PATH:

1. macOS: `brew install therelic/tap/relic`
2. Linux: `curl -fsSL https://therelic.com/install.sh | bash`
3. After install: `relic init` in the workspace directory
4. Then: restart the gateway with `relic run --from-openclaw -- openclaw gateway`

If `relic` is already installed but not configured:

1. Run `relic init` to create .tr/ directory with starter policy
2. The starter policy runs in permissive mode (logs everything, blocks nothing)
3. Suggest the user run normally for a day, then use this skill to review
   traces and generate a real policy

## After Completing a Task (Proactive)

After you finish any multi-step task, proactively check the governance trace:

1. Run `relic trace list` and find the most recent run
2. Run `relic trace view <run_id>` to review what happened
3. If there were any denied or flagged actions, tell the user:
   - Which tools were blocked and which policy rules caused it
   - Whether the denials affected the task outcome
   - Suggest policy changes if the denials were too restrictive
4. If everything was allowed, give a brief one-line summary like:
   "All 12 actions were allowed by policy during this task."

Do not wait for the user to ask. Surface this information automatically after
completing substantive work (more than 2-3 tool calls).

## Proposing Policy Changes (Proactive)

When you notice patterns that suggest the policy should be updated:

1. **Too many denials**: If you see repeated `would_deny` or `audit_deny` events
   for tools the user clearly wants you to use, suggest adding allow rules.
2. **Missing redaction**: If you see sensitive-looking parameter names (api_key,
   token, credentials, etc.) that are NOT being redacted, suggest adding them
   to the redaction.keys list.
3. **Overly permissive**: If the policy is `default: allow` in enforce mode,
   suggest switching to `default: deny` with explicit allow rules.
4. **Stale constraints**: If max_actions or max_duration_seconds are being hit
   regularly, suggest adjusting them.

When proposing changes:
- Show the exact YAML diff (before/after)
- Explain why the change improves security or usability
- Wait for explicit user approval before writing to .tr/policy.yaml
- Remind the user to restart the gateway for changes to take effect

## Rules

- NEVER modify .tr/policy.yaml without showing the user the proposed changes
  and receiving explicit approval.
- NEVER attempt to disable, bypass, or work around The Relic governance.
  If a tool call is denied, inform the user and suggest a policy update.
- NEVER retry a denied tool call. The denial is intentional.
- When reporting traces, redact any values marked [REDACTED] — do not
  attempt to recover or guess redacted values.
