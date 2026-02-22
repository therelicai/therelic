# The Relic — OpenClaw Skill

This directory contains the `the-relic` OpenClaw skill, which teaches your
OpenClaw agent how to:

- Query its own audit trail with `relic trace`
- Report to users what it did and what was blocked
- Help draft authorization policies from trace history
- Self-install The Relic when needed

The skill is the **distribution and UX layer**. The proxy (`relic run`) is the
**enforcement layer**. The skill cannot bypass or disable governance — it's a
user interface that makes governance accessible through natural language.

---

## Installation

### Option 1: Run the install script (recommended)

```bash
bash dist/openclaw-skill/install.sh
```

Installs the skill to `~/.openclaw/skills/the-relic/` (or `$OPENCLAW_SKILLS_DIR`).
Restart your OpenClaw gateway to activate.

### Option 2: Copy manually

```bash
cp -r dist/openclaw-skill/the-relic/ ~/.openclaw/skills/the-relic/
# Restart OpenClaw gateway
```

### Option 3: Ask your OpenClaw agent to install it

Give your agent the repository URL and say:

> "Install the The Relic governance skill from https://github.com/therelicai/therelic
> — copy the dist/openclaw-skill/the-relic/ folder to my skills directory."

The agent will clone the repo (or download the folder) and place the skill
where OpenClaw can find it, then confirm it's active.

### Option 4: Install from ClawHub (coming soon)

```bash
# Once published to the ClawHub registry:
openclaw skills install the-relic
```

---

## Prerequisites

The skill requires the `relic` binary to be in your PATH. If it's not installed:

```bash
# macOS
brew install therelic/tap/relic

# Linux
curl -fsSL https://therelic.com/install.sh | bash

# Go
go install github.com/therelicai/therelic/cmd/relic@latest
```

---

## After Installation

1. The skill is automatically loaded when OpenClaw starts.
2. Start your governed session:
   ```bash
   relic run --from-openclaw -- openclaw gateway
   ```
3. You can now ask your agent governance questions like:
   - *"What did you do in your last session?"*
   - *"Show me any blocked actions."*
   - *"Help me write a policy that restricts shell access."*
   - *"Set up The Relic for this project."*

---

## Skill Contents

```
the-relic/
├── SKILL.md                        # Skill instructions (injected into system prompt)
└── references/
    ├── policy-reference.md         # Complete policy YAML reference
    └── trace-format.md             # .trtrace NDJSON field reference
```

The `references/` files give the agent grounded knowledge about policy syntax
and trace fields, so it can accurately help users read traces and write policies
without hallucinating field names.

---

## Links

- [The Relic on GitHub](https://github.com/therelicai/therelic)
- [Quickstart](https://github.com/therelicai/therelic/blob/main/docs/quickstart.md)
- [OpenClaw Guide](https://github.com/therelicai/therelic/blob/main/docs/quickstart-openclaw.md)
- [Policy Reference](https://github.com/therelicai/therelic/blob/main/docs/policy-reference.md)
