#!/bin/bash
# install.sh — Install the The Relic OpenClaw skill
#
# Usage:
#   bash dist/openclaw-skill/install.sh
#
# By default, installs to ~/.openclaw/skills/the-relic/.
# Override with: OPENCLAW_SKILLS_DIR=/custom/path bash install.sh

set -euo pipefail

SKILL_DIR="${OPENCLAW_SKILLS_DIR:-$HOME/.openclaw/skills}"
DEST="$SKILL_DIR/the-relic"

# Resolve the directory containing this script so it works from any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$SCRIPT_DIR/the-relic"

if [ ! -d "$SOURCE" ]; then
    echo "Error: skill source directory not found at $SOURCE" >&2
    echo "Run this script from the The Relic repository root:" >&2
    echo "  bash dist/openclaw-skill/install.sh" >&2
    exit 1
fi

# Create the skills directory if it doesn't exist.
mkdir -p "$SKILL_DIR"

# Remove any existing installation before copying.
if [ -d "$DEST" ]; then
    echo "Removing existing installation at $DEST"
    rm -rf "$DEST"
fi

# Copy the skill.
cp -r "$SOURCE" "$DEST"

echo "The Relic skill installed to $DEST"
echo ""
echo "Files installed:"
find "$DEST" -type f | sort | sed "s|$SKILL_DIR/||"
echo ""

# Check if relic is installed.
if command -v relic >/dev/null 2>&1; then
    RELIC_VERSION=$(relic --version 2>&1 | head -1 || echo "unknown")
    echo "✓ relic binary found: $RELIC_VERSION"
else
    echo "⚠ relic binary not found in PATH."
    echo "  Install it before using the skill:"
    echo ""
    if [[ "$(uname)" == "Darwin" ]]; then
        echo "  brew install therelic/tap/relic"
    else
        echo "  curl -fsSL https://therelic.com/install.sh | bash"
    fi
    echo ""
fi

echo "Restart your OpenClaw gateway to activate the skill:"
echo "  relic run --from-openclaw -- openclaw gateway"
