package cli

import (
	"fmt"
	"os"

	"github.com/therelicai/therelic/internal/config"
	"github.com/therelicai/therelic/internal/policy"
	"github.com/spf13/cobra"
)

// starterPolicy is the default .tr/policy.yaml written by `relic init`.
// It uses permissive mode so developers can run agents immediately without
// writing any rules — the trace shows what would have been denied.
const starterPolicy = `version: "1"

agent:
  name: "my-agent"
  version: "1.0.0"

# Mode controls what happens when an action is denied:
#   permissive — allow the action, record it as "would_deny" in the trace
#   audit      — allow the action, record it as "audit_deny" in the trace
#   enforce    — block the action, return an error to the agent
mode: permissive

# Default decision when no rule matches.
default: deny

# Keys and headers redacted before writing to trace files.
redaction:
  keys:
    - password
    - secret
    - token
    - api_key
    - apikey
    - access_token
    - refresh_token
    - private_key
  headers:
    - Authorization
    - X-Api-Key
    - X-Auth-Token
    - Cookie

# Rules evaluated top-to-bottom. First match wins.
# Uncomment and edit to allow specific tools.
rules: []
  # - id: allow-web-search
  #   protocol: mcp
  #   method: tool_call
  #   target: "web_search"
  #   action: allow

  # - id: allow-web-fetch
  #   protocol: mcp
  #   method: tool_call
  #   target: "web_fetch"
  #   action: allow

  # - id: deny-shell
  #   protocol: mcp
  #   method: tool_call
  #   target: "{shell,execute_command,run_script}"
  #   action: deny

constraints:
  max_actions: 1000
  max_duration_seconds: 3600

# --- Zero-Trust Extensions (uncomment to enable) ---

# Require a valid ed25519 signature on this policy file.
# Use 'relic keygen' to generate a keypair and 'relic policy sign' to sign.
# signature_required: true

# Filesystem sandbox — restrict agent file access to explicit mounts.
# filesystem:
#   enabled: true
#   mounts:
#     - source: ./data
#       target: data
#       mode: ro           # read-only
#     - source: ./output
#       target: output
#       mode: rw           # read-write
#   deny_patterns:
#     - "**/.env"
#     - "**/credentials*"
#     - "**/*.key"
#     - "**/*.pem"

# Network policy — DNS-level allow/deny for outbound HTTP/HTTPS.
# network:
#   dns_allow:
#     - "api.example.com"
#     - "*.googleapis.com"
#   dns_deny:
#     - "*.evil.com"
#     - "malware.io"
`

// starterMCP is the default .tr/mcp.yaml written by `relic init`.
const starterMCP = `# The Relic MCP Server Configuration
# List the MCP servers your agent uses. The Relic will start a proxy in front
# of each one. Remove this file if you use --from-openclaw or --from-claude-config.

servers: []
  # stdio transport example (most common):
  # - name: filesystem
  #   transport: stdio
  #   command: "npx"
  #   args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]

  # HTTP+SSE transport example:
  # - name: web-search
  #   transport: sse
  #   url: "http://localhost:3001/mcp"
`

func newInitCmd() *cobra.Command {
	var flagForce bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize The Relic in the current project",
		Long: `Create the .tr/ directory with a starter policy and MCP configuration.

  .tr/
  ├── policy.yaml   # Starter policy (permissive mode)
  ├── mcp.yaml      # MCP server configuration
  └── traces/       # Run traces are stored here

Run 'relic policy validate' after editing policy.yaml to check for errors.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit(cmd.OutOrStdout(), config.DefaultPaths(), flagForce)
		},
	}

	cmd.Flags().BoolVar(&flagForce, "force", false, "Overwrite existing .tr/ directory")
	return cmd
}

// runInit creates the .tr/ directory structure.
func runInit(out interface{ Write([]byte) (int, error) }, paths config.Paths, force bool) error {
	// Check for existing directory.
	if _, err := os.Stat(paths.Root); err == nil {
		if !force {
			fmt.Fprintf(out, "Warning: %s already exists. Use --force to overwrite files.\n", paths.Root)
			// Still create traces/ and any missing files, but don't overwrite.
		}
	}

	// Create directories.
	for _, dir := range []string{paths.Root, paths.TracesDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("init: create directory %s: %w", dir, err)
		}
	}

	// Write policy.yaml — skip if exists and not forcing.
	if err := writeIfAbsent(paths.PolicyFile, []byte(starterPolicy), force); err != nil {
		return fmt.Errorf("init: write policy.yaml: %w", err)
	}

	// Write mcp.yaml — skip if exists and not forcing.
	if err := writeIfAbsent(paths.MCPFile, []byte(starterMCP), force); err != nil {
		return fmt.Errorf("init: write mcp.yaml: %w", err)
	}

	// Record initial policy creation in the immutable history log.
	policyData, _ := os.ReadFile(paths.PolicyFile)
	policy.AppendHistory(paths.HistoryFile, policy.HistoryEntry{
		Action:     "create",
		PolicyHash: policy.PolicyHash(policyData),
		Actor:      "cli",
		Message:    "initial policy created by relic init",
	})

	fmt.Fprintf(out, "Initialized The Relic in %s/\n", paths.Root)
	fmt.Fprintf(out, "  %s\n", paths.PolicyFile)
	fmt.Fprintf(out, "  %s\n", paths.MCPFile)
	fmt.Fprintf(out, "  %s/\n", paths.TracesDir)
	fmt.Fprintf(out, "\nEdit %s to define your authorization policy.\n", paths.PolicyFile)
	fmt.Fprintf(out, "Run 'relic policy validate' to check policy syntax.\n")

	return nil
}

// writeIfAbsent writes data to path. If the file exists and force is false,
// it is skipped (no error). If force is true, it is overwritten.
func writeIfAbsent(path string, data []byte, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return nil // already exists, skip
		}
	}
	return os.WriteFile(path, data, 0o644)
}
