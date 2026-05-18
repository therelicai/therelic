package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// newConnectCmd returns the `relic connect <client>` command.
//
// Each adapter rewrites a client's MCP server config so every entry
// gets wrapped in `relic proxy-stdio`. Tool calls flow through Relic;
// traces accumulate in --trace-dir (default ~/.relic/traces).
// Adapters are idempotent: re-running detects an already-wrapped
// entry and leaves it alone.
//
// v1 ships claude-code. Cursor and Claude Desktop adapters follow the
// same pattern; each one knows where its client's config lives.
func newConnectCmd() *cobra.Command {
	var (
		flagTraceDir   string
		flagPolicyPath string
		flagDryRun     bool
		flagUnwrap     bool
	)
	cmd := &cobra.Command{
		Use:   "connect <client>",
		Short: "Wire an agent client (claude-code, cursor) to route MCP traffic through Relic",
		Long: `Rewrite a supported agent client's MCP server configuration so every
tool call flows through 'relic proxy-stdio'. Backs up the original
file before touching it. Idempotent: running twice leaves the config
unchanged the second time.

Supported clients:
  claude-code        ~/.claude.json (user-scope mcpServers and per-project
                     mcpServers under projects.<path>.mcpServers)

Examples:
  relic connect claude-code
  relic connect claude-code --dry-run
  relic connect claude-code --unwrap   # restore original commands
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := args[0]
			traceDir := flagTraceDir
			if traceDir == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("resolve home dir: %w", err)
				}
				traceDir = filepath.Join(home, ".relic", "traces")
			}
			if err := os.MkdirAll(traceDir, 0o755); err != nil {
				return fmt.Errorf("mkdir trace dir: %w", err)
			}

			switch client {
			case "claude-code":
				return connectClaudeCode(cmd, claudeCodeOpts{
					traceDir:   traceDir,
					policyPath: flagPolicyPath,
					dryRun:     flagDryRun,
					unwrap:     flagUnwrap,
				})
			default:
				return fmt.Errorf("unknown client %q. supported: claude-code", client)
			}
		},
	}
	cmd.Flags().StringVar(&flagTraceDir, "trace-dir", "", "Directory to write .trtrace files (default ~/.relic/traces)")
	cmd.Flags().StringVar(&flagPolicyPath, "policy", "", "Policy file path applied by the proxy (optional)")
	cmd.Flags().BoolVar(&flagDryRun, "dry-run", false, "Show what would change without writing")
	cmd.Flags().BoolVar(&flagUnwrap, "unwrap", false, "Restore the original commands from the backup")
	return cmd
}

type claudeCodeOpts struct {
	traceDir   string
	policyPath string
	dryRun     bool
	unwrap     bool
}

// MCP server entry as Claude Code stores it. We only touch command +
// args; transport, env, and other fields are preserved verbatim.
type mcpServer struct {
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	// Catch-all so we round-trip fields we don't know about.
	Extra map[string]any `json:"-"`
}

// Sentinel arg that lets us recognize an already-wrapped entry across
// re-runs of `relic connect`. Survives in args; harmless to the
// proxy-stdio command itself because it's after the `--` separator.
const wrapMarker = "--relic-wrapped"

func connectClaudeCode(cmd *cobra.Command, opts claudeCodeOpts) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(home, ".claude.json")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("Claude Code config not found at %s. Run `claude` once to create it.", cfgPath)
		}
		return fmt.Errorf("read %s: %w", cfgPath, err)
	}

	// Round-trip via map[string]any so we preserve every key we don't
	// understand. Claude Code's config schema grows; a typed struct
	// would silently drop fields.
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parse %s: %w", cfgPath, err)
	}

	// Find every place an mcpServers map lives.
	targets := findMCPServerMaps(cfg)
	if len(targets) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No MCP servers found in ~/.claude.json.")
		fmt.Fprintln(cmd.OutOrStdout(), "Run `claude mcp add <name> -- <command>` to register one, then re-run `relic connect claude-code`.")
		return nil
	}

	relicPath, err := os.Executable()
	if err != nil {
		relicPath = "relic"
	}

	changes := 0
	for _, t := range targets {
		for name, entry := range t {
			m, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			if opts.unwrap {
				if unwrapEntry(m) {
					changes++
				}
				continue
			}
			if wrapEntry(m, relicPath, name, opts) {
				changes++
			}
		}
	}

	if changes == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "Already up to date. No changes needed.")
		return nil
	}

	if opts.dryRun {
		out, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Fprintf(cmd.OutOrStdout(), "Would change %d MCP server entr(y/ies). Diff preview suppressed; re-run without --dry-run to apply.\n", changes)
		_ = out
		return nil
	}

	// Back up the original. Suffix with a timestamp so successive
	// connects don't overwrite the prior backup; the user can pick
	// which one to restore.
	stamp := time.Now().UTC().Format("20060102-150405")
	backup := cfgPath + ".relic-backup-" + stamp
	if err := os.WriteFile(backup, raw, 0o600); err != nil {
		return fmt.Errorf("write backup %s: %w", backup, err)
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(cfgPath, out, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", cfgPath, err)
	}
	verb := "wrapped"
	if opts.unwrap {
		verb = "unwrapped"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s %d MCP server entr(y/ies). Backup: %s\n", strings.Title(verb), changes, backup)
	fmt.Fprintf(cmd.OutOrStdout(), "Restart Claude Code for the change to take effect.\n")
	return nil
}

// findMCPServerMaps returns pointers to every `mcpServers` map inside
// the Claude Code config. Claude Code stores them at the top level
// (user-scope) and per-project under projects.<path>.mcpServers.
func findMCPServerMaps(cfg map[string]any) []map[string]any {
	var out []map[string]any
	if m, ok := cfg["mcpServers"].(map[string]any); ok {
		out = append(out, m)
	}
	if proj, ok := cfg["projects"].(map[string]any); ok {
		for _, v := range proj {
			pm, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if m, ok := pm["mcpServers"].(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

// wrapEntry rewrites one MCP server entry so its command becomes
// `relic proxy-stdio -- <original-command> <original-args...>`.
// Returns true if a change was made.
func wrapEntry(m map[string]any, relicPath, name string, opts claudeCodeOpts) bool {
	cmdRaw, _ := m["command"].(string)
	if cmdRaw == "" {
		return false // sse / http transports — nothing to wrap (yet)
	}
	// Detect "already wrapped" by looking for the marker arg.
	args := toStrings(m["args"])
	for _, a := range args {
		if a == wrapMarker {
			return false
		}
	}

	// Build the new args list. Marker arg first so we recognize this
	// entry on a re-run; then proxy flags; then `--`; then the
	// original command + args.
	newArgs := []string{
		"proxy-stdio",
		wrapMarker,
		"--agent-name=" + name,
		"--trace-dir=" + opts.traceDir,
	}
	if opts.policyPath != "" {
		newArgs = append(newArgs, "--policy="+opts.policyPath)
	}
	newArgs = append(newArgs, "--", cmdRaw)
	newArgs = append(newArgs, args...)

	m["command"] = relicPath
	m["args"] = newArgs
	return true
}

// unwrapEntry reverses wrapEntry by splicing out everything before the
// `--` separator and restoring the original command.
func unwrapEntry(m map[string]any) bool {
	args := toStrings(m["args"])
	// Find the proxy-stdio + marker prefix.
	if len(args) < 4 || args[0] != "proxy-stdio" {
		return false
	}
	hasMarker := false
	for _, a := range args {
		if a == wrapMarker {
			hasMarker = true
			break
		}
	}
	if !hasMarker {
		return false
	}
	// Find the `--` separator.
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep == -1 || sep == len(args)-1 {
		return false
	}
	m["command"] = args[sep+1]
	if sep+2 < len(args) {
		m["args"] = args[sep+2:]
	} else {
		delete(m, "args")
	}
	return true
}

func toStrings(v any) []string {
	a, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(a))
	for _, x := range a {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
