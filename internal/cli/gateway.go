package cli

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/therelicai/therelic/internal/proxy"
)

// newGatewayCmd returns the `relic gateway` command.
//
// The gateway is a single stdio MCP server that multiplexes N upstream
// MCP servers behind one connection. An MCP client (Claude Code,
// Cursor) adds exactly one entry pointing at `relic gateway`; the
// gateway loads its upstream list from ~/.relic/gateway.yaml and
// proxies every tool call to the right upstream, recording each call
// to a .trtrace.
//
// Config (~/.relic/gateway.yaml):
//
//   trace_dir: ~/.relic/traces   # optional, default $HOME/.relic/traces
//   policy:    ~/.relic/policy.yaml  # optional
//   servers:
//     - name: filesystem
//       command: npx
//       args: [-y, "@modelcontextprotocol/server-filesystem", "/data"]
//     - name: git
//       command: npx
//       args: [-y, "@modelcontextprotocol/server-git", "--repository", "."]
//
// Tool names get prefixed with their upstream's name + "__" so a
// client sees "filesystem__read_file" rather than just "read_file";
// this prevents collisions when two upstreams expose the same tool.
func newGatewayCmd() *cobra.Command {
	var (
		flagConfig   string
		flagTraceDir string
		flagPolicy   string
	)

	cmd := &cobra.Command{
		Use:   "gateway",
		Short: "Run a stdio MCP gateway multiplexing N upstream MCP servers",
		Long: `Stdio MCP server that fans out to multiple upstream servers
configured in ~/.relic/gateway.yaml (override with --config). One
config entry per upstream; tool names are namespaced with
"<upstream>__" so collisions are impossible.

Add to a Claude Code project:

  claude mcp add relic-gateway -- relic gateway

Or in claude_desktop_config.json:

  "relic-gateway": { "command": "relic", "args": ["gateway"] }
`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

			home, _ := os.UserHomeDir()
			if flagConfig == "" {
				flagConfig = filepath.Join(home, ".relic", "gateway.yaml")
			}
			if flagTraceDir == "" {
				flagTraceDir = filepath.Join(home, ".relic", "traces")
			}

			cfg, err := loadGatewayConfig(flagConfig)
			if err != nil {
				return fmt.Errorf("load gateway config: %w", err)
			}
			if len(cfg.Servers) == 0 {
				return fmt.Errorf("no upstream servers configured in %s. add at least one under `servers:` and restart.", flagConfig)
			}
			if cfg.TraceDir == "" {
				cfg.TraceDir = flagTraceDir
			}
			if cfg.PolicyPath == "" {
				cfg.PolicyPath = flagPolicy
			}
			if err := os.MkdirAll(cfg.TraceDir, 0o755); err != nil {
				return fmt.Errorf("mkdir trace dir: %w", err)
			}

			gw, err := proxy.NewMCPGateway(proxy.GatewayConfig{
				Upstreams:  asGatewayUpstreams(cfg.Servers),
				TraceDir:   cfg.TraceDir,
				PolicyPath: cfg.PolicyPath,
				Logger:     logger,
			})
			if err != nil {
				return err
			}
			defer gw.Close()
			return gw.ServeStdio(cmd.Context(), os.Stdin, os.Stdout)
		},
	}

	cmd.Flags().StringVar(&flagConfig, "config", "", "Path to gateway.yaml (default ~/.relic/gateway.yaml)")
	cmd.Flags().StringVar(&flagTraceDir, "trace-dir", "", "Directory for .trtrace files (default ~/.relic/traces)")
	cmd.Flags().StringVar(&flagPolicy, "policy", "", "Policy file applied to every upstream (optional)")
	return cmd
}

// gatewayConfig mirrors the YAML schema described above.
type gatewayConfig struct {
	TraceDir   string                 `yaml:"trace_dir"`
	PolicyPath string                 `yaml:"policy"`
	Servers    []gatewayUpstreamYAML  `yaml:"servers"`
}

type gatewayUpstreamYAML struct {
	Name    string   `yaml:"name"`
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`
}

func loadGatewayConfig(path string) (*gatewayConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg gatewayConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for i, s := range cfg.Servers {
		if s.Name == "" {
			return nil, fmt.Errorf("servers[%d]: name is required", i)
		}
		if s.Command == "" {
			return nil, fmt.Errorf("servers[%d] (%s): command is required", i, s.Name)
		}
	}
	return &cfg, nil
}

func asGatewayUpstreams(in []gatewayUpstreamYAML) []proxy.GatewayUpstream {
	out := make([]proxy.GatewayUpstream, 0, len(in))
	for _, s := range in {
		out = append(out, proxy.GatewayUpstream{Name: s.Name, Command: s.Command, Args: s.Args})
	}
	return out
}
