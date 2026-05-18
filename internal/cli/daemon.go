package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/spf13/cobra"

	"github.com/therelicai/therelic/internal/api"
	"github.com/therelicai/therelic/internal/policy"
	"github.com/therelicai/therelic/internal/proxy"
	"github.com/therelicai/therelic/internal/redact"
	"github.com/therelicai/therelic/internal/trace"
)

// newDaemonCmd returns the `relic daemon` command.
//
// The daemon is a long-running process with two responsibilities:
//
//   1. HTTP proxy on a configurable port. Any tool that respects
//      HTTP_PROXY can route through this and have its HTTP/HTTPS
//      traffic governed and traced.
//
//   2. Trace pusher. Watches a trace directory and pushes finished
//      .trtrace files to the configured platform every push-interval.
//
// The MCP side is the sibling `relic gateway` subcommand. Gateway
// runs over stdio so individual MCP clients spawn it directly.
func newDaemonCmd() *cobra.Command {
	var (
		flagTraceDir     string
		flagPolicyPath   string
		flagPushInterval time.Duration
		flagNoHTTP       bool
		flagNoPush       bool
	)

	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run a long-lived Relic daemon (HTTP proxy + trace pusher)",
		Long: `Start a persistent local process that:

  - Listens on an ephemeral port as an HTTP proxy. Set HTTP_PROXY /
    HTTPS_PROXY in any tool to route its traffic through it.
  - Watches --trace-dir for .trtrace files and pushes them to the
    Relic platform every --push-interval (RELIC_API_URL +
    RELIC_API_KEY must be set).

Designed to coexist with stdio MCP wrapping (see 'relic connect
claude-code'); the proxy-stdio shim writes into the same --trace-dir
the daemon pushes from.

Stop with Ctrl-C.
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

			home, _ := os.UserHomeDir()
			if flagTraceDir == "" {
				flagTraceDir = filepath.Join(home, ".relic", "traces")
			}
			if err := os.MkdirAll(flagTraceDir, 0o755); err != nil {
				return fmt.Errorf("mkdir trace dir: %w", err)
			}

			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			var wg sync.WaitGroup
			var httpProxy *proxy.HTTPLogger
			var writer *trace.TraceWriter
			var runID string

			if !flagNoHTTP {
				pol, polErr := loadDaemonPolicy(flagPolicyPath)
				if polErr != nil {
					logger.Warn("policy load failed; using permissive default", "error", polErr)
					pol = permissivePolicy()
				}
				eng := policy.NewEngine(pol)
				runID = ulid.Make().String()
				w, err := trace.NewTraceWriter(flagTraceDir, runID)
				if err != nil {
					return fmt.Errorf("trace writer: %w", err)
				}
				writer = w
				_ = writer.WriteRunStart(runID, "relic-daemon", "", "", "local")

				redactor := redact.NewRedactor(pol.Redaction)
				httpProxy = proxy.NewHTTPLogger(runID, eng, redactor, func(ev trace.ActionEvent) {
					_ = writer.WriteAction(ev)
				})
				if _, err := httpProxy.Start(); err != nil {
					return fmt.Errorf("start http proxy: %w", err)
				}
				logger.Info("HTTP proxy started", "addr", httpProxy.Addr(), "hint", fmt.Sprintf("export HTTP_PROXY=%s HTTPS_PROXY=%s", httpProxy.Addr(), httpProxy.Addr()))
			}

			if !flagNoPush {
				if _, err := api.NewClientFromEnv(); err != nil {
					logger.Warn("trace pusher disabled: " + err.Error())
				} else {
					wg.Add(1)
					go func() {
						defer wg.Done()
						runTracePusher(ctx, logger, flagTraceDir, flagPushInterval)
					}()
				}
			}

			logger.Info("relic daemon running",
				"trace_dir", flagTraceDir,
				"push_interval", flagPushInterval,
				"signal", "send SIGINT to stop")
			<-ctx.Done()
			logger.Info("shutting down")

			if httpProxy != nil {
				_ = httpProxy.Close()
			}
			if writer != nil {
				_ = writer.WriteRunEnd(runID, 0, 0, 0, 0, 0)
				_ = writer.Close()
			}
			wg.Wait()
			return nil
		},
	}

	cmd.Flags().StringVar(&flagTraceDir, "trace-dir", "", "Directory holding .trtrace files (default ~/.relic/traces)")
	cmd.Flags().StringVar(&flagPolicyPath, "policy", "", "Policy file applied by the HTTP proxy")
	cmd.Flags().DurationVar(&flagPushInterval, "push-interval", 30*time.Second, "How often to push finished traces to the platform")
	cmd.Flags().BoolVar(&flagNoHTTP, "no-http", false, "Skip the HTTP proxy (trace pusher only)")
	cmd.Flags().BoolVar(&flagNoPush, "no-push", false, "Skip the trace pusher (HTTP proxy only)")
	return cmd
}

// loadDaemonPolicy returns a policy for the daemon's HTTP proxy.
// Order: explicit flag, ~/.relic/policy.yaml, error (caller falls
// back to permissive).
func loadDaemonPolicy(path string) (*policy.Policy, error) {
	if path == "" {
		home, _ := os.UserHomeDir()
		candidate := filepath.Join(home, ".relic", "policy.yaml")
		if _, err := os.Stat(candidate); err == nil {
			path = candidate
		}
	}
	if path == "" {
		return permissivePolicy(), nil
	}
	return policy.Load(path)
}

// permissivePolicy is the daemon's fallback when no policy file is
// present. Permissive mode means "record everything; deny nothing"
// which is the right default for an observe-first deployment.
func permissivePolicy() *policy.Policy {
	return &policy.Policy{
		Version: "1",
		Agent:   policy.AgentIdentity{Name: "relic-daemon", Version: "0"},
		Mode:    "permissive",
		Default: "allow",
	}
}

// runTracePusher iterates --trace-dir on every tick, finds .trtrace
// files that haven't been touched recently (so we don't push a file
// still being written), and pushes each one to the configured platform.
func runTracePusher(ctx context.Context, logger *slog.Logger, traceDir string, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pushFinishedTraces(ctx, logger, traceDir)
		}
	}
}

const finishedAfterIdle = 5 * time.Second

func pushFinishedTraces(ctx context.Context, logger *slog.Logger, traceDir string) {
	entries, err := os.ReadDir(traceDir)
	if err != nil {
		logger.Warn("trace pusher: read dir", "error", err)
		return
	}
	now := time.Now()
	me, _ := os.Executable()
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".trtrace" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) < finishedAfterIdle {
			continue
		}
		runID := e.Name()[:len(e.Name())-len(".trtrace")]
		full := filepath.Join(traceDir, e.Name())
		out, err := exec.CommandContext(ctx, me, "trace", "push", "--dir", traceDir, runID).CombinedOutput()
		if err != nil {
			logger.Warn("trace pusher: push failed", "run_id", runID, "error", err, "out", string(out))
			continue
		}
		_ = os.Remove(full)
		logger.Info("trace pushed", "run_id", runID)
	}
}
