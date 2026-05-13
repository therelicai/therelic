package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/therelicai/therelic/internal/api"
	"github.com/therelicai/therelic/internal/config"
	"github.com/therelicai/therelic/internal/delegation"
	"github.com/therelicai/therelic/internal/exfiltration"
	"github.com/therelicai/therelic/internal/policy"
	"github.com/therelicai/therelic/internal/proxy"
	"github.com/therelicai/therelic/internal/redact"
	"github.com/therelicai/therelic/internal/sandbox"
	"github.com/therelicai/therelic/internal/signing"
	"github.com/therelicai/therelic/internal/trace"
	"github.com/oklog/ulid/v2"
	"github.com/spf13/cobra"
)

// ExitError is returned by the run command's RunE when the child process exits
// with a non-zero code. main.go checks for this type and calls os.Exit with
// the correct code, preserving the child's exit status transparently.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit status %d", e.Code)
}

func newRunCmd() *cobra.Command {
	var (
		flagEnv              string
		flagVerbose          bool
		flagQuiet            bool
		flagPolicy           string // path to policy.yaml; default: .tr/policy.yaml
		flagMode             string // override policy mode: enforce | audit | permissive
		flagTraceDir         string // hidden; lets tests redirect trace output
		flagWatch            bool   // hot-reload policy file on change
		flagRequireSignature bool   // require ed25519 policy signature before running
		flagPubKey           string // path to ed25519 public key for signature verification
		flagFromOpenClaw     bool   // load MCP servers from ~/.openclaw/openclaw.json
		flagOpenClawCfg      string // override openclaw.json path
		flagOpenClawAgent    string // restrict to one agent's MCP servers
	)

	cmd := &cobra.Command{
		Use:   "run [flags] -- <command> [args...]",
		Short: "Run an agent command under The Relic governance",
		Long: `Spawn a command as a governed agent process.

All arguments after -- are passed to the agent command unchanged.

Examples:
  relic run -- python my_agent.py
  relic run --env production -- openclaw gateway
  relic run --mode audit -- claude
  relic run --policy custom-policy.yaml -- my_agent
  relic run --from-openclaw -- openclaw gateway`,
		Args:         cobra.ArbitraryArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("no command specified — usage: relic run [flags] -- <command> [args...]")
			}
			traceDir := flagTraceDir
			if traceDir == "" {
				traceDir = filepath.Join(".tr", "traces")
			}
			opts := runOptions{
				env:              flagEnv,
				verbose:          flagVerbose,
				quiet:            flagQuiet,
				policyPath:       flagPolicy,
				modeOverride:     flagMode,
				traceDir:         traceDir,
				watch:            flagWatch,
				requireSignature: flagRequireSignature,
				pubKeyPath:       flagPubKey,
				fromOpenClaw:     flagFromOpenClaw,
				openClawCfg:      flagOpenClawCfg,
				openClawAgent:    flagOpenClawAgent,
			}
			return runAgent(cmd.ErrOrStderr(), args, opts)
		},
	}

	cmd.Flags().StringVar(&flagEnv, "env", "local", "Environment label (dev/staging/production/local)")
	cmd.Flags().BoolVar(&flagVerbose, "verbose", false, "Print actions to stdout as they happen")
	cmd.Flags().BoolVar(&flagQuiet, "quiet", false, "Suppress the post-run summary line")
	cmd.Flags().StringVar(&flagPolicy, "policy", "", "Path to policy.yaml (default: .tr/policy.yaml)")
	cmd.Flags().StringVar(&flagMode, "mode", "", "Override policy mode: enforce | audit | permissive")
	cmd.Flags().BoolVar(&flagWatch, "watch", false, "Watch the policy file and hot-reload on change")
	cmd.Flags().BoolVar(&flagRequireSignature, "require-signature", false, "Require a valid ed25519 policy signature before running")
	cmd.Flags().StringVar(&flagPubKey, "pubkey", "", "Path to ed25519 public key for policy signature verification")
	cmd.Flags().StringVar(&flagTraceDir, "trace-dir", "", "Trace directory override (default: .tr/traces)")
	cmd.Flags().MarkHidden("trace-dir") //nolint:errcheck
	cmd.Flags().BoolVar(&flagFromOpenClaw, "from-openclaw", false, "Load MCP servers from ~/.openclaw/openclaw.json and start OpenClaw with proxy interposition")
	cmd.Flags().StringVar(&flagOpenClawCfg, "openclaw-config", "", "Path to openclaw.json (overrides --from-openclaw default path)")
	cmd.Flags().StringVar(&flagOpenClawAgent, "openclaw-agent", "", "Only proxy MCP servers belonging to this agent ID")

	return cmd
}

// runOptions bundles all the flags passed to runAgent to keep the signature
// manageable as new flags are added.
type runOptions struct {
	env              string
	verbose          bool
	quiet            bool
	policyPath       string
	modeOverride     string
	traceDir         string
	watch            bool
	requireSignature bool
	pubKeyPath       string
	fromOpenClaw     bool
	openClawCfg      string
	openClawAgent    string
}

// actionStats tracks per-run action counts. Updated by the proxy's onAction
// callback and read when writing the run-end trace event.
type actionStats struct {
	mu      sync.Mutex
	total   int
	allowed int
	denied  int
}

func (s *actionStats) record(auth string) {
	s.mu.Lock()
	s.total++
	// "deny" in enforce mode and "audit_deny" in audit mode both indicate
	// the policy decided to refuse the action — they belong in the denied
	// bucket. "would_deny" (permissive mode) similarly. Anything else
	// (including "allow" and the empty string) counts as allowed.
	switch auth {
	case "deny", "audit_deny", "would_deny":
		s.denied++
	default:
		s.allowed++
	}
	s.mu.Unlock()
}

func (s *actionStats) snapshot() (total, allowed, denied int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total, s.allowed, s.denied
}

// httpWiring bundles the resources for the HTTP metadata logger.
type httpWiring struct {
	logger *proxy.HTTPLogger
	port   int
}

// proxyWiring bundles the resources needed to run and tear down the MCP proxy.
//
// Using os.Pipe() (not io.Pipe()) is critical: exec.Cmd dup2s *os.File
// arguments directly without spawning an I/O goroutine.  io.Pipe() would cause
// exec to spawn a goroutine that blocks forever on Read, deadlocking child.Wait().
//
// NOTE: Go's exec.Cmd does NOT close parent-held *os.File copies in
// closeAfterStart — only files it creates internally (for io.Reader/Writer
// Stdin/Stdout) get that treatment.  Therefore childStdoutW remains open in
// the parent after Start().  We must close it ourselves after child.Wait() so
// that childStdoutR (held by the proxy goroutine) eventually sees io.EOF.
type proxyWiring struct {
	proxy        *proxy.MCPProxy
	childStdin   *os.File // child.Stdin  (childStdinR; proxy writes to childStdinW)
	childStdout  *os.File // child.Stdout (childStdoutW; proxy reads from childStdoutR)
	proxyStdoutR *os.File // proxy reads from here; close after Wait() for fd cleanup
	done         chan struct{} // closed when ServeStdio goroutine exits
}

// runAgent is the core logic, separated from cobra so it is easy to test.
// errW receives the post-run summary line (cobra's ErrOrStderr in production;
// a bytes.Buffer in tests).
func runAgent(errW io.Writer, args []string, opts runOptions) error {
	runID := ulid.Make().String()
	start := time.Now()

	// Detect delegation — determine if this session is a child in a delegation chain.
	parentRunID, parentPolicyPath, delegationRoot, delegationDepth, isChild := delegation.DetectParentSession()

	if isChild && parentPolicyPath != "" {
		if _, err := delegation.LoadCachedPolicy(parentPolicyPath); err != nil {
			fmt.Fprintf(errW, "relic: warning: load parent policy %s: %v\n", parentPolicyPath, err)
		}
	}

	// Create trace writer — creates .tr/traces/ if needed.
	// When RELIC_TRACE_KEY is set, the writer seals every event with
	// an HMAC chain so the platform (or `relic trace verify`) can
	// detect tampering. The per-run key is derived from the master
	// secret + runID; the runtime never ships the raw key.
	var traceChainKey []byte
	if masterSecret := loadTraceMasterSecret(errW); len(masterSecret) > 0 {
		traceChainKey = trace.GenerateChainKey(runID, masterSecret)
	}
	tw, err := trace.NewTraceWriterWithKey(opts.traceDir, runID, traceChainKey)
	if err != nil {
		return fmt.Errorf("run: create trace writer: %w", err)
	}

	// Slice 14: optional live-feed streamer. Standalone mode (no
	// RELIC_API_URL + RELIC_API_KEY) returns a nil streamer; nil-safe
	// methods make the streaming call sites unconditional. Sealed
	// event lines from the writer are tee'd into the streamer's queue
	// so the disk and network paths see byte-identical bytes.
	streamer, streamerErr := api.NewStreamerFromEnv()
	if streamerErr != nil {
		fmt.Fprintf(errW, "relic: warning: streamer disabled: %v\n", streamerErr)
	}
	if streamer != nil {
		tw.SetSealedSink(func(line []byte) { _ = streamer.Submit(line) })
		defer streamer.Close()
	}

	// Write run-start event (with delegation info when applicable).
	startEvent := trace.RunEvent{
		V:      1,
		T:      "run",
		TS:     time.Now().UTC().Format(time.RFC3339Nano),
		Run:    runID,
		Agent:  args[0],
		Env:    opts.env,
		Status: "start",
	}
	if isChild {
		startEvent.FromRun = parentRunID
		startEvent.Corr = delegationRoot
		startEvent.DelegationDepth = &delegationDepth
		startEvent.DelegationRoot = delegationRoot
	}
	if err := tw.WriteEvent(startEvent); err != nil {
		tw.Close()
		return fmt.Errorf("run: write run start: %w", err)
	}

	var stats actionStats

	// Resolve the relic directory and policy path.
	relicDir := filepath.Dir(opts.traceDir)
	policyPath := opts.policyPath
	if policyPath == "" {
		policyPath = filepath.Join(relicDir, "policy.yaml")
	}

	// Signature verification — reject unsigned/tampered policies in secure mode.
	if opts.requireSignature || opts.pubKeyPath != "" {
		pubKey := opts.pubKeyPath
		if pubKey == "" {
			pubKey = filepath.Join(relicDir, "keys", "policy.pub")
		}
		if err := signing.VerifyFile(policyPath, pubKey); err != nil {
			tw.Close() //nolint:errcheck
			return fmt.Errorf("run: policy signature verification failed: %w", err)
		}
		fmt.Fprintf(errW, "relic: policy signature verified (%s)\n", policyPath)
	}

	// Load policy and create the authorization engine + redactor.
	eng, red, loadedPolicy := loadEngineRedactorAndPolicy(errW, relicDir, opts.policyPath, opts.modeOverride)

	// Filesystem sandbox creation when policy has filesystem config enabled.
	var sb *sandbox.Sandbox
	if loadedPolicy != nil && loadedPolicy.Filesystem.Enabled {
		mounts := make([]sandbox.Mount, len(loadedPolicy.Filesystem.Mounts))
		for i, m := range loadedPolicy.Filesystem.Mounts {
			mounts[i] = sandbox.Mount{
				Source: m.Source,
				Target: m.Target,
				Mode:   sandbox.MountMode(m.Mode),
			}
		}
		sb, err = sandbox.New(sandbox.Config{
			Enabled:      true,
			Mounts:       mounts,
			DenyPatterns: loadedPolicy.Filesystem.DenyPatterns,
		}, runID)
		if err != nil {
			tw.Close() //nolint:errcheck
			return fmt.Errorf("run: create filesystem sandbox: %w", err)
		}
		defer sb.Cleanup()
		fmt.Fprintf(errW, "relic: filesystem sandbox active (%d mounts)\n", len(mounts))
	}

	// Slice 15: --watch is driven by an agent-facing SSE channel
	// (GET /v1/agents/:name/policy_updates), not fsnotify on a local
	// file. The previous fsnotify path is removed entirely — single
	// reload mechanism, no parallel paths. Standalone-mode users who
	// relied on fsnotify lose --watch; everything else (run, trace,
	// pull-once) continues to work without an API key.
	//
	// The reload sequence is: SSE frame arrives → pull policy via
	// existing api.Client.PullPolicy → parse + validate → SwapPolicy
	// on the in-memory engine → report applied hash. SwapPolicy is
	// safe under concurrent Evaluate (proven by
	// policy.TestEngineSwapDuringInFlightEvaluate); in-flight calls
	// complete under their starting policy. The per-run HMAC chain
	// key is not rotated.
	var policyWatcherCancel context.CancelFunc
	if opts.watch {
		policyClient, perr := api.NewClientFromEnv()
		if perr != nil {
			fmt.Fprintf(errW, "relic: --watch requires RELIC_API_KEY (+ RELIC_API_URL); hot reload disabled\n")
		} else {
			agentName := ""
			if loadedPolicy != nil && loadedPolicy.Agent.Name != "" {
				agentName = loadedPolicy.Agent.Name
			}
			if agentName == "" {
				fmt.Fprintf(errW, "relic: --watch needs agent.name in the policy; hot reload disabled\n")
			} else {
				watchCtx, cancel := context.WithCancel(context.Background())
				policyWatcherCancel = cancel
				go runPolicyWatcher(watchCtx, errW, policyClient, agentName, opts.modeOverride, eng, tw, runID, policyPath)
			}
		}
	}

	// MCP proxy wiring: either via .tr/mcp.yaml (default) or openclaw.json.
	var wiring *proxyWiring
	var openClawTmpFile string // temp file to clean up after run

	if opts.fromOpenClaw || opts.openClawCfg != "" {
		// OpenClaw mode: generate modified config with proxy-stdio wrappers.
		openClawTmpFile = setupOpenClawProxying(errW, runID, opts.traceDir, opts.openClawCfg, opts.openClawAgent)
		// In OpenClaw mode the MCP proxying is handled by proxy-stdio subprocesses,
		// so no stdio proxy wiring is needed in this process.
	} else {
		// Standard mode: attempt to load .tr/mcp.yaml and start the MCP proxy.
		mcpYAML := filepath.Join(relicDir, "mcp.yaml")
		wiring = maybeStartProxy(runID, mcpYAML, eng, red, tw, &stats, errW)
	}

	// Attach sandbox to MCP proxy if both exist.
	if wiring != nil && sb != nil {
		wiring.proxy.SetSandbox(sb)
	}

	// Attach sequence anomaly detector to MCP proxy if rules are configured.
	if wiring != nil && loadedPolicy != nil && len(loadedPolicy.Sequences.Rules) > 0 {
		det := policy.NewSequenceDetector(loadedPolicy.Sequences)
		wiring.proxy.SetSequenceDetector(det)
		fmt.Fprintf(errW, "relic: sequence detector active (%d rules, window=%d)\n",
			len(loadedPolicy.Sequences.Rules), loadedPolicy.Sequences.Window)
	}

	// Exfiltration guard wiring.
	var exfilGuard *exfiltration.Guard
	if loadedPolicy != nil && loadedPolicy.Exfiltration.Enabled {
		exfilGuard = exfiltration.NewGuard(loadedPolicy.Exfiltration)
		if exfilGuard != nil {
			if wiring != nil {
				wiring.proxy.SetExfiltrationGuard(exfilGuard)
			}
			fmt.Fprintf(errW, "relic: exfiltration guard active\n")
		}
	}

	// Start the HTTP metadata logger and set HTTP_PROXY / HTTPS_PROXY.
	httpW := startHTTPLogger(runID, eng, red, tw, &stats, errW)

	// Apply network policy to the HTTP logger.
	if httpW != nil && loadedPolicy != nil && (len(loadedPolicy.Network.DNSAllow) > 0 || len(loadedPolicy.Network.DNSDeny) > 0) {
		httpW.logger.SetNetworkPolicy(loadedPolicy.Network.DNSAllow, loadedPolicy.Network.DNSDeny)
	}

	// Attach exfiltration guard to the HTTP logger.
	if httpW != nil && exfilGuard != nil {
		httpW.logger.SetExfiltrationGuard(exfilGuard)
	}

	// Build child process.
	child := exec.Command(args[0], args[1:]...)
	child.Stderr = os.Stderr
	childEnv := append(sanitizeEnv(os.Environ()),
		"RELIC_RUN_ID="+runID,
		"RELIC_TRACE_DIR="+opts.traceDir,
		"RELIC_GOVERNED=1",
	)
	if opts.policyPath != "" {
		childEnv = append(childEnv, "RELIC_POLICY="+opts.policyPath)
	}
	if httpW != nil {
		proxyAddr := fmt.Sprintf("http://127.0.0.1:%d", httpW.port)
		childEnv = append(childEnv,
			"HTTP_PROXY="+proxyAddr,
			"HTTPS_PROXY="+proxyAddr,
			"http_proxy="+proxyAddr,
			"https_proxy="+proxyAddr,
			"no_proxy=",
			"NO_PROXY=",
		)
	}
	if openClawTmpFile != "" {
		childEnv = append(childEnv, "OPENCLAW_CONFIG="+openClawTmpFile)
	}

	// Delegation env vars — propagate chain so sub-agents can detect their parent.
	delegRoot := delegationRoot
	if delegRoot == "" {
		delegRoot = runID
	}
	policyForChild := opts.policyPath
	if policyForChild == "" {
		policyForChild = filepath.Join(filepath.Dir(opts.traceDir), "policy.yaml")
	}
	childEnv = append(childEnv,
		delegation.EnvParentRunID+"="+runID,
		fmt.Sprintf("%s=%d", delegation.EnvDelegationDepth, delegationDepth+1),
		delegation.EnvDelegationRoot+"="+delegRoot,
		delegation.EnvParentPolicy+"="+policyForChild,
	)

	child.Env = childEnv

	if wiring != nil {
		child.Stdin = wiring.childStdin
		child.Stdout = wiring.childStdout
	} else {
		child.Stdin = os.Stdin
		child.Stdout = os.Stdout
	}

	// Start child.
	if err := child.Start(); err != nil {
		durationMs := int(time.Since(start).Milliseconds())
		tw.WriteRunEnd(runID, 1, durationMs, 0, 0, 0) //nolint:errcheck
		tw.Close()                                     //nolint:errcheck
		if wiring != nil {
			wiring.proxyStdoutR.Close()
			<-wiring.done
			wiring.proxy.Close()
		}
		return fmt.Errorf("run: start %q: %w", args[0], err)
	}

	// Forward SIGINT and SIGTERM to the child.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			if child.Process != nil {
				child.Process.Signal(sig) //nolint:errcheck
			}
		}
	}()

	// Wait for child. Because we used *os.File for Stdin/Stdout (when proxy is
	// active), exec created no I/O goroutines — Wait() returns immediately.
	waitErr := child.Wait()
	signal.Stop(sigCh)
	close(sigCh)

	// Stop the policy watcher (slice 15: SSE subscription cancel).
	if policyWatcherCancel != nil {
		policyWatcherCancel()
	}

	// Tear down the HTTP logger.
	if httpW != nil {
		httpW.logger.Close() //nolint:errcheck
	}

	// Clean up the temporary openclaw config file if one was written.
	if openClawTmpFile != "" {
		os.Remove(openClawTmpFile) //nolint:errcheck
	}

	// Tear down the MCP proxy.
	if wiring != nil {
		// Closing childStdoutW releases the last writer reference so
		// childStdoutR.Read() returns io.EOF, unblocking ServeStdio's scanner.
		wiring.childStdout.Close()
		<-wiring.done               // wait for ServeStdio goroutine to finish
		wiring.proxyStdoutR.Close() // fd cleanup after goroutine is done
		wiring.proxy.Close()        // kill the MCP server subprocess
	}

	// Determine exit code.
	exitCode := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	durationMs := int(time.Since(start).Milliseconds())
	total, allowed, denied := stats.snapshot()

	if err := tw.WriteRunEnd(runID, exitCode, durationMs, total, allowed, denied); err != nil {
		fmt.Fprintf(errW, "relic: warning: failed to write run-end trace: %v\n", err)
	}
	if err := tw.Close(); err != nil {
		fmt.Fprintf(errW, "relic: warning: failed to close trace writer: %v\n", err)
	}

	if !opts.quiet {
		tracePath := filepath.Join(opts.traceDir, runID+".trtrace")
		dur := time.Duration(durationMs) * time.Millisecond
		fmt.Fprintf(errW,
			"The Relic: %d actions, %d allowed, %d denied  [run=%s duration=%s trace=%s]\n",
			total, allowed, denied, runID, dur.Round(time.Millisecond), tracePath,
		)
	}

	if exitCode != 0 {
		return &ExitError{Code: exitCode}
	}
	return nil
}

// loadEngineRedactorAndPolicy loads the policy file and returns a policy.Engine,
// a *redact.Redactor, and the loaded *Policy.
//
// Resolution order:
//  1. policyPath (--policy flag)
//  2. relicDir/policy.yaml
//  3. If neither exists: permissive engine + empty redactor + nil policy
//
// modeOverride ("enforce" | "audit" | "permissive") replaces the policy's
// mode field when non-empty, letting `--mode` override the file.
func loadEngineRedactorAndPolicy(errW io.Writer, relicDir, policyPath, modeOverride string) (*policy.Engine, *redact.Redactor, *policy.Policy) {
	if policyPath == "" {
		policyPath = filepath.Join(relicDir, "policy.yaml")
	}

	p, err := config.LoadPolicy(policyPath)
	if err != nil {
		p = &policy.Policy{
			Version: "1",
			Agent:   policy.AgentIdentity{Name: "unknown"},
			Mode:    "permissive",
			Default: "deny",
		}
		if modeOverride != "" {
			p.Mode = modeOverride
		}
		return policy.NewEngine(p), redact.NewRedactor(p.Redaction), nil
	}

	if modeOverride != "" {
		p.Mode = modeOverride
	}

	return policy.NewEngine(p), redact.NewRedactor(p.Redaction), p
}

// maybeStartProxy tries to load .tr/mcp.yaml and start an MCPProxy for the
// first configured stdio server. Returns nil if the file is missing, unreadable,
// or has no stdio servers — callers fall back to direct stdin/stdout.
func maybeStartProxy(
	runID, mcpYAML string,
	eng *policy.Engine,
	red *redact.Redactor,
	tw *trace.TraceWriter,
	stats *actionStats,
	errW io.Writer,
) *proxyWiring {
	cfg, err := config.LoadMCPConfig(mcpYAML)
	if err != nil {
		return nil
	}

	stdioServers := cfg.StdioServers()
	if len(stdioServers) == 0 {
		return nil
	}

	srv := stdioServers[0]

	onAction := func(ev trace.ActionEvent) {
		if err := tw.WriteAction(ev); err != nil {
			fmt.Fprintf(errW, "relic: warning: write action trace: %v\n", err)
		}
		stats.record(ev.Auth)
	}
	// Slice 14: intent emission. The writer's sealed-sink tee feeds
	// the optional streamer; standalone-mode runtimes still write
	// IntentEvents to the local .trtrace, just without the network leg.
	onIntent := func(ev trace.IntentEvent) {
		if err := tw.WriteIntent(ev); err != nil {
			fmt.Fprintf(errW, "relic: warning: write intent trace: %v\n", err)
		}
	}

	p := proxy.NewMCPProxy(runID, srv.Command, srv.Args, eng, red, onAction)
	p.SetIntentEmitter(onIntent)
	if srv.Integrity != nil {
		p.SetIntegrity(srv.Integrity)
	}
	if err := p.Start(); err != nil {
		fmt.Fprintf(errW, "relic: warning: mcp proxy start: %v\n", err)
		return nil
	}

	childStdinR, childStdinW, err := os.Pipe()
	if err != nil {
		fmt.Fprintf(errW, "relic: warning: mcp proxy pipe: %v\n", err)
		p.Close()
		return nil
	}
	childStdoutR, childStdoutW, err := os.Pipe()
	if err != nil {
		fmt.Fprintf(errW, "relic: warning: mcp proxy pipe: %v\n", err)
		childStdinR.Close()
		childStdinW.Close()
		p.Close()
		return nil
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer childStdinW.Close()
		if err := p.ServeStdio(nil, childStdoutR, childStdinW); err != nil {
			fmt.Fprintf(errW, "relic: warning: mcp proxy: %v\n", err)
		}
	}()

	return &proxyWiring{
		proxy:        p,
		childStdin:   childStdinR,
		childStdout:  childStdoutW,
		proxyStdoutR: childStdoutR,
		done:         done,
	}
}

// setupOpenClawProxying reads openclaw.json (from cfgPath or the default
// location), wraps stdio MCP servers with proxy-stdio, and writes a modified
// openclaw.json to a temp file.  Returns the path to the temp file so the
// caller can set OPENCLAW_CONFIG and clean up afterwards.  Returns "" on
// failure — the caller proceeds without openclaw proxying.
func setupOpenClawProxying(errW io.Writer, runID, traceDir, cfgPath, agentFilter string) string {
	if cfgPath == "" {
		var err error
		cfgPath, err = config.DefaultOpenClawConfigPath()
		if err != nil {
			fmt.Fprintf(errW, "relic: warning: openclaw default path: %v\n", err)
			return ""
		}
	}

	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		fmt.Fprintf(errW, "relic: warning: read openclaw config %s: %v\n", cfgPath, err)
		return ""
	}

	cfg, err := config.ParseOpenClawConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(errW, "relic: warning: parse openclaw config: %v\n", err)
		return ""
	}

	// Optionally restrict to a single agent's servers.
	// (In openclaw.json there is no per-agent server list today; the filter
	// is reserved for future multi-agent layouts where each agent declares its
	// own mcpServers subset.)
	servers := cfg.Servers
	if agentFilter != "" {
		// Check that the requested agent ID exists.
		found := false
		for _, a := range cfg.Agents {
			if a.ID == agentFilter {
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(errW, "relic: warning: openclaw agent %q not found in config\n", agentFilter)
		}
		// Server filtering by agent will be supported once openclaw.json
		// gains per-agent mcpServers sections; for now all servers are used.
	}

	relicExe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(errW, "relic: warning: resolve relic executable: %v\n", err)
		return ""
	}

	modified, err := config.GenerateModifiedConfig(raw, servers, relicExe, runID, traceDir)
	if err != nil {
		fmt.Fprintf(errW, "relic: warning: generate modified openclaw config: %v\n", err)
		return ""
	}

	// Write to a temp file that the child process can read.
	tmp, err := os.CreateTemp("", "relic-openclaw-*.json")
	if err != nil {
		fmt.Fprintf(errW, "relic: warning: create openclaw temp file: %v\n", err)
		return ""
	}
	defer tmp.Close()
	if _, err := tmp.Write(modified); err != nil {
		fmt.Fprintf(errW, "relic: warning: write openclaw temp file: %v\n", err)
		os.Remove(tmp.Name()) //nolint:errcheck
		return ""
	}
	return tmp.Name()
}

// sanitizeEnv strips dangerous environment variables before spawning the child process.
// Prevents: proxy override attacks, TLS verification bypass, library injection,
// and The Relic internal variable spoofing.
func sanitizeEnv(env []string) []string {
	blocked := map[string]bool{
		// Proxy overrides — prevent routing traffic away from our proxy.
		"HTTP_PROXY": true, "HTTPS_PROXY": true, "ALL_PROXY": true,
		"http_proxy": true, "https_proxy": true, "all_proxy": true,
		"NO_PROXY": true, "no_proxy": true,
		// TLS bypass — prevent disabling certificate verification.
		"NODE_TLS_REJECT_UNAUTHORIZED": true,
		"PYTHONHTTPSVERIFY": true,
		"GIT_SSL_NO_VERIFY": true,
		"CURL_CA_BUNDLE": true,
		"SSL_CERT_FILE": true,
		// Library injection — prevent loading malicious shared libraries.
		"LD_PRELOAD": true,
		"DYLD_INSERT_LIBRARIES": true,
		"LD_LIBRARY_PATH": true,
		"DYLD_LIBRARY_PATH": true,
	}

	var result []string
	for _, kv := range env {
		key := kv
		for i, c := range kv {
			if c == '=' {
				key = kv[:i]
				break
			}
		}
		if blocked[key] {
			continue
		}
		// Block RELIC_ variable spoofing.
		if len(key) > 6 && key[:6] == "RELIC_" {
			continue
		}
		result = append(result, kv)
	}
	return result
}

// startHTTPLogger creates and starts the HTTP metadata logger.
// Returns nil on failure — the caller runs the child without HTTP_PROXY set.
func startHTTPLogger(
	runID string,
	eng *policy.Engine,
	red *redact.Redactor,
	tw *trace.TraceWriter,
	stats *actionStats,
	errW io.Writer,
) *httpWiring {
	onAction := func(ev trace.ActionEvent) {
		if err := tw.WriteAction(ev); err != nil {
			fmt.Fprintf(errW, "relic: warning: write http action trace: %v\n", err)
		}
		stats.record(ev.Auth)
	}

	logger := proxy.NewHTTPLogger(runID, eng, red, onAction)
	port, err := logger.Start()
	if err != nil {
		fmt.Fprintf(errW, "relic: warning: http logger start: %v\n", err)
		return nil
	}
	return &httpWiring{logger: logger, port: port}
}

// runPolicyWatcher subscribes to the platform's per-agent policy
// update SSE channel and applies notifications via the existing
// eng.SwapPolicy mechanism. Slice 15's reload trigger.
//
// On each notification: pull policy via the existing /v1/agents/:name/
// policy endpoint, parse + validate, hot-swap in-memory, and POST
// /v1/agents/:name/policy_applied to advance the dashboard's apply
// counter. Failures along the way are logged to errW and reflected
// as a policy_reload error event in the trace; the run continues
// under the previous policy.
//
// Reconnects use exponential backoff capped at 30s. SubscribePolicyUpdates
// blocks until the server closes the connection or ctx is cancelled,
// so this function's outer loop only iterates on reconnect.
func runPolicyWatcher(
	ctx context.Context,
	errW io.Writer,
	client *api.Client,
	agentName, modeOverride string,
	eng *policy.Engine,
	tw *trace.TraceWriter,
	runID, policyPath string,
) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := client.SubscribePolicyUpdates(ctx, agentName, func(u api.PolicyUpdate) {
			// Pull the YAML the platform just notified us about, then
			// swap in place. The pull deduplicates: if the same hash
			// arrives twice (e.g., reconnect replay), the swap is a
			// no-op and we still report applied to nudge the dashboard.
			pullCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			yamlBytes, perr := client.PullPolicy(pullCtx, agentName)
			if perr != nil {
				fmt.Fprintf(errW, "relic: policy pull on update failed: %v\n", perr)
				tw.WritePolicyReload(runID, policyPath, "error", perr.Error()) //nolint:errcheck
				return
			}
			parsed, parseErr := policy.Parse(yamlBytes)
			if parseErr != nil {
				fmt.Fprintf(errW, "relic: policy parse on update failed: %v\n", parseErr)
				tw.WritePolicyReload(runID, policyPath, "error", parseErr.Error()) //nolint:errcheck
				return
			}
			if errs := policy.Validate(parsed, false); len(errs) > 0 {
				fmt.Fprintf(errW, "relic: policy validate on update failed: %v\n", errs[0])
				tw.WritePolicyReload(runID, policyPath, "error", errs[0].Error()) //nolint:errcheck
				return
			}
			if modeOverride != "" {
				parsed.Mode = modeOverride
			}
			// SwapPolicy is safe under in-flight Evaluate (RLock'd
			// read of the current pointer; the swap publishes a new
			// pointer atomically). The per-run HMAC chain key is
			// derived from runID + master secret and is NOT touched
			// here — verification continues end-to-end across the
			// swap.
			eng.SwapPolicy(parsed)
			fmt.Fprintf(errW, "relic: policy hot-reloaded (set %q, hash %s, version %d)\n",
				u.PolicySetName, u.PolicyHash, u.Version)
			tw.WritePolicyReload(runID, policyPath, "ok", "") //nolint:errcheck

			if reportErr := client.ReportPolicyApplied(pullCtx, agentName, u.PolicyHash); reportErr != nil {
				fmt.Fprintf(errW, "relic: report applied failed: %v\n", reportErr)
				// Non-fatal: the dashboard's counter will lag; the
				// next notification or a manual sync will reconcile.
			}
		})
		if ctx.Err() != nil {
			return
		}
		// The SSE stream ended (timeout / proxy / platform restart).
		// Back off and retry. Stderr message keeps the operator informed
		// without flooding under sustained outage.
		if err != nil {
			fmt.Fprintf(errW, "relic: policy update stream disconnected: %v (retry in %s)\n", err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
