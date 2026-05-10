package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/therelicai/therelic/internal/trace"
)

// validRunID is the conservative set of characters we accept for a
// CLI-supplied run id. ULIDs are upper-case base32; we also allow
// dashes and underscores so users can paste custom ids from other
// runners. Anything outside this set risks path traversal via
// filepath.Join("traces", runID + ".trtrace").
var validRunID = regexp.MustCompile(`^[A-Za-z0-9_\-]{1,64}$`)

// ANSI color codes. Disabled automatically when writing to a non-tty or when
// NO_COLOR is set.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiBlue   = "\033[34m"
	ansiGreen  = "\033[32m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiGray   = "\033[90m"
	ansiCyan   = "\033[36m"
)

// colorizer wraps a writer and controls whether ANSI codes are emitted.
type colorizer struct {
	w      io.Writer
	enable bool
}

func (c *colorizer) colorize(code, s string) string {
	if !c.enable {
		return s
	}
	return code + s + ansiReset
}

func (c *colorizer) blue(s string) string   { return c.colorize(ansiBlue, s) }
func (c *colorizer) green(s string) string  { return c.colorize(ansiGreen, s) }
func (c *colorizer) red(s string) string    { return c.colorize(ansiRed, s) }
func (c *colorizer) yellow(s string) string { return c.colorize(ansiYellow, s) }
func (c *colorizer) gray(s string) string   { return c.colorize(ansiGray, s) }
func (c *colorizer) bold(s string) string   { return c.colorize(ansiBold, s) }
func (c *colorizer) cyan(s string) string   { return c.colorize(ansiCyan, s) }

// isTTY returns true when w is an *os.File connected to a terminal.
func isTTY(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// newTraceViewCmd returns `relic trace view <run_id>`.
func newTraceViewCmd() *cobra.Command {
	var (
		flagDenied bool
		flagJSON   bool
		flagFollow bool
		flagDir    string
	)

	cmd := &cobra.Command{
		Use:   "view <run_id>",
		Short: "Display trace events for a run",
		Long: `Display trace events for a run.

Run events are shown in blue. Allowed actions in green. Denied actions in red.
Audit-mode denials (audit_deny) and permissive-mode denials (would_deny) are
shown in yellow.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := args[0]
			if !validRunID.MatchString(runID) {
				return fmt.Errorf("invalid run id %q (must match %s)", runID, validRunID.String())
			}

			if flagDir == "" {
				flagDir = filepath.Join(".tr", "traces")
			}
			tracePath := filepath.Join(flagDir, runID+".trtrace")

			if _, err := os.Stat(tracePath); os.IsNotExist(err) {
				return fmt.Errorf("trace file not found: %s\n(looked in %s)", runID, flagDir)
			}

			out := cmd.OutOrStdout()
			col := &colorizer{w: out, enable: isTTY(out)}

			if flagJSON {
				return outputJSON(out, tracePath)
			}

			if flagFollow {
				return outputFollow(cmd.Context(), out, col, tracePath, flagDenied)
			}

			return outputFormatted(out, col, tracePath, flagDenied)
		},
	}

	cmd.Flags().BoolVar(&flagDenied, "denied", false, "Only show denied actions")
	cmd.Flags().BoolVar(&flagJSON, "json", false, "Output raw NDJSON lines")
	cmd.Flags().BoolVar(&flagFollow, "follow", false, "Tail the file and show new events as they arrive")
	cmd.Flags().StringVar(&flagDir, "dir", "", "Trace directory (default: .tr/traces)")

	return cmd
}

// outputJSON cats the raw .trtrace file to w.
func outputJSON(w io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

// outputFormatted reads all events and prints formatted output.
func outputFormatted(w io.Writer, col *colorizer, path string, deniedOnly bool) error {
	events, err := trace.ReadTrace(path)
	if err != nil {
		return err
	}
	for _, ev := range events {
		if deniedOnly && ev.T == "action" && !ev.IsDenied() {
			continue
		}
		fmt.Fprintln(w, renderEvent(col, ev))
	}
	return nil
}

// outputFollow streams events from a live trace file.
func outputFollow(ctx context.Context, w io.Writer, col *colorizer, path string, deniedOnly bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ch := trace.ReadTraceStream(ctx, path, true)
	for r := range ch {
		if r.Err != nil {
			return r.Err
		}
		ev := r.Event
		if deniedOnly && ev.T == "action" && !ev.IsDenied() {
			continue
		}
		fmt.Fprintln(w, renderEvent(col, ev))
	}
	return nil
}

// renderEvent formats a single TraceEvent as a human-readable string.
func renderEvent(col *colorizer, ev trace.TraceEvent) string {
	ts := formatTS(ev.TS)

	switch ev.T {
	case "run":
		return renderRunEvent(col, ts, ev)
	case "action":
		return renderActionEvent(col, ts, ev)
	default:
		return col.gray(fmt.Sprintf("[%s] UNKNOWN  t=%s run=%s", ts, ev.T, ev.Run))
	}
}

func renderRunEvent(col *colorizer, ts string, ev trace.TraceEvent) string {
	var sb strings.Builder

	switch ev.Status {
	case "start":
		sb.WriteString(col.blue(fmt.Sprintf("[%s] %s  run=%s agent=%s v=%s env=%s",
			ts,
			col.bold("RUN START"),
			ev.Run,
			ev.Agent,
			ev.AgentV,
			ev.Env,
		)))
	case "end":
		total, allowed, denied := ptrInt(ev.ActionsTotal), ptrInt(ev.ActionsAllowed), ptrInt(ev.ActionsDenied)
		dur := formatDuration(ev.DurationMs)
		exitStr := fmt.Sprintf("%d", ptrInt(ev.Exit))

		line := fmt.Sprintf("[%s] %s  run=%s exit=%s duration=%s actions=%d allowed=%d denied=%d",
			ts,
			col.bold("RUN END  "),
			ev.Run,
			exitStr,
			dur,
			total,
			allowed,
			denied,
		)
		if denied > 0 {
			sb.WriteString(col.yellow(line))
		} else {
			sb.WriteString(col.blue(line))
		}
	default:
		sb.WriteString(col.blue(fmt.Sprintf("[%s] RUN  run=%s status=%s", ts, ev.Run, ev.Status)))
	}

	if ev.Corr != "" {
		sb.WriteString(col.gray(fmt.Sprintf(" corr=%s", ev.Corr)))
	}
	return sb.String()
}

func renderActionEvent(col *colorizer, ts string, ev trace.TraceEvent) string {
	var sb strings.Builder

	label, colorFn := authLabel(col, ev.Auth)

	line := fmt.Sprintf("[%s] %s  #%-3d %s %-12s %s  rule=%s",
		ts,
		label,
		ev.Seq,
		ev.Proto,
		ev.Method,
		col.cyan(ev.Target),
		ev.Rule,
	)
	sb.WriteString(colorFn(line))

	if ev.ToAgent != "" {
		sb.WriteString(col.gray(fmt.Sprintf(" to=%s", ev.ToAgent)))
	}
	return sb.String()
}

// authLabel returns a fixed-width label string and a colorize function for the
// given auth decision.
func authLabel(col *colorizer, auth string) (string, func(string) string) {
	switch auth {
	case "allow":
		return col.green("ALLOW  "), col.green
	case "deny":
		return col.red("DENY   "), col.red
	case "audit_deny":
		return col.yellow("A_DENY "), col.yellow
	case "would_deny":
		return col.yellow("W_DENY "), col.yellow
	default:
		return col.gray("UNKNOWN"), col.gray
	}
}

// formatTS parses an RFC3339 timestamp and returns a short HH:MM:SS string.
func formatTS(ts string) string {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		if len(ts) >= 19 {
			return ts[11:19] // best-effort: take the time portion
		}
		return ts
	}
	return t.UTC().Format("15:04:05")
}

// formatDuration converts milliseconds to a human-readable string.
func formatDuration(ms *int) string {
	if ms == nil {
		return "?"
	}
	d := time.Duration(*ms) * time.Millisecond
	if d < time.Second {
		return fmt.Sprintf("%dms", *ms)
	}
	return d.Round(time.Millisecond).String()
}

func ptrInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
