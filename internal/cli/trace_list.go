package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/therelicai/therelic/internal/trace"
	"github.com/spf13/cobra"
)

// runSummary holds the extracted metadata for a single run, built from the
// run_start and run_end events in a .trtrace file.
type runSummary struct {
	RunID      string
	Agent      string
	Env        string
	StartedAt  time.Time
	DurationMs int  // 0 when the run has not yet ended
	Exit       int
	Total      int
	Allowed    int
	Denied     int
	hasEnd     bool // false when run_end event was not found (interrupted run)
}

// newTraceListCmd returns `relic trace list`.
func newTraceListCmd() *cobra.Command {
	var (
		flagAgent      string
		flagHasDenials bool
		flagDir        string
		flagLimit      int
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List recent agent runs",
		Long: `List recent agent runs, most recent first.

Each line shows: run_id, agent name, start time, duration, and action counts.

Examples:
  relic trace list
  relic trace list --agent my-agent
  relic trace list --has-denials`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if flagDir == "" {
				flagDir = filepath.Join(".tr", "traces")
			}

			runs, err := scanTraces(flagDir)
			if err != nil {
				return err
			}

			// Apply filters.
			filtered := make([]runSummary, 0, len(runs))
			for _, r := range runs {
				if flagAgent != "" && !strings.Contains(strings.ToLower(r.Agent), strings.ToLower(flagAgent)) {
					continue
				}
				if flagHasDenials && r.Denied == 0 {
					continue
				}
				filtered = append(filtered, r)
			}

			out := cmd.OutOrStdout()
			col := &colorizer{w: out, enable: isTTY(out)}

			if len(filtered) == 0 {
				fmt.Fprintln(out, col.gray("No runs found."))
				return nil
			}

			// Apply limit (0 = no limit).
			display := filtered
			if flagLimit > 0 && flagLimit < len(filtered) {
				display = filtered[:flagLimit]
			}

			printTraceList(out, col, display)
			return nil
		},
	}

	cmd.Flags().StringVar(&flagAgent, "agent", "", "Filter by agent name (substring match)")
	cmd.Flags().BoolVar(&flagHasDenials, "has-denials", false, "Only show runs with at least one denied action")
	cmd.Flags().StringVar(&flagDir, "dir", "", "Trace directory (default: .tr/traces)")
	cmd.Flags().IntVar(&flagLimit, "limit", 0, "Maximum number of runs to display (0 = all)")

	return cmd
}

// scanTraces reads all .trtrace files in dir, extracts run metadata, and
// returns them sorted by start time descending (most recent first).
func scanTraces(dir string) ([]runSummary, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("trace list: read dir %s: %w", dir, err)
	}

	var runs []runSummary
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".trtrace") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		s, err := readRunSummary(path)
		if err != nil {
			// Skip unreadable / malformed files silently.
			continue
		}
		runs = append(runs, s)
	}

	// Sort most recent first.
	sort.Slice(runs, func(i, j int) bool {
		return runs[i].StartedAt.After(runs[j].StartedAt)
	})
	return runs, nil
}

// readRunSummary opens one .trtrace file and extracts run metadata from the
// run_start and run_end events. Other event types are ignored.
func readRunSummary(path string) (runSummary, error) {
	events, err := trace.ReadTrace(path)
	if err != nil {
		return runSummary{}, err
	}

	var s runSummary
	s.RunID = runIDFromPath(path)

	hasStart := false
	for _, ev := range events {
		if ev.T != "run" {
			continue
		}
		switch ev.Status {
		case "start":
			hasStart = true
			s.Agent = ev.Agent
			s.Env = ev.Env
			if t, err := time.Parse(time.RFC3339Nano, ev.TS); err == nil {
				s.StartedAt = t
			}
		case "end":
			s.hasEnd = true
			s.DurationMs = ptrInt(ev.DurationMs)
			s.Exit = ptrInt(ev.Exit)
			s.Total = ptrInt(ev.ActionsTotal)
			s.Allowed = ptrInt(ev.ActionsAllowed)
			s.Denied = ptrInt(ev.ActionsDenied)
		}
	}

	if !hasStart {
		return runSummary{}, fmt.Errorf("no run_start event in %s", path)
	}
	return s, nil
}

// runIDFromPath strips the directory and ".trtrace" extension.
func runIDFromPath(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(base, ".trtrace")
}

// printTraceList renders the run list to w.
func printTraceList(w io.Writer, col *colorizer, runs []runSummary) {
	// Header
	header := fmt.Sprintf("%-26s  %-20s  %-10s  %-19s  %s",
		"RUN ID", "AGENT", "ENV", "STARTED", "ACTIONS")
	fmt.Fprintln(w, col.bold(header))
	fmt.Fprintln(w, col.gray(strings.Repeat("─", 90)))

	for _, r := range runs {
		startStr := r.StartedAt.UTC().Format("2006-01-02 15:04:05")
		if r.StartedAt.IsZero() {
			startStr = "unknown"
		}

		agent := r.Agent
		if agent == "" {
			agent = "(unknown)"
		}
		if len(agent) > 20 {
			agent = agent[:17] + "..."
		}

		env := r.Env
		if env == "" {
			env = "-"
		}

		actionStr := formatActionCounts(r)
		durStr := ""
		if r.hasEnd {
			durStr = " " + formatDurationMs(r.DurationMs)
		} else {
			durStr = col.yellow(" (running)")
		}

		line := fmt.Sprintf("%-26s  %-20s  %-10s  %s%s  %s",
			r.RunID, agent, env, startStr, durStr, actionStr)

		if r.Denied > 0 {
			fmt.Fprintln(w, col.yellow(line))
		} else {
			fmt.Fprintln(w, line)
		}
	}
}

// formatActionCounts returns a compact "N total (A allow, D deny)" string.
func formatActionCounts(r runSummary) string {
	if !r.hasEnd {
		return ""
	}
	if r.Denied > 0 {
		return fmt.Sprintf("%d actions (%d allowed, %d denied)", r.Total, r.Allowed, r.Denied)
	}
	return fmt.Sprintf("%d actions (%d allowed)", r.Total, r.Allowed)
}

// formatDurationMs converts milliseconds to a human-readable string.
func formatDurationMs(ms int) string {
	d := time.Duration(ms) * time.Millisecond
	if d < time.Second {
		return fmt.Sprintf("%dms", ms)
	}
	return d.Round(time.Millisecond).String()
}
