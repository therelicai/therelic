package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/therelicai/therelic/internal/trace"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/spf13/cobra"
)

// searchMatch holds a single matching action event with the run context needed
// for display.
type searchMatch struct {
	RunID string
	Agent string
	Event trace.TraceEvent
}

// newTraceSearchCmd returns `relic trace search`.
func newTraceSearchCmd() *cobra.Command {
	var (
		flagTarget string
		flagProto  string
		flagAuth   string
		flagDir    string
		flagLimit  int
	)

	cmd := &cobra.Command{
		Use:   "search",
		Short: "Search action events across all trace files",
		Long: `Search for action events matching the given criteria across all .trtrace files.
Multiple flags are ANDed together. All flags are optional; with no flags, all
action events are returned.

Examples:
  relic trace search --auth deny
  relic trace search --target "web_*"
  relic trace search --proto mcp --target "db_*"
  relic trace search --proto http --auth allow`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if flagDir == "" {
				flagDir = filepath.Join(".tr", "traces")
			}

			matches, err := searchTraces(flagDir, flagTarget, flagProto, flagAuth)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			col := &colorizer{w: out, enable: isTTY(out)}

			if len(matches) == 0 {
				fmt.Fprintln(out, col.gray("No matching events found."))
				return nil
			}

			display := matches
			if flagLimit > 0 && flagLimit < len(matches) {
				display = matches[:flagLimit]
			}

			printSearchResults(out, col, display)
			return nil
		},
	}

	cmd.Flags().StringVar(&flagTarget, "target", "", "Filter by target glob (e.g. \"web_*\", \"*.example.com:*\")")
	cmd.Flags().StringVar(&flagProto, "proto", "", "Filter by protocol (e.g. mcp, http, https)")
	cmd.Flags().StringVar(&flagAuth, "auth", "", "Filter by auth decision (allow, deny, audit_deny, would_deny)")
	cmd.Flags().StringVar(&flagDir, "dir", "", "Trace directory (default: .tr/traces)")
	cmd.Flags().IntVar(&flagLimit, "limit", 0, "Maximum number of results (0 = all)")

	return cmd
}

// searchTraces scans all .trtrace files in dir and returns matching action
// events. All filter arguments are optional ("" = no filter for that field).
// target is a doublestar glob pattern.
func searchTraces(dir, targetGlob, proto, auth string) ([]searchMatch, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("trace search: read dir %s: %w", dir, err)
	}

	var matches []searchMatch
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".trtrace") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		fileMatches, err := searchFile(path, targetGlob, proto, auth)
		if err != nil {
			// Skip unreadable / malformed files.
			continue
		}
		matches = append(matches, fileMatches...)
	}
	return matches, nil
}

// searchFile scans one .trtrace file and returns matching action events.
func searchFile(path, targetGlob, proto, auth string) ([]searchMatch, error) {
	events, err := trace.ReadTrace(path)
	if err != nil {
		return nil, err
	}

	// Extract the agent name from the run_start event for context.
	agent := ""
	for _, ev := range events {
		if ev.T == "run" && ev.Status == "start" {
			agent = ev.Agent
			break
		}
	}
	runID := runIDFromPath(path)

	var matches []searchMatch
	for _, ev := range events {
		if ev.T != "action" {
			continue
		}
		if !matchesFilter(ev, targetGlob, proto, auth) {
			continue
		}
		matches = append(matches, searchMatch{
			RunID: runID,
			Agent: agent,
			Event: ev,
		})
	}
	return matches, nil
}

// matchesFilter returns true when ev satisfies all non-empty filter criteria.
func matchesFilter(ev trace.TraceEvent, targetGlob, proto, auth string) bool {
	if proto != "" && ev.Proto != proto {
		return false
	}
	if auth != "" && ev.Auth != auth {
		return false
	}
	if targetGlob != "" {
		matched, err := doublestar.Match(targetGlob, ev.Target)
		if err != nil || !matched {
			return false
		}
	}
	return true
}

// printSearchResults renders the search matches to w.
func printSearchResults(w io.Writer, col *colorizer, matches []searchMatch) {
	prevRunID := ""
	for _, m := range matches {
		// Print a run separator when the run changes.
		if m.RunID != prevRunID {
			agent := m.Agent
			if agent == "" {
				agent = "(unknown)"
			}
			fmt.Fprintln(w, col.gray(fmt.Sprintf("── run=%s agent=%s", m.RunID, agent)))
			prevRunID = m.RunID
		}
		fmt.Fprintln(w, renderSearchEvent(col, m))
	}
}

// renderSearchEvent formats a single search result line.
func renderSearchEvent(col *colorizer, m searchMatch) string {
	ev := m.Event
	ts := formatTS(ev.TS)
	label, colorFn := authLabel(col, ev.Auth)

	return colorFn(fmt.Sprintf("  [%s] %s  #%-3d %s %-12s %s  rule=%s",
		ts,
		label,
		ev.Seq,
		ev.Proto,
		ev.Method,
		col.cyan(ev.Target),
		ev.Rule,
	))
}
