package cli

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/therelicai/therelic/internal/api"
	"github.com/therelicai/therelic/internal/config"
)

func newTracePushCmd() *cobra.Command {
	var flagDir string
	cmd := &cobra.Command{
		Use:          "push [run-id]",
		Short:        "Upload traces to The Relic platform",
		Long:         "Upload .trtrace files to The Relic platform for hosted storage, analysis, and governance.",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := api.NewClientFromEnv()
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n\n", err)
				fmt.Fprintf(cmd.ErrOrStderr(), "To get started:\n")
				fmt.Fprintf(cmd.ErrOrStderr(), "  1. Bring up a Relic platform (https://github.com/therelicai/therelic-platform)\n")
				fmt.Fprintf(cmd.ErrOrStderr(), "  2. Create an API key in the dashboard (or with `docker compose exec relic-api ...`)\n")
				fmt.Fprintf(cmd.ErrOrStderr(), "  3. export RELIC_API_KEY=<your-key>\n")
				fmt.Fprintf(cmd.ErrOrStderr(), "  4. export RELIC_API_URL=<your-platform-url>  (default: http://localhost:8080/v1)\n")
				return err
			}

			traceDir := flagDir
			if traceDir == "" {
				paths := config.DefaultPaths()
				traceDir = paths.TracesDir
			}

			if len(args) > 0 {
				return pushSingleTrace(cmd, client, traceDir, args[0])
			}
			return pushLatestTrace(cmd, client, traceDir)
		},
	}
	cmd.Flags().StringVar(&flagDir, "dir", "", "Directory holding .trtrace files (default: .tr/traces)")
	return cmd
}

func pushSingleTrace(cmd *cobra.Command, client *api.Client, traceDir, runID string) error {
	pattern := filepath.Join(traceDir, runID+"*.trtrace")
	matches, _ := filepath.Glob(pattern)
	if len(matches) == 0 {
		return fmt.Errorf("no trace file found for run %s", runID)
	}

	return pushTraceFile(cmd, client, matches[0], runID)
}

func pushLatestTrace(cmd *cobra.Command, client *api.Client, traceDir string) error {
	matches, _ := filepath.Glob(filepath.Join(traceDir, "*.trtrace"))
	if len(matches) == 0 {
		return fmt.Errorf("no trace files found in %s", traceDir)
	}
	latest := matches[len(matches)-1]
	runID := filepath.Base(latest)
	runID = runID[:len(runID)-len(".trtrace")]

	return pushTraceFile(cmd, client, latest, runID)
}

func pushTraceFile(cmd *cobra.Command, client *api.Client, path, runID string) error {
	fmt.Fprintf(cmd.OutOrStdout(), "Uploading %s...\n", filepath.Base(path))

	meta := extractTraceMeta(path)

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		f, err := os.Open(path)
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		defer f.Close()
		gz := gzip.NewWriter(pw)
		defer gz.Close()
		io.Copy(gz, f)
	}()

	if err := client.PushTrace(context.Background(), runID, pr, meta); err != nil {
		return fmt.Errorf("push failed: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Uploaded run %s\n", runID)
	return nil
}

func extractTraceMeta(path string) api.TraceMeta {
	meta := api.TraceMeta{Environment: "default"}

	f, err := os.Open(path)
	if err != nil {
		return meta
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	for dec.More() {
		var event map[string]any
		if err := dec.Decode(&event); err != nil {
			break
		}

		// Both run-start and run-end events use t="run" — they are
		// distinguished by the "status" field. Field names match the JSON
		// tags on trace.RunEvent (agent_v, policy, actions_total, ms, etc.).
		if t, _ := event["t"].(string); t != "run" {
			continue
		}

		switch event["status"] {
		case "start":
			if a, ok := event["agent"].(string); ok && a != "" {
				meta.AgentName = a
			}
			if v, ok := event["agent_v"].(string); ok && v != "" {
				meta.AgentVersion = v
			}
			if p, ok := event["policy"].(string); ok && p != "" {
				meta.PolicyHash = p
			}
			if e, ok := event["env"].(string); ok && e != "" {
				meta.Environment = e
			}
		case "end":
			if v, ok := event["actions_total"].(float64); ok {
				meta.ActionsTotal = int(v)
			}
			if v, ok := event["actions_allowed"].(float64); ok {
				meta.ActionsAllowed = int(v)
			}
			if v, ok := event["actions_denied"].(float64); ok {
				meta.ActionsDenied = int(v)
			}
			if v, ok := event["ms"].(float64); ok {
				meta.DurationMs = int(v)
			}
			if v, ok := event["exit"].(float64); ok {
				meta.ExitCode = int(v)
			}
		}
	}

	return meta
}
