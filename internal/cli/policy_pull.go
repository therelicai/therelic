package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/therelicai/therelic/internal/api"
	"github.com/therelicai/therelic/internal/config"
	"github.com/therelicai/therelic/internal/policy"
)

func newPolicyPullCmd() *cobra.Command {
	var (
		flagAgent  string
		flagOut    string
		flagDryRun bool
		flagForce  bool
	)

	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Pull the current policy for an agent from the control plane",
		Long: `Fetch the authoritative policy YAML for the named agent from the
control plane and write it to .tr/policy.yaml.

The control plane is the policy authority. Agents pull from it; local files
are a fallback when offline. Pulled policies are validated before being
written — invalid YAML is rejected without overwriting the local file.

Requires RELIC_API_KEY. Override the endpoint with RELIC_API_URL.`,
		Example: `  # Pull policy for the agent declared in .tr/policy.yaml
  relic policy pull

  # Pull policy for a specific agent and overwrite the local copy
  relic policy pull --agent data-pipeline-agent --force

  # Print the pulled policy without writing it
  relic policy pull --dry-run`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPolicyPull(cmd, flagAgent, flagOut, flagDryRun, flagForce)
		},
	}

	cmd.Flags().StringVar(&flagAgent, "agent", "", "Agent name (default: agent.name from .tr/policy.yaml)")
	cmd.Flags().StringVar(&flagOut, "out", "", "Output path (default: .tr/policy.yaml)")
	cmd.Flags().BoolVar(&flagDryRun, "dry-run", false, "Print fetched policy without writing")
	cmd.Flags().BoolVar(&flagForce, "force", false, "Overwrite local policy even if it has unsigned local edits")
	return cmd
}

func runPolicyPull(cmd *cobra.Command, agentName, outPath string, dryRun, force bool) error {
	out := cmd.OutOrStdout()
	errOut := cmd.ErrOrStderr()

	paths := config.DefaultPaths()
	if outPath == "" {
		outPath = paths.PolicyFile
	}

	// Resolve agent name from local policy if not provided.
	if agentName == "" {
		name, err := agentNameFromLocalPolicy(paths.PolicyFile)
		if err != nil {
			fmt.Fprintf(errOut, "Error: %v\n", err)
			fmt.Fprintf(errOut, "Specify an agent explicitly with --agent.\n")
			return &ExitError{Code: 1}
		}
		agentName = name
	}

	client, err := api.NewClientFromEnv()
	if err != nil {
		fmt.Fprintf(errOut, "Error: %s\n\n", err)
		fmt.Fprintf(errOut, "To pull from the control plane:\n")
		fmt.Fprintf(errOut, "  1. Bring up a Relic platform (https://github.com/therelicai/therelic-platform)\n")
		fmt.Fprintf(errOut, "  2. Create an API key in the dashboard\n")
		fmt.Fprintf(errOut, "  3. export RELIC_API_KEY=<your-key>\n")
		fmt.Fprintf(errOut, "  4. export RELIC_API_URL=<your-platform-url>  (default: http://localhost:8080/v1)\n")
		return &ExitError{Code: 1}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Fprintf(out, "Pulling policy for %q from %s...\n", agentName, client.BaseURL)

	yaml, err := client.PullPolicy(ctx, agentName)
	if err != nil {
		fmt.Fprintf(errOut, "Error: %v\n", err)
		return &ExitError{Code: 1}
	}

	// Validate the fetched policy before touching the local file.
	parsed, err := policy.Parse(yaml)
	if err != nil {
		fmt.Fprintf(errOut, "Error: control plane returned invalid YAML: %v\n", err)
		return &ExitError{Code: 1}
	}
	if errs := policy.Validate(parsed, false); len(errs) > 0 {
		fmt.Fprintf(errOut, "Error: control plane returned an invalid policy:\n")
		for _, e := range errs {
			fmt.Fprintf(errOut, "  - %s\n", e.Error())
		}
		return &ExitError{Code: 1}
	}

	if dryRun {
		fmt.Fprintf(out, "--- pulled policy (dry-run, %d bytes) ---\n", len(yaml))
		_, _ = out.Write(yaml)
		if len(yaml) > 0 && yaml[len(yaml)-1] != '\n' {
			fmt.Fprintln(out)
		}
		return nil
	}

	// Refuse to overwrite local edits unless --force.
	if !force {
		if drift, err := localPolicyHasDrift(outPath, yaml); err == nil && drift {
			fmt.Fprintf(errOut, "Error: %s differs from the control plane copy.\n", outPath)
			fmt.Fprintf(errOut, "Re-run with --force to overwrite local edits, or push your changes first.\n")
			return &ExitError{Code: 1}
		}
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("policy pull: create %s: %w", filepath.Dir(outPath), err)
	}
	if err := os.WriteFile(outPath, yaml, 0o644); err != nil {
		return fmt.Errorf("policy pull: write %s: %w", outPath, err)
	}

	fmt.Fprintf(out, "Wrote %s (%d bytes)\n", outPath, len(yaml))
	fmt.Fprintf(out, "Run 'relic policy validate' to inspect, or 'relic run' to execute under it.\n")
	return nil
}

// agentNameFromLocalPolicy returns the agent.name field from the local
// policy file, used as the default when --agent is not specified.
func agentNameFromLocalPolicy(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	p, err := policy.Parse(data)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", path, err)
	}
	if p.Agent.Name == "" {
		return "", fmt.Errorf("%s has no agent.name; pass --agent explicitly", path)
	}
	return p.Agent.Name, nil
}

// localPolicyHasDrift reports whether the local file differs from the
// pulled policy, ignoring trailing whitespace differences. Missing local
// file is not drift.
func localPolicyHasDrift(path string, pulled []byte) (bool, error) {
	local, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	trim := func(b []byte) []byte { return bytes.TrimRight(b, " \t\r\n") }
	return !bytes.Equal(trim(local), trim(pulled)), nil
}
