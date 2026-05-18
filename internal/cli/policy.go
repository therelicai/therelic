package cli

import (
	"fmt"
	"os"

	"github.com/therelicai/therelic/internal/config"
	"github.com/therelicai/therelic/internal/policy"
	"github.com/spf13/cobra"
)

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage The Relic authorization policies",
	}

	cmd.AddCommand(newPolicyInitCmd())
	cmd.AddCommand(newPolicyValidateCmd())
	cmd.AddCommand(newPolicyHistoryCmd())
	cmd.AddCommand(newPolicyPullCmd())
	cmd.AddCommand(newPolicySignCmd())
	cmd.AddCommand(newPolicyVerifyCmd())

	return cmd
}

// ---------------------------------------------------------------------------
// relic policy init
// ---------------------------------------------------------------------------

func newPolicyInitCmd() *cobra.Command {
	var flagForce bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a starter policy.yaml",
		Long: `Write a starter .tr/policy.yaml in permissive mode.

If the file already exists, use --force to overwrite it.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			paths := config.DefaultPaths()
			if err := os.MkdirAll(paths.Root, 0o755); err != nil {
				return fmt.Errorf("policy init: create %s: %w", paths.Root, err)
			}
			if err := writeIfAbsent(paths.PolicyFile, []byte(starterPolicy), flagForce); err != nil {
				return fmt.Errorf("policy init: write %s: %w", paths.PolicyFile, err)
			}
			if flagForce {
				fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s\n", paths.PolicyFile)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Created %s\n", paths.PolicyFile)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Run 'relic policy validate' to check syntax.\n")
			return nil
		},
	}

	cmd.Flags().BoolVar(&flagForce, "force", false, "Overwrite existing policy.yaml")
	return cmd
}

// ---------------------------------------------------------------------------
// relic policy validate
// ---------------------------------------------------------------------------

func newPolicyValidateCmd() *cobra.Command {
	var (
		flagPath   string
		flagStrict bool
	)

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Check policy.yaml for syntax and semantic errors",
		Long: `Parse and validate .tr/policy.yaml.

Exits 0 if the policy is valid, 1 if there are errors.
Use --strict to also flag permissive security settings.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if flagPath == "" {
				flagPath = config.DefaultPaths().PolicyFile
			}
			return runPolicyValidate(cmd.OutOrStdout(), cmd.ErrOrStderr(), flagPath, flagStrict)
		},
	}

	cmd.Flags().StringVar(&flagPath, "policy", "", "Path to policy file (default: .tr/policy.yaml)")
	cmd.Flags().BoolVar(&flagStrict, "strict", false, "Warn on insecure settings (e.g. default:allow in enforce mode)")
	return cmd
}

// ---------------------------------------------------------------------------
// relic policy history
// ---------------------------------------------------------------------------

func newPolicyHistoryCmd() *cobra.Command {
	var flagPath string

	cmd := &cobra.Command{
		Use:   "history",
		Short: "Show the append-only policy change log",
		Long: `Display the immutable history of policy changes recorded in .tr/policy.log.

Each entry includes a timestamp, action, policy hash, and actor.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if flagPath == "" {
				flagPath = config.DefaultPaths().HistoryFile
			}
			return runPolicyHistory(cmd.OutOrStdout(), cmd.ErrOrStderr(), flagPath)
		},
	}

	cmd.Flags().StringVar(&flagPath, "log", "", "Path to history log (default: .tr/policy.log)")
	return cmd
}

func runPolicyHistory(out, errOut interface{ Write([]byte) (int, error) }, logPath string) error {
	entries, err := policy.ReadHistory(logPath)
	if err != nil {
		fmt.Fprintf(errOut, "Error: %v\n", err)
		return &ExitError{Code: 1}
	}
	if len(entries) == 0 {
		fmt.Fprintf(out, "No policy history found in %s\n", logPath)
		return nil
	}

	for _, e := range entries {
		line := fmt.Sprintf("[%s] %s hash=%s", e.Timestamp, e.Action, e.PolicyHash)
		if e.Actor != "" {
			line += fmt.Sprintf(" actor=%s", e.Actor)
		}
		if e.Message != "" {
			line += fmt.Sprintf(" %s", e.Message)
		}
		fmt.Fprintln(out, line)
	}
	return nil
}

// runPolicyValidate is the core logic, separated for testing.
func runPolicyValidate(out, errOut interface{ Write([]byte) (int, error) }, path string, strict bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(errOut, "Error: cannot read %s: %v\n", path, err)
		return &ExitError{Code: 1}
	}

	p, err := policy.Parse(data)
	if err != nil {
		fmt.Fprintf(errOut, "Error: %s: invalid YAML: %v\n", path, err)
		return &ExitError{Code: 1}
	}

	errs := policy.Validate(p, strict)
	if len(errs) == 0 {
		fmt.Fprintf(out, "Policy valid: %s\n", path)
		return nil
	}

	fmt.Fprintf(errOut, "Policy has %d error(s) in %s:\n\n", len(errs), path)
	for _, e := range errs {
		fmt.Fprintf(errOut, "  - %s\n", e.Error())
	}
	return &ExitError{Code: 1}
}
