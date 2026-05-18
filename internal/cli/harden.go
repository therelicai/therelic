package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/therelicai/therelic/internal/config"
	"github.com/therelicai/therelic/internal/policy"
)

type hardenCheck struct {
	ID          string
	Description string
	Check       func(p *policy.Policy) bool // returns true if issue found
	Fix         string
	Severity    string // "critical", "warning", "info"
}

type hardenResult struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Fix         string `json:"fix"`
}

type hardenReport struct {
	Policy  string         `json:"policy"`
	Mode    string         `json:"mode"`
	Default string         `json:"default"`
	Issues  []hardenResult `json:"issues"`
	Passed  int            `json:"passed"`
	Total   int            `json:"total"`
}

var hardenChecks = []hardenCheck{
	{
		ID:       "permissive-mode",
		Severity: "critical",
		Description: "Policy is in permissive mode. Denied actions are silently allowed.",
		Fix:      "Set mode: audit (or mode: enforce for production)",
		Check:    func(p *policy.Policy) bool { return p.Mode == "permissive" },
	},
	{
		ID:       "default-allow",
		Severity: "critical",
		Description: "Default action is 'allow'. Unrecognized tools pass without rules.",
		Fix:      "Set default: deny",
		Check:    func(p *policy.Policy) bool { return p.Default == "allow" },
	},
	{
		ID:       "no-rules",
		Severity: "warning",
		Description: "No authorization rules defined. All actions fall to the default.",
		Fix:      "Add rules for your agent's tools",
		Check:    func(p *policy.Policy) bool { return len(p.Rules) == 0 },
	},
	{
		ID:       "no-network-policy",
		Severity: "warning",
		Description: "No network policy (dns_allow/dns_deny). Agent can reach any host.",
		Fix:      "Add network.dns_allow to restrict outbound connections",
		Check: func(p *policy.Policy) bool {
			return len(p.Network.DNSAllow) == 0 && len(p.Network.DNSDeny) == 0
		},
	},
	{
		ID:       "no-filesystem-sandbox",
		Severity: "warning",
		Description: "Filesystem sandbox is disabled. Agent has full file access.",
		Fix:      "Enable filesystem with explicit mounts",
		Check:    func(p *policy.Policy) bool { return !p.Filesystem.Enabled },
	},
	{
		ID:       "no-exfiltration-guard",
		Severity: "warning",
		Description: "Exfiltration guard is not enabled. Outbound URLs are not inspected.",
		Fix:      "Enable exfiltration detection",
		Check:    func(p *policy.Policy) bool { return !p.Exfiltration.Enabled },
	},
	{
		ID:       "no-sequence-rules",
		Severity: "warning",
		Description: "No sequence detection rules. Multi-step attack chains are not monitored.",
		Fix:      "Add sequence rules",
		Check:    func(p *policy.Policy) bool { return len(p.Sequences.Rules) == 0 },
	},
	{
		ID:       "no-signature",
		Severity: "info",
		Description: "Policy signature is not required. Policy files can be modified without detection.",
		Fix:      "Set signature_required: true",
		Check:    func(p *policy.Policy) bool { return !p.SignatureRequired },
	},
	{
		ID:       "no-constraints",
		Severity: "info",
		Description: "No action/duration constraints. Agent can run indefinitely.",
		Fix:      "Set max_actions and max_duration_seconds",
		Check: func(p *policy.Policy) bool {
			return p.Constraints.MaxActions == 0 && p.Constraints.MaxDurationSeconds == 0
		},
	},
}

func newHardenCmd() *cobra.Command {
	var flagPolicy string
	var flagJSON bool

	cmd := &cobra.Command{
		Use:   "harden",
		Short: "Analyze policy and report security recommendations",
		Long: `Reads the policy file and checks for weak configurations.
Prints actionable security recommendations grouped by severity.

Exit code 0 if no critical issues are found, 1 otherwise.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if flagPolicy == "" {
				flagPolicy = config.DefaultPaths().PolicyFile
			}
			return runHarden(cmd.OutOrStdout(), flagPolicy, flagJSON)
		},
	}

	cmd.Flags().StringVar(&flagPolicy, "policy", "", "Path to policy file (default: .tr/policy.yaml)")
	cmd.Flags().BoolVar(&flagJSON, "json", false, "Output results as JSON")
	return cmd
}

func runHarden(out io.Writer, policyPath string, jsonOut bool) error {
	p, err := policy.Load(policyPath)
	if err != nil {
		return fmt.Errorf("harden: %w", err)
	}

	report := evaluate(p, policyPath)

	if jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	printReport(out, report)

	for _, issue := range report.Issues {
		if issue.Severity == "critical" {
			return fmt.Errorf("%d critical issue(s) found", countBySeverity(report.Issues, "critical"))
		}
	}
	return nil
}

func evaluate(p *policy.Policy, policyPath string) hardenReport {
	report := hardenReport{
		Policy:  policyPath,
		Mode:    p.Mode,
		Default: p.Default,
		Total:   len(hardenChecks),
	}

	for _, c := range hardenChecks {
		if c.Check(p) {
			report.Issues = append(report.Issues, hardenResult{
				ID:          c.ID,
				Severity:    c.Severity,
				Description: c.Description,
				Fix:         c.Fix,
			})
		}
	}

	report.Passed = report.Total - len(report.Issues)
	return report
}

func printReport(out io.Writer, r hardenReport) {
	fmt.Fprintf(out, "relic harden -- Security Analysis\n\n")
	fmt.Fprintf(out, "Policy: %s\n", r.Policy)
	fmt.Fprintf(out, "Mode: %s | Default: %s\n\n", r.Mode, r.Default)

	printed := false
	for _, sev := range []struct {
		key    string
		header string
	}{
		{"critical", "[CRITICAL]"},
		{"warning", "[WARNING]"},
		{"info", "[INFO]"},
	} {
		issues := filterBySeverity(r.Issues, sev.key)
		if len(issues) == 0 {
			continue
		}
		printed = true
		fmt.Fprintf(out, "%s\n", sev.header)
		for _, issue := range issues {
			fmt.Fprintf(out, "  [%s] %s\n", issue.ID, issue.Description)
			fmt.Fprintf(out, "    Fix: %s\n", issue.Fix)
		}
		fmt.Fprintln(out)
	}

	if !printed {
		fmt.Fprintln(out, "No issues found. Policy is well-hardened.")
		fmt.Fprintln(out)
	}

	fmt.Fprintf(out, "Score: %d/%d checks passed\n", r.Passed, r.Total)
}

func filterBySeverity(issues []hardenResult, severity string) []hardenResult {
	var out []hardenResult
	for _, issue := range issues {
		if issue.Severity == severity {
			out = append(out, issue)
		}
	}
	return out
}

func countBySeverity(issues []hardenResult, severity string) int {
	n := 0
	for _, issue := range issues {
		if issue.Severity == severity {
			n++
		}
	}
	return n
}
