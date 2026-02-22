package cli

import "github.com/spf13/cobra"

// NewRootCmd returns the root cobra command for the relic CLI.
func NewRootCmd(version string) *cobra.Command {
	root := &cobra.Command{
		Use:          "relic",
		Short:        "The Relic — authorization and audit for autonomous AI agents",
		Version:      version,
		SilenceErrors: true, // main.go handles error printing and os.Exit
	}

	root.AddCommand(newInitCmd())
	root.AddCommand(newRunCmd())
	root.AddCommand(newTraceCmd())
	root.AddCommand(newPolicyCmd())
	root.AddCommand(newProxyStdioCmd())
	root.AddCommand(newFingerprintCmd())
	root.AddCommand(newIdentityCmd())
	root.AddCommand(newKeygenCmd())

	return root
}
