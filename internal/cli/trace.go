package cli

import "github.com/spf13/cobra"

// newTraceCmd returns the `relic trace` parent command.
// Subcommands (view, list, search) are registered here.
func newTraceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trace",
		Short: "Inspect and query .trtrace files",
	}

	cmd.AddCommand(newTraceViewCmd())
	cmd.AddCommand(newTraceListCmd())
	cmd.AddCommand(newTraceSearchCmd())
	cmd.AddCommand(newTraceVerifyCmd())
	cmd.AddCommand(newTracePushCmd())

	return cmd
}
