package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/therelicai/therelic/internal/api"
	"github.com/therelicai/therelic/internal/config"
	"github.com/therelicai/therelic/internal/identity"
)

func newIdentityRegisterCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "register",
		Short:        "Register agent identity with The Relic platform",
		Long:         "Upload the local identity manifest to The Relic platform for agent registry and policy distribution.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := api.NewClientFromEnv()
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n\n", err)
				fmt.Fprintf(cmd.ErrOrStderr(), "To get started:\n")
				fmt.Fprintf(cmd.ErrOrStderr(), "  1. Sign up at https://therelic.dev\n")
				fmt.Fprintf(cmd.ErrOrStderr(), "  2. Create an API key in Settings\n")
				fmt.Fprintf(cmd.ErrOrStderr(), "  3. export RELIC_API_KEY=<your-key>\n")
				return err
			}

			paths := config.DefaultPaths()
			manifestPath := filepath.Join(paths.Root, "identity.json")

			manifest, err := identity.LoadManifest(manifestPath)
			if err != nil {
				return fmt.Errorf("load identity manifest: %w (run 'relic identity init' first)", err)
			}

			payload, err := json.Marshal(map[string]any{
				"name":              manifest.Agent.Name,
				"version":           manifest.Agent.Version,
				"identity_manifest": manifest,
				"capabilities_hash": manifest.CapabilitiesHash,
				"policy_hash":       manifest.PolicyHash,
			})
			if err != nil {
				return fmt.Errorf("marshal manifest: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Registering agent %s...\n", manifest.Agent.Name)

			if err := client.RegisterAgent(context.Background(), bytes.NewReader(payload)); err != nil {
				return fmt.Errorf("registration failed: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Agent %s registered with The Relic platform\n", manifest.Agent.Name)
			return nil
		},
	}
}
