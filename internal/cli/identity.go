package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/therelicai/therelic/internal/config"
	"github.com/therelicai/therelic/internal/identity"
)

func newIdentityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Manage agent identity manifests",
	}
	cmd.AddCommand(newIdentityInitCmd())
	cmd.AddCommand(newIdentityVerifyCmd())
	cmd.AddCommand(newIdentityShowCmd())
	cmd.AddCommand(newIdentityRegisterCmd())
	return cmd
}

func newIdentityInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "init",
		Short:        "Generate identity key and signed manifest",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			paths := config.DefaultPaths()
			keyPath := filepath.Join(paths.Root, "identity.key")
			manifestPath := filepath.Join(paths.Root, "identity.json")

			key, err := identity.GenerateKey()
			if err != nil {
				return err
			}
			if err := identity.SaveKey(keyPath, key); err != nil {
				return err
			}

			agentName, agentVersion := "unknown", ""
			if p, err := config.LoadPolicy(paths.PolicyFile); err == nil {
				agentName = p.Agent.Name
				agentVersion = p.Agent.Version
			}

			m := identity.CreateManifest(key, agentName, agentVersion, "", "")
			if err := identity.SaveManifest(manifestPath, m); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Identity initialized:\n")
			fmt.Fprintf(cmd.OutOrStdout(), "  Key:         %s\n", keyPath)
			fmt.Fprintf(cmd.OutOrStdout(), "  Manifest:    %s\n", manifestPath)
			fmt.Fprintf(cmd.OutOrStdout(), "  Agent:       %s\n", agentName)
			fmt.Fprintf(cmd.OutOrStdout(), "  Fingerprint: %s\n", m.Agent.Fingerprint)
			return nil
		},
	}
}

func newIdentityVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "verify",
		Short:        "Verify the current identity manifest",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			paths := config.DefaultPaths()
			keyPath := filepath.Join(paths.Root, "identity.key")
			manifestPath := filepath.Join(paths.Root, "identity.json")

			key, err := identity.LoadKey(keyPath)
			if err != nil {
				return fmt.Errorf("load key: %w", err)
			}

			m, err := identity.LoadManifest(manifestPath)
			if err != nil {
				return fmt.Errorf("load manifest: %w", err)
			}

			if !identity.VerifyManifest(key, m) {
				fmt.Fprintf(cmd.OutOrStdout(), "FAIL: manifest signature is invalid\n")
				return fmt.Errorf("identity verification failed")
			}

			fmt.Fprintf(cmd.OutOrStdout(), "OK: identity manifest is valid\n")
			fmt.Fprintf(cmd.OutOrStdout(), "  Agent:       %s %s\n", m.Agent.Name, m.Agent.Version)
			fmt.Fprintf(cmd.OutOrStdout(), "  Fingerprint: %s\n", m.Agent.Fingerprint)
			return nil
		},
	}
}

func newIdentityShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "show",
		Short:        "Display identity manifest details",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			paths := config.DefaultPaths()
			manifestPath := filepath.Join(paths.Root, "identity.json")

			m, err := identity.LoadManifest(manifestPath)
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Agent Identity Manifest\n")
			fmt.Fprintf(cmd.OutOrStdout(), "  Version:          %s\n", m.Version)
			fmt.Fprintf(cmd.OutOrStdout(), "  Agent:            %s %s\n", m.Agent.Name, m.Agent.Version)
			fmt.Fprintf(cmd.OutOrStdout(), "  Fingerprint:      %s\n", m.Agent.Fingerprint)
			fmt.Fprintf(cmd.OutOrStdout(), "  Signed By:        %s\n", m.Agent.SignedBy)
			fmt.Fprintf(cmd.OutOrStdout(), "  Created:          %s\n", m.CreatedAt)
			if m.CapabilitiesHash != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "  Capabilities Hash: %s\n", m.CapabilitiesHash)
			}
			if m.PolicyHash != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "  Policy Hash:       %s\n", m.PolicyHash)
			}
			return nil
		},
	}
}
