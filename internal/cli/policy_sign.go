package cli

import (
	"fmt"

	"github.com/therelicai/therelic/internal/config"
	"github.com/therelicai/therelic/internal/signing"
	"github.com/spf13/cobra"
)

func newPolicySignCmd() *cobra.Command {
	var flagKey string

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Cryptographically sign a policy file",
		Long: `Sign .tr/policy.yaml using an ed25519 private key.

Creates a detached signature file (policy.yaml.sig) alongside the policy.
Use 'relic keygen' to generate a keypair first.

In zero-trust mode (signature_required: true in the policy), agents will
reject any policy that doesn't have a valid signature.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			policyPath := config.DefaultPaths().PolicyFile
			sigPath, err := signing.SignFile(policyPath, flagKey)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Signed: %s\n", policyPath)
			fmt.Fprintf(cmd.OutOrStdout(), "Signature: %s\n", sigPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&flagKey, "key", "", "Path to ed25519 private key (required)")
	cmd.MarkFlagRequired("key") //nolint:errcheck
	return cmd
}

func newPolicyVerifyCmd() *cobra.Command {
	var flagPubKey string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a policy file's cryptographic signature",
		Long: `Verify that .tr/policy.yaml has a valid ed25519 signature.

This checks:
  1. The .sig file exists alongside the policy
  2. The signature was made by the holder of the corresponding private key
  3. The policy content hasn't been modified since signing

If verification fails, the policy may have been tampered with.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			policyPath := config.DefaultPaths().PolicyFile
			if err := signing.VerifyFile(policyPath, flagPubKey); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "FAILED: %v\n", err)
				return &ExitError{Code: 1}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "VERIFIED: %s has a valid signature\n", policyPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&flagPubKey, "pubkey", "", "Path to ed25519 public key (required)")
	cmd.MarkFlagRequired("pubkey") //nolint:errcheck
	return cmd
}
