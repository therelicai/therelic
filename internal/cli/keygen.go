package cli

import (
	"fmt"
	"path/filepath"

	"github.com/therelicai/therelic/internal/signing"
	"github.com/spf13/cobra"
)

func newKeygenCmd() *cobra.Command {
	var (
		flagDir  string
		flagName string
	)

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an ed25519 keypair for policy signing",
		Long: `Generate a new ed25519 keypair for cryptographic policy signing.

The private key (.key) is used to sign policies with 'relic policy sign'.
The public key (.pub) is distributed to agents for verification.

Store the private key securely — anyone with it can sign policies.
Distribute the public key to all systems that need to verify policies.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if flagDir == "" {
				flagDir = filepath.Join(".tr", "keys")
			}
			privPath, pubPath, err := signing.GenerateKeyPair(flagDir, flagName)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Private key: %s (keep secure!)\n", privPath)
			fmt.Fprintf(cmd.OutOrStdout(), "Public key:  %s (distribute to agents)\n", pubPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&flagDir, "dir", "", "Directory for keys (default: .tr/keys)")
	cmd.Flags().StringVar(&flagName, "name", "policy", "Key name prefix (default: policy)")
	return cmd
}
