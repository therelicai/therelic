package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/therelicai/therelic/internal/config"
	"github.com/therelicai/therelic/internal/fingerprint"

	"github.com/spf13/cobra"
)

func newFingerprintCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Generate or compare agent capability fingerprints",
		Long: `Profile the agent's tool surface and detect changes between runs.

On first run, generates .tr/capabilities.json with a hash of all available tools.
On subsequent runs, compares with the existing manifest and reports changes.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			paths := config.DefaultPaths()
			capPath := filepath.Join(paths.Root, "capabilities.json")
			return runFingerprint(cmd.OutOrStdout(), capPath)
		},
	}
	return cmd
}

func runFingerprint(out interface{ Write([]byte) (int, error) }, capPath string) error {
	existing, err := fingerprint.LoadManifest(capPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if existing == nil {
		m := &fingerprint.Manifest{
			Version:      "1",
			Capabilities: []fingerprint.Capability{},
			Hash:         fingerprint.CapabilitiesHash(nil),
			GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		}
		if err := fingerprint.SaveManifest(capPath, m); err != nil {
			return err
		}
		fmt.Fprintf(out, "Created %s (hash: %s)\n", capPath, m.Hash)
		fmt.Fprintf(out, "Run your agent once to populate capabilities, then run fingerprint again.\n")
		return nil
	}

	fmt.Fprintf(out, "Capabilities manifest: %s\n", capPath)
	fmt.Fprintf(out, "  Hash:       %s\n", existing.Hash)
	fmt.Fprintf(out, "  Generated:  %s\n", existing.GeneratedAt)
	fmt.Fprintf(out, "  Tools:      %d\n", len(existing.Capabilities))

	if len(existing.Capabilities) > 0 {
		data, _ := json.MarshalIndent(existing.Capabilities, "  ", "  ")
		fmt.Fprintf(out, "  Capabilities:\n  %s\n", data)
	}

	return nil
}
