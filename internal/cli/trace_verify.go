package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/therelicai/therelic/internal/trace"
)

func newTraceVerifyCmd() *cobra.Command {
	var flagKey string

	cmd := &cobra.Command{
		Use:   "verify <trace-file>",
		Short: "Verify the integrity of a trace file's HMAC chain",
		Long: `Verify that a .trtrace file hasn't been tampered with.

This checks the HMAC chain embedded in trace events. Any modification,
insertion, or deletion of events will break the chain and be detected.

Requires the HMAC key that was used when the trace was created.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			tracePath := args[0]
			raw, err := os.ReadFile(tracePath)
			if err != nil {
				return fmt.Errorf("read trace: %w", err)
			}

			lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
			var events []json.RawMessage
			for _, line := range lines {
				if line == "" {
					continue
				}
				events = append(events, json.RawMessage(line))
			}

			if len(events) == 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "WARN: trace file is empty\n")
				return nil
			}

			var firstEvent map[string]json.RawMessage
			if err := json.Unmarshal(events[0], &firstEvent); err == nil {
				if _, hasHMAC := firstEvent["hmac"]; !hasHMAC {
					fmt.Fprintf(cmd.OutOrStdout(), "INFO: trace has no HMAC chain (created without integrity protection)\n")
					fmt.Fprintf(cmd.OutOrStdout(), "Events: %d\n", len(events))
					return nil
				}
			}

			// --key takes a hex-encoded HMAC secret per the flag help.
			// Previously we used the hex string literal as the key,
			// which made every verify succeed against a trace sealed
			// with the actual raw bytes — silently breaking the entire
			// integrity guarantee. Decode here so the bytes match the
			// runtime's IntegrityChain key.
			key, err := hex.DecodeString(strings.TrimSpace(flagKey))
			if err != nil {
				return fmt.Errorf("--key must be a hex-encoded HMAC secret: %w", err)
			}
			if err := trace.VerifyChain(events, key); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "FAILED: %v\n", err)
				return &ExitError{Code: 1}
			}

			fmt.Fprintf(cmd.OutOrStdout(), "VERIFIED: %s — all %d events have valid HMAC chain\n", tracePath, len(events))
			return nil
		},
	}

	cmd.Flags().StringVar(&flagKey, "key", "", "HMAC key (hex-encoded) used for trace integrity")
	cmd.MarkFlagRequired("key") //nolint:errcheck
	return cmd
}
