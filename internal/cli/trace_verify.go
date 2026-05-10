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
	var flagPerRun bool

	cmd := &cobra.Command{
		Use:   "verify <trace-file>",
		Short: "Verify the integrity of a trace file's HMAC chain",
		Long: `Verify that a .trtrace file hasn't been tampered with.

This checks the HMAC chain embedded in trace events. Any modification,
insertion, or deletion of events will break the chain and be detected.

By default --key is treated as the trace master secret (hex-encoded) and
the per-run verification key is derived from the run ID found in the
trace. Pass --raw-key if you already have the per-run key in hand.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			tracePath := args[0]
			raw, err := os.ReadFile(tracePath)
			if err != nil {
				return fmt.Errorf("read trace: %w", err)
			}

			lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
			eventLines := make([][]byte, 0, len(lines))
			for _, line := range lines {
				if line == "" {
					continue
				}
				eventLines = append(eventLines, []byte(line))
			}

			if len(eventLines) == 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "WARN: trace file is empty\n")
				return nil
			}

			var firstEvent map[string]json.RawMessage
			if err := json.Unmarshal(eventLines[0], &firstEvent); err != nil {
				return fmt.Errorf("parse first event: %w", err)
			}
			if _, hasHMAC := firstEvent["hmac"]; !hasHMAC {
				fmt.Fprintf(cmd.OutOrStdout(), "INFO: trace has no HMAC chain (created without integrity protection)\n")
				fmt.Fprintf(cmd.OutOrStdout(), "Events: %d\n", len(eventLines))
				return nil
			}

			master, err := hex.DecodeString(strings.TrimSpace(flagKey))
			if err != nil {
				return fmt.Errorf("--key must be a hex-encoded HMAC secret: %w", err)
			}

			key := master
			if !flagPerRun {
				// Derive the per-run key the same way the writer does:
				// HMAC(master, "relic-trace-chain-v1:" + runID). Without
				// this step a master-secret verify would always fail,
				// which is the failure mode this flag was added to
				// prevent.
				var runIDRaw string
				if rid, ok := firstEvent["run"]; ok {
					_ = json.Unmarshal(rid, &runIDRaw)
				}
				if runIDRaw == "" {
					return fmt.Errorf("trace first event missing run id; pass --raw-key if you have the per-run key directly")
				}
				key = trace.GenerateChainKey(runIDRaw, master)
			}

			if err := trace.VerifyChain(eventLines, key); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "FAILED: %v\n", err)
				return &ExitError{Code: 1}
			}

			fmt.Fprintf(cmd.OutOrStdout(), "VERIFIED: %s — all %d events have valid HMAC chain\n", tracePath, len(eventLines))
			return nil
		},
	}

	cmd.Flags().StringVar(&flagKey, "key", "", "Trace master secret (hex-encoded); per-run key derived from run id unless --raw-key is set")
	cmd.Flags().BoolVar(&flagPerRun, "raw-key", false, "Treat --key as the already-derived per-run HMAC key (skip derivation)")
	cmd.MarkFlagRequired("key") //nolint:errcheck
	return cmd
}
