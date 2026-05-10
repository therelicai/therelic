package cli

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// traceMasterSecretEnv is the env var that turns on tamper-evident
// trace sealing. The value is a hex-encoded master secret (32+ bytes
// recommended). Per-run keys are derived from this secret + runID so
// the platform can verify each upload without the runtime shipping
// raw keys over the wire.
const traceMasterSecretEnv = "RELIC_TRACE_KEY"

// loadTraceMasterSecret reads the trace master secret from the
// environment and returns the decoded bytes. Returns nil when sealing
// is disabled (env var unset or empty), which the writer treats as
// "skip the HMAC chain".
//
// errW receives a one-line stderr warning when the env var is set but
// can't be decoded — we don't want to silently fail open in that case,
// but we also don't want to crash the agent if a user typo'd a hex
// string. Returning nil + warning splits the difference.
func loadTraceMasterSecret(errW io.Writer) []byte {
	raw := strings.TrimSpace(os.Getenv(traceMasterSecretEnv))
	if raw == "" {
		return nil
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		fmt.Fprintf(errW, "relic: warning: %s is not valid hex (%v) — trace sealing disabled\n", traceMasterSecretEnv, err)
		return nil
	}
	if len(key) < 16 {
		fmt.Fprintf(errW, "relic: warning: %s is shorter than 16 bytes — trace sealing disabled\n", traceMasterSecretEnv)
		return nil
	}
	return key
}
