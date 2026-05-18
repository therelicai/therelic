package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/therelicai/therelic/internal/config"
)

// VerifyResult is the outcome of a server integrity check.
type VerifyResult struct {
	Verified bool
	Reason   string
	Expected string
	Actual   string
}

// VerifyServer checks the integrity of an MCP server executable.
// It resolves the command to a full path, hashes it, and compares against
// the expected digest in the integrity config.
func VerifyServer(command string, integrity *config.MCPServerIntegrity) VerifyResult {
	if integrity == nil {
		return VerifyResult{Verified: true, Reason: "no integrity config (unverified)"}
	}

	if integrity.SHA256 == "" {
		if integrity.Required {
			return VerifyResult{
				Verified: false,
				Reason:   "integrity required but no sha256 configured",
			}
		}
		return VerifyResult{Verified: true, Reason: "no sha256 configured (unverified)"}
	}

	path, err := exec.LookPath(command)
	if err != nil {
		return VerifyResult{
			Verified: false,
			Reason:   fmt.Sprintf("resolve command %q: %v", command, err),
			Expected: integrity.SHA256,
		}
	}

	actual, err := HashFile(path)
	if err != nil {
		return VerifyResult{
			Verified: false,
			Reason:   fmt.Sprintf("hash %q: %v", path, err),
			Expected: integrity.SHA256,
		}
	}

	if actual != integrity.SHA256 {
		return VerifyResult{
			Verified: false,
			Reason:   "sha256 mismatch",
			Expected: integrity.SHA256,
			Actual:   actual,
		}
	}

	return VerifyResult{
		Verified: true,
		Reason:   "sha256 match",
		Expected: integrity.SHA256,
		Actual:   actual,
	}
}

// HashFile computes the SHA-256 hex digest of the file at path.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
