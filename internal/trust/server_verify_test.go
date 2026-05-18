package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/therelicai/therelic/internal/config"
)

func TestVerifyServer_NilIntegrity(t *testing.T) {
	r := VerifyServer("anything", nil)
	if !r.Verified {
		t.Fatalf("expected verified, got: %s", r.Reason)
	}
	if r.Reason != "no integrity config (unverified)" {
		t.Fatalf("unexpected reason: %s", r.Reason)
	}
}

func TestVerifyServer_EmptySHA256_NotRequired(t *testing.T) {
	r := VerifyServer("anything", &config.MCPServerIntegrity{Required: false})
	if !r.Verified {
		t.Fatalf("expected verified, got: %s", r.Reason)
	}
	if r.Reason != "no sha256 configured (unverified)" {
		t.Fatalf("unexpected reason: %s", r.Reason)
	}
}

func TestVerifyServer_EmptySHA256_Required(t *testing.T) {
	r := VerifyServer("anything", &config.MCPServerIntegrity{Required: true})
	if r.Verified {
		t.Fatal("expected not verified when required but no sha256")
	}
}

func TestVerifyServer_MatchingHash(t *testing.T) {
	tmp := writeTempExe(t, "hello-relic")
	h := sha256Hex(t, tmp)

	r := VerifyServer(tmp, &config.MCPServerIntegrity{SHA256: h})
	if !r.Verified {
		t.Fatalf("expected verified, got: %s (expected=%s actual=%s)", r.Reason, r.Expected, r.Actual)
	}
	if r.Actual != h {
		t.Fatalf("actual hash mismatch: got %s want %s", r.Actual, h)
	}
}

func TestVerifyServer_MismatchedHash(t *testing.T) {
	tmp := writeTempExe(t, "hello-relic")
	wrong := "deadbeef" + "00000000000000000000000000000000000000000000000000000000"

	r := VerifyServer(tmp, &config.MCPServerIntegrity{SHA256: wrong})
	if r.Verified {
		t.Fatal("expected not verified on hash mismatch")
	}
	if r.Reason != "sha256 mismatch" {
		t.Fatalf("unexpected reason: %s", r.Reason)
	}
	if r.Expected != wrong {
		t.Fatalf("expected field wrong: got %s", r.Expected)
	}
}

func TestVerifyServer_NonExistentCommand(t *testing.T) {
	r := VerifyServer("nonexistent-binary-xyz-42", &config.MCPServerIntegrity{
		SHA256:   "abc123",
		Required: true,
	})
	if r.Verified {
		t.Fatal("expected not verified for nonexistent command")
	}
}

func TestHashFile_KnownContent(t *testing.T) {
	content := []byte("The Relic governance framework\n")
	tmp := filepath.Join(t.TempDir(), "known.txt")
	if err := os.WriteFile(tmp, content, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := HashFile(tmp)
	if err != nil {
		t.Fatal(err)
	}

	want := sha256Hex(t, tmp)
	if got != want {
		t.Fatalf("HashFile got %s want %s", got, want)
	}

	// Double-check against manual computation.
	sum := sha256.Sum256(content)
	manual := hex.EncodeToString(sum[:])
	if got != manual {
		t.Fatalf("HashFile got %s want %s (manual)", got, manual)
	}
}

func TestHashFile_NonExistent(t *testing.T) {
	_, err := HashFile("/no/such/file/ever")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// writeTempExe creates a temp file with known content and returns its path.
func writeTempExe(t *testing.T, content string) string {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "test-exe")
	if err := os.WriteFile(tmp, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return tmp
}

// sha256Hex reads a file and returns its SHA-256 hex digest.
func sha256Hex(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
