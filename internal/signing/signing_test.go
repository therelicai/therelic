package signing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath, err := GenerateKeyPair(dir, "test")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if _, err := os.Stat(privPath); err != nil {
		t.Errorf("private key not found: %v", err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Errorf("public key not found: %v", err)
	}

	info, _ := os.Stat(privPath)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("private key permissions: %o, want 0600", info.Mode().Perm())
	}
}

func TestSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath, err := GenerateKeyPair(dir, "test")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	data := []byte("version: 1\nagent:\n  name: test\n")
	sig, err := Sign(data, privPath)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("signature length: %d, want 64", len(sig))
	}

	if err := Verify(data, sig, pubPath); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_TamperedData(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath, _ := GenerateKeyPair(dir, "test")

	data := []byte("original policy content")
	sig, _ := Sign(data, privPath)

	tampered := []byte("tampered policy content")
	if err := Verify(tampered, sig, pubPath); err == nil {
		t.Error("expected verification failure for tampered data")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	dir := t.TempDir()
	privPath1, _, _ := GenerateKeyPair(dir, "key1")
	_, pubPath2, _ := GenerateKeyPair(dir, "key2")

	data := []byte("policy content")
	sig, _ := Sign(data, privPath1)

	if err := Verify(data, sig, pubPath2); err == nil {
		t.Error("expected verification failure with wrong public key")
	}
}

func TestSignFile_VerifyFile(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath, _ := GenerateKeyPair(dir, "test")

	policyPath := filepath.Join(dir, "policy.yaml")
	content := []byte("version: \"1\"\nagent:\n  name: banking-agent\nmode: enforce\ndefault: deny\n")
	os.WriteFile(policyPath, content, 0o644)

	sigPath, err := SignFile(policyPath, privPath)
	if err != nil {
		t.Fatalf("SignFile: %v", err)
	}
	if sigPath != policyPath+".sig" {
		t.Errorf("sigPath: %q, want %q", sigPath, policyPath+".sig")
	}

	if err := VerifyFile(policyPath, pubPath); err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
}

func TestVerifyFile_TamperedPolicy(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath, _ := GenerateKeyPair(dir, "test")

	policyPath := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyPath, []byte("original"), 0o644)
	SignFile(policyPath, privPath)

	os.WriteFile(policyPath, []byte("tampered — default: allow"), 0o644)

	if err := VerifyFile(policyPath, pubPath); err == nil {
		t.Error("expected verification failure for tampered policy file")
	}
}

func TestVerifyFile_MissingSignature(t *testing.T) {
	dir := t.TempDir()
	_, pubPath, _ := GenerateKeyPair(dir, "test")

	policyPath := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyPath, []byte("unsigned policy"), 0o644)

	if err := VerifyFile(policyPath, pubPath); err == nil {
		t.Error("expected error for unsigned policy")
	}
}

func TestLoadPrivateKey_InvalidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.key")
	os.WriteFile(path, []byte("not a pem file"), 0o600)

	if _, err := LoadPrivateKey(path); err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestLoadPublicKey_InvalidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pub")
	os.WriteFile(path, []byte("not a pem file"), 0o644)

	if _, err := LoadPublicKey(path); err == nil {
		t.Error("expected error for invalid PEM")
	}
}
