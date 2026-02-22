package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeyLength(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(key))
	}
}

func TestGenerateKeyUniqueness(t *testing.T) {
	k1, _ := GenerateKey()
	k2, _ := GenerateKey()
	if string(k1) == string(k2) {
		t.Fatal("two generated keys should not be identical")
	}
}

func TestSaveLoadKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")

	key, _ := GenerateKey()
	if err := SaveKey(path, key); err != nil {
		t.Fatalf("SaveKey: %v", err)
	}

	loaded, err := LoadKey(path)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}

	if string(key) != string(loaded) {
		t.Fatal("round-tripped key does not match original")
	}
}

func TestKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")

	key, _ := GenerateKey()
	if err := SaveKey(path, key); err != nil {
		t.Fatalf("SaveKey: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Fatalf("expected permissions 0600, got %04o", perm)
	}
}

func TestCreateAndVerifyManifest(t *testing.T) {
	key, _ := GenerateKey()
	m := CreateManifest(key, "test-agent", "1.0.0", "cap-hash", "pol-hash")

	if !VerifyManifest(key, m) {
		t.Fatal("VerifyManifest should pass for a freshly created manifest")
	}
}

func TestTamperAgentName(t *testing.T) {
	key, _ := GenerateKey()
	m := CreateManifest(key, "test-agent", "1.0.0", "", "")

	m.Agent.Name = "evil-agent"
	if VerifyManifest(key, m) {
		t.Fatal("VerifyManifest should fail after tampering with agent name")
	}
}

func TestTamperCapabilitiesHash(t *testing.T) {
	key, _ := GenerateKey()
	m := CreateManifest(key, "test-agent", "1.0.0", "original-cap", "")

	m.CapabilitiesHash = "tampered-cap"
	if VerifyManifest(key, m) {
		t.Fatal("VerifyManifest should fail after tampering with capabilities hash")
	}
}

func TestTamperPolicyHash(t *testing.T) {
	key, _ := GenerateKey()
	m := CreateManifest(key, "test-agent", "1.0.0", "", "original-pol")

	m.PolicyHash = "tampered-pol"
	if VerifyManifest(key, m) {
		t.Fatal("VerifyManifest should fail after tampering with policy hash")
	}
}

func TestSignatureDeterministic(t *testing.T) {
	key, _ := GenerateKey()

	m1 := &AgentIdentityManifest{
		Version:   "1",
		CreatedAt: "2025-01-01T00:00:00Z",
		Agent: AgentInfo{
			Name:        "agent",
			Version:     "1.0",
			Fingerprint: computeFingerprint(key),
			SignedBy:    "hmac-sha256",
		},
	}
	m2 := &AgentIdentityManifest{
		Version:   "1",
		CreatedAt: "2025-01-01T00:00:00Z",
		Agent: AgentInfo{
			Name:        "agent",
			Version:     "1.0",
			Fingerprint: computeFingerprint(key),
			SignedBy:    "hmac-sha256",
		},
	}

	sig1 := sign(key, m1)
	sig2 := sign(key, m2)

	if sig1 != sig2 {
		t.Fatalf("signatures should be deterministic for identical input: %s != %s", sig1, sig2)
	}
}

func TestFingerprintDeterministic(t *testing.T) {
	key, _ := GenerateKey()
	fp1 := computeFingerprint(key)
	fp2 := computeFingerprint(key)
	if fp1 != fp2 {
		t.Fatalf("fingerprint should be deterministic: %s != %s", fp1, fp2)
	}
}

func TestSaveLoadManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	key, _ := GenerateKey()
	m := CreateManifest(key, "round-trip-agent", "2.0", "cap123", "pol456")

	if err := SaveManifest(path, m); err != nil {
		t.Fatalf("SaveManifest: %v", err)
	}

	loaded, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}

	if !VerifyManifest(key, loaded) {
		t.Fatal("loaded manifest should verify against the original key")
	}
	if loaded.Agent.Name != "round-trip-agent" {
		t.Fatalf("expected agent name round-trip-agent, got %s", loaded.Agent.Name)
	}
}

func TestWrongKeyFailsVerify(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	m := CreateManifest(key1, "agent", "1.0", "", "")
	if VerifyManifest(key2, m) {
		t.Fatal("VerifyManifest should fail with a different key")
	}
}
