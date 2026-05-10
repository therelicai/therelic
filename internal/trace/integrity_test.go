package trace

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// sealForTest is the test surface for the writer-side sealing logic.
// We reuse sealEventLine directly so the tests verify the exact bytes
// the runtime will produce — anything that splits the writer and the
// verifier into separate canonicalisation paths is the bug we just
// fixed and we don't want to reintroduce it.
func sealForTest(t *testing.T, chain *IntegrityChain, obj map[string]any) []byte {
	t.Helper()
	canonical, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sealed, err := sealEventLine(chain, canonical)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return sealed
}

func TestIntegrityChain_SealAndVerify(t *testing.T) {
	key := []byte("test-secret-key-32bytes-minimum!")
	chain := NewIntegrityChain(key)

	events := []map[string]any{
		{"t": "run", "status": "start", "run": "R001"},
		{"t": "action", "target": "echo", "auth": "allow", "run": "R001"},
		{"t": "action", "target": "add", "auth": "deny", "run": "R001"},
		{"t": "run", "status": "end", "run": "R001"},
	}
	var raw [][]byte
	for _, ev := range events {
		raw = append(raw, sealForTest(t, chain, ev))
	}
	if err := VerifyChain(raw, key); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

func TestIntegrityChain_DetectsTampering(t *testing.T) {
	key := []byte("test-secret-key-32bytes-minimum!")
	chain := NewIntegrityChain(key)

	raw := [][]byte{
		sealForTest(t, chain, map[string]any{"t": "run", "status": "start", "run": "R001"}),
		sealForTest(t, chain, map[string]any{"t": "action", "target": "echo", "auth": "allow", "run": "R001"}),
		sealForTest(t, chain, map[string]any{"t": "action", "target": "shell", "auth": "deny", "run": "R001"}),
	}

	// Swap "allow" → "deny" on event 1 while keeping the existing MAC.
	raw[1] = []byte(strings.Replace(string(raw[1]), `"auth":"allow"`, `"auth":"deny"`, 1))

	err := VerifyChain(raw, key)
	if err == nil {
		t.Fatal("expected chain verification to fail after tampering")
	}
	if !errors.Is(err, ErrChainMismatch) {
		t.Fatalf("expected ErrChainMismatch, got %v", err)
	}
}

func TestIntegrityChain_DetectsInsertion(t *testing.T) {
	key := []byte("test-secret-key-32bytes-minimum!")
	chain := NewIntegrityChain(key)

	start := sealForTest(t, chain, map[string]any{"t": "run", "status": "start", "run": "R001"})
	end := sealForTest(t, chain, map[string]any{"t": "run", "status": "end", "run": "R001"})

	// Forge a "valid-looking" event sealed against a clean chain — it
	// would pass on its own but not when spliced into a real chain
	// because the prevHMAC at insertion time won't match.
	fakeChain := NewIntegrityChain(key)
	fakeEv := sealForTest(t, fakeChain, map[string]any{"t": "action", "target": "shell_exec", "auth": "allow", "run": "R001"})

	inserted := [][]byte{start, fakeEv, end}
	if err := VerifyChain(inserted, key); err == nil {
		t.Fatal("expected chain verification to fail after insertion")
	}
}

func TestIntegrityChain_DetectsDeletion(t *testing.T) {
	key := []byte("test-secret-key-32bytes-minimum!")
	chain := NewIntegrityChain(key)

	raw := [][]byte{
		sealForTest(t, chain, map[string]any{"t": "run", "status": "start", "run": "R001"}),
		sealForTest(t, chain, map[string]any{"t": "action", "target": "echo", "auth": "allow", "run": "R001"}),
		sealForTest(t, chain, map[string]any{"t": "action", "target": "secret", "auth": "deny", "run": "R001"}),
		sealForTest(t, chain, map[string]any{"t": "run", "status": "end", "run": "R001"}),
	}

	deleted := [][]byte{raw[0], raw[1], raw[3]}
	if err := VerifyChain(deleted, key); err == nil {
		t.Fatal("expected chain verification to fail after deletion")
	}
}

func TestIntegrityChain_WrongKey(t *testing.T) {
	key1 := []byte("correct-key-for-signing-events!")
	key2 := []byte("wrong-key-used-for-verification")
	chain := NewIntegrityChain(key1)

	raw := [][]byte{
		sealForTest(t, chain, map[string]any{"t": "run", "status": "start", "run": "R001"}),
	}
	if err := VerifyChain(raw, key2); err == nil {
		t.Fatal("expected chain verification to fail with wrong key")
	}
}

func TestGenerateChainKey_Deterministic(t *testing.T) {
	secret := []byte("master-secret")
	k1 := GenerateChainKey("run-001", secret)
	k2 := GenerateChainKey("run-001", secret)
	k3 := GenerateChainKey("run-002", secret)

	if string(k1) != string(k2) {
		t.Error("same inputs should produce same key")
	}
	if string(k1) == string(k3) {
		t.Error("different run IDs should produce different keys")
	}
}

func TestIntegrityChain_MissingHMACField(t *testing.T) {
	key := []byte("test-key")
	raw := [][]byte{
		[]byte(`{"t":"run","status":"start"}`),
	}
	err := VerifyChain(raw, key)
	if err == nil {
		t.Fatal("expected error for missing hmac field")
	}
	if !errors.Is(err, ErrMissingHMAC) {
		t.Fatalf("expected ErrMissingHMAC, got %v", err)
	}
}

// TestIntegrityChain_StructFieldOrder regression-tests the bug that
// the previous VerifyChain implementation hid: when the writer emits
// a struct (RunEvent) whose JSON field order isn't alphabetical, the
// old map-based VerifyChain would re-marshal the keys in sorted order
// and recompute a different HMAC. The new VerifyChain extracts the
// canonical bytes directly so any struct order works.
func TestIntegrityChain_StructFieldOrder(t *testing.T) {
	key := []byte("test-secret-key")
	chain := NewIntegrityChain(key)

	exit := 0
	dur := 42
	total, allowed, denied := 5, 4, 1
	ev := RunEvent{
		V:              1,
		T:              "run",
		TS:             "2024-01-01T00:00:00Z",
		Run:            "R001",
		Status:         "end",
		Exit:           &exit,
		DurationMs:     &dur,
		ActionsTotal:   &total,
		ActionsAllowed: &allowed,
		ActionsDenied:  &denied,
	}
	canonical, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal RunEvent: %v", err)
	}
	sealed, err := sealEventLine(chain, canonical)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := VerifyChain([][]byte{sealed}, key); err != nil {
		t.Fatalf("VerifyChain over struct-marshalled event: %v", err)
	}
}

func TestSplitSealedLine_Malformed(t *testing.T) {
	cases := map[string]string{
		"not-object":          `"hello"`,
		"unterminated":        `{"t":"run","hmac":"abc`,
		"missing-hmac":        `{"t":"run","other":"x"}`,
		"non-hex-mac":         `{"t":"run","hmac":"not-hex!"}`,
		"empty-with-no-hmac":  `{}`,
		"empty-object-w-hmac": `{"hmac":"deadbeef"}`,
	}
	for name, in := range cases {
		_, _, err := splitSealedLine([]byte(in))
		if name == "empty-object-w-hmac" {
			if err != nil {
				t.Errorf("case %q: expected success, got %v", name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("case %q: expected error, got nil", name)
		}
	}
}
