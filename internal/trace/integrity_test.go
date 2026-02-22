package trace

import (
	"encoding/json"
	"testing"
)

func TestIntegrityChain_SealAndVerify(t *testing.T) {
	key := []byte("test-secret-key-32bytes-minimum!")

	events := []map[string]any{
		{"t": "run", "status": "start", "run": "R001"},
		{"t": "action", "target": "echo", "auth": "allow", "run": "R001"},
		{"t": "action", "target": "add", "auth": "deny", "run": "R001"},
		{"t": "run", "status": "end", "run": "R001"},
	}

	chain := NewIntegrityChain(key)
	var rawEvents []json.RawMessage

	for _, ev := range events {
		canonical, _ := json.Marshal(ev)
		hmacStr := chain.Seal(canonical)
		ev["hmac"] = hmacStr
		full, _ := json.Marshal(ev)
		rawEvents = append(rawEvents, full)
	}

	if err := VerifyChain(rawEvents, key); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

func TestIntegrityChain_DetectsTampering(t *testing.T) {
	key := []byte("test-secret-key-32bytes-minimum!")

	events := []map[string]any{
		{"t": "run", "status": "start", "run": "R001"},
		{"t": "action", "target": "echo", "auth": "allow", "run": "R001"},
		{"t": "action", "target": "shell", "auth": "deny", "run": "R001"},
	}

	chain := NewIntegrityChain(key)
	var rawEvents []json.RawMessage

	for _, ev := range events {
		canonical, _ := json.Marshal(ev)
		hmacStr := chain.Seal(canonical)
		ev["hmac"] = hmacStr
		full, _ := json.Marshal(ev)
		rawEvents = append(rawEvents, full)
	}

	tampered := map[string]any{
		"t": "action", "target": "echo", "auth": "deny", "run": "R001",
		"hmac": "",
	}
	var origEvent map[string]any
	json.Unmarshal(rawEvents[1], &origEvent)
	tampered["hmac"] = origEvent["hmac"]
	rawEvents[1], _ = json.Marshal(tampered)

	if err := VerifyChain(rawEvents, key); err == nil {
		t.Error("expected chain verification to fail after tampering")
	}
}

func TestIntegrityChain_DetectsInsertion(t *testing.T) {
	key := []byte("test-secret-key-32bytes-minimum!")

	events := []map[string]any{
		{"t": "run", "status": "start", "run": "R001"},
		{"t": "run", "status": "end", "run": "R001"},
	}

	chain := NewIntegrityChain(key)
	var rawEvents []json.RawMessage

	for _, ev := range events {
		canonical, _ := json.Marshal(ev)
		hmacStr := chain.Seal(canonical)
		ev["hmac"] = hmacStr
		full, _ := json.Marshal(ev)
		rawEvents = append(rawEvents, full)
	}

	fakeChain := NewIntegrityChain(key)
	fakeEv := map[string]any{"t": "action", "target": "shell_exec", "auth": "allow", "run": "R001"}
	fakeCanonical, _ := json.Marshal(fakeEv)
	fakeEv["hmac"] = fakeChain.Seal(fakeCanonical)
	fakeRaw, _ := json.Marshal(fakeEv)

	insertedEvents := make([]json.RawMessage, 3)
	insertedEvents[0] = rawEvents[0]
	insertedEvents[1] = fakeRaw
	insertedEvents[2] = rawEvents[1]

	if err := VerifyChain(insertedEvents, key); err == nil {
		t.Error("expected chain verification to fail after insertion")
	}
}

func TestIntegrityChain_DetectsDeletion(t *testing.T) {
	key := []byte("test-secret-key-32bytes-minimum!")

	events := []map[string]any{
		{"t": "run", "status": "start", "run": "R001"},
		{"t": "action", "target": "echo", "auth": "allow", "run": "R001"},
		{"t": "action", "target": "secret", "auth": "deny", "run": "R001"},
		{"t": "run", "status": "end", "run": "R001"},
	}

	chain := NewIntegrityChain(key)
	var rawEvents []json.RawMessage

	for _, ev := range events {
		canonical, _ := json.Marshal(ev)
		hmacStr := chain.Seal(canonical)
		ev["hmac"] = hmacStr
		full, _ := json.Marshal(ev)
		rawEvents = append(rawEvents, full)
	}

	deletedEvents := []json.RawMessage{rawEvents[0], rawEvents[1], rawEvents[3]}

	if err := VerifyChain(deletedEvents, key); err == nil {
		t.Error("expected chain verification to fail after deletion")
	}
}

func TestIntegrityChain_WrongKey(t *testing.T) {
	key1 := []byte("correct-key-for-signing-events!")
	key2 := []byte("wrong-key-used-for-verification")

	events := []map[string]any{
		{"t": "run", "status": "start", "run": "R001"},
	}

	chain := NewIntegrityChain(key1)
	var rawEvents []json.RawMessage

	for _, ev := range events {
		canonical, _ := json.Marshal(ev)
		hmacStr := chain.Seal(canonical)
		ev["hmac"] = hmacStr
		full, _ := json.Marshal(ev)
		rawEvents = append(rawEvents, full)
	}

	if err := VerifyChain(rawEvents, key2); err == nil {
		t.Error("expected chain verification to fail with wrong key")
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
	rawEvents := []json.RawMessage{
		json.RawMessage(`{"t":"run","status":"start"}`),
	}
	if err := VerifyChain(rawEvents, key); err == nil {
		t.Error("expected error for missing hmac field")
	}
}
