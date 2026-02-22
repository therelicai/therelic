package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyHash_Deterministic(t *testing.T) {
	data := []byte("version: 1\nmode: enforce\n")
	h1 := PolicyHash(data)
	h2 := PolicyHash(data)
	if h1 != h2 {
		t.Errorf("PolicyHash not deterministic: %s != %s", h1, h2)
	}
	if len(h1) != 16 {
		t.Errorf("expected 16 hex chars, got %d: %s", len(h1), h1)
	}
}

func TestPolicyHash_DifferentInputs(t *testing.T) {
	h1 := PolicyHash([]byte("aaa"))
	h2 := PolicyHash([]byte("bbb"))
	if h1 == h2 {
		t.Error("different inputs produced same hash")
	}
}

func TestAppendHistory_CreatesFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "policy.log")

	err := AppendHistory(logPath, HistoryEntry{
		Action:     "create",
		PolicyHash: "abc123",
		Actor:      "cli",
		Message:    "test entry",
	})
	if err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), `"action":"create"`) {
		t.Errorf("log missing action field: %s", data)
	}
	if !strings.Contains(string(data), `"policy_hash":"abc123"`) {
		t.Errorf("log missing policy_hash field: %s", data)
	}
}

func TestAppendHistory_SetsTimestamp(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "policy.log")

	err := AppendHistory(logPath, HistoryEntry{
		Action:     "update",
		PolicyHash: "def456",
	})
	if err != nil {
		t.Fatalf("AppendHistory: %v", err)
	}

	entries, err := ReadHistory(logPath)
	if err != nil {
		t.Fatalf("ReadHistory: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Timestamp == "" {
		t.Error("expected auto-set timestamp, got empty string")
	}
}

func TestAppendHistory_PreservesExplicitTimestamp(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "policy.log")
	ts := "2025-01-01T00:00:00Z"

	AppendHistory(logPath, HistoryEntry{
		Timestamp:  ts,
		Action:     "validate",
		PolicyHash: "abc",
	})

	entries, _ := ReadHistory(logPath)
	if len(entries) != 1 || entries[0].Timestamp != ts {
		t.Errorf("expected timestamp %s, got %v", ts, entries)
	}
}

func TestAppendHistory_AppendsMultiple(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "policy.log")

	for i := 0; i < 3; i++ {
		AppendHistory(logPath, HistoryEntry{
			Action:     "update",
			PolicyHash: "hash",
		})
	}

	entries, err := ReadHistory(logPath)
	if err != nil {
		t.Fatalf("ReadHistory: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}

func TestReadHistory_NonexistentFile(t *testing.T) {
	entries, err := ReadHistory(filepath.Join(t.TempDir(), "nope.log"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entries != nil {
		t.Errorf("expected nil entries, got %v", entries)
	}
}

func TestReadHistory_SkipsMalformedLines(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "policy.log")

	good, _ := json.Marshal(HistoryEntry{Action: "create", PolicyHash: "aaa"})
	content := string(good) + "\nNOT JSON\n" + string(good) + "\n"
	os.WriteFile(logPath, []byte(content), 0o644)

	entries, err := ReadHistory(logPath)
	if err != nil {
		t.Fatalf("ReadHistory: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 valid entries (skipping malformed), got %d", len(entries))
	}
}

func TestReadHistory_EmptyFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "policy.log")
	os.WriteFile(logPath, []byte(""), 0o644)

	entries, err := ReadHistory(logPath)
	if err != nil {
		t.Fatalf("ReadHistory: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}
