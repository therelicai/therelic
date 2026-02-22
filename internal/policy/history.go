package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type HistoryEntry struct {
	Timestamp  string `json:"ts"`
	Action     string `json:"action"`
	PolicyHash string `json:"policy_hash"`
	Actor      string `json:"actor,omitempty"`
	Message    string `json:"message,omitempty"`
}

func PolicyHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:8])
}

func AppendHistory(logPath string, entry HistoryEntry) error {
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("history: open %s: %w", logPath, err)
	}
	defer f.Close()

	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("history: marshal: %w", err)
	}
	line = append(line, '\n')
	_, err = f.Write(line)
	return err
}

func ReadHistory(logPath string) ([]HistoryEntry, error) {
	data, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("history: read %s: %w", logPath, err)
	}

	var entries []HistoryEntry
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var e HistoryEntry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
