package trace

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// IntegrityChain maintains a rolling HMAC chain over trace events.
// Each event's HMAC covers the event data + the previous HMAC, forming
// a tamper-evident chain. Modifying, inserting, or removing any event
// invalidates all subsequent HMACs.
type IntegrityChain struct {
	key      []byte
	prevHMAC []byte
}

// NewIntegrityChain creates a chain keyed with the given secret.
func NewIntegrityChain(key []byte) *IntegrityChain {
	return &IntegrityChain{
		key:      key,
		prevHMAC: nil,
	}
}

// Seal computes the HMAC for an event, incorporating the chain state.
// Returns the hex-encoded HMAC. Advances the chain — must be called in order.
func (c *IntegrityChain) Seal(eventJSON []byte) string {
	mac := hmac.New(sha256.New, c.key)
	mac.Write(eventJSON)
	if c.prevHMAC != nil {
		mac.Write(c.prevHMAC)
	}
	h := mac.Sum(nil)
	c.prevHMAC = h
	return hex.EncodeToString(h)
}

// VerifyChain verifies the HMAC chain over a sequence of trace events.
// Each event must have a "hmac" field. Returns nil if the chain is valid.
func VerifyChain(events []json.RawMessage, key []byte) error {
	chain := NewIntegrityChain(key)

	for i, raw := range events {
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return fmt.Errorf("event %d: unmarshal: %w", i, err)
		}

		hmacField, ok := envelope["hmac"]
		if !ok {
			return fmt.Errorf("event %d: missing hmac field (trace has no integrity chain)", i)
		}

		var storedHMAC string
		if err := json.Unmarshal(hmacField, &storedHMAC); err != nil {
			return fmt.Errorf("event %d: unmarshal hmac: %w", i, err)
		}

		delete(envelope, "hmac")
		canonical, err := json.Marshal(envelope)
		if err != nil {
			return fmt.Errorf("event %d: re-marshal: %w", i, err)
		}

		computed := chain.Seal(canonical)
		if computed != storedHMAC {
			return fmt.Errorf("event %d: HMAC mismatch (chain broken — trace may have been tampered with)", i)
		}
	}
	return nil
}

// GenerateChainKey derives a per-run HMAC key from a run ID and a master secret.
func GenerateChainKey(runID string, masterSecret []byte) []byte {
	mac := hmac.New(sha256.New, masterSecret)
	mac.Write([]byte("relic-trace-chain-v1:"))
	mac.Write([]byte(runID))
	return mac.Sum(nil)
}
