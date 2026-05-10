package trace

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// ErrMissingHMAC is returned when an event in the chain has no hmac field.
// Surfaced separately so callers can distinguish "this trace was never
// sealed" from "this trace was sealed but the chain is broken".
var ErrMissingHMAC = errors.New("trace: event missing hmac field")

// ErrChainMismatch is returned when an event's stored HMAC doesn't
// match what the chain recomputes. This is the canonical signal that
// a trace has been tampered with (or sealed with a different key).
var ErrChainMismatch = errors.New("trace: HMAC mismatch (chain broken)")

// hmacSuffix is the byte sequence written by sealEventLine before
// the hex MAC. We strip from this marker rightward to recover the
// original sealed bytes for verification without re-marshalling.
var hmacSuffix = []byte(`,"hmac":"`)
var hmacSuffixEmpty = []byte(`"hmac":"`)

// VerifyChain verifies the HMAC chain over a sequence of trace event
// lines. Each line must be a JSON object whose final field is `hmac`,
// emitted by sealEventLine. Returns nil if the chain is valid.
//
// We extract the MAC by splitting the line at the `,"hmac":"` (or
// `"hmac":"` for {}-only events) suffix rather than round-tripping
// through encoding/json. Round-tripping a map sorts the keys, which
// silently breaks verification when the writer emits a struct whose
// fields aren't in alphabetical order — the exact failure mode that
// the original implementation of this function hit in practice.
func VerifyChain(events [][]byte, key []byte) error {
	chain := NewIntegrityChain(key)
	for i, raw := range events {
		canonical, mac, err := splitSealedLine(raw)
		if err != nil {
			return fmt.Errorf("event %d: %w", i, err)
		}
		computed := chain.Seal(canonical)
		if !hmac.Equal([]byte(computed), []byte(mac)) {
			return fmt.Errorf("event %d: %w", i, ErrChainMismatch)
		}
	}
	return nil
}

// splitSealedLine peels the `hmac` suffix off a sealed event and
// returns the canonical (unsealed) bytes plus the hex MAC.
func splitSealedLine(line []byte) (canonical []byte, mac string, err error) {
	if len(line) < 2 || line[0] != '{' || line[len(line)-1] != '}' {
		return nil, "", fmt.Errorf("not a JSON object")
	}
	// Trailing field is `,"hmac":"<hex>"}` or `{"hmac":"<hex>"}` for
	// the degenerate empty-object case.
	idx := bytes.LastIndex(line, hmacSuffix)
	leadingComma := true
	if idx < 0 {
		idx = bytes.LastIndex(line, hmacSuffixEmpty)
		if idx < 0 || idx != 1 {
			return nil, "", ErrMissingHMAC
		}
		leadingComma = false
	}
	// Hex MAC is between the opening quote (after ":\"") and the
	// final '"}' suffix.
	macStart := idx + len(hmacSuffix)
	if !leadingComma {
		macStart = idx + len(hmacSuffixEmpty)
	}
	macEnd := len(line) - 2 // strip `"}`
	if macEnd <= macStart {
		return nil, "", fmt.Errorf("malformed hmac field")
	}
	macBytes := line[macStart:macEnd]
	if _, err := hex.DecodeString(string(macBytes)); err != nil {
		return nil, "", fmt.Errorf("hmac is not hex: %w", err)
	}
	// Canonical bytes = everything before the hmac suffix, then `}`.
	canonical = make([]byte, 0, idx+1)
	canonical = append(canonical, line[:idx]...)
	canonical = append(canonical, '}')
	return canonical, string(macBytes), nil
}

// GenerateChainKey derives a per-run HMAC key from a run ID and a master secret.
func GenerateChainKey(runID string, masterSecret []byte) []byte {
	mac := hmac.New(sha256.New, masterSecret)
	mac.Write([]byte("relic-trace-chain-v1:"))
	mac.Write([]byte(runID))
	return mac.Sum(nil)
}
