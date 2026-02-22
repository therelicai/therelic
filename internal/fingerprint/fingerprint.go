package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

type Capability struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // "tool", "resource", "prompt"
	Description string `json:"description,omitempty"`
}

type Manifest struct {
	Version      string       `json:"version"`
	Agent        string       `json:"agent,omitempty"`
	Capabilities []Capability `json:"capabilities"`
	Hash         string       `json:"hash"`
	GeneratedAt  string       `json:"generated_at"`
}

func CapabilitiesHash(caps []Capability) string {
	sorted := make([]Capability, len(caps))
	copy(sorted, caps)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Type != sorted[j].Type {
			return sorted[i].Type < sorted[j].Type
		}
		return sorted[i].Name < sorted[j].Name
	})
	data, _ := json.Marshal(sorted)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: read %s: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("fingerprint: parse %s: %w", path, err)
	}
	return &m, nil
}

func SaveManifest(path string, m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("fingerprint: marshal: %w", err)
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

type DiffResult struct {
	Added   []Capability
	Removed []Capability
}

func Diff(old, new_ []Capability) DiffResult {
	oldSet := make(map[string]Capability)
	for _, c := range old {
		oldSet[c.Type+":"+c.Name] = c
	}
	newSet := make(map[string]Capability)
	for _, c := range new_ {
		newSet[c.Type+":"+c.Name] = c
	}

	var result DiffResult
	for key, c := range newSet {
		if _, ok := oldSet[key]; !ok {
			result.Added = append(result.Added, c)
		}
	}
	for key, c := range oldSet {
		if _, ok := newSet[key]; !ok {
			result.Removed = append(result.Removed, c)
		}
	}
	return result
}
