package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type AgentIdentityManifest struct {
	Version          string    `json:"version"`
	Agent            AgentInfo `json:"agent"`
	CreatedAt        string    `json:"created_at"`
	Org              string    `json:"org,omitempty"`
	CapabilitiesHash string    `json:"capabilities_hash,omitempty"`
	PolicyHash       string    `json:"policy_hash,omitempty"`
	Signature        string    `json:"signature"`
}

type AgentInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Fingerprint string `json:"fingerprint"`
	SignedBy    string `json:"signed_by"`
}

func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("identity: generate key: %w", err)
	}
	return key, nil
}

func SaveKey(path string, key []byte) error {
	encoded := hex.EncodeToString(key) + "\n"
	return os.WriteFile(path, []byte(encoded), 0o600)
}

func LoadKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity: read key %s: %w", path, err)
	}
	trimmed := string(data)
	for len(trimmed) > 0 && (trimmed[len(trimmed)-1] == '\n' || trimmed[len(trimmed)-1] == '\r') {
		trimmed = trimmed[:len(trimmed)-1]
	}
	key, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("identity: decode key: %w", err)
	}
	return key, nil
}

func CreateManifest(key []byte, agentName, agentVersion, capHash, policyHash string) *AgentIdentityManifest {
	fp := computeFingerprint(key)
	m := &AgentIdentityManifest{
		Version:          "1",
		CreatedAt:        time.Now().UTC().Format(time.RFC3339),
		CapabilitiesHash: capHash,
		PolicyHash:       policyHash,
		Agent: AgentInfo{
			Name:        agentName,
			Version:     agentVersion,
			Fingerprint: fp,
			SignedBy:    "hmac-sha256",
		},
	}
	m.Signature = sign(key, m)
	return m
}

func VerifyManifest(key []byte, m *AgentIdentityManifest) bool {
	expected := sign(key, m)
	return hmac.Equal([]byte(expected), []byte(m.Signature))
}

func SaveManifest(path string, m *AgentIdentityManifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("identity: marshal manifest: %w", err)
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func LoadManifest(path string) (*AgentIdentityManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity: read manifest %s: %w", path, err)
	}
	var m AgentIdentityManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("identity: parse manifest: %w", err)
	}
	return &m, nil
}

func computeFingerprint(key []byte) string {
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:])
}

func sign(key []byte, m *AgentIdentityManifest) string {
	canonical := canonicalJSON(m)
	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil))
}

func canonicalJSON(m *AgentIdentityManifest) []byte {
	type noSig struct {
		Version          string    `json:"version"`
		Agent            AgentInfo `json:"agent"`
		CreatedAt        string    `json:"created_at"`
		Org              string    `json:"org,omitempty"`
		CapabilitiesHash string    `json:"capabilities_hash,omitempty"`
		PolicyHash       string    `json:"policy_hash,omitempty"`
	}
	data, _ := json.Marshal(noSig{
		Version:          m.Version,
		Agent:            m.Agent,
		CreatedAt:        m.CreatedAt,
		Org:              m.Org,
		CapabilitiesHash: m.CapabilitiesHash,
		PolicyHash:       m.PolicyHash,
	})
	return data
}
