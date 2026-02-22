// Package signing provides ed25519-based cryptographic signing and verification
// for The Relic policy files. This is the foundation of zero-trust policy
// enforcement: without a valid signature from a trusted key, a policy cannot
// be loaded in secure mode.
//
// Key format: PEM-encoded ed25519 keys (PRIVATE KEY / PUBLIC KEY).
// Signature format: raw ed25519 signature (64 bytes), base64-encoded in .sig files.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// GenerateKeyPair creates a new ed25519 keypair and writes PEM files to dir.
func GenerateKeyPair(dir, name string) (privPath, pubPath string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("signing: generate key: %w", err)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("signing: mkdir %s: %w", dir, err)
	}

	privPath = filepath.Join(dir, name+".key")
	pubPath = filepath.Join(dir, name+".pub")

	if err := writePrivateKey(privPath, priv); err != nil {
		return "", "", err
	}
	if err := writePublicKey(pubPath, pub); err != nil {
		return "", "", err
	}

	return privPath, pubPath, nil
}

// Sign produces a detached ed25519 signature over data.
func Sign(data []byte, keyPath string) ([]byte, error) {
	priv, err := LoadPrivateKey(keyPath)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, data), nil
}

// Verify checks a detached ed25519 signature over data.
func Verify(data, signature []byte, keyPath string) error {
	pub, err := LoadPublicKey(keyPath)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, data, signature) {
		return fmt.Errorf("signing: signature verification failed — policy may have been tampered with")
	}
	return nil
}

// SignFile reads a file, signs it, and writes the signature to <path>.sig.
func SignFile(filePath, keyPath string) (sigPath string, err error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("signing: read %s: %w", filePath, err)
	}
	sig, err := Sign(data, keyPath)
	if err != nil {
		return "", err
	}
	sigPath = filePath + ".sig"
	encoded := base64.StdEncoding.EncodeToString(sig)
	if err := os.WriteFile(sigPath, []byte(encoded+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("signing: write %s: %w", sigPath, err)
	}
	return sigPath, nil
}

// VerifyFile reads a file and its .sig companion and verifies the signature.
func VerifyFile(filePath, pubKeyPath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("signing: read %s: %w", filePath, err)
	}
	sigPath := filePath + ".sig"
	sigB64, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("signing: read signature %s: %w (policy is unsigned)", sigPath, err)
	}
	sig, err := base64.StdEncoding.DecodeString(trimNewlines(string(sigB64)))
	if err != nil {
		return fmt.Errorf("signing: decode signature %s: %w", sigPath, err)
	}
	return Verify(data, sig, pubKeyPath)
}

// LoadPrivateKey reads a PEM-encoded ed25519 private key.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signing: read private key %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("signing: %s: no PEM block found", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing: parse private key %s: %w", path, err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing: %s: not an ed25519 private key", path)
	}
	return edKey, nil
}

// LoadPublicKey reads a PEM-encoded ed25519 public key.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signing: read public key %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("signing: %s: no PEM block found", path)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing: parse public key %s: %w", path, err)
	}
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signing: %s: not an ed25519 public key", path)
	}
	return edKey, nil
}

func writePrivateKey(path string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("signing: marshal private key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return fmt.Errorf("signing: write %s: %w", path, err)
	}
	return nil
}

func writePublicKey(path string, key ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fmt.Errorf("signing: marshal public key: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o644); err != nil {
		return fmt.Errorf("signing: write %s: %w", path, err)
	}
	return nil
}

func trimNewlines(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
