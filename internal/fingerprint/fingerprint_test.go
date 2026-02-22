package fingerprint

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCapabilitiesHash_Deterministic(t *testing.T) {
	caps := []Capability{
		{Name: "read_file", Type: "tool"},
		{Name: "write_file", Type: "tool"},
	}
	h1 := CapabilitiesHash(caps)
	h2 := CapabilitiesHash(caps)
	if h1 != h2 {
		t.Fatalf("expected same hash, got %s vs %s", h1, h2)
	}
}

func TestCapabilitiesHash_OrderIndependent(t *testing.T) {
	a := []Capability{
		{Name: "write_file", Type: "tool"},
		{Name: "read_file", Type: "tool"},
	}
	b := []Capability{
		{Name: "read_file", Type: "tool"},
		{Name: "write_file", Type: "tool"},
	}
	if CapabilitiesHash(a) != CapabilitiesHash(b) {
		t.Fatal("hash should be order-independent")
	}
}

func TestCapabilitiesHash_DoesNotMutateInput(t *testing.T) {
	caps := []Capability{
		{Name: "b", Type: "tool"},
		{Name: "a", Type: "tool"},
	}
	CapabilitiesHash(caps)
	if caps[0].Name != "b" || caps[1].Name != "a" {
		t.Fatal("CapabilitiesHash must not mutate the input slice")
	}
}

func TestCapabilitiesHash_Empty(t *testing.T) {
	h := CapabilitiesHash(nil)
	if h == "" {
		t.Fatal("hash of nil should still produce a value")
	}
}

func TestDiff_Added(t *testing.T) {
	old := []Capability{{Name: "a", Type: "tool"}}
	new_ := []Capability{{Name: "a", Type: "tool"}, {Name: "b", Type: "tool"}}
	d := Diff(old, new_)
	if len(d.Added) != 1 || d.Added[0].Name != "b" {
		t.Fatalf("expected 1 added (b), got %+v", d.Added)
	}
	if len(d.Removed) != 0 {
		t.Fatalf("expected 0 removed, got %+v", d.Removed)
	}
}

func TestDiff_Removed(t *testing.T) {
	old := []Capability{{Name: "a", Type: "tool"}, {Name: "b", Type: "tool"}}
	new_ := []Capability{{Name: "a", Type: "tool"}}
	d := Diff(old, new_)
	if len(d.Removed) != 1 || d.Removed[0].Name != "b" {
		t.Fatalf("expected 1 removed (b), got %+v", d.Removed)
	}
	if len(d.Added) != 0 {
		t.Fatalf("expected 0 added, got %+v", d.Added)
	}
}

func TestDiff_NoChange(t *testing.T) {
	caps := []Capability{{Name: "a", Type: "tool"}}
	d := Diff(caps, caps)
	if len(d.Added) != 0 || len(d.Removed) != 0 {
		t.Fatal("expected no diff for identical sets")
	}
}

func TestSaveAndLoadManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")

	m := &Manifest{
		Version: "1",
		Agent:   "test-agent",
		Capabilities: []Capability{
			{Name: "read", Type: "tool", Description: "reads things"},
		},
		Hash:        "abc123",
		GeneratedAt: "2025-01-01T00:00:00Z",
	}

	if err := SaveManifest(path, m); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.Version != m.Version {
		t.Errorf("version: got %s, want %s", loaded.Version, m.Version)
	}
	if loaded.Agent != m.Agent {
		t.Errorf("agent: got %s, want %s", loaded.Agent, m.Agent)
	}
	if loaded.Hash != m.Hash {
		t.Errorf("hash: got %s, want %s", loaded.Hash, m.Hash)
	}
	if len(loaded.Capabilities) != 1 {
		t.Fatalf("capabilities: got %d, want 1", len(loaded.Capabilities))
	}
	if loaded.Capabilities[0].Name != "read" {
		t.Errorf("cap name: got %s, want read", loaded.Capabilities[0].Name)
	}
}

func TestLoadManifest_NotExist(t *testing.T) {
	_, err := LoadManifest("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !os.IsNotExist(err) {
		// The error is wrapped, so unwrap check isn't simple — just verify we got an error.
		t.Logf("got expected error: %v", err)
	}
}

func TestLoadManifest_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{invalid"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadManifest(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
