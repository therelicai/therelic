package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/therelicai/therelic/internal/policy"
)

// RelicDir is the project-level directory created by `relic init`.
const RelicDir = ".tr"

// Paths returns the canonical paths for all files inside a .tr directory.
type Paths struct {
	Root             string // .tr/
	PolicyFile       string // .tr/policy.yaml
	MCPFile          string // .tr/mcp.yaml
	TracesDir        string // .tr/traces/
	HistoryFile      string // .tr/policy.log
	CapabilitiesFile string // .tr/capabilities.json
}

// DefaultPaths returns Paths rooted at ".tr" relative to the current directory.
func DefaultPaths() Paths {
	return PathsFor(RelicDir)
}

// PathsFor returns Paths rooted at the given directory.
func PathsFor(relicDir string) Paths {
	return Paths{
		Root:             relicDir,
		PolicyFile:       filepath.Join(relicDir, "policy.yaml"),
		MCPFile:          filepath.Join(relicDir, "mcp.yaml"),
		TracesDir:        filepath.Join(relicDir, "traces"),
		HistoryFile:      filepath.Join(relicDir, "policy.log"),
		CapabilitiesFile: filepath.Join(relicDir, "capabilities.json"),
	}
}

// LoadPolicy reads and parses the policy file at path.
// Returns the parsed policy and any parse error. Validation is separate.
func LoadPolicy(path string) (*policy.Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read policy %s: %w", path, err)
	}
	p, err := policy.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("config: parse policy %s: %w", path, err)
	}
	return p, nil
}
