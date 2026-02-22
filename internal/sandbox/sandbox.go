// Package sandbox provides filesystem isolation for governed agent processes.
// It creates a controlled workspace where agents can only access explicitly
// mounted paths with specified permissions (read-only or read-write).
//
// This is an application-level sandbox enforced through the MCP proxy's
// path validation. On Linux, kernel-level namespace isolation can be layered
// on top for defense-in-depth.
package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// MountMode controls whether a mounted path is read-only or read-write.
type MountMode string

const (
	ModeReadOnly  MountMode = "ro"
	ModeReadWrite MountMode = "rw"
)

// Mount defines a single filesystem mount binding a host path into the sandbox.
type Mount struct {
	Source string    `yaml:"source"`
	Target string    `yaml:"target"`
	Mode   MountMode `yaml:"mode"`
}

// Config defines the filesystem sandbox configuration from the policy YAML.
type Config struct {
	Enabled      bool     `yaml:"enabled"`
	Mounts       []Mount  `yaml:"mounts"`
	DenyPatterns []string `yaml:"deny_patterns"`
}

// Sandbox manages the isolated filesystem workspace for an agent run.
type Sandbox struct {
	root    string
	mounts  []resolvedMount
	denyPat []string
}

type resolvedMount struct {
	hostPath    string
	sandboxPath string
	mode        MountMode
}

// New creates and populates a sandbox workspace. The workspace is a temp
// directory with symlinks to the mounted host paths.
func New(cfg Config, runID string) (*Sandbox, error) {
	root, err := os.MkdirTemp("", "relic-sandbox-"+runID+"-")
	if err != nil {
		return nil, fmt.Errorf("sandbox: create workspace: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("sandbox: resolve workspace path: %w", err)
	}

	sb := &Sandbox{
		root:    root,
		denyPat: cfg.DenyPatterns,
	}

	for _, m := range cfg.Mounts {
		hostAbs, err := filepath.Abs(m.Source)
		if err != nil {
			sb.Cleanup()
			return nil, fmt.Errorf("sandbox: resolve source %q: %w", m.Source, err)
		}

		if _, err := os.Stat(hostAbs); err != nil {
			sb.Cleanup()
			return nil, fmt.Errorf("sandbox: source %q does not exist: %w", m.Source, err)
		}

		hostReal, err := filepath.EvalSymlinks(hostAbs)
		if err != nil {
			sb.Cleanup()
			return nil, fmt.Errorf("sandbox: resolve symlinks for %q: %w", hostAbs, err)
		}

		sandboxPath := filepath.Join(root, m.Target)
		if err := os.MkdirAll(filepath.Dir(sandboxPath), 0o755); err != nil {
			sb.Cleanup()
			return nil, fmt.Errorf("sandbox: mkdir for mount %q: %w", m.Target, err)
		}

		if err := os.Symlink(hostReal, sandboxPath); err != nil {
			sb.Cleanup()
			return nil, fmt.Errorf("sandbox: symlink %q → %q: %w", hostReal, sandboxPath, err)
		}

		sb.mounts = append(sb.mounts, resolvedMount{
			hostPath:    hostReal,
			sandboxPath: sandboxPath,
			mode:        m.Mode,
		})
	}

	return sb, nil
}

// Root returns the sandbox workspace root directory.
func (sb *Sandbox) Root() string {
	return sb.root
}

// ValidatePath checks whether a file operation is permitted by the sandbox policy.
// operation is one of: "read", "write", "delete", "list"
func (sb *Sandbox) ValidatePath(operation, path string) error {
	absPath, err := sb.resolvePath(path)
	if err != nil {
		return fmt.Errorf("sandbox: deny %s %q: %w", operation, path, err)
	}

	for _, pattern := range sb.denyPat {
		matched, _ := doublestar.Match(pattern, absPath)
		if matched {
			return fmt.Errorf("sandbox: deny %s %q: matches deny pattern %q", operation, path, pattern)
		}
		matched, _ = doublestar.Match(pattern, filepath.Base(absPath))
		if matched {
			return fmt.Errorf("sandbox: deny %s %q: matches deny pattern %q", operation, path, pattern)
		}
	}

	mount := sb.findMount(absPath)
	if mount == nil {
		return fmt.Errorf("sandbox: deny %s %q: path is outside all allowed mounts", operation, path)
	}

	if isWriteOp(operation) && mount.mode == ModeReadOnly {
		return fmt.Errorf("sandbox: deny %s %q: mount %q is read-only", operation, path, mount.sandboxPath)
	}

	return nil
}

// Cleanup removes the sandbox workspace directory.
func (sb *Sandbox) Cleanup() {
	if sb.root != "" {
		os.RemoveAll(sb.root)
	}
}

func (sb *Sandbox) resolvePath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(sb.root, path)
	}
	cleaned := filepath.Clean(path)

	if resolved, err := filepath.EvalSymlinks(cleaned); err == nil {
		return resolved, nil
	}

	resolved := resolveExistingPrefix(cleaned)

	if strings.HasPrefix(resolved, sb.root) {
		return resolved, nil
	}
	for _, m := range sb.mounts {
		if strings.HasPrefix(resolved, m.hostPath) {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("path escapes sandbox root")
}

func (sb *Sandbox) findMount(absPath string) *resolvedMount {
	for i := range sb.mounts {
		m := &sb.mounts[i]
		if strings.HasPrefix(absPath, m.hostPath) || strings.HasPrefix(absPath, m.sandboxPath) {
			return m
		}
	}
	return nil
}

func isWriteOp(op string) bool {
	switch op {
	case "write", "delete", "create", "move", "mkdir":
		return true
	}
	return false
}

func resolveExistingPrefix(path string) string {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		return filepath.Join(resolved, base)
	}
	return filepath.Join(resolveExistingPrefix(dir), base)
}
