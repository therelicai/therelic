package policy

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const watcherPolicyYAML = `version: "1"
agent:
  name: test-agent
mode: enforce
default: deny
rules:
  - id: allow-all
    protocol: "*"
    method: "*"
    target: "*"
    action: allow
`

const watcherPolicyYAMLv2 = `version: "1"
agent:
  name: test-agent
mode: audit
default: deny
rules:
  - id: allow-all
    protocol: "*"
    method: "*"
    target: "*"
    action: allow
`

const watcherInvalidPolicyYAML = `version: "1"
agent:
  name: ""
mode: enforce
default: deny
`

func writePolicyFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
}

func TestWatcher_FileChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writePolicyFile(t, path, watcherPolicyYAML)

	var mu sync.Mutex
	var gotPolicy *Policy
	var gotErr error
	called := make(chan struct{}, 1)

	w := NewWatcher(path, func(p *Policy, err error) {
		mu.Lock()
		gotPolicy = p
		gotErr = err
		mu.Unlock()
		select {
		case called <- struct{}{}:
		default:
		}
	})
	w.interval = 50 * time.Millisecond
	w.Start()
	defer w.Stop()

	// Wait for initial poll to establish baseline mtime.
	time.Sleep(100 * time.Millisecond)

	// Modify the file — bump mtime by writing new content.
	writePolicyFile(t, path, watcherPolicyYAMLv2)

	select {
	case <-called:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotErr != nil {
		t.Fatalf("unexpected error: %v", gotErr)
	}
	if gotPolicy == nil {
		t.Fatal("expected non-nil policy")
	}
	if gotPolicy.Mode != "audit" {
		t.Errorf("expected mode=audit, got %q", gotPolicy.Mode)
	}
}

func TestWatcher_InvalidPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writePolicyFile(t, path, watcherPolicyYAML)

	var mu sync.Mutex
	var gotErr error
	called := make(chan struct{}, 1)

	w := NewWatcher(path, func(p *Policy, err error) {
		mu.Lock()
		gotErr = err
		mu.Unlock()
		select {
		case called <- struct{}{}:
		default:
		}
	})
	w.interval = 50 * time.Millisecond
	w.Start()
	defer w.Stop()

	time.Sleep(100 * time.Millisecond)

	writePolicyFile(t, path, watcherInvalidPolicyYAML)

	select {
	case <-called:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for error callback")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotErr == nil {
		t.Fatal("expected error for invalid policy, got nil")
	}
}

func TestWatcher_NoChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writePolicyFile(t, path, watcherPolicyYAML)

	callCount := 0
	var mu sync.Mutex

	w := NewWatcher(path, func(p *Policy, err error) {
		mu.Lock()
		callCount++
		mu.Unlock()
	})
	w.interval = 50 * time.Millisecond
	w.Start()
	defer w.Stop()

	// Let several poll cycles run without modifying the file.
	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if callCount != 0 {
		t.Errorf("expected 0 callbacks for unchanged file, got %d", callCount)
	}
}

func TestWatcher_StopClean(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writePolicyFile(t, path, watcherPolicyYAML)

	w := NewWatcher(path, func(p *Policy, err error) {})
	w.interval = 50 * time.Millisecond
	w.Start()

	// Stop should return quickly without hanging.
	done := make(chan struct{})
	go func() {
		w.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return in time")
	}

	// Calling Stop again should not panic.
	w.Stop()
}
