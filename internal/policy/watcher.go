package policy

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// WatchCallback is invoked whenever the watched policy file changes.
// Exactly one of newPolicy or err will be non-nil.
type WatchCallback func(newPolicy *Policy, err error)

// Watcher polls a policy file for changes and invokes a callback when the
// file is modified. It uses mtime-based detection with no external dependencies.
type Watcher struct {
	path     string
	interval time.Duration
	callback WatchCallback
	done     chan struct{}
	once     sync.Once
	lastMod  time.Time
}

// NewWatcher creates a Watcher that monitors path and calls callback on change.
func NewWatcher(path string, callback WatchCallback) *Watcher {
	return &Watcher{
		path:     path,
		interval: 500 * time.Millisecond,
		callback: callback,
		done:     make(chan struct{}),
	}
}

// Start records the current mtime and begins the background polling loop.
func (w *Watcher) Start() {
	if info, err := os.Stat(w.path); err == nil {
		w.lastMod = info.ModTime()
	}
	go w.loop()
}

// Stop terminates the polling loop. Safe to call multiple times.
func (w *Watcher) Stop() {
	w.once.Do(func() { close(w.done) })
}

func (w *Watcher) loop() {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-w.done:
			return
		case <-ticker.C:
			w.check()
		}
	}
}

func (w *Watcher) check() {
	info, err := os.Stat(w.path)
	if err != nil {
		return
	}
	if !info.ModTime().After(w.lastMod) {
		return
	}
	w.lastMod = info.ModTime()

	p, err := Load(w.path)
	if err != nil {
		w.callback(nil, fmt.Errorf("watch: reload %s: %w", w.path, err))
		return
	}
	errs := Validate(p, false)
	if len(errs) > 0 {
		w.callback(nil, fmt.Errorf("watch: invalid policy: %v", errs[0]))
		return
	}
	w.callback(p, nil)
}
