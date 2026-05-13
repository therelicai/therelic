package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestNewStreamerFromEnv_StandaloneMode pins the load-bearing
// guarantee for slice 14: without BOTH RELIC_API_URL and
// RELIC_API_KEY, the streamer returns (nil, nil) and the caller must
// treat that as "streaming disabled." Standalone-mode runtimes never
// touch the network.
func TestNewStreamerFromEnv_StandaloneMode(t *testing.T) {
	t.Setenv(EnvAPIKey, "")
	t.Setenv(EnvBaseURL, "")
	s, err := NewStreamerFromEnv()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if s != nil {
		t.Fatal("standalone mode (no env): expected nil streamer")
	}

	t.Setenv(EnvAPIKey, "rk_test")
	t.Setenv(EnvBaseURL, "")
	s, err = NewStreamerFromEnv()
	if err != nil || s != nil {
		t.Fatal("key without url: expected nil streamer")
	}

	t.Setenv(EnvAPIKey, "")
	t.Setenv(EnvBaseURL, "http://example.com")
	s, err = NewStreamerFromEnv()
	if err != nil || s != nil {
		t.Fatal("url without key: expected nil streamer")
	}
}

// TestStreamer_DeliversToPlatform proves the success path: each
// Submit() lands as a POST to /intents with the exact bytes we
// submitted, carrying the Authorization header. The Streamer never
// reseals — disk and network see byte-identical lines.
func TestStreamer_DeliversToPlatform(t *testing.T) {
	var (
		mu       sync.Mutex
		received [][]byte
		auths    []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/intents") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		received = append(received, body)
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	t.Setenv(EnvAPIKey, "rk_test_42")
	t.Setenv(EnvBaseURL, srv.URL)
	s, err := NewStreamerFromEnv()
	if err != nil || s == nil {
		t.Fatalf("streamer init failed: err=%v s=%v", err, s)
	}
	defer s.Close()

	lines := [][]byte{
		[]byte(`{"t":"intent","run":"r1","seq":1,"target":"web_search"}`),
		[]byte(`{"t":"action","run":"r1","seq":1,"target":"web_search","auth":"allow"}`),
	}
	for _, l := range lines {
		if !s.Submit(l) {
			t.Fatalf("Submit returned false for %s", l)
		}
	}

	// Drain — the worker is async, so wait for both lines to land.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		if n == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 2 {
		t.Fatalf("got %d events, want 2", len(received))
	}
	for i, want := range lines {
		if string(received[i]) != string(want) {
			t.Errorf("event %d: got %q want %q", i, received[i], want)
		}
	}
	for i, a := range auths {
		if a != "Bearer rk_test_42" {
			t.Errorf("auth %d: got %q want Bearer rk_test_42", i, a)
		}
	}
	if s.Dropped() != 0 {
		t.Errorf("Dropped=%d, want 0 on happy path", s.Dropped())
	}
}

// TestStreamer_DropsOnOverflow verifies the bounded-queue contract:
// when the worker is stalled, Submit returns false immediately rather
// than blocking the proxy's hot path. The runtime's promise is that
// streaming failures never affect enforcement timing.
func TestStreamer_DropsOnOverflow(t *testing.T) {
	// Server that never returns — forces the worker to stay parked on
	// flush, leaving the queue to fill.
	hold := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-hold
	}))
	defer func() {
		close(hold)
		srv.Close()
	}()

	t.Setenv(EnvAPIKey, "rk_test")
	t.Setenv(EnvBaseURL, srv.URL)
	s, err := NewStreamerFromEnv()
	if err != nil || s == nil {
		t.Fatalf("streamer init: %v %v", err, s)
	}
	defer s.Close()

	// First event: worker grabs it, blocks on the stalled HTTP.
	// Subsequent: fill the queue, then expect drops.
	var submitted, dropped int
	for i := 0; i < queueDepth+10; i++ {
		if s.Submit([]byte(`{"t":"intent","seq":1}`)) {
			submitted++
		} else {
			dropped++
		}
	}
	if dropped < 5 {
		t.Errorf("dropped=%d, want at least 5 once queue fills", dropped)
	}
	// Dropped counter reflects what Submit drops (the test doesn't
	// observe in-flight worker flushes since the server is stalled).
	if s.Dropped() < uint64(dropped) {
		t.Errorf("counter inconsistent: dropped=%d counter=%d", dropped, s.Dropped())
	}
}

// Compile-time sanity check that envs we'd touch aren't leaked from
// the test harness — Go's t.Setenv handles unset on teardown.
var _ = os.Getenv
