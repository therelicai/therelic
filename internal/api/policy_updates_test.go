package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSubscribePolicyUpdates_DeliversFrames pins the slice-15 wire
// contract: the runtime's SSE reader yields one PolicyUpdate per
// `event: policy_update` frame the platform writes, with the fields
// the dashboard's apply-state counter depends on (Hash, Version,
// AgentName).
func TestSubscribePolicyUpdates_DeliversFrames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/agents/code-assist/policy_updates") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer rk_test_42" {
			t.Errorf("auth header: got %q", got)
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("response writer doesn't support Flush")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		writeFrame := func(hash string, version int) {
			payload, _ := json.Marshal(map[string]any{
				"org_id":          "org-A",
				"agent_name":      "code-assist",
				"policy_hash":     hash,
				"version":         version,
				"policy_set_name": "prod-baseline",
				"published_at":    "2026-05-13T12:00:00Z",
			})
			fmt.Fprintf(w, "event: policy_update\ndata: %s\n\n", payload)
			flusher.Flush()
		}
		// Two frames, then a comment line that should be ignored.
		writeFrame("abc12345", 1)
		writeFrame("def67890", 2)
		_, _ = io.WriteString(w, ": ping\n\n")
		flusher.Flush()
		// Hold open briefly so the client reads both frames before
		// the connection closes.
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv.Close()

	client := &Client{
		BaseURL:    srv.URL,
		APIKey:     "rk_test_42",
		HTTPClient: srv.Client(),
	}

	var (
		mu       sync.Mutex
		received []PolicyUpdate
	)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := client.SubscribePolicyUpdates(ctx, "code-assist", func(u PolicyUpdate) {
		mu.Lock()
		received = append(received, u)
		mu.Unlock()
	})
	// The server closes when the handler returns; that's normal end-
	// of-stream. The function returns nil on a graceful end.
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 2 {
		t.Fatalf("got %d updates, want 2", len(received))
	}
	if received[0].PolicyHash != "abc12345" || received[0].Version != 1 {
		t.Errorf("frame 0: %+v", received[0])
	}
	if received[1].PolicyHash != "def67890" || received[1].Version != 2 {
		t.Errorf("frame 1: %+v", received[1])
	}
}

// TestReportPolicyApplied_RoundTrip confirms the POST surface +
// payload that closes the apply loop on the dashboard.
func TestReportPolicyApplied_RoundTrip(t *testing.T) {
	var (
		mu       sync.Mutex
		gotPath  string
		gotAuth  string
		gotBody  map[string]string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := &Client{BaseURL: srv.URL, APIKey: "rk_test", HTTPClient: srv.Client()}
	if err := client.ReportPolicyApplied(context.Background(), "code-assist", "abc12345"); err != nil {
		t.Fatalf("report: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.HasSuffix(gotPath, "/agents/code-assist/policy_applied") {
		t.Errorf("path: %q", gotPath)
	}
	if gotAuth != "Bearer rk_test" {
		t.Errorf("auth: %q", gotAuth)
	}
	if gotBody["hash"] != "abc12345" {
		t.Errorf("body hash: %q", gotBody["hash"])
	}
}
