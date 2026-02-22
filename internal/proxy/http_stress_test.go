package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/therelicai/therelic/internal/policy"
	"github.com/therelicai/therelic/internal/trace"
)

func TestHTTPLogger_ConcurrentRequests_NoDroppedEvents(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer target.Close()

	var mu sync.Mutex
	var events []trace.ActionEvent

	logger := NewHTTPLogger("stress-run", nil, nil, func(ev trace.ActionEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})
	port, err := logger.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer logger.Close()

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			MaxIdleConnsPerHost: 100,
		},
	}

	const numRequests = 100
	var wg sync.WaitGroup
	var errors int32

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := client.Get(fmt.Sprintf("%s/path/%d", target.URL, i))
			if err != nil {
				atomic.AddInt32(&errors, 1)
				t.Logf("request %d failed: %v", i, err)
				return
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				atomic.AddInt32(&errors, 1)
				t.Logf("request %d: status=%d", i, resp.StatusCode)
			}
		}(i)
	}

	wg.Wait()

	mu.Lock()
	eventCount := len(events)
	mu.Unlock()

	errCount := int(atomic.LoadInt32(&errors))
	expectedEvents := numRequests - errCount

	if eventCount != expectedEvents {
		t.Errorf("expected %d trace events, got %d (errors=%d)", expectedEvents, eventCount, errCount)
	}

	seenSeq := make(map[int]bool)
	mu.Lock()
	for _, ev := range events {
		if seenSeq[ev.Seq] {
			t.Errorf("duplicate sequence number: %d", ev.Seq)
		}
		seenSeq[ev.Seq] = true
	}
	mu.Unlock()
}

func TestHTTPLogger_ConcurrentRequests_WithPolicy_NoDuplicates(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	eng := policy.NewEngine(&policy.Policy{
		Version: "1",
		Agent:   policy.AgentIdentity{Name: "stress"},
		Mode:    "enforce",
		Default: "deny",
		Rules: []policy.Rule{
			{ID: "allow-all-http", Protocol: "http", Method: "*", Target: "**", Action: "allow"},
		},
	})

	var mu sync.Mutex
	var events []trace.ActionEvent

	logger := NewHTTPLogger("stress-policy-run", eng, nil, func(ev trace.ActionEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})
	port, err := logger.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer logger.Close()

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			MaxIdleConnsPerHost: 50,
		},
	}

	const numRequests = 50
	var wg sync.WaitGroup

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := client.Get(target.URL + "/test")
			if err != nil {
				return
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
		}(i)
	}

	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	for _, ev := range events {
		if ev.Auth != "allow" {
			t.Errorf("expected auth=allow with allow-all policy, got %q", ev.Auth)
		}
		if ev.Run != "stress-policy-run" {
			t.Errorf("run ID mismatch: %q", ev.Run)
		}
	}

	seenSeq := make(map[int]bool)
	for _, ev := range events {
		if seenSeq[ev.Seq] {
			t.Errorf("duplicate seq %d", ev.Seq)
		}
		seenSeq[ev.Seq] = true
	}
}

func TestHTTPLogger_ConcurrentDenyAndAllow(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	eng := policy.NewEngine(&policy.Policy{
		Version: "1",
		Agent:   policy.AgentIdentity{Name: "mixed"},
		Mode:    "enforce",
		Default: "deny",
		Rules: []policy.Rule{
			{ID: "allow-get", Protocol: "http", Method: "GET", Target: "**", Action: "allow"},
		},
	})

	var mu sync.Mutex
	var events []trace.ActionEvent

	logger := NewHTTPLogger("stress-mixed-run", eng, nil, func(ev trace.ActionEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})
	port, err := logger.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer logger.Close()

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			MaxIdleConnsPerHost: 50,
		},
	}

	const numRequests = 30
	var wg sync.WaitGroup

	for i := 0; i < numRequests; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			resp, err := client.Get(target.URL + "/allowed")
			if err != nil {
				return
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
		}()
		go func() {
			defer wg.Done()
			resp, err := client.Post(target.URL+"/denied", "text/plain", nil)
			if err != nil {
				return
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
		}()
	}

	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	var allows, denies int
	for _, ev := range events {
		switch ev.Auth {
		case "allow":
			allows++
		case "deny":
			denies++
		default:
			t.Errorf("unexpected auth: %q", ev.Auth)
		}
	}

	if allows == 0 {
		t.Error("expected some allow events")
	}
	if denies == 0 {
		t.Error("expected some deny events")
	}
	t.Logf("concurrent mixed: %d allows, %d denies, %d total", allows, denies, len(events))
}
