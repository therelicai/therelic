package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/therelicai/therelic/internal/trace"
)

func TestHTTPLogger_NetworkPolicy_DenyPattern(t *testing.T) {
	var events []trace.ActionEvent
	logger := NewHTTPLogger("net-test", nil, nil, func(ev trace.ActionEvent) {
		events = append(events, ev)
	})
	logger.SetNetworkPolicy(nil, []string{"*.evil.com", "malware.io"})

	port, err := logger.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer logger.Close()

	proxyURL, _ := url.Parse("http://127.0.0.1:" + itoa(port))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get("http://api.evil.com/steal-data")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: %d, want 403", resp.StatusCode)
	}

	if len(events) == 0 {
		t.Fatal("expected at least one deny event")
	}
	if events[0].Auth != "deny" {
		t.Errorf("auth: %q, want deny", events[0].Auth)
	}
}

func TestHTTPLogger_NetworkPolicy_AllowList(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		io.WriteString(w, "ok") //nolint:errcheck
	}))
	defer backend.Close()

	var eventCount int32
	logger := NewHTTPLogger("net-allow-test", nil, nil, func(ev trace.ActionEvent) {
		atomic.AddInt32(&eventCount, 1)
	})
	logger.SetNetworkPolicy([]string{"127.0.0.1"}, nil)

	port, err := logger.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer logger.Close()

	proxyURL, _ := url.Parse("http://127.0.0.1:" + itoa(port))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(backend.URL + "/data")
	if err != nil {
		t.Fatalf("request to allowed host: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("allowed host status: %d, want 200", resp.StatusCode)
	}

	resp2, err := client.Get("http://unauthorized-host.com/exfiltrate")
	if err != nil {
		t.Fatalf("request to denied host: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("denied host status: %d, want 403", resp2.StatusCode)
	}
}

func TestHTTPLogger_NetworkPolicy_EmptyAllowsDeny(t *testing.T) {
	logger := NewHTTPLogger("net-empty-test", nil, nil, func(ev trace.ActionEvent) {})

	deny := logger.checkNetworkPolicy("any-host.com")
	if deny != nil {
		t.Errorf("empty policy should not deny, got: %+v", deny)
	}
}

func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}
