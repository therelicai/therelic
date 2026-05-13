package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// PolicyUpdate is the slice-15 SSE notification shape — runtime's
// view of policyfeed.Notification. Decoded from each `data:` frame
// the platform writes to GET /v1/agents/:name/policy_updates.
type PolicyUpdate struct {
	OrgID         string    `json:"org_id"`
	AgentName     string    `json:"agent_name"`
	PolicyHash    string    `json:"policy_hash"`
	Version       int       `json:"version"`
	PolicySetName string    `json:"policy_set_name"`
	PublishedAt   time.Time `json:"published_at"`
}

// SubscribePolicyUpdates opens an SSE connection to the platform's
// agent-facing policy_updates channel and yields parsed notifications
// to `onUpdate` until ctx is cancelled or the connection drops.
//
// Like internal/api/stream.go, we use fetch (net/http) instead of
// any SSE library: the protocol is small enough that a 30-line
// parser is more honest than an external dependency. The connection
// is long-lived; callers wrap this in a reconnect loop.
//
// The returned error is non-nil when the connection setup fails
// (4xx/5xx, network error) or the stream ends abnormally. Normal
// cancellation via ctx returns nil.
func (c *Client) SubscribePolicyUpdates(ctx context.Context, agentName string, onUpdate func(PolicyUpdate)) error {
	url := fmt.Sprintf("%s/agents/%s/policy_updates", c.BaseURL, agentName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("subscribe policy updates: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("subscribe policy updates: open: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("subscribe policy updates: HTTP %d: %s", resp.StatusCode, string(body))
	}

	return parseSSE(resp.Body, func(event, data string) {
		if event != "policy_update" {
			return
		}
		var u PolicyUpdate
		if err := json.Unmarshal([]byte(data), &u); err != nil {
			return
		}
		onUpdate(u)
	})
}

// ReportPolicyApplied advances the agent's applied-state on the
// platform. Called after a successful hot-reload so the dashboard's
// "n/m on hash" counter advances. Returns the response error verbatim
// when the platform rejects (404 if the agent isn't registered,
// typically).
func (c *Client) ReportPolicyApplied(ctx context.Context, agentName, hash string) error {
	url := fmt.Sprintf("%s/agents/%s/policy_applied", c.BaseURL, agentName)
	body, err := json.Marshal(map[string]string{"hash": hash})
	if err != nil {
		return fmt.Errorf("report policy applied: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("report policy applied: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("report policy applied: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("report policy applied: HTTP %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// parseSSE reads the standard SSE wire format from r and calls cb
// once per complete frame. Frames are separated by blank lines.
// Lines starting with ":" are comments (used for keepalive) and
// ignored. Returns when r reaches EOF or yields an error.
//
// We deliberately keep the parser minimal — we only consume event:
// and data: lines, and we don't preserve multi-line data fields
// (the platform always writes single-line data).
func parseSSE(r io.Reader, cb func(event, data string)) error {
	scanner := bufio.NewScanner(r)
	// Allow generously large frames — a policy_update notification
	// is small, but a malformed or attacker-crafted stream shouldn't
	// be able to crash the runtime by exceeding the default 64 KiB
	// scanner buffer either way.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var event, data string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if event != "" && data != "" {
				cb(event, data)
			}
			event = ""
			data = ""
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue // comment / keepalive
		}
		if strings.HasPrefix(line, "event:") {
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}
		if strings.HasPrefix(line, "data:") {
			data = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			continue
		}
		// retry:, id:, unknown fields — ignored.
	}
	return scanner.Err()
}
