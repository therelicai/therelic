package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const (
	// DefaultBaseURL points at a local self-hosted platform. The
	// relic CLI is source-available and meant to run against any
	// Postgres + S3 + auth backend you choose; we don't operate a
	// hosted control plane on your behalf. Override with RELIC_API_URL
	// to point at your deployment.
	DefaultBaseURL = "http://localhost:8080/v1"
	EnvAPIKey      = "RELIC_API_KEY"
	EnvBaseURL     = "RELIC_API_URL"
)

type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

func NewClientFromEnv() (*Client, error) {
	key := os.Getenv(EnvAPIKey)
	if key == "" {
		return nil, fmt.Errorf("no API key configured. Run `relic init` after bringing up a Relic platform (see https://github.com/therelicai/therelic-platform), then set RELIC_API_KEY")
	}
	base := os.Getenv(EnvBaseURL)
	if base == "" {
		base = DefaultBaseURL
	}
	return &Client{
		BaseURL:    base,
		APIKey:     key,
		HTTPClient: http.DefaultClient,
	}, nil
}

// IsConnectionRefused returns true if the error chain contains
// ECONNREFUSED. Used by the CLI to print a "platform isn't running"
// hint when the default localhost endpoint isn't reachable.
func IsConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	// Fallback string match for OSes where errno isn't exposed
	// through the error chain (Windows in some configurations).
	return strings.Contains(err.Error(), "connection refused")
}

// UnreachableHint returns an actionable error message when a network
// call to BaseURL failed because the platform isn't running. Returns
// the original error wrapped with the original cause preserved when
// the failure isn't a connection-refused case.
func (c *Client) UnreachableHint(err error) error {
	if !IsConnectionRefused(err) {
		return err
	}
	hint := fmt.Sprintf("cannot reach Relic platform at %s. Run `docker compose up` in therelic-platform, or set RELIC_API_URL to a reachable endpoint", c.BaseURL)
	return fmt.Errorf("%s: %w", hint, err)
}


// PushTrace uploads a gzipped .trtrace file for the given run.
func (c *Client) PushTrace(ctx context.Context, runID string, body io.Reader, meta TraceMeta) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/traces", body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("X-Relic-Run-ID", runID)
	req.Header.Set("X-Relic-Agent-Name", meta.AgentName)
	req.Header.Set("X-Relic-Agent-Version", meta.AgentVersion)
	req.Header.Set("X-Relic-Policy-Hash", meta.PolicyHash)
	req.Header.Set("X-Relic-Environment", meta.Environment)
	req.Header.Set("X-Relic-Actions-Total", strconv.Itoa(meta.ActionsTotal))
	req.Header.Set("X-Relic-Actions-Allowed", strconv.Itoa(meta.ActionsAllowed))
	req.Header.Set("X-Relic-Actions-Denied", strconv.Itoa(meta.ActionsDenied))
	req.Header.Set("X-Relic-Duration-Ms", strconv.Itoa(meta.DurationMs))
	req.Header.Set("X-Relic-Exit-Code", strconv.Itoa(meta.ExitCode))

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return c.UnreachableHint(fmt.Errorf("upload trace: %w", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// RegisterAgent posts an identity manifest to the platform.
func (c *Client) RegisterAgent(ctx context.Context, manifest io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/agents", manifest)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return c.UnreachableHint(fmt.Errorf("register agent: %w", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// PullPolicy fetches the current policy YAML for the named agent from the
// control plane. The control plane is the policy authority; agents pull from
// it. Returns raw policy YAML bytes suitable for writing to .tr/policy.yaml.
func (c *Client) PullPolicy(ctx context.Context, agentName string) ([]byte, error) {
	url := fmt.Sprintf("%s/agents/%s/policy", c.BaseURL, agentName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, c.UnreachableHint(fmt.Errorf("pull policy: %w", err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		_ = json.Unmarshal(body, &errResp)
		if msg := errResp["error"]; msg != "" {
			return nil, fmt.Errorf("policy pull failed (HTTP %d): %s", resp.StatusCode, msg)
		}
		return nil, fmt.Errorf("policy pull failed (HTTP %d)", resp.StatusCode)
	}

	var envelope struct {
		Policy string `json:"policy"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decode policy response: %w", err)
	}
	if envelope.Policy == "" {
		return nil, fmt.Errorf("policy pull: control plane returned an empty policy for %q", agentName)
	}
	return []byte(envelope.Policy), nil
}

// TraceMeta holds trace metadata sent as headers during upload.
type TraceMeta struct {
	AgentName      string
	AgentVersion   string
	PolicyHash     string
	Environment    string
	ActionsTotal   int
	ActionsAllowed int
	ActionsDenied  int
	DurationMs     int
	ExitCode       int
}
