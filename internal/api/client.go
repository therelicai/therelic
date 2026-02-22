package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
)

const (
	DefaultBaseURL = "https://api.therelic.dev/v1"
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
		return nil, fmt.Errorf("no API key configured — sign up at https://therelic.dev and set RELIC_API_KEY")
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
		return fmt.Errorf("upload trace: %w", err)
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
		return fmt.Errorf("register agent: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// PullPolicy fetches the current policy for the named agent.
func (c *Client) PullPolicy(ctx context.Context, agentName string) ([]byte, error) {
	url := fmt.Sprintf("%s/agents/%s/policy", c.BaseURL, agentName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pull policy: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		json.Unmarshal(body, &errResp)
		return nil, fmt.Errorf("policy pull failed (HTTP %d): %s", resp.StatusCode, errResp["error"])
	}

	return body, nil
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
