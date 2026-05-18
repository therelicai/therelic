package exfiltration

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"

	"github.com/therelicai/therelic/internal/policy"
)

// Default sensitive patterns cover common secret formats.
var DefaultPatterns = []string{
	`sk_live_[a-zA-Z0-9]{20,}`,
	`sk_test_[a-zA-Z0-9]{20,}`,
	`pk_live_[a-zA-Z0-9]{20,}`,
	`pk_test_[a-zA-Z0-9]{20,}`,
	`ghp_[a-zA-Z0-9]{36,}`,
	`gho_[a-zA-Z0-9]{36,}`,
	`github_pat_[a-zA-Z0-9_]{20,}`,
	`AKIA[A-Z0-9]{16}`,
	`eyJ[a-zA-Z0-9_-]{10,}\.`,
	`[a-zA-Z0-9_-]{40,}`,
}

// networkTools lists MCP tool names that make outbound HTTP requests.
var networkTools = map[string]bool{
	"web_fetch":    true,
	"fetch":        true,
	"http_request": true,
	"curl":         true,
	"wget":         true,
	"request":      true,
}

// Guard inspects outbound URLs for signs of data exfiltration.
// It checks query parameter values against known secret patterns
// and entropy thresholds.
type Guard struct {
	patterns       []*regexp.Regexp
	maxEntropy     float64
	minValueLength int
	action         string // "deny" or "audit"
}

// Result describes a triggered exfiltration rule.
type Result struct {
	Triggered bool
	RuleID    string // e.g. "exfiltration:pattern", "exfiltration:entropy"
	Reason    string
	Value     string // the suspicious value (truncated)
}

// NewGuard creates an exfiltration guard from the policy config.
func NewGuard(cfg policy.ExfiltrationConfig) *Guard {
	if !cfg.Enabled {
		return nil
	}

	maxEntropy := cfg.MaxQueryEntropy
	if maxEntropy <= 0 {
		maxEntropy = 4.5
	}
	minLen := cfg.MinValueLength
	if minLen <= 0 {
		minLen = 16
	}
	action := cfg.BlockAction
	if action == "" {
		action = "deny"
	}

	patternStrs := cfg.SensitivePatterns
	if len(patternStrs) == 0 {
		patternStrs = DefaultPatterns
	}

	var patterns []*regexp.Regexp
	for _, p := range patternStrs {
		if re, err := regexp.Compile(p); err == nil {
			patterns = append(patterns, re)
		}
	}

	return &Guard{
		patterns:       patterns,
		maxEntropy:     maxEntropy,
		minValueLength: minLen,
		action:         action,
	}
}

// Action returns the configured block action ("deny" or "audit").
func (g *Guard) Action() string {
	return g.action
}

// CheckURL parses rawURL and inspects query parameter values for secrets or
// high-entropy strings. Returns nil if nothing suspicious is found.
func (g *Guard) CheckURL(rawURL string) *Result {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	for key, values := range u.Query() {
		for _, val := range values {
			if r := g.checkValue(val, key); r != nil {
				return r
			}
		}
	}

	// Also check path segments for embedded secrets.
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "" {
			continue
		}
		if r := g.checkValue(seg, "path"); r != nil {
			return r
		}
	}

	return nil
}

// CheckParams inspects MCP tool call parameters for outbound URLs.
// Only tools that make HTTP requests are checked.
func (g *Guard) CheckParams(params json.RawMessage, toolName string) *Result {
	if !networkTools[toolName] {
		return nil
	}
	if len(params) == 0 {
		return nil
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(params, &m); err != nil {
		return nil
	}

	urlKeys := []string{"url", "uri", "href", "endpoint"}
	for _, key := range urlKeys {
		raw, ok := m[key]
		if !ok {
			continue
		}
		var urlStr string
		if json.Unmarshal(raw, &urlStr) == nil && urlStr != "" {
			if r := g.CheckURL(urlStr); r != nil {
				return r
			}
		}
	}

	return nil
}

func (g *Guard) checkValue(val, paramName string) *Result {
	if len(val) < g.minValueLength {
		return nil
	}

	for _, re := range g.patterns {
		if re.MatchString(val) {
			return &Result{
				Triggered: true,
				RuleID:    "exfiltration:pattern",
				Reason:    fmt.Sprintf("query param %q matches sensitive pattern %q", paramName, re.String()),
				Value:     truncate(val, 32),
			}
		}
	}

	if e := shannonEntropy(val); e > g.maxEntropy {
		return &Result{
			Triggered: true,
			RuleID:    "exfiltration:entropy",
			Reason:    fmt.Sprintf("query param %q has high entropy (%.2f bits/char)", paramName, e),
			Value:     truncate(val, 32),
		}
	}

	return nil
}

func shannonEntropy(s string) float64 {
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len([]rune(s)))
	var entropy float64
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
