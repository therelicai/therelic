// Package redact removes sensitive values from trace events before they are
// written to disk. It implements the Stage 1 redaction rules from
// architecture section 7.4: simple key-name matching (case-insensitive),
// recursive for nested JSON objects, no regex patterns.
package redact

import (
	"encoding/json"
	"strings"

	"github.com/therelicai/therelic/internal/policy"
)

const placeholder = "[REDACTED]"

// placeholderJSON is the pre-encoded JSON string for the placeholder.
var placeholderJSON = func() json.RawMessage {
	b, _ := json.Marshal(placeholder)
	return b
}()

// Redactor applies the configured redaction rules to trace event parameters
// and HTTP headers. The zero value (nil keys/headers) is safe and performs no
// redaction. All methods are safe for concurrent use (read-only after creation).
type Redactor struct {
	keys    []string // lowercased parameter key names
	headers []string // lowercased HTTP header names
}

// NewRedactor creates a Redactor from the given configuration.
// Key and header names are lowercased at construction time for efficient
// case-insensitive comparison at redaction time.
func NewRedactor(cfg policy.RedactionConfig) *Redactor {
	r := &Redactor{
		keys:    make([]string, len(cfg.Keys)),
		headers: make([]string, len(cfg.Headers)),
	}
	for i, k := range cfg.Keys {
		r.keys[i] = strings.ToLower(k)
	}
	for i, h := range cfg.Headers {
		r.headers[i] = strings.ToLower(h)
	}
	return r
}

// RedactParams scans the top-level keys of a JSON object (and recursively all
// nested objects) against the configured redaction key list. Each matching key's
// value is replaced with "[REDACTED]". Non-object JSON values (arrays, strings,
// numbers, null) are returned unchanged. Returns the original bytes if parsing
// fails or no keys are configured.
//
// Array elements that are objects are also scanned recursively.
func (r *Redactor) RedactParams(params json.RawMessage) json.RawMessage {
	if len(params) == 0 || len(r.keys) == 0 {
		return params
	}
	result, changed := r.redactValue(params)
	if !changed {
		return params
	}
	return result
}

// RedactHeaders returns a copy of the header map with values replaced by
// "[REDACTED]" for any header whose name (case-insensitive) is in the
// configured headers list. Returns the original map if no headers are
// configured or no matches are found.
func (r *Redactor) RedactHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 || len(r.headers) == 0 {
		return headers
	}
	// Scan first to avoid allocating if nothing matches.
	modified := false
	for k := range headers {
		if r.matchHeader(k) {
			modified = true
			break
		}
	}
	if !modified {
		return headers
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		if r.matchHeader(k) {
			out[k] = placeholder
		} else {
			out[k] = v
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Internal recursion
// ---------------------------------------------------------------------------

// redactValue inspects a single JSON value and applies redaction rules.
// It returns the (possibly modified) bytes and whether any change was made.
func (r *Redactor) redactValue(raw json.RawMessage) (json.RawMessage, bool) {
	if len(raw) == 0 {
		return raw, false
	}
	switch raw[0] {
	case '{':
		return r.redactObject(raw)
	case '[':
		return r.redactArray(raw)
	default:
		return raw, false
	}
}

// redactObject processes a JSON object, redacting matching keys and recursing.
func (r *Redactor) redactObject(raw json.RawMessage) (json.RawMessage, bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw, false
	}

	changed := false
	out := make(map[string]json.RawMessage, len(obj))
	for k, v := range obj {
		if r.matchKey(k) {
			out[k] = placeholderJSON
			changed = true
		} else {
			redacted, mod := r.redactValue(v)
			out[k] = redacted
			if mod {
				changed = true
			}
		}
	}
	if !changed {
		return raw, false
	}
	result, err := json.Marshal(out)
	if err != nil {
		return raw, false
	}
	return result, true
}

// redactArray processes a JSON array, recursing into any object elements.
func (r *Redactor) redactArray(raw json.RawMessage) (json.RawMessage, bool) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return raw, false
	}

	changed := false
	out := make([]json.RawMessage, len(arr))
	for i, v := range arr {
		redacted, mod := r.redactValue(v)
		out[i] = redacted
		if mod {
			changed = true
		}
	}
	if !changed {
		return raw, false
	}
	result, err := json.Marshal(out)
	if err != nil {
		return raw, false
	}
	return result, true
}

func (r *Redactor) matchKey(key string) bool {
	lower := strings.ToLower(key)
	for _, k := range r.keys {
		if k == lower {
			return true
		}
	}
	return false
}

func (r *Redactor) matchHeader(header string) bool {
	lower := strings.ToLower(header)
	for _, h := range r.headers {
		if h == lower {
			return true
		}
	}
	return false
}
