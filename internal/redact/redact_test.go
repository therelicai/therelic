package redact

import (
	"encoding/json"
	"testing"

	"github.com/therelicai/therelic/internal/policy"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func makeRedactor(keys, headers []string) *Redactor {
	return NewRedactor(policy.RedactionConfig{Keys: keys, Headers: headers})
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// assertJSONEqual compares two JSON byte slices semantically (key order irrelevant).
func assertJSONEqual(t *testing.T, got, want json.RawMessage) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("got is invalid JSON: %v\n  got=%s", err, got)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatalf("want is invalid JSON: %v\n  want=%s", err, want)
	}
	gotJSON, _ := json.Marshal(g)
	wantJSON, _ := json.Marshal(w)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("JSON mismatch:\n  got  = %s\n  want = %s", gotJSON, wantJSON)
	}
}

// ---------------------------------------------------------------------------
// RedactParams — flat object
// ---------------------------------------------------------------------------

func TestRedactParams_MatchingKeyRedacted(t *testing.T) {
	r := makeRedactor([]string{"password"}, nil)
	input := mustMarshal(map[string]any{"password": "secret123", "query": "hello"})
	got := r.RedactParams(input)
	want := mustMarshal(map[string]any{"password": "[REDACTED]", "query": "hello"})
	assertJSONEqual(t, got, want)
}

func TestRedactParams_CaseInsensitiveKey(t *testing.T) {
	r := makeRedactor([]string{"password"}, nil)
	// Key in JSON is "Password" (capital P), config has "password".
	input := mustMarshal(map[string]any{"Password": "secret", "x": 1})
	got := r.RedactParams(input)
	want := mustMarshal(map[string]any{"Password": "[REDACTED]", "x": 1})
	assertJSONEqual(t, got, want)
}

func TestRedactParams_NonMatchingKeyUntouched(t *testing.T) {
	r := makeRedactor([]string{"password"}, nil)
	input := mustMarshal(map[string]any{"query": "hello", "count": 42})
	got := r.RedactParams(input)
	assertJSONEqual(t, got, input)
}

func TestRedactParams_MultipleMatchingKeys(t *testing.T) {
	r := makeRedactor([]string{"password", "token", "secret"}, nil)
	input := mustMarshal(map[string]any{
		"password": "pw",
		"token":    "tok",
		"secret":   "sec",
		"name":     "alice",
	})
	got := r.RedactParams(input)
	want := mustMarshal(map[string]any{
		"password": "[REDACTED]",
		"token":    "[REDACTED]",
		"secret":   "[REDACTED]",
		"name":     "alice",
	})
	assertJSONEqual(t, got, want)
}

func TestRedactParams_EmptyRedactionConfig_NoChange(t *testing.T) {
	r := makeRedactor(nil, nil)
	input := mustMarshal(map[string]any{"password": "secret", "x": 1})
	got := r.RedactParams(input)
	assertJSONEqual(t, got, input)
}

func TestRedactParams_EmptyParams_ReturnedUnchanged(t *testing.T) {
	r := makeRedactor([]string{"password"}, nil)
	var empty json.RawMessage
	got := r.RedactParams(empty)
	if len(got) != 0 {
		t.Errorf("expected empty, got %s", got)
	}
}

func TestRedactParams_NullParams_ReturnedUnchanged(t *testing.T) {
	r := makeRedactor([]string{"password"}, nil)
	input := json.RawMessage(`null`)
	got := r.RedactParams(input)
	if string(got) != "null" {
		t.Errorf("got=%s want null", got)
	}
}

func TestRedactParams_ArrayParams_ReturnedUnchanged(t *testing.T) {
	r := makeRedactor([]string{"password"}, nil)
	input := mustMarshal([]string{"a", "b"})
	got := r.RedactParams(input)
	// Arrays are recursed but have no keys to match.
	assertJSONEqual(t, got, input)
}

func TestRedactParams_StringParams_ReturnedUnchanged(t *testing.T) {
	r := makeRedactor([]string{"password"}, nil)
	input := json.RawMessage(`"just a string"`)
	got := r.RedactParams(input)
	if string(got) != `"just a string"` {
		t.Errorf("got=%s", got)
	}
}

// ---------------------------------------------------------------------------
// RedactParams — nested objects
// ---------------------------------------------------------------------------

func TestRedactParams_NestedObject_KeyRedacted(t *testing.T) {
	r := makeRedactor([]string{"token"}, nil)
	input := mustMarshal(map[string]any{
		"auth": map[string]any{"token": "abc123"},
		"user": "bob",
	})
	got := r.RedactParams(input)
	want := mustMarshal(map[string]any{
		"auth": map[string]any{"token": "[REDACTED]"},
		"user": "bob",
	})
	assertJSONEqual(t, got, want)
}

func TestRedactParams_DeepNesting_RedactedAtEveryLevel(t *testing.T) {
	r := makeRedactor([]string{"secret"}, nil)
	input := mustMarshal(map[string]any{
		"a": map[string]any{
			"b": map[string]any{
				"secret": "deep-value",
				"other":  "ok",
			},
		},
	})
	got := r.RedactParams(input)
	want := mustMarshal(map[string]any{
		"a": map[string]any{
			"b": map[string]any{
				"secret": "[REDACTED]",
				"other":  "ok",
			},
		},
	})
	assertJSONEqual(t, got, want)
}

func TestRedactParams_BothTopLevelAndNested(t *testing.T) {
	r := makeRedactor([]string{"password"}, nil)
	input := mustMarshal(map[string]any{
		"password": "top",
		"creds": map[string]any{
			"password": "nested",
			"username": "alice",
		},
	})
	got := r.RedactParams(input)
	want := mustMarshal(map[string]any{
		"password": "[REDACTED]",
		"creds": map[string]any{
			"password": "[REDACTED]",
			"username": "alice",
		},
	})
	assertJSONEqual(t, got, want)
}

func TestRedactParams_ArrayOfObjects_Recursed(t *testing.T) {
	r := makeRedactor([]string{"token"}, nil)
	input := mustMarshal([]any{
		map[string]any{"token": "tok1", "id": 1},
		map[string]any{"token": "tok2", "id": 2},
	})
	got := r.RedactParams(input)
	want := mustMarshal([]any{
		map[string]any{"token": "[REDACTED]", "id": 1},
		map[string]any{"token": "[REDACTED]", "id": 2},
	})
	assertJSONEqual(t, got, want)
}

// ---------------------------------------------------------------------------
// RedactParams — invalid / edge cases
// ---------------------------------------------------------------------------

func TestRedactParams_InvalidJSON_ReturnedUnchanged(t *testing.T) {
	r := makeRedactor([]string{"password"}, nil)
	input := json.RawMessage(`{invalid json}`)
	got := r.RedactParams(input)
	if string(got) != string(input) {
		t.Errorf("expected unchanged invalid JSON, got=%s", got)
	}
}

func TestRedactParams_ValueIsNumber_Redacted(t *testing.T) {
	r := makeRedactor([]string{"pin"}, nil)
	input := mustMarshal(map[string]any{"pin": 1234, "name": "alice"})
	got := r.RedactParams(input)
	want := mustMarshal(map[string]any{"pin": "[REDACTED]", "name": "alice"})
	assertJSONEqual(t, got, want)
}

func TestRedactParams_ValueIsBool_Redacted(t *testing.T) {
	r := makeRedactor([]string{"secret"}, nil)
	input := mustMarshal(map[string]any{"secret": true, "ok": false})
	got := r.RedactParams(input)
	want := mustMarshal(map[string]any{"secret": "[REDACTED]", "ok": false})
	assertJSONEqual(t, got, want)
}

func TestRedactParams_ValueIsNull_Redacted(t *testing.T) {
	r := makeRedactor([]string{"password"}, nil)
	input := json.RawMessage(`{"password":null,"x":1}`)
	got := r.RedactParams(input)
	want := mustMarshal(map[string]any{"password": "[REDACTED]", "x": 1})
	assertJSONEqual(t, got, want)
}

// ---------------------------------------------------------------------------
// RedactHeaders
// ---------------------------------------------------------------------------

func TestRedactHeaders_MatchingHeaderRedacted(t *testing.T) {
	r := makeRedactor(nil, []string{"Authorization"})
	headers := map[string]string{
		"Authorization": "Bearer xyz",
		"Content-Type":  "application/json",
	}
	got := r.RedactHeaders(headers)
	if got["Authorization"] != "[REDACTED]" {
		t.Errorf("Authorization=%q want [REDACTED]", got["Authorization"])
	}
	if got["Content-Type"] != "application/json" {
		t.Errorf("Content-Type=%q want application/json", got["Content-Type"])
	}
}

func TestRedactHeaders_CaseInsensitiveHeader(t *testing.T) {
	r := makeRedactor(nil, []string{"authorization"})
	headers := map[string]string{
		"Authorization": "Bearer token",
	}
	got := r.RedactHeaders(headers)
	if got["Authorization"] != "[REDACTED]" {
		t.Errorf("Authorization=%q want [REDACTED]", got["Authorization"])
	}
}

func TestRedactHeaders_NonMatchingHeader_Untouched(t *testing.T) {
	r := makeRedactor(nil, []string{"Authorization"})
	headers := map[string]string{"Content-Type": "text/plain"}
	got := r.RedactHeaders(headers)
	if got["Content-Type"] != "text/plain" {
		t.Errorf("Content-Type=%q want text/plain", got["Content-Type"])
	}
}

func TestRedactHeaders_EmptyRedactionConfig_NoChange(t *testing.T) {
	r := makeRedactor(nil, nil)
	headers := map[string]string{"Authorization": "Bearer token"}
	got := r.RedactHeaders(headers)
	if got["Authorization"] != "Bearer token" {
		t.Errorf("Authorization=%q want original value", got["Authorization"])
	}
}

func TestRedactHeaders_EmptyHeaders_ReturnedUnchanged(t *testing.T) {
	r := makeRedactor(nil, []string{"Authorization"})
	got := r.RedactHeaders(map[string]string{})
	if len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}
}

func TestRedactHeaders_MultipleHeadersRedacted(t *testing.T) {
	r := makeRedactor(nil, []string{"Authorization", "X-Api-Key", "Cookie"})
	headers := map[string]string{
		"Authorization": "Bearer token",
		"X-Api-Key":     "key123",
		"Cookie":        "session=abc",
		"Content-Type":  "application/json",
	}
	got := r.RedactHeaders(headers)
	for _, h := range []string{"Authorization", "X-Api-Key", "Cookie"} {
		if got[h] != "[REDACTED]" {
			t.Errorf("%s=%q want [REDACTED]", h, got[h])
		}
	}
	if got["Content-Type"] != "application/json" {
		t.Errorf("Content-Type=%q want original", got["Content-Type"])
	}
}

// ---------------------------------------------------------------------------
// NewRedactor construction
// ---------------------------------------------------------------------------

func TestNewRedactor_NilConfig_Safe(t *testing.T) {
	r := NewRedactor(policy.RedactionConfig{})
	params := mustMarshal(map[string]any{"password": "secret"})
	// Should return unchanged.
	got := r.RedactParams(params)
	assertJSONEqual(t, got, params)
}

func TestNewRedactor_KeysCaseNormalized(t *testing.T) {
	// Config uses uppercase; JSON uses lowercase — should still match.
	r := makeRedactor([]string{"PASSWORD"}, nil)
	input := mustMarshal(map[string]any{"password": "pw"})
	got := r.RedactParams(input)
	want := mustMarshal(map[string]any{"password": "[REDACTED]"})
	assertJSONEqual(t, got, want)
}
