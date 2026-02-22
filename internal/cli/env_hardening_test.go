package cli

import (
	"testing"
)

func TestSanitizeEnv_RemovesProxyOverrides(t *testing.T) {
	env := []string{
		"HOME=/home/user",
		"PATH=/usr/bin",
		"HTTP_PROXY=http://attacker:8080",
		"HTTPS_PROXY=http://attacker:8080",
		"http_proxy=http://attacker:8080",
		"https_proxy=http://attacker:8080",
		"NO_PROXY=*",
		"no_proxy=*",
		"ALL_PROXY=socks5://attacker",
		"EDITOR=vim",
	}

	result := sanitizeEnv(env)

	allowed := map[string]bool{"HOME": true, "PATH": true, "EDITOR": true}
	for _, kv := range result {
		key := kv
		for i, c := range kv {
			if c == '=' {
				key = kv[:i]
				break
			}
		}
		if !allowed[key] {
			t.Errorf("blocked env var leaked through: %s", key)
		}
	}
	if len(result) != 3 {
		t.Errorf("expected 3 vars, got %d: %v", len(result), result)
	}
}

func TestSanitizeEnv_RemovesTLSBypass(t *testing.T) {
	env := []string{
		"HOME=/home/user",
		"NODE_TLS_REJECT_UNAUTHORIZED=0",
		"PYTHONHTTPSVERIFY=0",
		"GIT_SSL_NO_VERIFY=1",
	}

	result := sanitizeEnv(env)
	if len(result) != 1 {
		t.Errorf("expected 1 var, got %d: %v", len(result), result)
	}
}

func TestSanitizeEnv_RemovesLibraryInjection(t *testing.T) {
	env := []string{
		"HOME=/home/user",
		"LD_PRELOAD=/tmp/evil.so",
		"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib",
		"LD_LIBRARY_PATH=/tmp/evil",
	}

	result := sanitizeEnv(env)
	if len(result) != 1 {
		t.Errorf("expected 1 var, got %d: %v", len(result), result)
	}
}

func TestSanitizeEnv_RemovesRelicOverrides(t *testing.T) {
	env := []string{
		"HOME=/home/user",
		"RELIC_RUN_ID=attacker-id",
		"RELIC_TRACE_DIR=/dev/null",
		"RELIC_POLICY=/tmp/evil-policy.yaml",
		"RELIC_GOVERNED=0",
	}

	result := sanitizeEnv(env)
	if len(result) != 1 {
		t.Errorf("expected 1 var, got %d: %v", len(result), result)
	}
}

func TestSanitizeEnv_PreservesNormalVars(t *testing.T) {
	env := []string{
		"HOME=/home/user",
		"PATH=/usr/bin:/usr/local/bin",
		"GOPATH=/home/user/go",
		"EDITOR=vim",
		"SHELL=/bin/bash",
		"LANG=en_US.UTF-8",
		"TERM=xterm-256color",
		"MY_APP_CONFIG=custom-value",
	}

	result := sanitizeEnv(env)
	if len(result) != len(env) {
		t.Errorf("expected all %d vars preserved, got %d", len(env), len(result))
	}
}
