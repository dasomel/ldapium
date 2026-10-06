package config

import (
	"reflect"
	"testing"
)

// CORS_ALLOWED_ORIGINS (change package api-error-envelope, D218-12, AC-012):
// exact scheme://host[:port] origins only; anything that could widen the
// policy or never match a browser Origin refuses to start.
func TestLoad_CORSAllowedOrigins(t *testing.T) {
	base := map[string]string{
		"LDAP_URL":       "ldap://ldap.example.com:389",
		"LDAP_BASE_DN":   "dc=example,dc=com",
		"SESSION_SECRET": "01234567890123456789012345678901",
	}
	load := func(raw string) (Config, error) {
		m := map[string]string{"CORS_ALLOWED_ORIGINS": raw}
		for k, v := range base {
			m[k] = v
		}
		return Load(env(m))
	}

	for _, empty := range []string{"", "   "} {
		cfg, err := load(empty)
		if err != nil || len(cfg.CORSAllowedOrigins) != 0 {
			t.Errorf("CORS_ALLOWED_ORIGINS=%q: got %v, %v; want no origins (CORS off)", empty, cfg.CORSAllowedOrigins, err)
		}
	}

	good := map[string][]string{
		"https://app.example":                             {"https://app.example"},
		"http://localhost:5173":                           {"http://localhost:5173"},
		"https://a.example, https://b.example:8443":       {"https://a.example", "https://b.example:8443"},
		"HTTPS://App.Example":                             {"https://app.example"},
		"https://a.example,https://a.example":             {"https://a.example"},
		"http://[::1]:3000":                               {"http://[::1]:3000"},
		"https://console.corp.example,http://10.0.0.5:80": {"https://console.corp.example", "http://10.0.0.5:80"},
	}
	for raw, want := range good {
		cfg, err := load(raw)
		if err != nil {
			t.Errorf("%q rejected: %v", raw, err)
			continue
		}
		if !reflect.DeepEqual(cfg.CORSAllowedOrigins, want) {
			t.Errorf("%q = %v, want %v", raw, cfg.CORSAllowedOrigins, want)
		}
	}

	bad := []string{
		"*", "https://*.example", "https://*", "null", "NULL", "https://a.example,*",
		"https://app.example/", "https://app.example/path", "https://app.example?x=1", "https://app.example#f",
		"https://user@app.example", "https://user:pw@app.example", "app.example", "//app.example", "ftp://app.example",
		"https://", "https://:443", "https://a.example,,https://b.example", "https://a.example,", ",https://a.example",
		"https://a.example:port", "javascript:alert(1)", "https://app example", "https://a.example https://b.example",
	}
	for _, raw := range bad {
		if _, err := load(raw); err == nil {
			t.Errorf("%q accepted, want a startup error", raw)
		}
	}
}
