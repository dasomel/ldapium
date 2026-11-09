package config

import "testing"

// UI_BASE_PATH (change ui-base-path, D1): empty or "/" is the root, anything
// else is normalized to a leading "/" without a trailing one, and values that
// could escape a cookie Path or a Location header refuse to start.
func TestLoad_UIBasePath(t *testing.T) {
	load := func(raw string) (Config, error) {
		return Load(env(map[string]string{
			"LDAP_URL":       "ldap://ldap.example.com:389",
			"LDAP_BASE_DN":   "dc=example,dc=com",
			"SESSION_SECRET": "01234567890123456789012345678901",
			"UI_BASE_PATH":   raw,
		}))
	}

	good := map[string]string{
		"":            "",
		"   ":         "",
		"/":           "",
		"ldapium":     "/ldapium",
		"/ldapium":    "/ldapium",
		"/ldapium/":   "/ldapium",
		" /ldapium ":  "/ldapium",
		"/a/b":        "/a/b",
		"/a.b_c~d-e1": "/a.b_c~d-e1",
		"/LDAP":       "/LDAP",
		"/..a":        "/..a",
	}
	for raw, want := range good {
		cfg, err := load(raw)
		if err != nil {
			t.Errorf("%q rejected: %v", raw, err)
			continue
		}
		if cfg.BasePath != want {
			t.Errorf("%q = %q, want %q", raw, cfg.BasePath, want)
		}
	}

	for _, raw := range []string{"/a//b", "//", "/a//", "/a/../b", "/..", "/.", "/%2e", "/a%2Fb", "/a b", "/a?x", "/a#x", "/a;b", `/a\b`, "/é", "/a/./b"} {
		if _, err := load(raw); err == nil {
			t.Errorf("%q accepted, want error", raw)
		}
	}
}
