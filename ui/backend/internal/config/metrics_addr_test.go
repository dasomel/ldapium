package config

import (
	"strings"
	"testing"
)

func TestLoad_MetricsAddr(t *testing.T) {
	base := map[string]string{
		"LDAP_URL":       "ldap://ldap.example.com:389",
		"LDAP_BASE_DN":   "dc=example,dc=com",
		"SESSION_SECRET": "01234567890123456789012345678901",
	}
	with := func(kv ...string) func(string) string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return env(m)
	}

	cfg, err := Load(with())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MetricsAddr != "" {
		t.Errorf("MetricsAddr = %q, want empty (listener off) by default", cfg.MetricsAddr)
	}

	for _, ok := range []string{"127.0.0.1:9331", ":9331", "0.0.0.0:9331", "[::1]:9331", "metrics.internal:9331", " 127.0.0.1:9331 "} {
		cfg, err := Load(with("METRICS_ADDR", ok))
		if err != nil {
			t.Errorf("METRICS_ADDR=%q rejected: %v", ok, err)
			continue
		}
		if cfg.MetricsAddr != strings.TrimSpace(ok) {
			t.Errorf("METRICS_ADDR=%q stored as %q", ok, cfg.MetricsAddr)
		}
	}

	for _, bad := range []string{"9331", "127.0.0.1", "127.0.0.1:", "127.0.0.1:0", "127.0.0.1:70000", "127.0.0.1:http", "127.0.0.1:-1", "http://127.0.0.1:9331", "127.0.0.1:9331/metrics", "a b:9331"} {
		if _, err := Load(with("METRICS_ADDR", bad)); err == nil {
			t.Errorf("METRICS_ADDR=%q accepted, want an error", bad)
		}
	}

	// The metrics listener must not collide with the public one.
	if _, err := Load(with("METRICS_ADDR", ":8080")); err == nil {
		t.Error("METRICS_ADDR equal to the default LISTEN_ADDR accepted")
	}
	if _, err := Load(with("LISTEN_ADDR", "127.0.0.1:9000", "METRICS_ADDR", "127.0.0.1:9000")); err == nil {
		t.Error("METRICS_ADDR equal to LISTEN_ADDR accepted")
	}
}
