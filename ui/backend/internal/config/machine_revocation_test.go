package config

import (
	"strings"
	"testing"
	"time"
)

func revEnv(over map[string]string) func(string) string {
	m := map[string]string{"MACHINE_REVOCATION_ENABLED": "true"}
	for k, v := range over {
		m[k] = v
	}
	return machineEnv(m)
}

// machine-token-revocation T-010: off by default, ignored with machine auth
// off, and with its own switch off no sub-value is read.
func TestMachineRevocation_DisabledReadsNothing(t *testing.T) {
	garbage := map[string]string{
		"MACHINE_REVOCATION_REFRESH": "nope", "MACHINE_REVOCATION_MAX_STALE": "-1",
		"MACHINE_REVOCATION_SENTINEL_MAX_AGE": "x", "MACHINE_REVOCATION_BASE_DN": "dc=example,dc=org",
		"MACHINE_REVOCATION_MAX_ENTRIES": "99999",
	}
	for name, over := range map[string]map[string]string{
		"unset":              nil,
		"false":              {"MACHINE_REVOCATION_ENABLED": "false"},
		"false with garbage": merge(garbage, map[string]string{"MACHINE_REVOCATION_ENABLED": "false"}),
		"unset with garbage": garbage,
		"machine auth off":   merge(garbage, map[string]string{"MACHINE_REVOCATION_ENABLED": "true", "MACHINE_AUTH_ENABLED": "-", "UI_TRUSTED_PROXIES": "-"}),
		"machine off, bogus": {"MACHINE_REVOCATION_ENABLED": "maybe", "MACHINE_AUTH_ENABLED": "-", "UI_TRUSTED_PROXIES": "-"},
	} {
		cfg, err := Load(machineEnv(over))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if cfg.Machine.Revocation != (RevocationConfig{}) {
			t.Errorf("%s: want zero config, got %+v", name, cfg.Machine.Revocation)
		}
	}
}

func merge(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func TestMachineRevocation_Defaults(t *testing.T) {
	cfg, err := Load(revEnv(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := RevocationConfig{
		Enabled: true, Refresh: 5 * time.Second, MaxStale: 15 * time.Second, SentinelMaxAge: 5 * time.Minute,
		BaseDN: "ou=revocations,ou=system,dc=example,dc=org", MaxEntries: 2000,
	}
	if cfg.Machine.Revocation != want {
		t.Fatalf("got %+v want %+v", cfg.Machine.Revocation, want)
	}
	ttl, skew, refresh, stale := cfg.Machine.RevocationRetentionInputs()
	if ttl != 10*time.Minute || skew != 30*time.Second || refresh != 5*time.Second || stale != 15*time.Second {
		t.Fatalf("inputs: %v %v %v %v", ttl, skew, refresh, stale)
	}
}

func TestMachineRevocation_Ranges(t *testing.T) {
	const (
		R = "MACHINE_REVOCATION_REFRESH"
		S = "MACHINE_REVOCATION_MAX_STALE"
		A = "MACHINE_REVOCATION_SENTINEL_MAX_AGE"
		N = "MACHINE_REVOCATION_MAX_ENTRIES"
	)
	cases := []struct {
		name string
		env  map[string]string
		want string // "" = accepted
	}{
		{"refresh 1s", map[string]string{R: "1s"}, ""},
		{"refresh 999ms", map[string]string{R: "999ms"}, R},
		{"refresh 60s", map[string]string{R: "60s"}, ""},
		{"refresh 61s", map[string]string{R: "61s"}, R},
		{"refresh garbage", map[string]string{R: "x"}, R},
		{"stale below refresh+5s", map[string]string{R: "5s", S: "9s"}, "REFRESH + 5s"},
		{"stale == refresh+5s", map[string]string{R: "5s", S: "10s"}, ""},
		{"stale below refresh", map[string]string{R: "5s", S: "4s"}, S},
		{"stale 10m", map[string]string{S: "10m"}, ""},
		{"stale 10m+1ns", map[string]string{S: "10m0.000000001s"}, S},
		{"refresh 60s default stale", map[string]string{R: "60s"}, ""},
		{"refresh 60s stale 64s", map[string]string{R: "60s", S: "64s"}, "REFRESH + 5s"},
		{"sentinel 30s", map[string]string{A: "30s"}, ""},
		{"sentinel 29s", map[string]string{A: "29s"}, A},
		{"sentinel 1h", map[string]string{A: "1h"}, ""},
		{"sentinel 1h1s", map[string]string{A: "1h1s"}, A},
		{"entries 1", map[string]string{N: "1"}, ""},
		{"entries 0", map[string]string{N: "0"}, N},
		{"entries 2500", map[string]string{N: "2500"}, ""},
		{"entries 2501", map[string]string{N: "2501"}, N},
		{"entries garbage", map[string]string{N: "many"}, N},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(revEnv(tc.env))
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v (%+v)", tc.want, err, cfg.Machine.Revocation)
			}
		})
	}
}

func TestMachineRevocation_DefaultMaxStaleScales(t *testing.T) {
	for refresh, want := range map[string]time.Duration{"1s": 6 * time.Second, "2s": 7 * time.Second, "10s": 30 * time.Second, "60s": 3 * time.Minute} {
		cfg, err := Load(revEnv(map[string]string{"MACHINE_REVOCATION_REFRESH": refresh}))
		if err != nil {
			t.Fatalf("%s: %v", refresh, err)
		}
		if cfg.Machine.Revocation.MaxStale != want {
			t.Errorf("%s: MaxStale %v want %v", refresh, cfg.Machine.Revocation.MaxStale, want)
		}
	}
}

func TestMachineRevocation_BaseDN(t *testing.T) {
	cases := []struct {
		name, dn, want string // want "" = rejected
	}{
		{"canonical", "ou=revocations,ou=system,dc=example,dc=org", "ou=revocations,ou=system,dc=example,dc=org"},
		{"odd case and spaces", " OU = Revocations , OU=system, DC=example,dc=org", "ou=revocations,ou=system,dc=example,dc=org"},
		{"directly under root", "ou=revocations,dc=example,dc=org", "ou=revocations,dc=example,dc=org"},
		{"escaped value", `ou=\72evocations,ou=system,dc=example,dc=org`, "ou=revocations,ou=system,dc=example,dc=org"},
		{"root", "dc=example,dc=org", ""},
		{"ou alone (relative)", "ou=revocations", ""},
		{"wrong ou", "ou=system,dc=example,dc=org", ""},
		{"wrong ou name", "ou=revocation,ou=system,dc=example,dc=org", ""},
		{"wrong attribute", "cn=revocations,ou=system,dc=example,dc=org", ""},
		{"multi-valued RDN", "ou=revocations+cn=x,ou=system,dc=example,dc=org", ""},
		{"revocations not first", "ou=system,ou=revocations,dc=example,dc=org", ""},
		{"not a DN", "revocations", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(revEnv(map[string]string{"MACHINE_REVOCATION_BASE_DN": tc.dn}))
			if tc.want == "" {
				if err == nil || !strings.Contains(err.Error(), "MACHINE_REVOCATION_BASE_DN") {
					t.Fatalf("want BASE_DN error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Machine.Revocation.BaseDN; got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
