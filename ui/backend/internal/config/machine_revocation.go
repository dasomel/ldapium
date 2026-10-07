package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// RevocationConfig is the machine token revocation configuration (change
// package machine-token-revocation, T-010, D3/D4/D12). It is parsed and
// validated only; no consumer reads it yet, so it cannot change behaviour.
type RevocationConfig struct {
	Enabled bool
	// Refresh is the snapshot refresh period; MaxStale is how long a snapshot
	// stays usable after a failed refresh (counted from the query start).
	Refresh  time.Duration
	MaxStale time.Duration
	// SentinelMaxAge is the oldest sentinel ts a refresh accepts (REQ-013).
	SentinelMaxAge time.Duration
	// BaseDN is the canonical ou=revocations,... search base (never the root).
	BaseDN string
	// MaxEntries bounds the active entries one refresh may return.
	MaxEntries int
}

// Revocation sizing: the client size limit is MaxEntries+2 and a response is
// capped at 1 MiB, so MaxEntries x ~400 B must fit. 2500 x 400 B = 1,000,000 B
// <= 1 MiB; the upper bound below is that check made static.
const (
	revocationMaxEntriesHi  = 2500
	revocationEntryBytes    = 400
	revocationResponseBytes = 1 << 20
	revocationMinStaleGap   = 5 * time.Second
)

var _ [revocationResponseBytes - revocationMaxEntriesHi*revocationEntryBytes]struct{} // build fails if the cap outgrows 1 MiB

// loadMachineRevocation parses MACHINE_REVOCATION_* (D12). It is ignored (and
// reads nothing) when machine auth is off, and with ENABLED unset/false no
// sub-value is read. MAX_STALE defaults to 3 x REFRESH, raised to REFRESH + 5 s
// so a 1 s REFRESH still yields a default that passes the startup check. Every range violation is a startup failure.
func loadMachineRevocation(getenv func(string) string, cfg *Config) (RevocationConfig, error) {
	var r RevocationConfig
	on, err := boolEnv(getenv, "MACHINE_REVOCATION_ENABLED", false)
	if err != nil || !on {
		return r, err
	}
	r.Enabled = true

	d := machineDurations{getenv: getenv}
	r.Refresh = d.get("MACHINE_REVOCATION_REFRESH", 5*time.Second, time.Second, time.Minute)
	if d.err != nil {
		return RevocationConfig{}, d.err
	}
	r.MaxStale = d.get("MACHINE_REVOCATION_MAX_STALE", max(3*r.Refresh, r.Refresh+revocationMinStaleGap), r.Refresh, 10*time.Minute)
	r.SentinelMaxAge = d.get("MACHINE_REVOCATION_SENTINEL_MAX_AGE", 5*time.Minute, 30*time.Second, time.Hour)
	if d.err != nil {
		return RevocationConfig{}, d.err
	}
	if r.MaxStale < r.Refresh+revocationMinStaleGap {
		return RevocationConfig{}, fmt.Errorf("MACHINE_REVOCATION_MAX_STALE must be at least MACHINE_REVOCATION_REFRESH + 5s")
	}

	n := machineInts{getenv: getenv}
	r.MaxEntries = n.get("MACHINE_REVOCATION_MAX_ENTRIES", 2000, 1, revocationMaxEntriesHi)
	if n.err != nil {
		return RevocationConfig{}, n.err
	}

	raw := strings.TrimSpace(getenv("MACHINE_REVOCATION_BASE_DN"))
	if raw == "" {
		raw = "ou=revocations,ou=system," + cfg.BaseDN
	}
	if r.BaseDN, err = canonRevocationBaseDN(raw); err != nil {
		return RevocationConfig{}, err
	}
	return r, nil
}

// canonRevocationBaseDN accepts exactly "ou=revocations,<parent...>": a
// single-valued first RDN naming ou=revocations (case-insensitive) and at least
// one parent RDN, so neither the root nor any other container qualifies (D4).
// The result is canonical: lower-case attribute types, "revocations".
func canonRevocationBaseDN(raw string) (string, error) {
	const msg = "MACHINE_REVOCATION_BASE_DN must be a DN of the form ou=revocations,<parent DN>"
	dn, err := ldap.ParseDN(raw)
	if err != nil || len(dn.RDNs) < 2 {
		return "", fmt.Errorf("%s", msg)
	}
	first := dn.RDNs[0]
	if len(first.Attributes) != 1 || !strings.EqualFold(first.Attributes[0].Type, "ou") ||
		!strings.EqualFold(first.Attributes[0].Value, "revocations") {
		return "", fmt.Errorf("%s", msg)
	}
	for _, rdn := range dn.RDNs {
		for _, a := range rdn.Attributes {
			a.Type = strings.ToLower(a.Type)
		}
	}
	first.Attributes[0].Value = "revocations"
	return dn.String(), nil
}

// RevocationRetentionInputs are the four terms of the jti retention formula
// ret = MaxTTL + 3 x skew + REFRESH + MAX_STALE (CHANGE.md D2). The formula
// itself lives in one place (machineauth, T-012); config only exposes inputs.
func (m MachineConfig) RevocationRetentionInputs() (maxTTL, skew, refresh, maxStale time.Duration) {
	return m.MaxTTL, m.ClockSkew, m.Revocation.Refresh, m.Revocation.MaxStale
}
