package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// machine-write-scope-v2 T-020: W_cred configuration and start-up validation.
// Configuration only: directory.users.password.write stays an unopened scope
// (a ceiling naming it is still refused) and no operation binds as W_cred
// until T-026. T-028 adds what the run-time premise checks (D379-15/16) read:
// the ACL reader identity, the canaries and the pending TTL.

const (
	// credMinLengthDefault is the REQ-014 default policy floor (12).
	credMinLengthDefault = 12
	// T020-D1: the floor can be raised but never lowered below the documented
	// default, and is capped at validate.Password's 1024-character limit.
	// Cost: an operator cannot accept a pending policy shorter than 12.
	// Escape hatch: none at this unit; a lower floor needs a design revision.
	credMinLengthMax = 1024
	// T023-D2: MACHINE_WRITE_CRED_RATE_LIMIT_RPS, the global password budget
	// (REQ-013 default 1), is an integer 1-10 with a fixed burst of 1. Cost: no
	// burst knob, so a batch of initial passwords is paced at the rate. Escape
	// hatch: raise the rate; a higher cap widens the R-4 window (rate x timeout).
	credRateDefault = 1
	credRateMax     = 10
	// T028-D9: MACHINE_WRITE_CRED_PENDING_TTL, the TTL sweep's age (CHANGE.md
	// failure modes, Revision 8). Default 24h, 1h-720h. Cost: an automation that
	// sets the initial password later than this finds the marker gone (403, no
	// write). Escape hatch: raise it; the design fixes no value (a question for
	// the maintainer, not a decision).
	credPendingTTLDefault = 24 * time.Hour
	credPendingTTLMin     = time.Hour
	credPendingTTLMax     = 720 * time.Hour
)

// MachineWriteCredCanary is one canary set of D379-15 check 5, three entries
// inside one MACHINE_WRITE_CRED_SUBTREES DN, all administratively locked:
// WithPassword carries the pending marker and policy and a password (W_cred
// expects 50), Unmarked carries the pending policy but no marker and no
// password (50), Pending is a W_data-made pending account without a password
// (a 1-character value and a pre-hashed value both expect 19).
type MachineWriteCredCanary struct {
	WithPassword, Unmarked, Pending string
}

// DNs is the set in the configured order.
func (c MachineWriteCredCanary) DNs() []string {
	return []string{c.WithPassword, c.Unmarked, c.Pending}
}

// loadMachineWriteCredScope reads the remaining MACHINE_WRITE_CRED_* settings,
// only when MACHINE_WRITE_CRED_ENABLED is on (otherwise none is read):
//   - check 8 (D379-15): a non-empty MACHINE_WRITE_PRIVILEGED_GROUPS and
//     MACHINE_WRITE_CRED_SUBTREES ("client=dn|dn;..."; inclusion in the
//     client's MACHINE_WRITE_SUBTREES is checked by checkCredSubtrees, Q9);
//   - MACHINE_WRITE_CRED_MIN_LENGTH (default 12, T020-D1);
//   - MACHINE_WRITE_CRED_RATE_LIMIT_RPS (default 1, 1-10, T023-D2);
//   - MACHINE_WRITE_CRED_POLICY_DNS: optional ';'-separated allowlist, D26
//     form, strictly inside the base, at most 16, no case-folded duplicates;
//   - MACHINE_WRITE_CRED_PENDING_POLICY_DN (D379-18): required, D26 form,
//     strictly inside the base, distinct from the image's default policy, from
//     every protected identity and privileged group, and not in the allowlist.
//
// All policy DNs join the protected set. Errors never echo a value.
func loadMachineWriteCredScope(getenv func(string) string, cfg Config, m MachineConfig, w *MachineWriteConfig, base *ldap.DN, known map[string]bool) error {
	if !w.CredEnabled {
		return nil
	}
	if len(w.PrivilegedGroups) == 0 {
		return fmt.Errorf("MACHINE_WRITE_CRED_ENABLED requires MACHINE_WRITE_PRIVILEGED_GROUPS")
	}
	subtrees, err := parseMachineWriteClientDNs("MACHINE_WRITE_CRED_SUBTREES", getenv("MACHINE_WRITE_CRED_SUBTREES"), known)
	if err != nil {
		return err
	}
	if len(subtrees) == 0 {
		return fmt.Errorf("MACHINE_WRITE_CRED_ENABLED requires MACHINE_WRITE_CRED_SUBTREES for at least one client")
	}
	n := machineInts{getenv: getenv}
	minLength := n.get("MACHINE_WRITE_CRED_MIN_LENGTH", credMinLengthDefault, credMinLengthDefault, credMinLengthMax)
	rate := n.get("MACHINE_WRITE_CRED_RATE_LIMIT_RPS", credRateDefault, 1, credRateMax)
	if n.err != nil {
		return n.err
	}
	var policies []string
	var parsed []*ldap.DN
	for _, raw := range splitEntries(getenv("MACHINE_WRITE_CRED_POLICY_DNS")) {
		dn, err := canonicalWriteDN(raw)
		if err != nil {
			return fmt.Errorf("MACHINE_WRITE_CRED_POLICY_DNS: %w", err)
		}
		if !base.AncestorOfFold(dn) {
			return fmt.Errorf("MACHINE_WRITE_CRED_POLICY_DNS must lie strictly inside LDAP_BASE_DN")
		}
		for _, p := range parsed {
			if p.EqualFold(dn) {
				return fmt.Errorf("MACHINE_WRITE_CRED_POLICY_DNS lists a DN more than once")
			}
		}
		parsed = append(parsed, dn)
		policies = append(policies, raw)
	}
	if len(policies) > machineWriteMaxDNsPerClient {
		return fmt.Errorf("MACHINE_WRITE_CRED_POLICY_DNS allows at most %d DNs", machineWriteMaxDNsPerClient)
	}
	raw := getenv("MACHINE_WRITE_CRED_PENDING_POLICY_DN")
	if raw == "" {
		return fmt.Errorf("MACHINE_WRITE_CRED_ENABLED requires MACHINE_WRITE_CRED_PENDING_POLICY_DN")
	}
	pending, err := canonicalWriteDN(raw)
	if err != nil {
		return fmt.Errorf("MACHINE_WRITE_CRED_PENDING_POLICY_DN: %w", err)
	}
	if !base.AncestorOfFold(pending) {
		return fmt.Errorf("MACHINE_WRITE_CRED_PENDING_POLICY_DN must lie strictly inside LDAP_BASE_DN")
	}
	// T020-D2: "distinct from the default policy" is checked against the DN the
	// image writes into olcPPolicyDefault (image/entrypoint.sh). The live value
	// is read from cn=config only by the T-028 premise checks. Cost: a
	// deployment that moved its default policy is caught at T-028, not here.
	if def, _ := ldap.ParseDN("cn=default,ou=policies," + cfg.BaseDN); def.EqualFold(pending) {
		return fmt.Errorf("MACHINE_WRITE_CRED_PENDING_POLICY_DN must differ from the default password policy")
	}
	// T020-D3: the pending policy is the one policy every v2c target carries
	// (the W_cred filter names it), so it is not also an allowlist entry: one
	// DN, one meaning.
	for _, p := range parsed {
		if p.EqualFold(pending) {
			return fmt.Errorf("MACHINE_WRITE_CRED_PENDING_POLICY_DN must not be listed in MACHINE_WRITE_CRED_POLICY_DNS")
		}
	}
	for _, other := range machineWriteProtectedDNs(cfg, m, *w) {
		p, err := ldap.ParseDN(other)
		if err != nil || !writeIdentityDNUnambiguous(p) {
			return fmt.Errorf("MACHINE_WRITE_CRED_PENDING_POLICY_DN requires unambiguous protected identity DNs")
		}
		if p.EqualFold(pending) {
			return fmt.Errorf("MACHINE_WRITE_CRED_PENDING_POLICY_DN must be distinct from every protected identity and privileged group")
		}
	}
	w.CredSubtrees, w.CredMinLength, w.CredPolicyDNs, w.CredPendingPolicyDN = subtrees, minLength, policies, raw
	w.CredRateLimitRPS = rate
	d := machineDurations{getenv: getenv}
	w.CredPendingTTL = d.get("MACHINE_WRITE_CRED_PENDING_TTL", credPendingTTLDefault, credPendingTTLMin, credPendingTTLMax)
	if d.err != nil {
		return d.err
	}
	canaries, err := loadCredCanaries(getenv("MACHINE_WRITE_CRED_CANARIES"), cfg, m, *w, base)
	if err != nil {
		return err
	}
	w.CredCanaries = canaries
	return nil
}

// loadCredCanaries reads MACHINE_WRITE_CRED_CANARIES (D379-15 checks 5 and 8):
// ';'-separated sets "with-password|unmarked|pending", at most 16. T028-D1:
// every DN is canonical (D26), strictly inside the base, distinct from every
// other canary and protected DN, and the three DNs of a set lie strictly inside
// one MACHINE_WRITE_CRED_SUBTREES DN; every distinct cred subtree holds at least
// one complete set (a loose rule on a second subtree must meet a canary there,
// AC-010b). The canaries join the request-time protected set (no machine write
// may touch them) but not the ceiling-overlap identities: they live inside a
// ceiling by design. Errors never echo a value.
func loadCredCanaries(raw string, cfg Config, m MachineConfig, w MachineWriteConfig, base *ldap.DN) ([]MachineWriteCredCanary, error) {
	var subtrees []*ldap.DN
	for _, e := range w.CredSubtrees {
		for _, s := range e.DNs {
			dn, _ := ldap.ParseDN(s)
			dup := false
			for _, have := range subtrees {
				dup = dup || have.EqualFold(dn)
			}
			if !dup {
				subtrees = append(subtrees, dn)
			}
		}
	}
	var protected []*ldap.DN
	for _, other := range machineWriteProtectedDNs(cfg, m, w) {
		p, err := ldap.ParseDN(other)
		if err != nil {
			return nil, fmt.Errorf("MACHINE_WRITE_CRED_CANARIES requires parseable protected identity DNs")
		}
		protected = append(protected, p)
	}
	var out []MachineWriteCredCanary
	var seen []*ldap.DN
	covered := make([]bool, len(subtrees))
	for _, entry := range splitEntries(raw) {
		parts := strings.Split(entry, "|")
		if len(parts) != 3 {
			return nil, fmt.Errorf("MACHINE_WRITE_CRED_CANARIES entries are three DNs: with-password|unmarked|pending")
		}
		var set []*ldap.DN
		for _, part := range parts {
			dn, err := canonicalWriteDN(strings.TrimSpace(part))
			if err != nil {
				return nil, fmt.Errorf("MACHINE_WRITE_CRED_CANARIES: %w", err)
			}
			if !base.AncestorOfFold(dn) {
				return nil, fmt.Errorf("MACHINE_WRITE_CRED_CANARIES must lie strictly inside LDAP_BASE_DN")
			}
			for _, other := range append(append([]*ldap.DN(nil), seen...), protected...) {
				if other.EqualFold(dn) {
					return nil, fmt.Errorf("MACHINE_WRITE_CRED_CANARIES DNs must be distinct from each other and from every protected identity")
				}
			}
			seen = append(seen, dn)
			set = append(set, dn)
		}
		inside := false
		for i, s := range subtrees {
			if s.AncestorOfFold(set[0]) && s.AncestorOfFold(set[1]) && s.AncestorOfFold(set[2]) {
				inside, covered[i] = true, true
			}
		}
		if !inside {
			return nil, fmt.Errorf("MACHINE_WRITE_CRED_CANARIES sets must lie strictly inside one MACHINE_WRITE_CRED_SUBTREES DN")
		}
		out = append(out, MachineWriteCredCanary{WithPassword: strings.TrimSpace(parts[0]), Unmarked: strings.TrimSpace(parts[1]), Pending: strings.TrimSpace(parts[2])})
	}
	if len(out) > machineWriteMaxDNsPerClient {
		return nil, fmt.Errorf("MACHINE_WRITE_CRED_CANARIES allows at most %d sets", machineWriteMaxDNsPerClient)
	}
	for _, ok := range covered {
		if !ok {
			return nil, fmt.Errorf("MACHINE_WRITE_CRED_CANARIES requires a canary set inside every MACHINE_WRITE_CRED_SUBTREES DN")
		}
	}
	return out, nil
}

// checkCredSubtrees is Q9: every MACHINE_WRITE_CRED_SUBTREES DN equals or lies
// inside one of the same client's MACHINE_WRITE_SUBTREES ceilings, and is never
// a privileged group or below one. Overlap with the other protected DNs follows
// from the ceiling rule (a ceiling neither contains nor lies inside one).
func checkCredSubtrees(w MachineWriteConfig) error {
	ceilings := map[string][]*ldap.DN{}
	for _, e := range w.Subtrees {
		for _, raw := range e.DNs {
			dn, _ := ldap.ParseDN(raw)
			ceilings[e.ID] = append(ceilings[e.ID], dn)
		}
	}
	for _, e := range w.CredSubtrees {
		for _, raw := range e.DNs {
			dn, _ := ldap.ParseDN(raw)
			inside := false
			for _, c := range ceilings[e.ID] {
				inside = inside || c.EqualFold(dn) || c.AncestorOfFold(dn)
			}
			if !inside {
				return fmt.Errorf("MACHINE_WRITE_CRED_SUBTREES must lie within the same client's MACHINE_WRITE_SUBTREES")
			}
			for _, rawPriv := range w.PrivilegedGroups {
				p, _ := ldap.ParseDN(rawPriv)
				if p.EqualFold(dn) || p.AncestorOfFold(dn) {
					return fmt.Errorf("MACHINE_WRITE_CRED_SUBTREES must not be or lie below a privileged group")
				}
			}
		}
	}
	return nil
}
