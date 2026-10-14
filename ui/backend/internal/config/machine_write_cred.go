package config

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// machine-write-scope-v2 T-020: W_cred configuration and start-up validation.
// Configuration only: directory.users.password.write stays an unopened scope
// (a ceiling naming it is still refused) and no operation binds as W_cred
// until T-026. The run-time premise checks (D379-15/16, canaries, the ACL
// reader identity) are T-028.

const (
	// credMinLengthDefault is the REQ-014 default policy floor (12).
	credMinLengthDefault = 12
	// T020-D1: the floor can be raised but never lowered below the documented
	// default, and is capped at validate.Password's 1024-character limit.
	// Cost: an operator cannot accept a pending policy shorter than 12.
	// Escape hatch: none at this unit; a lower floor needs a design revision.
	credMinLengthMax = 1024
)

// loadMachineWriteCredScope reads the remaining MACHINE_WRITE_CRED_* settings,
// only when MACHINE_WRITE_CRED_ENABLED is on (otherwise none is read):
//   - check 8 (D379-15): a non-empty MACHINE_WRITE_PRIVILEGED_GROUPS and
//     MACHINE_WRITE_CRED_SUBTREES ("client=dn|dn;..."; inclusion in the
//     client's MACHINE_WRITE_SUBTREES is checked by checkCredSubtrees, Q9);
//   - MACHINE_WRITE_CRED_MIN_LENGTH (default 12, T020-D1);
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
	return nil
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
