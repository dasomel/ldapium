package config

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/idempotency"
)

// machine-write-scope T-011/T-012/T-016/T-019/T-013: write configuration. It is
// parsed and validated only when MACHINE_WRITE_ENABLED is on (when off nothing
// here is read), and the switch refuses itself when a prerequisite is missing.

const (
	machineWriteMaxDNsPerClient = 16
	machineWriteMaxDNLen        = 1024
)

// MachineWriteClientDNs is one client's exact DN list (write subtree ceilings or
// writable groups), in config order.
type MachineWriteClientDNs struct {
	ID  string
	DNs []string
}

// MachineWriteLimits is the write budget, separate from the read budget (D8d).
// Concurrent writes per client are fixed at one by the limiter.
type MachineWriteLimits struct {
	RPS         int
	Burst       int
	GlobalSlots int
}

// loadMachineWriteScope reads MACHINE_WRITE_SUBTREES (D8a, Q5), MACHINE_WRITE_GROUPS
// and MACHINE_WRITE_PRIVILEGED_GROUPS (REQ-019, D22) and the write limits (D8d).
// Syntax: "client=dn|dn;client2=dn" (v1 MACHINE_ALLOWED_CLIENTS is unchanged);
// the privileged list is ';'-separated. Empty means no write for that client.
// Cost: strict canonical spelling only; escape hatch: spell DNs canonically,
// never relax the check (D26).
func loadMachineWriteScope(getenv func(string) string, cfg Config, m MachineConfig, w *MachineWriteConfig) error {
	if !m.WriteEnabled {
		return nil
	}
	known := map[string]bool{}
	for _, c := range m.Clients {
		known[c.ID] = true
	}
	var err error
	if w.Subtrees, err = parseMachineWriteClientDNs("MACHINE_WRITE_SUBTREES", getenv("MACHINE_WRITE_SUBTREES"), known); err != nil {
		return err
	}
	if err := checkWriteHasWriter(m, w.Subtrees); err != nil {
		return err
	}
	if w.Groups, err = parseMachineWriteClientDNs("MACHINE_WRITE_GROUPS", getenv("MACHINE_WRITE_GROUPS"), known); err != nil {
		return err
	}
	for _, raw := range splitEntries(getenv("MACHINE_WRITE_PRIVILEGED_GROUPS")) {
		if _, err := canonicalWriteDN(raw); err != nil {
			return fmt.Errorf("MACHINE_WRITE_PRIVILEGED_GROUPS: %w", err)
		}
		w.PrivilegedGroups = append(w.PrivilegedGroups, raw)
	}
	base, err := ldap.ParseDN(cfg.BaseDN)
	if err != nil {
		return fmt.Errorf("MACHINE_WRITE_SUBTREES needs a valid LDAP_BASE_DN")
	}
	identities := machineWriteIdentityDNs(cfg, m, *w)
	for _, entry := range w.Subtrees {
		for _, raw := range entry.DNs {
			dn, _ := ldap.ParseDN(raw)
			// D20: a ceiling is a strict descendant of the base; the base itself and
			// anything outside it are refused.
			if err := checkWriteCeilingStrict(base, dn); err != nil {
				return err
			}
			if err := checkWriteCeilingOverlap(dn, identities, w.PrivilegedGroups); err != nil {
				return err
			}
		}
	}
	if err := checkWriteGroups(*w); err != nil {
		return err
	}
	n := machineInts{getenv: getenv}
	w.Limits = MachineWriteLimits{
		RPS:         n.get("MACHINE_WRITE_RATE_LIMIT_RPS", 1, 1, 100),
		Burst:       n.get("MACHINE_WRITE_RATE_LIMIT_BURST", 2, 1, 100),
		GlobalSlots: n.get("MACHINE_WRITE_GLOBAL_SLOTS", 2, 1, 64),
	}
	if n.err != nil {
		return n.err
	}
	return w.CheckIdempotencyQuota()
}

// checkWriteHasWriter is the T-013 self-refusal for "enabled but nothing can
// write": MACHINE_WRITE_ENABLED=true needs at least one client that has both a
// MACHINE_WRITE_SUBTREES ceiling and an opened write scope in its
// MACHINE_ALLOWED_CLIENTS ceiling. Otherwise startup fails instead of running with
// the switch on and every write answering 403.
func checkWriteHasWriter(m MachineConfig, subtrees []MachineWriteClientDNs) error {
	if len(subtrees) == 0 {
		return fmt.Errorf("MACHINE_WRITE_ENABLED requires MACHINE_WRITE_SUBTREES for at least one client")
	}
	open := map[string]bool{}
	for _, s := range MachineWriteOpenScopes {
		open[s] = true
	}
	ceiling := map[string]bool{}
	for _, c := range m.Clients {
		for _, s := range c.Scopes {
			ceiling[c.ID] = ceiling[c.ID] || open[s]
		}
	}
	for _, e := range subtrees {
		if ceiling[e.ID] {
			return nil
		}
	}
	return fmt.Errorf("MACHINE_WRITE_ENABLED requires a MACHINE_WRITE_SUBTREES client whose MACHINE_ALLOWED_CLIENTS ceiling names a write scope")
}

// checkWriteCeilingStrict is the D20 rule: a ceiling is a strict descendant of
// the base; the base itself, its parents and anything outside are refused.
func checkWriteCeilingStrict(base, ceiling *ldap.DN) error {
	if !base.AncestorOfFold(ceiling) {
		return fmt.Errorf("MACHINE_WRITE_SUBTREES must lie strictly inside LDAP_BASE_DN (the base itself is refused)")
	}
	return nil
}

// checkWriteCeilingOverlap refuses a ceiling equal to, below or above an
// identity DN, and equal to or below a privileged group. A ceiling may contain
// a privileged group's container (the request-time deny set wins, D19d). The
// exemption is by role: a DN that is also an identity is still refused.
func checkWriteCeilingOverlap(ceiling *ldap.DN, identities, groups []string) error {
	bad := fmt.Errorf("MACHINE_WRITE_SUBTREES must not overlap a protected identity (read, write, service-account, root, replication, administrator or privileged group DN)")
	for _, raw := range identities {
		p, err := ldap.ParseDN(raw)
		if err != nil {
			return fmt.Errorf("MACHINE_WRITE_SUBTREES requires parseable protected identity DNs")
		}
		if p.EqualFold(ceiling) || p.AncestorOfFold(ceiling) || ceiling.AncestorOfFold(p) {
			return bad
		}
	}
	for _, raw := range groups {
		p, err := ldap.ParseDN(raw)
		if err != nil {
			return fmt.Errorf("MACHINE_WRITE_SUBTREES requires parseable protected identity DNs")
		}
		if p.EqualFold(ceiling) || p.AncestorOfFold(ceiling) {
			return bad
		}
	}
	return nil
}

// checkWriteGroups: a writable group lies strictly inside the same client's
// ceiling, is never a privileged group (or below one), and a non-empty group
// list needs a non-empty deny set (REQ-019: privileged groups are named, not guessed).
func checkWriteGroups(w MachineWriteConfig) error {
	if len(w.Groups) > 0 && len(w.PrivilegedGroups) == 0 {
		return fmt.Errorf("MACHINE_WRITE_GROUPS requires MACHINE_WRITE_PRIVILEGED_GROUPS")
	}
	ceilings := map[string][]*ldap.DN{}
	for _, e := range w.Subtrees {
		for _, raw := range e.DNs {
			dn, _ := ldap.ParseDN(raw)
			ceilings[e.ID] = append(ceilings[e.ID], dn)
		}
	}
	for _, e := range w.Groups {
		if len(ceilings[e.ID]) == 0 {
			return fmt.Errorf("MACHINE_WRITE_GROUPS lists a client that has no MACHINE_WRITE_SUBTREES")
		}
		for _, raw := range e.DNs {
			g, _ := ldap.ParseDN(raw)
			inside := false
			for _, c := range ceilings[e.ID] {
				inside = inside || c.AncestorOfFold(g)
			}
			if !inside {
				return fmt.Errorf("MACHINE_WRITE_GROUPS must lie strictly inside the client's MACHINE_WRITE_SUBTREES")
			}
			for _, rawPriv := range w.PrivilegedGroups {
				p, _ := ldap.ParseDN(rawPriv)
				if p.EqualFold(g) || p.AncestorOfFold(g) {
					return fmt.Errorf("MACHINE_WRITE_GROUPS must not list a privileged group")
				}
			}
		}
	}
	return nil
}

// machineWriteHumanReserve is D23's "human share": per-subject quotas of the
// write clients plus this many subject-equivalents must fit MaxRecords, so
// machine clients can never take every record and starve human sessions
// (idempotency_capacity). D23 names the reserve but not its size; one
// subject-equivalent is the smallest share and an assumption of this unit.
const machineWriteHumanReserve = 1

// CheckIdempotencyQuota is the D23 startup check: MaxPerSubject x (write
// clients + human reserve) <= MaxRecords. With the store defaults (1000 per
// subject, 10000 records) that allows at most 9 write clients. The store runs
// with its default limits (httpapi.newIdempotency).
func (w MachineWriteConfig) CheckIdempotencyQuota() error {
	return checkMachineWriteQuota(idempotency.DefaultMaxPerSubject, idempotency.DefaultMaxRecords, len(w.Subtrees))
}

func checkMachineWriteQuota(maxPerSubject, maxRecords, clients int) error {
	if (clients+machineWriteHumanReserve)*maxPerSubject > maxRecords {
		return fmt.Errorf("MACHINE_WRITE_SUBTREES lists %d write clients; the idempotency store holds %d records at %d per subject and keeps %d subject share(s) for human sessions (at most %d clients)", clients, maxRecords, maxPerSubject, machineWriteHumanReserve, maxRecords/maxPerSubject-machineWriteHumanReserve)
	}
	return nil
}

// MachineWriteProtectedDNs is the REQ-016 protected set derived from the
// configuration: M, every enabled W_*, the service account, rootdns, the
// replication and administrator identities, administrator DNs and the
// privileged groups. It applies whatever a client ceiling says.
func (c Config) MachineWriteProtectedDNs() []string {
	return machineWriteProtectedDNs(c, c.Machine, c.Machine.Write)
}

func machineWriteProtectedDNs(cfg Config, m MachineConfig, w MachineWriteConfig) []string {
	return append(machineWriteIdentityDNs(cfg, m, w), w.PrivilegedGroups...)
}

// machineWriteIdentityDNs is the protected set without the privileged groups.
func machineWriteIdentityDNs(cfg Config, m MachineConfig, w MachineWriteConfig) []string {
	out := []string{m.BindDN, w.Data.BindDN}
	if w.LockEnabled {
		out = append(out, w.Lock.BindDN)
	}
	out = append(out, m.RootDNs...)
	out = append(out, "cn=replicator,"+cfg.BaseDN, "cn=admin,"+cfg.BaseDN)
	out = append(out, cfg.BackupAdminDNs...)
	out = append(out, cfg.AppProfilesAdminDNs...)
	if cfg.SSO.LDAPServiceAccountDN != "" {
		out = append(out, cfg.SSO.LDAPServiceAccountDN)
	}
	return out
}

func parseMachineWriteClientDNs(name, raw string, known map[string]bool) ([]MachineWriteClientDNs, error) {
	var out []MachineWriteClientDNs
	seen := map[string]bool{}
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, list, ok := strings.Cut(entry, "=")
		id = strings.TrimSpace(id)
		if !ok || id == "" || len(id) > machineSAMaxClientID || strings.ContainsAny(id, " \t,;=|") {
			return nil, fmt.Errorf("%s entries must look like clientId=dn|dn", name)
		}
		if !known[id] {
			return nil, fmt.Errorf("%s lists a client that is not in MACHINE_ALLOWED_CLIENTS", name)
		}
		if seen[id] {
			return nil, fmt.Errorf("%s lists a client more than once", name)
		}
		seen[id] = true
		var dns []string
		dup := map[string]bool{}
		for _, dn := range strings.Split(list, "|") {
			if _, err := canonicalWriteDN(dn); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			if dup[strings.ToLower(dn)] {
				return nil, fmt.Errorf("%s lists a DN more than once for a client", name)
			}
			dup[strings.ToLower(dn)] = true
			dns = append(dns, dn)
		}
		if len(dns) > machineWriteMaxDNsPerClient {
			return nil, fmt.Errorf("%s allows at most %d DNs per client", name, machineWriteMaxDNsPerClient)
		}
		out = append(out, MachineWriteClientDNs{ID: id, DNs: dns})
	}
	return out, nil
}

// canonicalWriteDN accepts only DNs the write guards can compare without
// guessing (D26/REQ-020a): lowercase uid/cn/ou/dc names, one value per RDN, no
// escapes, quotes or BER values, no stray whitespace, printable ASCII, and the
// exact canonical rendering. Relative DNs parse fine here; the caller's strict
// descendant rule refuses them. Errors never echo the value.
func canonicalWriteDN(raw string) (*ldap.DN, error) {
	bad := fmt.Errorf("DN is not in canonical form (lowercase uid/cn/ou/dc, no escapes, spaces or multi-valued RDNs)")
	if raw == "" || len(raw) > machineWriteMaxDNLen || strings.ContainsAny(raw, "\\#\"") {
		return nil, bad
	}
	dn, err := ldap.ParseDN(raw)
	if err != nil || len(dn.RDNs) == 0 {
		return nil, bad
	}
	parts := make([]string, 0, len(dn.RDNs))
	for _, rdn := range dn.RDNs {
		if len(rdn.Attributes) != 1 {
			return nil, bad
		}
		a := rdn.Attributes[0]
		switch a.Type {
		case "uid", "cn", "ou", "dc":
		default:
			return nil, bad
		}
		if a.Value == "" || strings.TrimSpace(a.Value) != a.Value || strings.Contains(a.Value, "  ") {
			return nil, bad
		}
		for _, ch := range a.Value {
			if ch < 32 || ch > 126 || strings.ContainsRune(",+;<>=", ch) {
				return nil, bad
			}
		}
		parts = append(parts, a.Type+"="+a.Value)
	}
	if strings.Join(parts, ",") != raw {
		return nil, bad
	}
	return dn, nil
}
