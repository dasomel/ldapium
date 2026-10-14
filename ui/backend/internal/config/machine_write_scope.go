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
	if err := loadMachineWriteCredScope(getenv, cfg, m, w, base, known); err != nil {
		return err
	}
	if w.GroupSeedDN, err = loadMachineWriteGroupSeed(getenv, cfg, m, *w, base); err != nil {
		return err
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
	if err := checkCredSubtrees(*w); err != nil {
		return err
	}
	if err := checkWriteGroups(*w); err != nil {
		return err
	}
	if err := checkLockNeedsPrivilegedGroups(m, *w); err != nil {
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

// loadMachineWriteGroupSeed reads MACHINE_WRITE_GROUP_SEED_DN (v2 D379-3, Q2). It
// is required as soon as any client ceiling names directory.groups.create, so a
// machine-created group never gets the W_data DN as its first member. The DN
// is canonical (D26), strictly inside the base and distinct from every other
// protected identity and privileged group; it joins the protected set (and so
// the ceiling-overlap rule) afterwards. Errors never echo the value.
// Cost: the operator creates one password-less entry; escape hatch: none, a
// seed that is a real principal would turn group creation into a grant.
func loadMachineWriteGroupSeed(getenv func(string) string, cfg Config, m MachineConfig, w MachineWriteConfig, base *ldap.DN) (string, error) {
	raw := getenv("MACHINE_WRITE_GROUP_SEED_DN")
	if raw == "" {
		for _, c := range m.Clients {
			for _, s := range c.Scopes {
				if s == "directory.groups.create" {
					return "", fmt.Errorf("MACHINE_WRITE_GROUP_SEED_DN is required when a client ceiling names directory.groups.create")
				}
			}
		}
		return "", nil
	}
	seed, err := canonicalWriteDN(raw)
	if err != nil {
		return "", fmt.Errorf("MACHINE_WRITE_GROUP_SEED_DN: %w", err)
	}
	if !base.AncestorOfFold(seed) {
		return "", fmt.Errorf("MACHINE_WRITE_GROUP_SEED_DN must lie strictly inside LDAP_BASE_DN")
	}
	for _, other := range machineWriteProtectedDNs(cfg, m, w) {
		p, err := ldap.ParseDN(other)
		if err != nil || !writeIdentityDNUnambiguous(p) {
			return "", fmt.Errorf("MACHINE_WRITE_GROUP_SEED_DN requires unambiguous protected identity DNs")
		}
		if p.EqualFold(seed) {
			return "", fmt.Errorf("MACHINE_WRITE_GROUP_SEED_DN must be distinct from every protected identity and privileged group")
		}
	}
	// D394-4 (#394 item 4): the reserved placeholder form is a direct child of
	// the container that holds W_data (the system container, @SYSTEM_DN@ of the
	// W ACL fragments, where D379-3 puts the seed). A real
	// principal elsewhere (a user under a people ou, a group, an application
	// account) is refused, whatever its name. Cost: the seed's location is
	// fixed. Escape hatch: none; move the seed entry. Residual: whether the
	// entry is bindable (carries userPassword) cannot be checked here, and no
	// shipped identity may read userPassword to check it later, so a
	// password-less seed stays an operator duty (machine-write-scope-v2 CHANGE.md
	// Revision 5).
	wdata, err := ldap.ParseDN(w.Data.BindDN)
	if err != nil || len(wdata.RDNs) < 2 ||
		!(&ldap.DN{RDNs: seed.RDNs[1:]}).EqualFold(&ldap.DN{RDNs: wdata.RDNs[1:]}) {
		return "", fmt.Errorf("MACHINE_WRITE_GROUP_SEED_DN must be a direct child of the container that holds MACHINE_WRITE_DATA_BIND_DN (the reserved placeholder form)")
	}
	return raw, nil
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

// checkLockNeedsPrivilegedGroups (D379-17): a lock ceiling needs a named deny
// set, otherwise the privileged-member refusal would pass everyone.
func checkLockNeedsPrivilegedGroups(m MachineConfig, w MachineWriteConfig) error {
	if len(w.PrivilegedGroups) > 0 {
		return nil
	}
	for _, c := range m.Clients {
		for _, s := range c.Scopes {
			if s == "directory.users.lock" {
				return fmt.Errorf("a client ceiling naming directory.users.lock requires MACHINE_WRITE_PRIVILEGED_GROUPS")
			}
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
// replication and administrator identities, administrator DNs, the group seed
// placeholder, the v2c policy entries and the privileged groups. It applies whatever a client ceiling says.
func (c Config) MachineWriteProtectedDNs() []string {
	return machineWriteProtectedDNs(c, c.Machine, c.Machine.Write)
}

func machineWriteProtectedDNs(cfg Config, m MachineConfig, w MachineWriteConfig) []string {
	out := append(machineWriteIdentityDNs(cfg, m, w), w.PrivilegedGroups...)
	// T028-D1: the canaries are protected at request time only (they lie inside
	// a ceiling, so they are not ceiling-overlap identities).
	for _, c := range w.CredCanaries {
		out = append(out, c.DNs()...)
	}
	return out
}

// machineWriteIdentityDNs is the protected set without the privileged groups.
func machineWriteIdentityDNs(cfg Config, m MachineConfig, w MachineWriteConfig) []string {
	out := []string{m.BindDN, w.Data.BindDN}
	if w.LockEnabled {
		out = append(out, w.Lock.BindDN)
	}
	// REQ-009: W_cred joins the protected set. T020-D4: so do the pending and
	// allowlisted policy entries, which a machine write must never edit.
	if w.CredEnabled {
		out = append(out, w.Cred.BindDN)
		// T-028: the cn=config reader (D379-16). Never an empty entry: an empty
		// DN would protect the whole tree.
		if w.CredACLReader.BindDN != "" {
			out = append(out, w.CredACLReader.BindDN)
		}
		if w.CredPendingPolicyDN != "" {
			out = append(out, w.CredPendingPolicyDN)
		}
		out = append(out, w.CredPolicyDNs...)
	}
	out = append(out, m.RootDNs...)
	out = append(out, "cn=replicator,"+cfg.BaseDN, "cn=admin,"+cfg.BaseDN)
	out = append(out, cfg.BackupAdminDNs...)
	out = append(out, cfg.AppProfilesAdminDNs...)
	if cfg.SSO.LDAPServiceAccountDN != "" {
		out = append(out, cfg.SSO.LDAPServiceAccountDN)
	}
	if w.GroupSeedDN != "" {
		out = append(out, w.GroupSeedDN)
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
