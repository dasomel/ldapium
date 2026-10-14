package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// loadMachineWrite parses MACHINE_WRITE_ENABLED (machine-write-scope D1, D10).
// Default off; when off nothing else MACHINE_WRITE_* is read (T-011 will add
// those behind this gate). Fail closed: the write switch needs the v1 machine
// auth, idempotency, the W identity and the scope configuration (see the loaders
// below); a missing prerequisite is a start-up error (T-013).
func loadMachineWrite(getenv func(string) string, machineEnabled bool) (bool, error) {
	on, err := boolEnv(getenv, "MACHINE_WRITE_ENABLED", false)
	if err != nil || !on {
		return false, err
	}
	if !machineEnabled {
		return false, fmt.Errorf("MACHINE_WRITE_ENABLED requires MACHINE_AUTH_ENABLED")
	}
	return true, nil
}

// MachineWriteIdentity is a configured bind identity, not permission to write.
type MachineWriteIdentity struct {
	BindDN       string
	BindPassword string
}

// MachineWriteConfig separates data, lock and credential identities (D3,
// D379-2). The credential compartment (v2c) is configuration only: no
// operation uses it until T-026 opens setPassword.
type MachineWriteConfig struct {
	Data        MachineWriteIdentity
	LockEnabled bool
	Lock        MachineWriteIdentity
	// CredEnabled is MACHINE_WRITE_CRED_ENABLED (REQ-001, default false); when
	// false no other MACHINE_WRITE_CRED_* variable is read and every Cred*
	// field stays zero.
	CredEnabled bool
	Cred        MachineWriteIdentity
	// CredSubtrees is MACHINE_WRITE_CRED_SUBTREES, per client and inside that
	// client's Subtrees (Q9). CredMinLength is the policy floor checked at run
	// time (D379-15 check 2), CredPolicyDNs the per-target policy allowlist
	// (check 3) and CredPendingPolicyDN the pending-account policy (D379-18).
	CredSubtrees        []MachineWriteClientDNs
	CredMinLength       int
	CredPolicyDNs       []string
	CredPendingPolicyDN string
	// CredRateLimitRPS is MACHINE_WRITE_CRED_RATE_LIMIT_RPS, the global password
	// budget (REQ-013, default 1 rps, T023-D2).
	CredRateLimitRPS int
	// Subtrees/Groups are per-client write ceilings and writable groups,
	// PrivilegedGroups the deny set, Limits the write budget (T-012/T-016/T-019).
	Subtrees         []MachineWriteClientDNs
	Groups           []MachineWriteClientDNs
	PrivilegedGroups []string
	Limits           MachineWriteLimits
	// AuditPlainTargetDN is MACHINE_WRITE_AUDIT_TARGET_DN (Resolved Q4, D6): the
	// write audit line carries the target DN in plaintext next to its
	// fingerprint. Default false (fingerprint only); read only when
	// MACHINE_WRITE_ENABLED is on.
	AuditPlainTargetDN bool
	// GroupSeedDN is MACHINE_WRITE_GROUP_SEED_DN (v2 D379-3): the fixed, non-bindable
	// placeholder a machine createGroup writes as the group's required first
	// member, instead of the W_data DN. Empty unless configured; part of the
	// protected set when set.
	GroupSeedDN string
}

func loadMachineWriteIdentities(getenv func(string) string, cfg Config, m MachineConfig) (MachineWriteConfig, error) {
	var w MachineWriteConfig
	if !m.WriteEnabled {
		return w, nil
	}
	if !cfg.IdempotencyEnabled {
		return w, fmt.Errorf("MACHINE_WRITE_ENABLED requires UI_IDEMPOTENCY_ENABLED")
	}
	var err error
	if w.Data, err = machineWriteIdentity(getenv, "MACHINE_WRITE_DATA", cfg, m); err != nil {
		return w, err
	}
	if w.AuditPlainTargetDN, err = boolEnv(getenv, "MACHINE_WRITE_AUDIT_TARGET_DN", false); err != nil {
		return w, err
	}
	if w.LockEnabled, err = boolEnv(getenv, "MACHINE_WRITE_LOCK_ENABLED", false); err != nil {
		return w, err
	}
	if !w.LockEnabled {
		// D379-2 (REQ-006): a lock ceiling without W_lock would be a scope that
		// can only answer 503. Refuse it at start-up instead.
		for _, c := range m.Clients {
			for _, s := range c.Scopes {
				if s == "directory.users.lock" {
					return w, fmt.Errorf("MACHINE_ALLOWED_CLIENTS names directory.users.lock, which requires MACHINE_WRITE_LOCK_ENABLED=true")
				}
			}
		}
	} else {
		if w.Lock, err = machineWriteIdentity(getenv, "MACHINE_WRITE_LOCK", cfg, m); err != nil {
			return w, err
		}
		data, _ := ldap.ParseDN(w.Data.BindDN)
		lock, _ := ldap.ParseDN(w.Lock.BindDN)
		if data.EqualFold(lock) {
			return w, fmt.Errorf("MACHINE_WRITE_DATA_BIND_DN and MACHINE_WRITE_LOCK_BIND_DN must be distinct")
		}
	}
	return w, loadMachineWriteCredIdentity(getenv, cfg, m, &w)
}

// loadMachineWriteCredIdentity reads MACHINE_WRITE_CRED_ENABLED and, only when it
// is on, the W_cred identity (REQ-009, D379-2): required, D26 form, and
// ParseDN-distinct from M, administrators, service accounts, rootdns, the
// replication identity, W_data and W_lock. Errors never echo the values; the
// password follows the bind-password Secret convention of the other W_*.
func loadMachineWriteCredIdentity(getenv func(string) string, cfg Config, m MachineConfig, w *MachineWriteConfig) error {
	// Unlike boolEnv, the diagnostic never echoes the raw value: a secret
	// mis-mapped into this variable must not reach the start-up log.
	if raw := strings.TrimSpace(getenv("MACHINE_WRITE_CRED_ENABLED")); raw != "" {
		on, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("MACHINE_WRITE_CRED_ENABLED must be true or false")
		}
		w.CredEnabled = on
	}
	if !w.CredEnabled {
		return nil
	}
	var err error
	if w.Cred, err = machineWriteIdentity(getenv, "MACHINE_WRITE_CRED", cfg, m); err != nil {
		return err
	}
	cred, _ := ldap.ParseDN(w.Cred.BindDN)
	others := []string{w.Data.BindDN}
	if w.LockEnabled {
		others = append(others, w.Lock.BindDN)
	}
	for _, raw := range others {
		if other, _ := ldap.ParseDN(raw); other.EqualFold(cred) {
			return fmt.Errorf("MACHINE_WRITE_CRED_BIND_DN must be distinct from MACHINE_WRITE_DATA_BIND_DN and MACHINE_WRITE_LOCK_BIND_DN")
		}
	}
	return nil
}

func machineWriteIdentity(getenv func(string) string, prefix string, cfg Config, m MachineConfig) (MachineWriteIdentity, error) {
	identity := MachineWriteIdentity{BindDN: strings.TrimSpace(getenv(prefix + "_BIND_DN")), BindPassword: getenv(prefix + "_BIND_PASSWORD")}
	if identity.BindDN == "" || identity.BindPassword == "" {
		return MachineWriteIdentity{}, fmt.Errorf("%s requires %s_BIND_DN and %s_BIND_PASSWORD", prefix, prefix, prefix)
	}
	dn, err := ldap.ParseDN(identity.BindDN)
	if err != nil {
		return MachineWriteIdentity{}, fmt.Errorf("%s_BIND_DN must be a valid DN", prefix)
	}
	// D19: reuse v1's administrator/root/service-account comparisons, adding M
	// and the fixed replication identity. Cost: explicit identity inventory;
	// extend it when another privileged identity is introduced, never fall back.
	protected := append([]string(nil), m.RootDNs...)
	protected = append(protected, m.BindDN, "cn=replicator,"+cfg.BaseDN)
	if err := checkMachineBindDN(identity.BindDN, cfg, protected); err != nil {
		return MachineWriteIdentity{}, fmt.Errorf("%s_BIND_DN must be distinct from read, administrator, service-account, root and replication identities", prefix)
	}
	// D19: reject ambiguous spellings on either side of the comparison.
	// Otherwise a named cn could appear distinct from a protected OID spelling.
	protected = append(protected, cfg.BackupAdminDNs...)
	protected = append(protected, cfg.AppProfilesAdminDNs...)
	if cfg.SSO.LDAPServiceAccountDN != "" {
		protected = append(protected, cfg.SSO.LDAPServiceAccountDN)
	}
	if !writeIdentityDNUnambiguous(dn) {
		return MachineWriteIdentity{}, fmt.Errorf("%s_BIND_DN requires named attribute types and unambiguous whitespace", prefix)
	}
	for _, raw := range protected {
		other, err := ldap.ParseDN(raw)
		if err != nil || !writeIdentityDNUnambiguous(other) {
			return MachineWriteIdentity{}, fmt.Errorf("%s requires unambiguous protected identity DNs", prefix)
		}
	}

	return identity, nil
}

// D26: slapd resolves schema aliases that ParseDN.EqualFold leaves distinct.
// A canonical type allowlist refuses commonName/userid/domainComponent aliases
// on both the writer and protected identities. Cost: unusual naming types are
// rejected; escape hatch: canonical uid/cn/ou/dc spelling, never a fallback bind.
func writeIdentityDNUnambiguous(dn *ldap.DN) bool {
	if dn == nil || len(dn.RDNs) == 0 {
		return false
	}
	for _, rdn := range dn.RDNs {
		seen := map[string]bool{}
		for _, a := range rdn.Attributes {
			typ := strings.ToLower(a.Type)
			switch typ {
			case "uid", "cn", "ou", "dc":
			default:
				return false
			}
			if seen[typ] {
				return false
			}
			seen[typ] = true
			if a.Value == "" || strings.TrimSpace(a.Value) != a.Value || strings.Contains(a.Value, "  ") {
				return false
			}
			for _, ch := range a.Value {
				if ch < 32 || ch > 126 {
					return false
				}
			}
		}
	}
	return true
}
