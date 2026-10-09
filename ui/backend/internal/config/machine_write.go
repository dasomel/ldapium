package config

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// loadMachineWrite parses MACHINE_WRITE_ENABLED (machine-write-scope D1, D10).
// Default off; when off nothing else MACHINE_WRITE_* is read (T-011 will add
// those behind this gate). Fail closed: the write switch needs the v1 machine
// auth. T-011 validates separate identities; the operation table stays empty.
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

// MachineWriteConfig separates data and lock identities (D3). Credential
// writes require separate approval (Resolved Q1); they have no config here.
type MachineWriteConfig struct {
	Data                   MachineWriteIdentity
	LockEnabled            bool
	Lock                   MachineWriteIdentity
	Subtrees               map[string][]string
	Groups                 map[string][]string
	PrivilegedGroups       []string
	RateLimitRPS           int
	RateLimitBurst         int
	MaxConcurrency         int
	AuditTargetDNPlaintext bool
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
	if w.LockEnabled, err = boolEnv(getenv, "MACHINE_WRITE_LOCK_ENABLED", false); err != nil {
		return w, err
	}
	if err := loadMachineWriteBounds(getenv, cfg, m, &w); err != nil {
		return w, err
	}
	if !w.LockEnabled {
		return w, nil
	}
	if w.Lock, err = machineWriteIdentity(getenv, "MACHINE_WRITE_LOCK", cfg, m); err != nil {
		return w, err
	}
	data, _ := ldap.ParseDN(w.Data.BindDN)
	lock, _ := ldap.ParseDN(w.Lock.BindDN)
	if data.EqualFold(lock) {
		return w, fmt.Errorf("MACHINE_WRITE_DATA_BIND_DN and MACHINE_WRITE_LOCK_BIND_DN must be distinct")
	}
	return w, nil
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
