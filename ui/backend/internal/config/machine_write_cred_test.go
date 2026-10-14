package config

import (
	"strconv"
	"strings"
	"testing"
)

// v2c T-020 (REQ-001, REQ-009, Q9, D379-15 check 8, D379-18): W_cred
// configuration and start-up validation. Nothing here opens an operation.

const (
	wcDN      = "cn=cred,ou=system," + wsBase
	wcPending = "cn=credential-pending,ou=policies," + wsBase
)

func credEnv(over map[string]string) func(string) string {
	values := map[string]string{
		"MACHINE_WRITE_CRED_ENABLED":           "true",
		"MACHINE_WRITE_CRED_BIND_DN":           wcDN,
		"MACHINE_WRITE_CRED_BIND_PASSWORD":     "private-cred",
		"MACHINE_WRITE_CRED_SUBTREES":          "machine-a=" + wsPeop,
		"MACHINE_WRITE_CRED_PENDING_POLICY_DN": wcPending,
	}
	for k, v := range over {
		values[k] = v
	}
	return writeScopeEnv(values)
}

func TestMachineWriteCredValid(t *testing.T) {
	cfg, err := Load(credEnv(map[string]string{"MACHINE_WRITE_CRED_POLICY_DNS": "cn=strict,ou=policies," + wsBase}))
	if err != nil {
		t.Fatal(err)
	}
	w := cfg.Machine.Write
	if !w.CredEnabled || w.Cred.BindDN != wcDN || w.Cred.BindPassword != "private-cred" || w.CredMinLength != 12 ||
		w.CredPendingPolicyDN != wcPending || len(w.CredPolicyDNs) != 1 ||
		len(w.CredSubtrees) != 1 || w.CredSubtrees[0].ID != "machine-a" || w.CredSubtrees[0].DNs[0] != wsPeop {
		t.Fatalf("unexpected cred config: %+v", w)
	}
	set := strings.ToLower(strings.Join(cfg.MachineWriteProtectedDNs(), "|"))
	for _, want := range []string{wcDN, wcPending, "cn=strict,ou=policies," + wsBase} {
		if !strings.Contains(set, want) {
			t.Errorf("%s missing from the protected set", want)
		}
	}
	// Enabling the compartment opens nothing: the password scope stays refused.
	_, err = Load(credEnv(map[string]string{"MACHINE_ALLOWED_CLIENTS": "machine-a=directory.users.read,directory.users.create,directory.users.password.write;machine-b=audit.read"}))
	if err == nil || !strings.Contains(err.Error(), "no operation uses yet") {
		t.Fatalf("password scope with W_cred on: %v", err)
	}
}

// REQ-001: off by default, and while off no other MACHINE_WRITE_CRED_* is read.
func TestMachineWriteCredOffNeverReadsSettings(t *testing.T) {
	for _, flag := range []string{"", "false"} {
		env := credEnv(map[string]string{"MACHINE_WRITE_CRED_ENABLED": flag, "MACHINE_WRITE_CRED_MIN_LENGTH": "garbage", "MACHINE_WRITE_CRED_RATE_LIMIT_RPS": "garbage"})
		cfg, err := Load(func(k string) string {
			if strings.HasPrefix(k, "MACHINE_WRITE_CRED_") && k != "MACHINE_WRITE_CRED_ENABLED" {
				t.Fatalf("flag %q: read disabled setting %s", flag, k)
			}
			return env(k)
		})
		if err != nil {
			t.Fatalf("flag %q: %v", flag, err)
		}
		w := cfg.Machine.Write
		if w.CredEnabled || w.Cred != (MachineWriteIdentity{}) || w.CredSubtrees != nil || w.CredMinLength != 0 || w.CredPolicyDNs != nil || w.CredPendingPolicyDN != "" || w.CredRateLimitRPS != 0 {
			t.Fatalf("flag %q: cred fields set: %+v", flag, w)
		}
		if strings.Contains(strings.ToLower(strings.Join(cfg.MachineWriteProtectedDNs(), "|")), "cn=cred,") {
			t.Fatalf("flag %q: disabled W_cred in the protected set", flag)
		}
	}
}

func TestMachineWriteCredFailClosed(t *testing.T) {
	lockOn := map[string]string{"MACHINE_WRITE_LOCK_ENABLED": "true", "MACHINE_WRITE_LOCK_BIND_DN": "cn=locker,ou=system," + wsBase, "MACHINE_WRITE_LOCK_BIND_PASSWORD": "private-lock"}
	with := func(base map[string]string, k, v string) map[string]string {
		out := map[string]string{k: v}
		for bk, bv := range base {
			out[bk] = bv
		}
		return out
	}
	many := make([]string, 17)
	for i := range many {
		many[i] = "cn=p" + strconv.Itoa(i) + ",ou=policies," + wsBase
	}
	cases := map[string]map[string]string{
		"flag malformed":         {"MACHINE_WRITE_CRED_ENABLED": "maybe"},
		"flag holds a secret":    {"MACHINE_WRITE_CRED_ENABLED": "private-mismapped-secret"},
		"no bind DN":             {"MACHINE_WRITE_CRED_BIND_DN": ""},
		"no bind password":       {"MACHINE_WRITE_CRED_BIND_PASSWORD": ""},
		"bind DN invalid":        {"MACHINE_WRITE_CRED_BIND_DN": "not a dn"},
		"privileged groups none": {"MACHINE_WRITE_PRIVILEGED_GROUPS": "", "MACHINE_WRITE_GROUPS": ""},
		"subtrees unset":         {"MACHINE_WRITE_CRED_SUBTREES": ""},
		"subtrees blank":         {"MACHINE_WRITE_CRED_SUBTREES": " ; "},
		"subtree other client":   {"MACHINE_WRITE_CRED_SUBTREES": "machine-a=ou=svc," + wsBase},
		"subtree above ceiling":  {"MACHINE_WRITE_CRED_SUBTREES": "machine-a=" + wsBase},
		"subtree outside":        {"MACHINE_WRITE_CRED_SUBTREES": "machine-a=ou=people,dc=other,dc=org"},
		"subtree sibling":        {"MACHINE_WRITE_CRED_SUBTREES": "machine-a=ou=peoplex," + wsBase},
		"subtree unknown client": {"MACHINE_WRITE_CRED_SUBTREES": "machine-z=" + wsPeop},
		"subtree client twice":   {"MACHINE_WRITE_CRED_SUBTREES": "machine-a=" + wsPeop + ";machine-a=ou=apps," + wsBase},
		"subtree no ceiling":     {"MACHINE_WRITE_SUBTREES": "machine-a=" + wsPeop, "MACHINE_WRITE_CRED_SUBTREES": "machine-a=" + wsPeop + ";machine-b=ou=svc," + wsBase},
		"subtree non-canonical":  {"MACHINE_WRITE_CRED_SUBTREES": "machine-a=OU=people," + wsBase},
		"subtree is privileged":  {"MACHINE_WRITE_CRED_SUBTREES": "machine-a=" + wsAdmin},
		"subtree below priv":     {"MACHINE_WRITE_CRED_SUBTREES": "machine-a=ou=x," + wsAdmin},
		"policy non-canonical":   {"MACHINE_WRITE_CRED_POLICY_DNS": "CN=strict,ou=policies," + wsBase},
		"policy outside base":    {"MACHINE_WRITE_CRED_POLICY_DNS": "cn=strict,ou=policies,dc=other,dc=org"},
		"policy is base":         {"MACHINE_WRITE_CRED_POLICY_DNS": wsBase},
		"policy duplicate fold":  {"MACHINE_WRITE_CRED_POLICY_DNS": "cn=strict,ou=policies," + wsBase + ";cn=STRICT,ou=policies," + wsBase},
		"policy too many":        {"MACHINE_WRITE_CRED_POLICY_DNS": strings.Join(many, ";")},
		"pending unset":          {"MACHINE_WRITE_CRED_PENDING_POLICY_DN": ""},
		"pending non-canonical":  {"MACHINE_WRITE_CRED_PENDING_POLICY_DN": "cn=credential-pending, ou=policies," + wsBase},
		"pending outside base":   {"MACHINE_WRITE_CRED_PENDING_POLICY_DN": "cn=credential-pending,ou=policies,dc=other,dc=org"},
		"pending is base":        {"MACHINE_WRITE_CRED_PENDING_POLICY_DN": wsBase},
		"pending is default":     {"MACHINE_WRITE_CRED_PENDING_POLICY_DN": "cn=default,ou=policies," + wsBase},
		"pending default fold":   {"MACHINE_WRITE_CRED_PENDING_POLICY_DN": "cn=DEFAULT,ou=policies," + wsBase},
		"pending in allowlist":   {"MACHINE_WRITE_CRED_POLICY_DNS": "cn=credential-PENDING,ou=policies," + wsBase},
		"pending is W_data":      {"MACHINE_WRITE_CRED_PENDING_POLICY_DN": "cn=writer,ou=system," + wsBase},
		"pending is W_cred":      {"MACHINE_WRITE_CRED_PENDING_POLICY_DN": wcDN},
		"pending is privileged":  {"MACHINE_WRITE_CRED_PENDING_POLICY_DN": wsAdmin},
		"pending is service":     {"MACHINE_WRITE_CRED_PENDING_POLICY_DN": "cn=service,ou=system," + wsBase},
		"pending is the seed":    {"MACHINE_WRITE_GROUP_SEED_DN": "cn=credential-pending,ou=system," + wsBase, "MACHINE_WRITE_CRED_PENDING_POLICY_DN": "cn=credential-pending,ou=system," + wsBase},
		"ceiling holds pending":  {"MACHINE_WRITE_SUBTREES": "machine-a=" + wsPeop + "|ou=policies," + wsBase + ";machine-b=ou=svc," + wsBase},
		"ceiling holds policy":   {"MACHINE_WRITE_SUBTREES": "machine-a=" + wsPeop + "|ou=strict," + wsBase + ";machine-b=ou=svc," + wsBase, "MACHINE_WRITE_CRED_POLICY_DNS": "cn=p,ou=strict," + wsBase},
		"ceiling holds W_cred":   {"MACHINE_WRITE_CRED_BIND_DN": "uid=cred,ou=apps," + wsBase},
		"cred is lock":           with(lockOn, "MACHINE_WRITE_CRED_BIND_DN", "cn=locker,ou=system,"+wsBase),
		"cred is lock folded":    with(lockOn, "MACHINE_WRITE_CRED_BIND_DN", "CN=LOCKER,OU=SYSTEM,DC=EXAMPLE,DC=ORG"),
	}
	for _, v := range []string{"", "0", "1", "11", "1025", "-12", "12.5", "abc", "0x10"} {
		cases["min length "+strconv.Quote(v)] = map[string]string{"MACHINE_WRITE_CRED_MIN_LENGTH": v}
	}
	delete(cases, `min length ""`) // empty means the default
	for _, v := range []string{"0", "11", "-1", "1.5", "abc", "0x2"} {
		cases["rate "+strconv.Quote(v)] = map[string]string{"MACHINE_WRITE_CRED_RATE_LIMIT_RPS": v}
	}
	for name, over := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(credEnv(over))
			if err == nil {
				t.Fatal("accepted")
			}
			if msg := err.Error(); strings.Contains(msg, "private-") || strings.Contains(msg, "credential-pending") || strings.Contains(msg, "cn=cred") || strings.Contains(msg, "maybe") {
				t.Fatalf("diagnostic echoes a value: %s", msg)
			}
		})
	}
}

// REQ-009: the D19/D26 variant table of the other W_*, applied to W_cred and
// extended with W_data and W_lock spellings.
func TestMachineWriteCredRejectsProtectedDNVariants(t *testing.T) {
	protected := []string{
		"cn=writer,ou=system,dc=example,dc=org",
		"CN=WRITER, OU=SYSTEM, DC=EXAMPLE, DC=ORG",
		`cn=wr\69ter,ou=system,dc=example,dc=org`,
		"cn=locker,ou=system,dc=example,dc=org",
		"CN=LOCKER,OU=SYSTEM,DC=EXAMPLE,DC=ORG",
		"cn=machine,ou=system,dc=example,dc=org",
		"CN=MACHINE, OU=SYSTEM, DC=EXAMPLE, DC=ORG",
		`cn=ma\63hine,ou=system,dc=example,dc=org`,
		"cn=admin,dc=example,dc=org",
		"CN=ADMIN,DC=EXAMPLE,DC=ORG",
		`cn=ad\6din,dc=example,dc=org`,
		"cn=replicator,dc=example,dc=org",
		"uid=backup,ou=system,dc=example,dc=org",
		"uid=profile,ou=system,dc=example,dc=org",
		"cn=service,ou=system,dc=example,dc=org",
		"CN=SERVICE,OU=SYSTEM,DC=EXAMPLE,DC=ORG",
		`cn=ser\76ice,ou=system,dc=example,dc=org`,
		"commonName=cred,ou=system,dc=example,dc=org",
		"2.5.4.3=cred,ou=system,dc=example,dc=org",
		"cn=two  spaces,ou=system,dc=example,dc=org",
	}
	for _, dn := range protected {
		_, err := Load(credEnv(map[string]string{
			"MACHINE_WRITE_CRED_BIND_DN": dn, "APP_PROFILES_ADMIN_DNS": "uid=profile,ou=system," + wsBase,
			"MACHINE_WRITE_LOCK_ENABLED": "true", "MACHINE_WRITE_LOCK_BIND_DN": "cn=locker,ou=system," + wsBase, "MACHINE_WRITE_LOCK_BIND_PASSWORD": "private-lock",
		}))
		if err == nil {
			t.Errorf("accepted protected identity %s", dn)
		} else if strings.Contains(err.Error(), "private-") {
			t.Errorf("%s: leaked a password: %v", dn, err)
		}
	}
	// W_lock off: a W_cred spelled like an unused lock DN is not a collision.
	if _, err := Load(credEnv(map[string]string{"MACHINE_WRITE_CRED_BIND_DN": "cn=locker,ou=system," + wsBase})); err != nil {
		t.Errorf("W_lock off: %v", err)
	}
}

func TestMachineWriteCredBoundaries(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{{"", 12}, {"12", 12}, {" 13 ", 13}, {"1024", 1024}} {
		cfg, err := Load(credEnv(map[string]string{"MACHINE_WRITE_CRED_MIN_LENGTH": tc.raw}))
		if err != nil || cfg.Machine.Write.CredMinLength != tc.want {
			t.Errorf("min length %q: %d, %v (want %d)", tc.raw, cfg.Machine.Write.CredMinLength, err, tc.want)
		}
	}
	// T023-D2: the global password budget, default 1, 1-10.
	for _, tc := range []struct {
		raw  string
		want int
	}{{"", 1}, {"1", 1}, {" 2 ", 2}, {"10", 10}} {
		cfg, err := Load(credEnv(map[string]string{"MACHINE_WRITE_CRED_RATE_LIMIT_RPS": tc.raw}))
		if err != nil || cfg.Machine.Write.CredRateLimitRPS != tc.want {
			t.Errorf("rate %q: %d, %v (want %d)", tc.raw, cfg.Machine.Write.CredRateLimitRPS, err, tc.want)
		}
	}
	// Q9: equal to a ceiling, strictly inside one, the second ceiling, and a
	// second client inside its own ceiling are all inside.
	for _, sub := range []string{
		"machine-a=" + wsPeop,
		"machine-a=ou=staff," + wsPeop,
		"machine-a=" + wsPeop + "|ou=apps," + wsBase,
		"machine-a=ou=apps," + wsBase + ";machine-b=ou=svc," + wsBase,
		"machine-a=cn=team," + wsPeop, // a writable, non-privileged group is not refused here
	} {
		if _, err := Load(credEnv(map[string]string{"MACHINE_WRITE_CRED_SUBTREES": sub})); err != nil {
			t.Errorf("%s: %v", sub, err)
		}
	}
	// 16 allowlist DNs is the limit, not 17 (see the fail-closed table).
	many := make([]string, 16)
	for i := range many {
		many[i] = "cn=p" + strconv.Itoa(i) + ",ou=policies," + wsBase
	}
	if _, err := Load(credEnv(map[string]string{"MACHINE_WRITE_CRED_POLICY_DNS": strings.Join(many, ";")})); err != nil {
		t.Errorf("16 policy DNs: %v", err)
	}
	// D379-18: the pending policy is required with its own diagnostic.
	if _, err := Load(credEnv(map[string]string{"MACHINE_WRITE_CRED_PENDING_POLICY_DN": ""})); err == nil || !strings.Contains(err.Error(), "requires MACHINE_WRITE_CRED_PENDING_POLICY_DN") {
		t.Errorf("unset pending policy: %v", err)
	}
	// The allowlist is optional.
	if cfg, err := Load(credEnv(nil)); err != nil || cfg.Machine.Write.CredPolicyDNs != nil {
		t.Errorf("no allowlist: %v", err)
	}
	// W_cred coexists with W_lock and the group seed.
	if _, err := Load(credEnv(map[string]string{
		"MACHINE_WRITE_LOCK_ENABLED": "true", "MACHINE_WRITE_LOCK_BIND_DN": "cn=locker,ou=system," + wsBase, "MACHINE_WRITE_LOCK_BIND_PASSWORD": "private-lock",
		"MACHINE_WRITE_GROUP_SEED_DN": wsSeed,
	})); err != nil {
		t.Errorf("with W_lock and seed: %v", err)
	}
	// The seed is checked against W_cred (it joins the protected set first).
	if _, err := Load(credEnv(map[string]string{"MACHINE_WRITE_GROUP_SEED_DN": wcDN})); err == nil {
		t.Error("seed equal to W_cred accepted")
	}
}
