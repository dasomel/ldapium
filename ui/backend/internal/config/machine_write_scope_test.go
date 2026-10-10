package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

const (
	wsBase  = "dc=example,dc=org"
	wsPeop  = "ou=people," + wsBase
	wsGroup = "cn=team," + wsPeop
	wsAdmin = "cn=admins," + wsPeop
)

func writeScopeEnv(over map[string]string) func(string) string {
	values := map[string]string{
		"MACHINE_WRITE_SUBTREES":          "machine-a=" + wsPeop + "|ou=apps," + wsBase + ";machine-b=ou=svc," + wsBase,
		"MACHINE_WRITE_GROUPS":            "machine-a=" + wsGroup,
		"MACHINE_WRITE_PRIVILEGED_GROUPS": wsAdmin,
		"MACHINE_WRITE_RATE_LIMIT_RPS":    "3",
		"MACHINE_WRITE_RATE_LIMIT_BURST":  "6",
		"MACHINE_WRITE_GLOBAL_SLOTS":      "4",
		"BACKUP_ADMIN_DNS":                "uid=backup,ou=system," + wsBase,
		"LDAP_SERVICE_ACCOUNT_DN":         "cn=service,ou=system," + wsBase,
	}
	for k, v := range over {
		values[k] = v
	}
	return writeIdentityEnv(values)
}

func TestMachineWriteScopeValid(t *testing.T) {
	cfg, err := Load(writeScopeEnv(nil))
	if err != nil {
		t.Fatal(err)
	}
	w := cfg.Machine.Write
	if len(w.Subtrees) != 2 || w.Subtrees[0].ID != "machine-a" || len(w.Subtrees[0].DNs) != 2 || w.Subtrees[1].DNs[0] != "ou=svc,"+wsBase {
		t.Fatalf("subtrees %+v", w.Subtrees)
	}
	if len(w.Groups) != 1 || w.Groups[0].DNs[0] != wsGroup || len(w.PrivilegedGroups) != 1 {
		t.Fatalf("groups %+v / %+v", w.Groups, w.PrivilegedGroups)
	}
	if w.Limits != (MachineWriteLimits{RPS: 3, Burst: 6, GlobalSlots: 4}) {
		t.Fatalf("limits %+v", w.Limits)
	}
	// Protected set: M, W_data, rootdn, replication/admin, backup admin, service account, privileged group.
	set := strings.ToLower(strings.Join(cfg.MachineWriteProtectedDNs(), "|"))
	for _, want := range []string{"cn=machine,", "cn=writer,", "cn=admin,dc=", "cn=replicator,", "uid=backup,", "cn=service,", "cn=admins,"} {
		if !strings.Contains(set, want) {
			t.Errorf("protected set lacks %s: %s", want, set)
		}
	}
	// Defaults with nothing set: no client may write.
	cfg, err = Load(writeIdentityEnv(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Machine.Write.Subtrees) != 0 || cfg.Machine.Write.Limits != (MachineWriteLimits{RPS: 1, Burst: 2, GlobalSlots: 2}) {
		t.Fatalf("defaults %+v", cfg.Machine.Write)
	}
}

func TestMachineWriteScopeRejectsSubtrees(t *testing.T) {
	cases := map[string]string{
		"base itself":       "machine-a=" + wsBase,
		"outside base":      "machine-a=ou=people,dc=other,dc=org",
		"relative DN":       "machine-a=ou=people",
		"upper-case type":   "machine-a=OU=people," + wsBase,
		"space after comma": "machine-a=ou=people, " + wsBase,
		"leading space":     "machine-a= ou=people," + wsBase,
		"space around =":    "machine-a=ou = people," + wsBase,
		"escape":            `machine-a=ou=peo\70le,` + wsBase,
		"escaped comma":     `machine-a=ou=a\,b,` + wsBase,
		"BER value":         "machine-a=ou=#0406706570706c," + wsBase,
		"quoted":            `machine-a=ou="people",` + wsBase,
		"multi-valued RDN":  "machine-a=ou=people+cn=x," + wsBase,
		"OID type":          "machine-a=2.5.4.11=people," + wsBase,
		"alias type":        "machine-a=organizationalUnitName=people," + wsBase,
		"double space":      "machine-a=ou=a  b," + wsBase,
		"empty DN":          "machine-a=",
		"empty alternative": "machine-a=" + wsPeop + "|",
		"not a DN":          "machine-a=not a dn",
		"no client":         wsPeop,
		"unknown client":    "machine-z=" + wsPeop,
		"duplicate client":  "machine-a=" + wsPeop + ";machine-a=ou=apps," + wsBase,
		"duplicate DN":      "machine-a=" + wsPeop + "|OU=PEOPLE," + wsBase,
		"equals M":          "machine-a=cn=machine,ou=system," + wsBase,
		"below M":           "machine-a=ou=x,cn=machine,ou=system," + wsBase,
		"covers M and W":    "machine-a=ou=system," + wsBase,
		"equals backup":     "machine-a=uid=backup,ou=system," + wsBase,
		"equals service":    "machine-a=cn=service,ou=system," + wsBase,
		"equals replicator": "machine-a=cn=replicator," + wsBase,
		"equals rootdn":     "machine-a=cn=admin," + wsBase,
		"equals privileged": "machine-a=" + wsAdmin,
		"below privileged":  "machine-a=ou=x," + wsAdmin,
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := Load(writeScopeEnv(map[string]string{"MACHINE_WRITE_SUBTREES": v, "MACHINE_WRITE_GROUPS": "-"}))
			if err == nil {
				t.Fatalf("accepted %q: %+v", v, cfg.Machine.Write.Subtrees)
			}
			if !strings.Contains(err.Error(), "MACHINE_WRITE_SUBTREES") {
				t.Fatalf("error %v does not name the variable", err)
			}
			if strings.Contains(err.Error(), "private-") {
				t.Fatal("leaked a secret")
			}
		})
	}
	// The ceiling may cover a privileged group's container: the request-time deny set wins (D19d).
	if _, err := Load(writeScopeEnv(map[string]string{"MACHINE_WRITE_SUBTREES": "machine-a=" + wsPeop})); err != nil {
		t.Fatalf("ceiling over a privileged group container refused: %v", err)
	}
}

func TestMachineWriteScopeRejectsGroups(t *testing.T) {
	cases := map[string]map[string]string{
		"outside ceiling":      {"MACHINE_WRITE_GROUPS": "machine-a=cn=team,ou=elsewhere," + wsBase},
		"equals ceiling":       {"MACHINE_WRITE_GROUPS": "machine-a=" + wsPeop},
		"other client ceiling": {"MACHINE_WRITE_GROUPS": "machine-b=" + wsGroup},
		"no ceiling at all":    {"MACHINE_WRITE_SUBTREES": "machine-b=ou=svc," + wsBase, "MACHINE_WRITE_GROUPS": "machine-a=" + wsGroup},
		"privileged listed":    {"MACHINE_WRITE_GROUPS": "machine-a=" + wsAdmin},
		"privileged case":      {"MACHINE_WRITE_GROUPS": "machine-a=cn=ADMINS," + wsPeop},
		"below privileged":     {"MACHINE_WRITE_GROUPS": "machine-a=cn=sub," + wsAdmin},
		"no deny set":          {"MACHINE_WRITE_PRIVILEGED_GROUPS": "-"},
		"OID type":             {"MACHINE_WRITE_GROUPS": "machine-a=2.5.4.3=team," + wsPeop},
		"escape":               {"MACHINE_WRITE_GROUPS": `machine-a=cn=te\61m,` + wsPeop},
		"multi-valued":         {"MACHINE_WRITE_GROUPS": "machine-a=cn=team+ou=x," + wsPeop},
		"upper-case type":      {"MACHINE_WRITE_GROUPS": "machine-a=CN=team," + wsPeop},
		"spacing":              {"MACHINE_WRITE_GROUPS": "machine-a=cn=team, " + wsPeop},
		"unknown client":       {"MACHINE_WRITE_GROUPS": "machine-z=" + wsGroup},
		"privileged OID":       {"MACHINE_WRITE_PRIVILEGED_GROUPS": "2.5.4.3=admins," + wsPeop},
		"privileged relative":  {"MACHINE_WRITE_PRIVILEGED_GROUPS": "cn=admins;cn=a  b," + wsPeop},
		"privileged escape":    {"MACHINE_WRITE_PRIVILEGED_GROUPS": `cn=adm\69ns,` + wsPeop},
	}
	for name, over := range cases {
		t.Run(name, func(t *testing.T) {
			if cfg, err := Load(writeScopeEnv(over)); err == nil {
				t.Fatalf("accepted: %+v", cfg.Machine.Write)
			}
		})
	}
}

func TestMachineWriteScopeLimitRanges(t *testing.T) {
	for _, tc := range []struct{ name, v string }{
		{"MACHINE_WRITE_RATE_LIMIT_RPS", "0"}, {"MACHINE_WRITE_RATE_LIMIT_RPS", "101"}, {"MACHINE_WRITE_RATE_LIMIT_RPS", "x"},
		{"MACHINE_WRITE_RATE_LIMIT_BURST", "0"}, {"MACHINE_WRITE_RATE_LIMIT_BURST", "101"},
		{"MACHINE_WRITE_GLOBAL_SLOTS", "0"}, {"MACHINE_WRITE_GLOBAL_SLOTS", "65"}, {"MACHINE_WRITE_GLOBAL_SLOTS", "-1"},
	} {
		if _, err := Load(writeScopeEnv(map[string]string{tc.name: tc.v})); err == nil || !strings.Contains(err.Error(), tc.name) {
			t.Errorf("%s=%s: %v", tc.name, tc.v, err)
		}
	}
	for _, tc := range []struct{ name, v string }{
		{"MACHINE_WRITE_RATE_LIMIT_RPS", "100"}, {"MACHINE_WRITE_RATE_LIMIT_BURST", "1"}, {"MACHINE_WRITE_GLOBAL_SLOTS", "64"},
	} {
		if _, err := Load(writeScopeEnv(map[string]string{tc.name: tc.v})); err != nil {
			t.Errorf("%s=%s: %v", tc.name, tc.v, err)
		}
	}
}

// D23: (write clients + human reserve) x MaxPerSubject must fit MaxRecords.
func TestMachineWriteScopeIdempotencyQuota(t *testing.T) {
	for _, tc := range []struct {
		per, total, clients int
		ok                  bool
	}{
		{1000, 10000, 9, true}, {1000, 10000, 10, false}, {1000, 10000, 0, true}, {1000, 1000, 0, true}, {1000, 1000, 1, false}, {1, 2, 1, true}, {2, 1, 1, false},
	} {
		if err := checkMachineWriteQuota(tc.per, tc.total, tc.clients); (err == nil) != tc.ok {
			t.Errorf("%+v: %v", tc, err)
		}
	}
	for n, ok := range map[int]bool{9: true, 10: false} {
		var allowed, subtrees []string
		for i := 0; i < n; i++ {
			allowed = append(allowed, fmt.Sprintf("c%d=audit.read", i))
			subtrees = append(subtrees, fmt.Sprintf("c%d=ou=u%d,%s", i, i, wsBase))
		}
		_, err := Load(writeScopeEnv(map[string]string{
			"MACHINE_ALLOWED_CLIENTS": strings.Join(allowed, ";"), "MACHINE_WRITE_SUBTREES": strings.Join(subtrees, ";"), "MACHINE_WRITE_GROUPS": "-",
		}))
		if (err == nil) != ok || (!ok && !strings.Contains(err.Error(), "idempotency store")) {
			t.Errorf("%d clients: %v", n, err)
		}
	}
}

// With writes off every new variable is ignored, even valid ones: nothing is
// read and the configuration equals the one without them.
func TestMachineWriteScopeOffReadsNothing(t *testing.T) {
	base := writeScopeEnv(map[string]string{"MACHINE_WRITE_ENABLED": "false"})
	read := map[string]bool{}
	cfg, err := Load(func(name string) string {
		if strings.HasPrefix(name, "MACHINE_WRITE_") {
			read[name] = true
		}
		return base(name)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(read) != 1 || !read["MACHINE_WRITE_ENABLED"] {
		t.Fatalf("read %v, want only MACHINE_WRITE_ENABLED", read)
	}
	plain, err := Load(machineEnv(map[string]string{"UI_IDEMPOTENCY_ENABLED": "true", "BACKUP_ADMIN_DNS": "uid=backup,ou=system," + wsBase, "LDAP_SERVICE_ACCOUNT_DN": "cn=service,ou=system," + wsBase}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg, plain) {
		t.Fatalf("v1 configuration changed:\n%+v\n%+v", cfg.Machine, plain.Machine)
	}
	// Garbage is just as invisible while off.
	if _, err := Load(machineEnv(map[string]string{"MACHINE_WRITE_SUBTREES": "x", "MACHINE_WRITE_GROUPS": "x", "MACHINE_WRITE_PRIVILEGED_GROUPS": "x", "MACHINE_WRITE_GLOBAL_SLOTS": "x"})); err != nil {
		t.Fatal(err)
	}
}

// Valid scope variables never replace the prerequisites: the switch still fails
// startup without idempotency, machine auth or identities.
func TestMachineWriteScopeEnabledStillNeedsPrerequisites(t *testing.T) {
	for want, over := range map[string]map[string]string{
		"requires UI_IDEMPOTENCY_ENABLED": {"UI_IDEMPOTENCY_ENABLED": "false"},
		"requires MACHINE_AUTH_ENABLED":   {"MACHINE_AUTH_ENABLED": "-"},
		"MACHINE_WRITE_DATA":              {"MACHINE_WRITE_DATA_BIND_DN": "-"},
	} {
		if _, err := Load(writeScopeEnv(over)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: %v, want %q", over, err, want)
		}
	}
}

// D20 on its own: the base has no protected DN in this check, so only the strict
// rule can refuse a ceiling equal to the base (the Load path is also covered by
// the overlap rule because cn=admin,<base> is always protected).
func TestMachineWriteCeilingStrictRule(t *testing.T) {
	base, _ := ldap.ParseDN(wsBase)
	for dn, ok := range map[string]bool{
		wsBase: false, "DC=Example,DC=Org": false, "dc=org": false, "dc=other,dc=org": false, "ou=people": false, wsPeop: true,
	} {
		d, _ := ldap.ParseDN(dn)
		if err := checkWriteCeilingStrict(base, d); (err == nil) != ok {
			t.Errorf("%q: %v", dn, err)
		}
	}
}

// The covering exemption belongs to privileged groups only: a DN that is also an
// administrator identity is refused when a ceiling covers it.
func TestMachineWriteCeilingExemptionIsByRole(t *testing.T) {
	over := map[string]string{"BACKUP_ADMIN_DNS": wsAdmin, "MACHINE_WRITE_GROUPS": "-"}
	if _, err := Load(writeScopeEnv(over)); err == nil || !strings.Contains(err.Error(), "MACHINE_WRITE_SUBTREES") {
		t.Fatalf("covering ceiling accepted for a DN that is also an administrator: %v", err)
	}
	over["MACHINE_WRITE_SUBTREES"] = "machine-a=ou=apps," + wsBase
	if _, err := Load(writeScopeEnv(over)); err != nil {
		t.Fatalf("non-covering ceiling refused: %v", err)
	}
}
