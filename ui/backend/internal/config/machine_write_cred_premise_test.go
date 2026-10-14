package config

import (
	"strings"
	"testing"
	"time"
)

// v2c T-028 (D379-15, D379-16): what the run-time premise checks read - the
// cn=config reader identity, the canaries and the pending TTL.

func TestMachineWriteCredPremiseSettingsValid(t *testing.T) {
	staff := "ou=staff," + wsPeop
	cfg, err := Load(credEnv(map[string]string{
		"MACHINE_WRITE_CRED_SUBTREES":    "machine-a=" + wsPeop + "|" + staff,
		"MACHINE_WRITE_CRED_CANARIES":    canarySet(wsPeop) + ";" + canarySet(staff),
		"MACHINE_WRITE_CRED_PENDING_TTL": "36h",
	}))
	if err != nil {
		t.Fatal(err)
	}
	w := cfg.Machine.Write
	if w.CredACLReader.BindDN != wcReader || w.CredACLReader.BindPassword != "private-reader" || w.CredPendingTTL != 36*time.Hour || len(w.CredCanaries) != 2 {
		t.Fatalf("unexpected premise config: reader=%q ttl=%s canaries=%d", w.CredACLReader.BindDN, w.CredPendingTTL, len(w.CredCanaries))
	}
	if c := w.CredCanaries[1]; c.WithPassword != "uid=canary-pw,"+staff || c.Unmarked != "uid=canary-unmarked,"+staff || c.Pending != "uid=canary-pending,"+staff {
		t.Fatalf("canary order: %+v", c)
	}
	set := strings.ToLower(strings.Join(cfg.MachineWriteProtectedDNs(), "|"))
	for _, want := range []string{wcReader, "uid=canary-pw," + wsPeop, "uid=canary-unmarked," + staff, "uid=canary-pending," + staff} {
		if !strings.Contains(set, want) {
			t.Errorf("%s missing from the protected set", want)
		}
	}
	// T028-D9: the default TTL.
	cfg, err = Load(credEnv(nil))
	if err != nil || cfg.Machine.Write.CredPendingTTL != 24*time.Hour {
		t.Fatalf("default TTL: %v %v", cfg.Machine.Write.CredPendingTTL, err)
	}
}

// Off: none of the T-028 variables is read (REQ-001); the existing off test
// covers every MACHINE_WRITE_CRED_* name, these included.
func TestMachineWriteCredPremiseOffFieldsZero(t *testing.T) {
	cfg, err := Load(credEnv(map[string]string{"MACHINE_WRITE_CRED_ENABLED": "false", "MACHINE_WRITE_CRED_CANARIES": "garbage", "MACHINE_WRITE_CRED_PENDING_TTL": "garbage"}))
	if err != nil {
		t.Fatal(err)
	}
	w := cfg.Machine.Write
	if w.CredACLReader != (MachineWriteIdentity{}) || w.CredCanaries != nil || w.CredPendingTTL != 0 {
		t.Fatalf("off: premise fields set: %+v", w)
	}
}

func TestMachineWriteCredPremiseFailClosed(t *testing.T) {
	staff := "ou=staff," + wsPeop
	lockOn := map[string]string{"MACHINE_WRITE_LOCK_ENABLED": "true", "MACHINE_WRITE_LOCK_BIND_DN": "cn=locker,ou=system," + wsBase, "MACHINE_WRITE_LOCK_BIND_PASSWORD": "private-lock"}
	withLock := func(k, v string) map[string]string {
		out := map[string]string{k: v}
		for lk, lv := range lockOn {
			out[lk] = lv
		}
		return out
	}
	cases := map[string]map[string]string{
		"reader DN unset":          {"MACHINE_WRITE_CRED_ACL_READER_DN": ""},
		"reader password unset":    {"MACHINE_WRITE_CRED_ACL_READER_PASSWORD": ""},
		"reader DN invalid":        {"MACHINE_WRITE_CRED_ACL_READER_DN": "not a dn"},
		"reader is W_data":         {"MACHINE_WRITE_CRED_ACL_READER_DN": "cn=writer,ou=system," + wsBase},
		"reader is W_data folded":  {"MACHINE_WRITE_CRED_ACL_READER_DN": "CN=WRITER, OU=SYSTEM, DC=EXAMPLE, DC=ORG"},
		"reader is W_cred":         {"MACHINE_WRITE_CRED_ACL_READER_DN": wcDN},
		"reader is W_lock":         withLock("MACHINE_WRITE_CRED_ACL_READER_DN", "cn=locker,ou=system,"+wsBase),
		"reader is M":              {"MACHINE_WRITE_CRED_ACL_READER_DN": "cn=machine,ou=system," + wsBase},
		"reader is admin":          {"MACHINE_WRITE_CRED_ACL_READER_DN": "cn=admin," + wsBase},
		"reader is replicator":     {"MACHINE_WRITE_CRED_ACL_READER_DN": "cn=replicator," + wsBase},
		"reader is service":        {"MACHINE_WRITE_CRED_ACL_READER_DN": "cn=service,ou=system," + wsBase},
		"reader alias type":        {"MACHINE_WRITE_CRED_ACL_READER_DN": "commonName=acl-reader,ou=system," + wsBase},
		"reader inside a ceiling":  {"MACHINE_WRITE_CRED_ACL_READER_DN": "uid=reader," + wsPeop},
		"canaries unset":           {"MACHINE_WRITE_CRED_CANARIES": ""},
		"canary set of two":        {"MACHINE_WRITE_CRED_CANARIES": "uid=a," + wsPeop + "|uid=b," + wsPeop},
		"canary set of four":       {"MACHINE_WRITE_CRED_CANARIES": canarySet(wsPeop) + "|uid=d," + wsPeop},
		"canary non-canonical":     {"MACHINE_WRITE_CRED_CANARIES": "UID=a," + wsPeop + "|uid=b," + wsPeop + "|uid=c," + wsPeop},
		"canary outside subtree":   {"MACHINE_WRITE_CRED_CANARIES": "uid=a,ou=apps," + wsBase + "|uid=b,ou=apps," + wsBase + "|uid=c,ou=apps," + wsBase},
		"canary set split":         {"MACHINE_WRITE_CRED_SUBTREES": "machine-a=" + staff + "|ou=apps," + wsBase, "MACHINE_WRITE_CRED_CANARIES": "uid=a," + staff + "|uid=b," + staff + "|uid=c,ou=apps," + wsBase},
		"canary is the subtree":    {"MACHINE_WRITE_CRED_CANARIES": wsPeop + "|uid=b," + wsPeop + "|uid=c," + wsPeop},
		"canary repeated":          {"MACHINE_WRITE_CRED_CANARIES": "uid=a," + wsPeop + "|uid=a," + wsPeop + "|uid=c," + wsPeop},
		"canary repeated folded":   {"MACHINE_WRITE_CRED_CANARIES": "uid=a," + wsPeop + "|uid=A," + wsPeop + "|uid=c," + wsPeop},
		"canary repeated set":      {"MACHINE_WRITE_CRED_CANARIES": canarySet(wsPeop) + ";uid=x," + wsPeop + "|uid=canary-pw," + wsPeop + "|uid=y," + wsPeop},
		"canary is privileged":     {"MACHINE_WRITE_CRED_CANARIES": wsAdmin + "|uid=b," + wsPeop + "|uid=c," + wsPeop},
		"second subtree uncovered": {"MACHINE_WRITE_CRED_SUBTREES": "machine-a=" + wsPeop + "|ou=apps," + wsBase, "MACHINE_WRITE_CRED_CANARIES": canarySet(wsPeop)},
		"nested subtree uncovered": {"MACHINE_WRITE_CRED_SUBTREES": "machine-a=" + wsPeop + "|" + staff, "MACHINE_WRITE_CRED_CANARIES": canarySet(wsPeop)},
		"other client uncovered":   {"MACHINE_WRITE_CRED_SUBTREES": "machine-a=" + wsPeop + ";machine-b=ou=svc," + wsBase, "MACHINE_WRITE_CRED_CANARIES": canarySet(wsPeop)},
		"ttl malformed":            {"MACHINE_WRITE_CRED_PENDING_TTL": "a day"},
		"ttl too short":            {"MACHINE_WRITE_CRED_PENDING_TTL": "59m"},
		"ttl too long":             {"MACHINE_WRITE_CRED_PENDING_TTL": "721h"},
	}
	many := make([]string, 17)
	for i := range many {
		many[i] = canarySet("ou=s" + string(rune('a'+i)) + "," + wsPeop)
	}
	cases["canary sets too many"] = map[string]string{"MACHINE_WRITE_CRED_CANARIES": strings.Join(many, ";")}
	for name, over := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(credEnv(over))
			if err == nil {
				t.Fatal("accepted")
			}
			if msg := err.Error(); strings.Contains(msg, "private-") || strings.Contains(msg, "canary-") || strings.Contains(msg, "acl-reader") || strings.Contains(msg, "a day") {
				t.Fatalf("diagnostic echoes a value: %s", msg)
			}
		})
	}
	// Boundaries that are accepted: 1h, 720h, 16 sets.
	for _, ttl := range []string{"1h", "720h", " 2h "} {
		if _, err := Load(credEnv(map[string]string{"MACHINE_WRITE_CRED_PENDING_TTL": ttl})); err != nil {
			t.Errorf("ttl %q: %v", ttl, err)
		}
	}
	if _, err := Load(credEnv(map[string]string{"MACHINE_WRITE_CRED_CANARIES": strings.Join(many[:16], ";")})); err != nil {
		t.Errorf("16 canary sets: %v", err)
	}
}
