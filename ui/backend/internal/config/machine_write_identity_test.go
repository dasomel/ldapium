package config

import (
	"strings"
	"testing"
)

func writeIdentityEnv(over map[string]string) func(string) string {
	// T-013: the switch refuses itself without a writer, so the fixture has one
	// client that holds a write scope and a ceiling.
	values := map[string]string{"MACHINE_WRITE_ENABLED": "true", "UI_IDEMPOTENCY_ENABLED": "true",
		"MACHINE_ALLOWED_CLIENTS":    "machine-a=directory.users.read,directory.groups.read,directory.users.create;machine-b=audit.read",
		"MACHINE_WRITE_SUBTREES":     "machine-a=ou=people,dc=example,dc=org",
		"MACHINE_WRITE_DATA_BIND_DN": "cn=writer,ou=system,dc=example,dc=org", "MACHINE_WRITE_DATA_BIND_PASSWORD": "private-data"}
	for k, v := range over {
		values[k] = v
	}
	return machineEnv(values)
}

func TestMachineWriteIdentitiesDefaultsAndIndependentLock(t *testing.T) {
	cfg, err := Load(writeIdentityEnv(map[string]string{"MACHINE_WRITE_LOCK_BIND_DN": "invalid", "MACHINE_WRITE_LOCK_BIND_PASSWORD": "invalid"}))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Machine.WriteEnabled || cfg.Machine.Write.LockEnabled || cfg.Machine.Write.Lock != (MachineWriteIdentity{}) || cfg.Machine.Write.Data.BindDN != "cn=writer,ou=system,dc=example,dc=org" {
		t.Fatal("unexpected write identity state")
	}
	cfg, err = Load(writeIdentityEnv(map[string]string{"MACHINE_WRITE_LOCK_ENABLED": "true", "MACHINE_WRITE_LOCK_BIND_DN": "cn=locker,ou=system,dc=example,dc=org", "MACHINE_WRITE_LOCK_BIND_PASSWORD": "private-lock"}))
	if err != nil || !cfg.Machine.Write.LockEnabled {
		t.Fatalf("distinct lock identity: %v", err)
	}
}

func TestMachineWriteIdentitiesFailClosed(t *testing.T) {
	cases := []map[string]string{
		{"UI_IDEMPOTENCY_ENABLED": "false"},
		{"MACHINE_AUTH_ENABLED": "false"},
		{"MACHINE_WRITE_DATA_BIND_DN": "-"},
		{"MACHINE_WRITE_DATA_BIND_PASSWORD": "-"},
		{"MACHINE_WRITE_DATA_BIND_DN": "not a dn"},
		{"MACHINE_WRITE_LOCK_ENABLED": "maybe"},
		{"MACHINE_WRITE_LOCK_ENABLED": "true"},
		{"MACHINE_WRITE_LOCK_ENABLED": "true", "MACHINE_WRITE_LOCK_BIND_DN": "cn=locker,ou=system,dc=example,dc=org"},
		{"MACHINE_WRITE_LOCK_ENABLED": "true", "MACHINE_WRITE_LOCK_BIND_DN": "CN=WRITER,OU=SYSTEM,DC=EXAMPLE,DC=ORG", "MACHINE_WRITE_LOCK_BIND_PASSWORD": "private-lock"},
		{"MACHINE_WRITE_DATA_BIND_DN": "2.5.4.3=admin,dc=example,dc=org"},
		{"MACHINE_WRITE_DATA_BIND_DN": "cn=two  spaces,dc=example,dc=org"},
		{"MACHINE_LDAP_ROOT_DNS": "2.5.4.3=root,dc=example,dc=org", "MACHINE_WRITE_DATA_BIND_DN": "cn=root,dc=example,dc=org"},
		{"MACHINE_LDAP_BIND_DN": "cn=two  spaces,dc=example,dc=org"},
	}
	for i, over := range cases {
		_, err := Load(writeIdentityEnv(over))
		if err == nil {
			t.Errorf("case %d accepted", i)
			continue
		}
		if strings.Contains(err.Error(), "private-") {
			t.Errorf("case %d leaked password", i)
		}
	}
}

func TestMachineWriteIdentitiesRejectProtectedDNVariants(t *testing.T) {
	protected := []string{
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
	}
	for _, dn := range protected {
		_, err := Load(writeIdentityEnv(map[string]string{"MACHINE_WRITE_DATA_BIND_DN": dn, "BACKUP_ADMIN_DNS": "uid=backup,ou=system,dc=example,dc=org", "APP_PROFILES_ADMIN_DNS": "uid=profile,ou=system,dc=example,dc=org", "LDAP_SERVICE_ACCOUNT_DN": "cn=service,ou=system,dc=example,dc=org"}))
		if err == nil {
			t.Errorf("accepted protected identity %s", dn)
		}
	}
}

func TestMachineWriteOffNeverReadsIdentities(t *testing.T) {
	base := machineEnv(nil)
	_, err := Load(func(name string) string {
		if strings.HasPrefix(name, "MACHINE_WRITE_") && name != "MACHINE_WRITE_ENABLED" {
			t.Fatalf("read disabled setting %s", name)
		}
		return base(name)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMachineWriteIdentityRejectsReorderedMultivaluedRDN(t *testing.T) {
	_, err := Load(writeIdentityEnv(map[string]string{"MACHINE_LDAP_ROOT_DNS": "cn=root+uid=admin,dc=example,dc=org", "MACHINE_WRITE_DATA_BIND_DN": "UID=ADMIN+CN=ROOT,dc=example,dc=org"}))
	if err == nil {
		t.Fatal("reordered root RDN accepted")
	}
}

// Resolved Q4: the plaintext target DN in the write audit line is an operator
// option, off by default, and read only behind MACHINE_WRITE_ENABLED.
func TestMachineWriteAuditTargetDNOption(t *testing.T) {
	cfg, err := Load(writeIdentityEnv(nil))
	if err != nil || cfg.Machine.Write.AuditPlainTargetDN {
		t.Fatalf("default must be fingerprint only: %v", err)
	}
	cfg, err = Load(writeIdentityEnv(map[string]string{"MACHINE_WRITE_AUDIT_TARGET_DN": "true"}))
	if err != nil || !cfg.Machine.Write.AuditPlainTargetDN {
		t.Fatalf("option not honoured: %v", err)
	}
	if _, err = Load(writeIdentityEnv(map[string]string{"MACHINE_WRITE_AUDIT_TARGET_DN": "maybe"})); err == nil {
		t.Fatal("a malformed value must fail startup")
	}
	// Write off: the option is not read, so even garbage is ignored.
	cfg, err = Load(machineEnv(map[string]string{"MACHINE_WRITE_AUDIT_TARGET_DN": "garbage"}))
	if err != nil || cfg.Machine.Write.AuditPlainTargetDN {
		t.Fatalf("option read while MACHINE_WRITE_ENABLED is off: %v", err)
	}
}

// v2b T-013 (D379-2, REQ-006): a lock ceiling without W_lock is a start-up
// error. directory.users.lock is not an opened scope yet (T-014), so the test
// opens it for its own duration; directory.users.unlock is never opened.
func TestMachineWriteLockCeilingNeedsW_lock(t *testing.T) {
	saved := MachineWriteOpenScopes
	MachineWriteOpenScopes = append(append([]string(nil), saved...), "directory.users.lock")
	t.Cleanup(func() { MachineWriteOpenScopes = saved })
	lock := map[string]string{"MACHINE_WRITE_LOCK_ENABLED": "true", "MACHINE_WRITE_LOCK_BIND_DN": "cn=locker,ou=system," + wsBase, "MACHINE_WRITE_LOCK_BIND_PASSWORD": "private-lock"}
	withLock := func(over map[string]string) map[string]string {
		out := map[string]string{"MACHINE_ALLOWED_CLIENTS": "machine-a=directory.users.read,directory.users.create,directory.users.lock;machine-b=audit.read"}
		for k, v := range over {
			out[k] = v
		}
		return out
	}
	if _, err := Load(writeScopeEnv(withLock(nil))); err == nil || !strings.Contains(err.Error(), "MACHINE_WRITE_LOCK_ENABLED") {
		t.Errorf("lock ceiling without W_lock: %v", err)
	}
	// Either client's ceiling counts, not only the writer with a subtree.
	if _, err := Load(writeScopeEnv(map[string]string{"MACHINE_ALLOWED_CLIENTS": "machine-a=directory.users.read,directory.users.create;machine-b=directory.users.lock"})); err == nil {
		t.Error("lock ceiling on a client without a write subtree was accepted")
	}
	if _, err := Load(writeScopeEnv(withLock(lock))); err != nil {
		t.Errorf("lock ceiling with W_lock: %v", err)
	}
	// No lock scope in any ceiling: W_lock stays optional and off.
	if _, err := Load(writeScopeEnv(map[string]string{"MACHINE_ALLOWED_CLIENTS": "machine-a=directory.users.read,directory.users.create;machine-b=audit.read"})); err != nil {
		t.Errorf("no lock scope: %v", err)
	}
	// Unlock stays an unopened vocabulary item with or without W_lock.
	for _, env := range []map[string]string{nil, lock} {
		over := map[string]string{"MACHINE_ALLOWED_CLIENTS": "machine-a=directory.users.read,directory.users.create,directory.users.unlock;machine-b=audit.read"}
		for k, v := range env {
			over[k] = v
		}
		if _, err := Load(writeScopeEnv(over)); err == nil || !strings.Contains(err.Error(), "no operation uses yet") {
			t.Errorf("unlock in a ceiling: %v", err)
		}
	}
}
