package config

import (
	"strings"
	"testing"
)

func writeIdentityEnv(over map[string]string) func(string) string {
	values := map[string]string{"MACHINE_WRITE_ENABLED": "true", "UI_IDEMPOTENCY_ENABLED": "true", "MACHINE_WRITE_DATA_BIND_DN": "cn=writer,ou=system,dc=example,dc=org", "MACHINE_WRITE_DATA_BIND_PASSWORD": "private-data"}
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
