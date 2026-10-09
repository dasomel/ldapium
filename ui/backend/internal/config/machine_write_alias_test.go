package config

import "testing"

func TestIndependentReviewRejectsLDAPAliases(t *testing.T) {
	for _, dn := range []string{"commonName=admin,dc=example,dc=org", "cn=admin,domainComponent=example,domainComponent=org", "commonName=machine,ou=system,dc=example,dc=org"} {
		_, err := Load(writeIdentityEnv(map[string]string{"MACHINE_WRITE_DATA_BIND_DN": dn}))
		if err == nil {
			t.Errorf("protected alias accepted: %s", dn)
		}
	}
}

func TestWriteIdentityAliasesFailClosedOnBothSides(t *testing.T) {
	for _, key := range []string{"MACHINE_WRITE_DATA_BIND_DN", "MACHINE_WRITE_LOCK_BIND_DN", "MACHINE_LDAP_BIND_DN", "MACHINE_LDAP_ROOT_DNS", "BACKUP_ADMIN_DNS", "APP_PROFILES_ADMIN_DNS", "LDAP_SERVICE_ACCOUNT_DN"} {
		t.Run(key, func(t *testing.T) {
			env := map[string]string{key: "commonName=identity,ou=system,dc=example,dc=org"}
			if key == "MACHINE_WRITE_LOCK_BIND_DN" {
				env["MACHINE_WRITE_LOCK_ENABLED"] = "true"
				env["MACHINE_WRITE_LOCK_BIND_PASSWORD"] = "lock-test-secret"
			}
			_, err := Load(writeIdentityEnv(env))
			if err == nil {
				t.Fatalf("alias accepted for %s", key)
			}
		})
	}
}

func TestWriterAndProtectedSchemaAliases(t *testing.T) {
	cfg, err := Load(writeIdentityEnv(nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"writer", "read", "root", "backup", "profile", "service", "lock"} {
		t.Run(key, func(t *testing.T) {
			c := cfg
			m := cfg.Machine
			env := map[string]string{"MACHINE_WRITE_DATA_BIND_DN": "cn=writer,ou=system,dc=example,dc=org", "MACHINE_WRITE_DATA_BIND_PASSWORD": "private-test"}
			alias := "commonName=identity,ou=system,dc=example,dc=org"
			switch key {
			case "writer":
				env["MACHINE_WRITE_DATA_BIND_DN"] = alias
			case "read":
				m.BindDN = alias
			case "root":
				m.RootDNs = []string{alias}
			case "backup":
				c.BackupAdminDNs = []string{alias}
			case "profile":
				c.AppProfilesAdminDNs = []string{alias}
			case "service":
				c.SSO.LDAPServiceAccountDN = alias
			case "lock":
				env["MACHINE_WRITE_LOCK_ENABLED"] = "true"
				env["MACHINE_WRITE_LOCK_BIND_DN"] = alias
				env["MACHINE_WRITE_LOCK_BIND_PASSWORD"] = "private-test"
			}
			_, err := loadMachineWriteIdentities(func(k string) string { return env[k] }, c, m)
			if err == nil {
				t.Fatalf("alias accepted at %s", key)
			}
		})
	}
}
