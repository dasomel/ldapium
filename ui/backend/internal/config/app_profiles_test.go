package config

import "testing"

func TestAppProfileAdminConfiguration(t *testing.T) {
	env := map[string]string{"LDAP_URL": "ldap://localhost:389", "LDAP_BASE_DN": "dc=example,dc=org", "SESSION_SECRET": "01234567890123456789012345678901", "APP_PROFILES_PATH": "/tmp/profiles.json"}
	get := func(k string) string { return env[k] }
	if _, err := Load(get); err == nil {
		t.Fatal("enabled profile storage without admin allowlist")
	}
	env["APP_PROFILES_ADMIN_DNS"] = " cn=one,dc=example ; cn=two,dc=example "
	cfg, err := Load(get)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AppProfilesAdminDNs) != 2 || cfg.AppProfilesAdminDNs[0] != "cn=one,dc=example" {
		t.Fatal(cfg.AppProfilesAdminDNs)
	}
}
