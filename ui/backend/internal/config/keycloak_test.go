package config

import "testing"

func TestKeycloakBoundary(t *testing.T) {
	env := map[string]string{"KEYCLOAK_ADMIN_URL": "https://sso.example", "KEYCLOAK_ADMIN_REALM": "company", "KEYCLOAK_ADMIN_CLIENT_ID": "ldapium-svc", "KEYCLOAK_ADMIN_CLIENT_SECRET": "test-secret", "KEYCLOAK_OBSERVE_CLIENTS": "custom"}
	get := func(k string) string { return env[k] }
	if _, err := loadKeycloak(get); err != nil {
		t.Fatal(err)
	}
	env["KEYCLOAK_DELEGATE_CLIENTS"] = "custom"
	if _, err := loadKeycloak(get); err == nil {
		t.Fatal("shared-realm write enabled")
	}
	env["KEYCLOAK_ISOLATED_REALM"] = "true"
	if _, err := loadKeycloak(get); err != nil {
		t.Fatal(err)
	}
	env["KEYCLOAK_OBSERVE_CLIENTS"] = "realm-management"
	if _, err := loadKeycloak(get); err == nil {
		t.Fatal("privileged client")
	}
	env["KEYCLOAK_OBSERVE_CLIENTS"] = "custom"
	env["KEYCLOAK_ADMIN_URL"] = "http://sso.example"
	env["KEYCLOAK_ALLOW_LOCAL_HTTP"] = "true"
	if _, err := loadKeycloak(get); err == nil {
		t.Fatal("remote HTTP")
	}
}
