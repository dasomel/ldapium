package config

import (
	"strings"
	"testing"
)

// A comma-joined root list is one valid, long DN whose leading RDNs are the
// real rootdns; the bind DN equal to any leading-RDN prefix is refused.
func TestMachine_CommaJoinedRootDNsRefused(t *testing.T) {
	joined := "cn=admin,dc=example,dc=org,cn=other,dc=example,dc=org"
	for _, bind := range []string{
		"cn=admin,dc=example,dc=org", "cn=admin", "cn=admin,dc=example",
		"CN=Admin, DC=Example,dc=org", "cn=admin,dc=example,dc=org,cn=other",
	} {
		_, err := Load(machineEnv(map[string]string{"MACHINE_LDAP_ROOT_DNS": joined, "MACHINE_LDAP_BIND_DN": bind}))
		if err == nil || !strings.Contains(err.Error(), "separate DN list entries with ';'") {
			t.Errorf("bind %q: want comma-joined refusal, got %v", bind, err)
		}
	}
}

func TestMachine_RootDNListsLegitimateForms(t *testing.T) {
	ok := []map[string]string{
		{}, // single legitimate DN, distinct bind
		{"MACHINE_LDAP_ROOT_DNS": " cn=admin,dc=example,dc=org ; cn=other,dc=example,dc=org ;"},
		{"MACHINE_LDAP_ROOT_DNS": ";cn=admin,dc=example,dc=org;;"},
		{"MACHINE_LDAP_ROOT_DNS": `cn=a\,b,dc=example,dc=org`, "MACHINE_LDAP_BIND_DN": `cn=a\,c,ou=system,dc=example,dc=org`},
		{"MACHINE_LDAP_ROOT_DNS": "CN=Admin,DC=Example,DC=Org", "MACHINE_LDAP_BIND_DN": "cn=machine,ou=system,dc=example,dc=org"},
	}
	for i, over := range ok {
		if _, err := Load(machineEnv(over)); err != nil {
			t.Errorf("case %d: %v", i, err)
		}
	}
	// An escaped comma is part of a value, not a separator: the bind DN equal
	// to the first RDN alone is a prefix and is refused.
	_, err := Load(machineEnv(map[string]string{
		"MACHINE_LDAP_ROOT_DNS": `cn=a\,b,dc=example,dc=org`, "MACHINE_LDAP_BIND_DN": `cn=a\,b`,
	}))
	if err == nil {
		t.Error("bind equal to a leading RDN with an escaped comma must be refused")
	}
}

func TestMachine_AudienceAccountRefused(t *testing.T) {
	for _, aud := range []string{"account", " Account ", "ACCOUNT"} {
		_, err := Load(machineEnv(map[string]string{"MACHINE_OIDC_AUDIENCE": aud}))
		if err == nil || !strings.Contains(err.Error(), "audience mapper") {
			t.Errorf("audience %q: got %v", aud, err)
		}
	}
	if _, err := Load(machineEnv(map[string]string{"MACHINE_OIDC_AUDIENCE": "account-api"})); err != nil {
		t.Errorf("account-api must be accepted: %v", err)
	}
}
