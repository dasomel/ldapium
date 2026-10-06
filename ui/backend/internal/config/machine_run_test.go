package config

import (
	"strings"
	"testing"
)

// D19: the bind DN may not equal ANY contiguous run of RDNs of a configured DN
// entry, so a comma-joined list cannot hide the 2nd, 3rd... real DN.
func TestMachine_BindDNContiguousRunRefused(t *testing.T) {
	two := "cn=admin,dc=example,dc=org,cn=other,dc=example,dc=org"
	three := "cn=a,dc=example,dc=org,cn=b,dc=example,dc=org,cn=c,dc=example,dc=org"
	cases := []struct{ name, roots, bind string }{
		{"second DN", two, "cn=other,dc=example,dc=org"},
		{"second DN case/space", two, "CN=Other, DC=Example ,dc=org"},
		{"middle DN of three", three, "cn=b,dc=example,dc=org"},
		{"last DN of three", three, "cn=c,dc=example,dc=org"},
		{"leading DN", two, "cn=admin,dc=example,dc=org"},
		{"pure suffix", "cn=admin,dc=example,dc=org", "dc=example,dc=org"},
		{"single middle RDN", two, "dc=example"},
		{"escaped comma value", `cn=a\,b,dc=example,dc=org,cn=x,dc=example,dc=org`, "cn=x,dc=example,dc=org"},
		{"escaped comma run", `cn=a\,b,dc=example,dc=org`, `cn=a\,b,dc=example`},
		{"multivalued RDN either order", "uid=x+cn=y,dc=example,dc=org", "cn=y+uid=x,dc=example,dc=org"},
		{"multivalued RDN inside a long list", "cn=a,dc=example,dc=org,uid=x+cn=y,dc=example,dc=org", "cn=y+uid=x,dc=example,dc=org"},
		{"semicolon list, DN as its own entry", "cn=a,dc=example,dc=org;cn=other,dc=example,dc=org", "cn=other,dc=example,dc=org"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(machineEnv(map[string]string{"MACHINE_LDAP_ROOT_DNS": tc.roots, "MACHINE_LDAP_BIND_DN": tc.bind}))
			if err == nil {
				t.Fatal("want startup failure")
			}
		})
	}
	// The comma-joined cases carry the ';' hint.
	_, err := Load(machineEnv(map[string]string{"MACHINE_LDAP_ROOT_DNS": two, "MACHINE_LDAP_BIND_DN": "cn=other,dc=example,dc=org"}))
	if err == nil || !strings.Contains(err.Error(), "separate DN list entries with ';'") {
		t.Errorf("second DN: %v", err)
	}
}

func TestMachine_BindDNNotAContiguousRunAccepted(t *testing.T) {
	cases := []struct{ roots, bind string }{
		{"cn=admin,dc=example,dc=org", "uid=machine,ou=svc,dc=example,dc=org"},
		{"cn=admin,dc=example,dc=org", "cn=machine,ou=system,dc=example,dc=org"},
		{"cn=admin,dc=example,dc=org;cn=other,dc=example,dc=org", "cn=machine,dc=example,dc=org"},
		{`cn=a\,b,dc=example,dc=org`, `cn=a,dc=example,dc=org`},
		{"cn=admin,dc=example,dc=org", "dc=org,cn=admin"}, // same RDNs, wrong order: not a run
		{"uid=x+cn=y,dc=example,dc=org", "uid=x,dc=example,dc=org"},
	}
	for _, tc := range cases {
		if _, err := Load(machineEnv(map[string]string{"MACHINE_LDAP_ROOT_DNS": tc.roots, "MACHINE_LDAP_BIND_DN": tc.bind})); err != nil {
			t.Errorf("roots %q bind %q: %v", tc.roots, tc.bind, err)
		}
	}
}
