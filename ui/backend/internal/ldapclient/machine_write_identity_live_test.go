//go:build live

package ldapclient

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

func TestMachineWriteIdentityLive(t *testing.T) {
	if os.Getenv("LDAPIUM_WRITE_IDENTITY_LIVE") != "1" {
		t.Skip("requires disposable live fixture")
	}
	password, err := os.ReadFile("/tmp/.write-identity-password")
	if err != nil {
		t.Fatal(err)
	}
	const base = "dc=example,dc=org"
	cfg := config.Config{LDAPURL: "ldap://127.0.0.1", BaseDN: base, Machine: config.MachineConfig{Enabled: true, WriteEnabled: true, BindDN: "cn=reader," + base, BindPassword: string(password)}}
	r := NewWriteIdentityReader(cfg, []string{"cn=writer," + base})
	if os.Getenv("LDAPIUM_WRITE_IDENTITY_DENIED_READ") == "1" {
		if err := r.Check(context.Background(), "uid=baseline,"+base, "inetOrgPerson"); err == nil {
			t.Fatal("ACL-hidden identity passed")
		}
		t.Log("PASS server-hidden identity attributes / zero-read ACL fail closed")
		return
	}

	for _, tc := range []struct {
		dn, class string
		allowed   bool
	}{
		{"uid=baseline," + base, "inetOrgPerson", true},
		{"UID=BASELINE,DC=example,DC=org", "inetOrgPerson", true},
		{"cn=baseline-group," + base, "groupOfNames", true},
		{"cn=baseline-group," + base, "inetOrgPerson", false},
		{"uid=baseline," + base, "groupOfNames", false},
		{"cn=reader," + base, "inetOrgPerson", false},
		{"cn=writer," + base, "inetOrgPerson", false},
		{"cn=admin," + base, "inetOrgPerson", false},
		{"cn=replicator," + base, "inetOrgPerson", false},
		{"commonName=writer," + base, "inetOrgPerson", false},
		{"0.9.2342.19200300.100.1.1=baseline," + base, "inetOrgPerson", false},
		{"uid=baseline,domainComponent=example,dc=org", "inetOrgPerson", false},
		{"uid=#0408626173656c696e65," + base, "inetOrgPerson", false},
	} {
		err := r.Check(context.Background(), tc.dn, tc.class)
		if tc.allowed && err != nil {
			t.Fatalf("allowed %s: %v", tc.dn, err)
		}
		if !tc.allowed && !errors.Is(err, domain.ErrPermissionDenied) {
			t.Fatalf("denied %s: %v", tc.dn, err)
		}
	}
	cfg.Machine.BindPassword = "incorrect-private-password"
	if err := NewWriteIdentityReader(cfg, nil).Check(context.Background(), "uid=baseline,"+base, "inetOrgPerson"); err == nil {
		t.Fatal("invalid M credentials passed")
	}
	cfg.Machine.BindPassword = string(password)
	if err := NewWriteIdentityReader(cfg, []string{"cn=missing," + base}).Check(context.Background(), "uid=baseline,"+base, "inetOrgPerson"); err == nil {
		t.Fatal("unresolved protected identity passed")
	}
	t.Log("PASS real read-only M: resolved UUID/entryDN/type, protected/alias refusal, invalid bind and unresolved protection fail closed")
}
