package ldapclient

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

func TestWriteIdentityRejectsAmbiguousDNBeforeDial(t *testing.T) {
	cfg := config.Config{LDAPURL: "ldap://127.0.0.1:1", BaseDN: "dc=example,dc=org", Machine: config.MachineConfig{Enabled: true, WriteEnabled: true, BindDN: "cn=reader,dc=example,dc=org"}}
	for _, raw := range []string{"userid=user,dc=example,dc=org", "uid=#040475736572,dc=example,dc=org", "cn=Two  Spaces,dc=example,dc=org", "cn=\u00e9,dc=example,dc=org", "cn=" + strings.Repeat("x", 4096) + ",dc=example,dc=org", "dc=example,dc=org", "cn=config", "cn=admin,dc=example,dc=org"} {
		err := NewWriteIdentityReader(cfg, nil).Check(context.Background(), raw, "inetOrgPerson")
		if !errors.Is(err, domain.ErrPermissionDenied) {
			t.Fatalf("%q dialed or passed: %v", raw, err)
		}
	}
	cfg.Machine.RootDNs = []string{"commonName=root,dc=example,dc=org"}
	if err := NewWriteIdentityReader(cfg, nil).Check(context.Background(), "uid=user,dc=example,dc=org", "inetOrgPerson"); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Fatalf("ambiguous protected policy dialed: %v", err)
	}
}

func TestWriteIdentityNotFoundMapping(t *testing.T) {
	if !noSuchObject(ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))) {
		t.Fatal("result 32 not recognised")
	}
	for _, err := range []error{nil, context.DeadlineExceeded, ldap.NewError(ldap.ErrorNetwork, errors.New("lost")), ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied"))} {
		if noSuchObject(err) {
			t.Errorf("%v treated as noSuchObject", err)
		}
	}
	// A missing target stays ErrNotFound; a missing protected identity becomes a
	// non-NotFound directory error; other errors pass through unchanged.
	if got := protectedReadError(domain.ErrNotFound); errors.Is(got, domain.ErrNotFound) || !errors.Is(got, errWriteIdentityDirectory) {
		t.Fatalf("protected not-found = %v", got)
	}
	if got := protectedReadError(domain.ErrPermissionDenied); !errors.Is(got, domain.ErrPermissionDenied) {
		t.Fatalf("protected denial = %v", got)
	}
}

// D379-8: memberOf values are compared as parsed DNs, not as strings, and a
// value that does not parse is a denial.
func TestMemberOfPrivileged(t *testing.T) {
	const admins = "cn=admins,ou=people,dc=example,dc=org"
	privileged := []string{admins, "cn=ops,ou=people,dc=example,dc=org"}
	for name, tc := range map[string]struct {
		memberOf []string
		denied   bool
	}{
		"no memberOf":         {nil, false},
		"other group":         {[]string{"cn=team,ou=people,dc=example,dc=org"}, false},
		"privileged":          {[]string{admins}, true},
		"second privileged":   {[]string{"cn=team,ou=people,dc=example,dc=org", "cn=ops,ou=people,dc=example,dc=org"}, true},
		"upper case":          {[]string{"CN=ADMINS,OU=People,DC=example,DC=org"}, true},
		"OID type":            {[]string{"2.5.4.3=admins,ou=people,dc=example,dc=org"}, true},
		"other type":          {[]string{"o=elsewhere,dc=example,dc=org"}, true},
		"escaped":             {[]string{`cn=adm\69ns,ou=people,dc=example,dc=org`}, true},
		"child of privileged": {[]string{"cn=sub,cn=admins,ou=people,dc=example,dc=org"}, false},
		"unparseable":         {[]string{"not a dn"}, true},
	} {
		err := memberOfPrivileged(tc.memberOf, privileged)
		if tc.denied != errors.Is(err, domain.ErrPermissionDenied) || (!tc.denied && err != nil) {
			t.Errorf("%s: %v, denied=%v", name, err, tc.denied)
		}
	}
	if err := memberOfPrivileged([]string{admins}, nil); err != nil {
		t.Errorf("no privileged groups configured: %v", err)
	}
	if err := memberOfPrivileged([]string{admins}, []string{"not a dn"}); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Errorf("unparseable privileged group: %v", err)
	}
}

func TestCheckNotPrivilegedRejectsBeforeDial(t *testing.T) {
	cfg := config.Config{LDAPURL: "ldap://127.0.0.1:1", BaseDN: "dc=example,dc=org", Machine: config.MachineConfig{Enabled: true, WriteEnabled: true, BindDN: "cn=reader,dc=example,dc=org"}}
	for _, raw := range []string{"userid=user,dc=example,dc=org", "uid=#040475736572,dc=example,dc=org", "dc=", ""} {
		if err := NewWriteIdentityReader(cfg, nil).CheckNotPrivileged(context.Background(), raw); !errors.Is(err, domain.ErrPermissionDenied) {
			t.Errorf("%q dialed or passed: %v", raw, err)
		}
	}
	cfg.Machine.WriteEnabled = false
	if err := NewWriteIdentityReader(cfg, nil).CheckNotPrivileged(context.Background(), "uid=user,dc=example,dc=org"); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Errorf("writes off: %v", err)
	}
}
