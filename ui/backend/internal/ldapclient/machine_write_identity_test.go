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

// D379-8/D379-17: memberOf values are compared as parsed DNs, attribute names
// case-insensitively, and anything that cannot be read or parsed is a denial.
func TestMemberOfPrivileged(t *testing.T) {
	const admins = "cn=admins,ou=people,dc=example,dc=org"
	privileged := []string{admins, "cn=ops,ou=people,dc=example,dc=org"}
	entry := func(name string, values ...string) *ldap.Entry {
		return ldap.NewEntry("uid=bob,ou=people,dc=example,dc=org", map[string][]string{name: values})
	}
	for name, tc := range map[string]struct {
		entry  *ldap.Entry
		denied bool
	}{
		"attribute absent":    {ldap.NewEntry("uid=bob,ou=people,dc=example,dc=org", nil), false},
		"other group":         {entry("memberOf", "cn=team,ou=people,dc=example,dc=org"), false},
		"privileged":          {entry("memberOf", admins), true},
		"lower-case name":     {entry("memberof", admins), true},
		"upper-case name":     {entry("MEMBEROF", admins), true},
		"mixed-case name":     {entry("MemberOf", admins), true},
		"second privileged":   {entry("memberOf", "cn=team,ou=people,dc=example,dc=org", "cn=ops,ou=people,dc=example,dc=org"), true},
		"upper case value":    {entry("memberOf", "CN=ADMINS,OU=People,DC=example,DC=org"), true},
		"OID type":            {entry("memberOf", "2.5.4.3=admins,ou=people,dc=example,dc=org"), true},
		"other type":          {entry("memberOf", "o=elsewhere,dc=example,dc=org"), true},
		"escaped":             {entry("memberOf", `cn=adm\69ns,ou=people,dc=example,dc=org`), true},
		"child of privileged": {entry("memberOf", "cn=sub,cn=admins,ou=people,dc=example,dc=org"), false},
		"unparseable":         {entry("memberOf", "not a dn"), true},
	} {
		err := memberOfPrivileged(tc.entry, privileged)
		if tc.denied != errors.Is(err, domain.ErrPermissionDenied) || (!tc.denied && err != nil) {
			t.Errorf("%s: %v, denied=%v", name, err, tc.denied)
		}
	}
	if err := memberOfPrivileged(entry("memberOf", admins), []string{"not a dn"}); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Errorf("unparseable privileged group: %v", err)
	}
}

// D379-17: the group side positively proves readability. A hidden member list
// (empty answer) is a denial, never "not a member".
func TestGroupListsMember(t *testing.T) {
	const bob = "uid=bob,ou=people,dc=example,dc=org"
	group := func(name string, values ...string) *ldap.Entry {
		return ldap.NewEntry("cn=admins,ou=people,dc=example,dc=org", map[string][]string{name: values})
	}
	for name, tc := range map[string]struct {
		group  *ldap.Entry
		denied bool
	}{
		"others only":      {group("member", "uid=alice,ou=people,dc=example,dc=org"), false},
		"listed":           {group("member", "uid=alice,ou=people,dc=example,dc=org", bob), true},
		"upper case DN":    {group("member", "UID=BOB,OU=People,DC=example,DC=org"), true},
		"lower-case name":  {group("member", bob), true},
		"mixed-case name":  {group("Member", bob), true},
		"attribute hidden": {ldap.NewEntry("cn=admins,ou=people,dc=example,dc=org", nil), true},
		"empty value list": {group("member"), true},
		"unparseable":      {group("member", "not a dn"), true},
	} {
		err := groupListsMember(tc.group, bob)
		if tc.denied != errors.Is(err, domain.ErrPermissionDenied) || (!tc.denied && err != nil) {
			t.Errorf("%s: %v, denied=%v", name, err, tc.denied)
		}
	}
}

func TestCheckNotPrivilegedRejectsBeforeDial(t *testing.T) {
	cfg := config.Config{LDAPURL: "ldap://127.0.0.1:1", BaseDN: "dc=example,dc=org", Machine: config.MachineConfig{Enabled: true, WriteEnabled: true, BindDN: "cn=reader,dc=example,dc=org"}}
	cfg.Machine.Write.PrivilegedGroups = []string{"cn=admins,dc=example,dc=org"}
	for _, raw := range []string{"userid=user,dc=example,dc=org", "uid=#040475736572,dc=example,dc=org", "dc=", ""} {
		if err := NewWriteIdentityReader(cfg, nil).CheckNotPrivileged(context.Background(), raw); !errors.Is(err, domain.ErrPermissionDenied) {
			t.Errorf("%q dialed or passed: %v", raw, err)
		}
	}
	// An empty privileged list denies instead of passing everyone (D379-17).
	cfg.Machine.Write.PrivilegedGroups = nil
	if err := NewWriteIdentityReader(cfg, nil).CheckNotPrivileged(context.Background(), "uid=user,dc=example,dc=org"); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Errorf("empty privileged list dialed or passed: %v", err)
	}
	cfg.Machine.Write.PrivilegedGroups = []string{"cn=admins,dc=example,dc=org"}
	cfg.Machine.WriteEnabled = false
	if err := NewWriteIdentityReader(cfg, nil).CheckNotPrivileged(context.Background(), "uid=user,dc=example,dc=org"); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Errorf("writes off: %v", err)
	}
}

// v2c T-020 (T020-D5): with the cred compartment on, W_cred is denied lexically
// before any dial and is not a protected identity resolved on every write, so
// data and lock writes never depend on the W_cred entry existing.
func TestWriteIdentityCredDeniedLexicallyNotResolved(t *testing.T) {
	const cred = "cn=cred,ou=system,dc=example,dc=org"
	cfg := config.Config{LDAPURL: "ldap://127.0.0.1:1", BaseDN: "dc=example,dc=org", Machine: config.MachineConfig{Enabled: true, WriteEnabled: true, BindDN: "cn=reader,dc=example,dc=org"}}
	cfg.Machine.Write.CredEnabled = true
	cfg.Machine.Write.Cred = config.MachineWriteIdentity{BindDN: cred, BindPassword: "private-cred"}
	r := NewWriteIdentityReader(cfg, []string{"cn=writer,ou=system,dc=example,dc=org"})
	for _, p := range r.protected {
		if strings.EqualFold(p, cred) {
			t.Fatal("W_cred is resolved on every write")
		}
	}
	for _, target := range []string{cred, "CN=CRED,OU=SYSTEM,DC=EXAMPLE,DC=ORG", "uid=x," + cred} {
		if err := r.Check(context.Background(), target, "inetOrgPerson"); !errors.Is(err, domain.ErrPermissionDenied) {
			t.Errorf("%s: %v, want a denial before dial", target, err)
		}
	}
	// Any other target reaches the directory (here: the closed port), not a denial.
	if err := r.Check(context.Background(), "uid=bob,ou=people,dc=example,dc=org", "inetOrgPerson"); !errors.Is(err, errWriteIdentityDirectory) {
		t.Fatalf("ordinary target = %v, want the dial failure", err)
	}
	// Off: the DN is not special.
	cfg.Machine.Write.CredEnabled = false
	if err := NewWriteIdentityReader(cfg, nil).Check(context.Background(), cred, "inetOrgPerson"); !errors.Is(err, errWriteIdentityDirectory) {
		t.Fatalf("cred off = %v, want the dial failure", err)
	}
}
