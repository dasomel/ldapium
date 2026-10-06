//go:build live

package ldapclient

import (
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// TestLiveAssertionDelete verifies against a real slapd that go-ldap's DelRequest
// with a critical assertion control (OID 1.3.6.1.1.12) carrying a mismatching
// (entryUUID, entryCSN) answers LDAP result code 122 (assertionFailed) and that
// ldapclient's error mappers (mapErr -> domain.ErrRevisionConflict and
// deleteOutcome -> domain.CreatePartial) classify it as designed.
func TestLiveAssertionDelete(t *testing.T) {
	env := getLiveEnv(t)
	conn := env.conn(t, env.adminDN, env.adminPW)

	dn := "uid=test-assert-del,ou=people," + env.root
	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	add.Attribute("uid", []string{"test-assert-del"})
	add.Attribute("cn", []string{"Test Assert Del"})
	add.Attribute("sn", []string{"Assert"})
	_ = conn.Del(ldap.NewDelRequest(dn, nil))
	if err := conn.Add(add); err != nil {
		t.Fatalf("add: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Del(ldap.NewDelRequest(dn, nil))
	})

	search := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", identityAttrs, nil)
	sr, err := conn.Search(search)
	if err != nil || len(sr.Entries) != 1 {
		t.Fatalf("read: %v", err)
	}
	id := entryToIdentity(sr.Entries[0])

	// 1. Mismatching entryCSN assertion Delete
	staleCSN := "20200101000000.000000Z#000000#000#000000"
	ctrls, err := identityControls(id.UUID, staleCSN)
	if err != nil {
		t.Fatalf("identityControls: %v", err)
	}

	delReq := ldap.NewDelRequest(dn, ctrls)
	err = conn.Del(delReq)
	if err == nil {
		t.Fatal("expected assertion error, got nil")
	}

	var le *ldap.Error
	if !errors.As(err, &le) {
		t.Fatalf("expected *ldap.Error, got %T: %v", err, err)
	}
	if le.ResultCode != ldap.LDAPResultAssertionFailed {
		t.Fatalf("expected result code 122 (assertionFailed), got %v", le.ResultCode)
	}

	// Verify API mapping in ldapclient:
	mapped := mapErr("delete user", err)
	if !errors.Is(mapped, domain.ErrRevisionConflict) {
		t.Fatalf("mapErr returned %v, want ErrRevisionConflict", mapped)
	}

	// Verify create compensation outcome mapping:
	outcome := deleteOutcome(err)
	if outcome != domain.CreatePartial {
		t.Fatalf("deleteOutcome returned %v, want CreatePartial", outcome)
	}

	// 2. Mismatching entryUUID assertion Delete
	fakeUUID := "00000000-0000-0000-0000-000000000000"
	ctrlsUUID, err := identityControls(fakeUUID, id.CSN)
	if err != nil {
		t.Fatalf("identityControls: %v", err)
	}
	err = conn.Del(ldap.NewDelRequest(dn, ctrlsUUID))
	if err == nil {
		t.Fatal("expected assertion error with fake UUID, got nil")
	}
	if !errors.As(err, &le) || le.ResultCode != ldap.LDAPResultAssertionFailed {
		t.Fatalf("expected result code 122, got %v", err)
	}

	// 3. Entry still survives the mismatching deletes
	sr2, err := conn.Search(search)
	if err != nil || len(sr2.Entries) != 1 {
		t.Fatal("entry was unexpectedly removed by failed assertion delete")
	}

	// 4. Matching assertion Delete succeeds
	matchCtrls, err := identityControls(id.UUID, id.CSN)
	if err != nil {
		t.Fatalf("identityControls matching: %v", err)
	}
	if err := conn.Del(ldap.NewDelRequest(dn, matchCtrls)); err != nil {
		t.Fatalf("matching delete: %v", err)
	}

	// 5. Entry is gone
	sr3, err := conn.Search(search)
	if err == nil && len(sr3.Entries) > 0 {
		t.Fatal("entry should be deleted")
	}
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		t.Fatalf("post-delete search failed with an unexpected error (not NoSuchObject): %v", err)
	}
}
