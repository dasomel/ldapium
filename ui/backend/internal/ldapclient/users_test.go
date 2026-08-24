package ldapclient

import (
	"reflect"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestEntryToUser_MapsMemberOf(t *testing.T) {
	e := ldap.NewEntry("uid=jdoe,ou=people,dc=example,dc=com", map[string][]string{
		"uid": {"jdoe"},
		"cn":  {"Jane Doe"},
		"sn":  {"Doe"},
		"memberOf": {
			"cn=Admins,ou=groups,dc=example,dc=com",
			"cn=Devs,ou=groups,dc=example,dc=com",
		},
	})

	u := entryToUser(e)

	want := []string{
		"cn=Admins,ou=groups,dc=example,dc=com",
		"cn=Devs,ou=groups,dc=example,dc=com",
	}
	if !reflect.DeepEqual(u.MemberOf, want) {
		t.Errorf("MemberOf = %v, want %v", u.MemberOf, want)
	}
}

func TestEntryToUser_NoMemberOf(t *testing.T) {
	e := ldap.NewEntry("uid=jdoe,ou=people,dc=example,dc=com", map[string][]string{
		"uid": {"jdoe"},
		"cn":  {"Jane Doe"},
		"sn":  {"Doe"},
	})

	u := entryToUser(e)

	if len(u.MemberOf) != 0 {
		t.Errorf("MemberOf = %v, want empty", u.MemberOf)
	}
}

func TestEntryToUser_MapsOrganizationalMetadata(t *testing.T) {
	e := ldap.NewEntry("uid=jdoe,ou=people,dc=example,dc=com", map[string][]string{
		"uid":              {"jdoe"},
		"cn":               {"Jane Doe"},
		"sn":               {"Doe"},
		"departmentNumber": {"4021"},
		"o":                {"Example Corp"},
		"ou":               {"Engineering"},
	})

	u := entryToUser(e)

	if u.Department != "4021" {
		t.Errorf("Department = %q, want %q", u.Department, "4021")
	}
	if u.Organization != "Example Corp" {
		t.Errorf("Organization = %q, want %q", u.Organization, "Example Corp")
	}
	if u.OrganizationalUnit != "Engineering" {
		t.Errorf("OrganizationalUnit = %q, want %q", u.OrganizationalUnit, "Engineering")
	}
}

func TestEntryToUser_NoOrganizationalMetadata(t *testing.T) {
	e := ldap.NewEntry("uid=jdoe,ou=people,dc=example,dc=com", map[string][]string{
		"uid": {"jdoe"},
		"cn":  {"Jane Doe"},
		"sn":  {"Doe"},
	})

	u := entryToUser(e)

	if u.Department != "" || u.Organization != "" || u.OrganizationalUnit != "" {
		t.Errorf("expected empty organizational fields, got Department=%q Organization=%q OrganizationalUnit=%q",
			u.Department, u.Organization, u.OrganizationalUnit)
	}
}

func TestUserAttrs_RequestsOrganizationalMetadata(t *testing.T) {
	for _, want := range []string{"departmentNumber", "o", "ou"} {
		found := false
		for _, a := range userAttrs {
			if a == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("userAttrs = %v, want it to include %q", userAttrs, want)
		}
	}
}

func TestReplaceOrClear(t *testing.T) {
	mod := ldap.NewModifyRequest("uid=jdoe,ou=people,dc=example,dc=com", nil)
	replaceOrClear(mod, "mail", "jdoe@example.com")
	replaceOrClear(mod, "departmentNumber", "")

	if len(mod.Changes) != 2 {
		t.Fatalf("Changes = %v, want exactly two", mod.Changes)
	}

	set, clear := mod.Changes[0], mod.Changes[1]
	if set.Operation != ldap.ReplaceAttribute || set.Modification.Type != "mail" ||
		len(set.Modification.Vals) != 1 || set.Modification.Vals[0] != "jdoe@example.com" {
		t.Errorf("set change = %+v, want Replace mail=[jdoe@example.com]", set)
	}

	// The regression this covers: an earlier version used Delete here,
	// which requires the attribute to already be present on the entry and
	// fails ("no such attribute") otherwise — verified live against a
	// running server before this test was written. Replace with zero
	// values succeeds either way (RFC 4511), which is why this asserts
	// Operation == ReplaceAttribute, not DeleteAttribute.
	if clear.Operation != ldap.ReplaceAttribute {
		t.Errorf("clear change Operation = %v, want ReplaceAttribute (not Delete — see comment)", clear.Operation)
	}
	if clear.Modification.Type != "departmentNumber" {
		t.Errorf("clear change Modification.Type = %q, want %q", clear.Modification.Type, "departmentNumber")
	}
	if len(clear.Modification.Vals) != 0 {
		t.Errorf("clear change Modification.Vals = %v, want none", clear.Modification.Vals)
	}
}

func TestUserAttrs_RequestsMemberOfExplicitly(t *testing.T) {
	// memberOf is an operational attribute computed by the memberof
	// overlay; it is never returned by a "*" wildcard and must be listed
	// by name, same as any other attribute requested here.
	found := false
	for _, a := range userAttrs {
		if a == "memberOf" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("userAttrs = %v, want it to include \"memberOf\"", userAttrs)
	}
}

func TestUserAttrs_RequestsPwdAccountLockedTimeExplicitly(t *testing.T) {
	found := false
	for _, a := range userAttrs {
		if a == "pwdAccountLockedTime" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("userAttrs = %v, want it to include \"pwdAccountLockedTime\"", userAttrs)
	}
}

func TestEntryToUser_Locked_WithTimestamp(t *testing.T) {
	e := ldap.NewEntry("uid=jdoe,ou=people,dc=example,dc=com", map[string][]string{
		"uid":                  {"jdoe"},
		"cn":                   {"Jane Doe"},
		"sn":                   {"Doe"},
		"pwdAccountLockedTime": {"20260812091501Z"},
	})

	u := entryToUser(e)

	if !u.Locked {
		t.Error("Locked = false, want true")
	}
	if u.LockedAt == nil {
		t.Fatal("LockedAt = nil, want a parsed timestamp")
	}
	want := time.Date(2026, 8, 12, 9, 15, 1, 0, time.UTC)
	if !u.LockedAt.Equal(want) {
		t.Errorf("LockedAt = %v, want %v", u.LockedAt, want)
	}
}

func TestEntryToUser_Locked_IndefiniteSentinel(t *testing.T) {
	// Still locked even though the sentinel value doesn't parse as a
	// timestamp — Locked must come from the attribute's presence, not from
	// parseLDAPGeneralizedTime succeeding.
	e := ldap.NewEntry("uid=jdoe,ou=people,dc=example,dc=com", map[string][]string{
		"uid":                  {"jdoe"},
		"cn":                   {"Jane Doe"},
		"sn":                   {"Doe"},
		"pwdAccountLockedTime": {"000001010000Z"},
	})

	u := entryToUser(e)

	if !u.Locked {
		t.Error("Locked = false, want true")
	}
	if u.LockedAt != nil {
		t.Errorf("LockedAt = %v, want nil for an unparseable sentinel value", u.LockedAt)
	}
}

func TestEntryToUser_NotLocked(t *testing.T) {
	e := ldap.NewEntry("uid=jdoe,ou=people,dc=example,dc=com", map[string][]string{
		"uid": {"jdoe"},
		"cn":  {"Jane Doe"},
		"sn":  {"Doe"},
	})

	u := entryToUser(e)

	if u.Locked {
		t.Error("Locked = true, want false when pwdAccountLockedTime is absent")
	}
	if u.LockedAt != nil {
		t.Errorf("LockedAt = %v, want nil", u.LockedAt)
	}
}

func TestUnlockModify_DeletesOnlyPwdAccountLockedTime(t *testing.T) {
	dn := "uid=jdoe,ou=people,dc=example,dc=com"
	mod := unlockModify(dn)

	if mod.DN != dn {
		t.Errorf("DN = %q, want %q", mod.DN, dn)
	}
	if len(mod.Changes) != 1 {
		t.Fatalf("Changes = %v, want exactly one change", mod.Changes)
	}

	change := mod.Changes[0]
	if change.Operation != ldap.DeleteAttribute {
		t.Errorf("Operation = %v, want DeleteAttribute", change.Operation)
	}
	if change.Modification.Type != "pwdAccountLockedTime" {
		t.Errorf("Modification.Type = %q, want %q", change.Modification.Type, "pwdAccountLockedTime")
	}
	// Deleting with no values removes the attribute outright, regardless
	// of its current value — we don't know or care what the timestamp is.
	if len(change.Modification.Vals) != 0 {
		t.Errorf("Modification.Vals = %v, want none", change.Modification.Vals)
	}

	// The one thing this function must never do: pwdFailureTime is
	// NO-USER-MODIFICATION, and slapd rejects the whole (atomic) modify —
	// unlocking nothing — if it's included alongside the lock delete. See
	// the unlockModify doc comment for the exact server error.
	for _, c := range mod.Changes {
		if c.Modification.Type == "pwdFailureTime" {
			t.Error("unlockModify must not touch pwdFailureTime")
		}
	}
}
