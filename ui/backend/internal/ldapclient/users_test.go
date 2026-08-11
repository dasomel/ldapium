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
