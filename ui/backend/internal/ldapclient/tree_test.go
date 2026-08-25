package ldapclient

import (
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// The tree browser probes for children with a one-entry search, so a node
// with two or more children answers "size limit exceeded" instead of
// returning entries. These cover that the probe reads such an answer as
// "has children" rather than as a failure.
func TestHasChildrenFromProbe(t *testing.T) {
	tests := []struct {
		name    string
		entries int
		err     error
		want    bool
	}{
		{
			name:    "one child returns one entry",
			entries: 1,
			want:    true,
		},
		{
			name: "no children returns nothing",
		},
		{
			name: "two or more children exceed the one-entry limit",
			err:  ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("size limit exceeded")),
			want: true,
		},
		{
			name: "children exist but are unreadable",
			err:  ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("insufficient access")),
		},
		{
			name: "parent vanished between listing and probing",
			err:  ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object")),
		},
		{
			name: "connection failure is not a claim about children",
			err:  errors.New("connection reset"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasChildrenFromProbe(tt.entries, tt.err); got != tt.want {
				t.Errorf("hasChildrenFromProbe(%d, %v) = %v, want %v", tt.entries, tt.err, got, tt.want)
			}
		})
	}
}

func TestEntryToDomainEntry_RedactsUserPassword(t *testing.T) {
	e := ldap.NewEntry("uid=jdoe,ou=people,dc=example,dc=com", map[string][]string{
		"uid":          {"jdoe"},
		"cn":           {"Jane Doe"},
		"userPassword": {"{ARGON2}$argon2id$v=19$m=7168,t=5,p=1$salt$hash"},
	})

	got := entryToDomainEntry(e)

	if _, present := got.Attributes["userPassword"]; present {
		t.Error("Attributes contains userPassword, want it redacted")
	}
	if got.Attributes["uid"][0] != "jdoe" || got.Attributes["cn"][0] != "Jane Doe" {
		t.Errorf("Attributes = %v, want uid/cn preserved alongside the redaction", got.Attributes)
	}
}

func TestEntryToDomainEntry_RedactionIsCaseInsensitive(t *testing.T) {
	// LDAP attribute names are case-insensitive on the wire; a server is
	// free to return "userpassword" or "UserPassword" just as validly as
	// "userPassword", and the redaction must not depend on it picking the
	// one spelling this file happens to compare against elsewhere.
	e := ldap.NewEntry("uid=jdoe,ou=people,dc=example,dc=com", map[string][]string{
		"uid":          {"jdoe"},
		"USERPASSWORD": {"{ARGON2}$argon2id$v=19$m=7168,t=5,p=1$salt$hash"},
	})

	got := entryToDomainEntry(e)

	if len(got.Attributes) != 1 {
		t.Errorf("Attributes = %v, want only uid to survive redaction", got.Attributes)
	}
	if _, present := got.Attributes["uid"]; !present {
		t.Error("Attributes missing uid, want it preserved")
	}
}
