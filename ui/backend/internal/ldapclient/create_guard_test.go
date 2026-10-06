package ldapclient

import (
	"errors"
	"slices"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

// The guard that runs BEFORE the password step: an untrusted entry (edited by
// another administrator, replaced, unreadable) must skip the password and
// delete nothing, and must say so with identity_changed.
func TestIdentityGuard(t *testing.T) {
	if err := identityGuard("uid=a,dc=x", goodIdentity(), nil, adminDN); err != nil {
		t.Fatalf("trusted identity rejected: %v", err)
	}
	other := goodIdentity()
	other.Modifier = "cn=other,dc=example,dc=org"
	for name, tc := range map[string]struct {
		id      entryIdentity
		readErr error
	}{
		"other modifier": {other, nil},
		"read failed":    {goodIdentity(), errors.New("no access")},
	} {
		err := identityGuard("uid=a,dc=x", tc.id, tc.readErr, adminDN)
		var ce *domain.CreateError
		if !errors.As(err, &ce) || ce.State != domain.CreateIdentityChanged || ce.DN != "uid=a,dc=x" {
			t.Errorf("%s: err = %v, want CreateError identity_changed", name, err)
		}
	}
}

func TestDeleteOutcome(t *testing.T) {
	cases := map[string]struct {
		err  error
		want domain.CreateState
	}{
		"deleted":          {nil, domain.CreateRolledBack},
		"assertion failed": {ldap.NewError(ldap.LDAPResultAssertionFailed, errors.New("x")), domain.CreatePartial},
		"no such object":   {ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("x")), domain.CreatePartial},
		"lost response":    {ldap.NewError(ldap.ErrorNetwork, errors.New("eof")), domain.CreateUnknown},
		"plain error":      {errors.New("boom"), domain.CreateUnknown},
	}
	for name, tc := range cases {
		if got := deleteOutcome(tc.err); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}

func TestIdentityReadRequestsModifierAndTimestamps(t *testing.T) {
	for _, want := range []string{"modifiersName", "createTimestamp", "modifyTimestamp"} {
		if !slices.Contains(identityAttrs, want) {
			t.Errorf("identity read does not request %s", want)
		}
	}
}
