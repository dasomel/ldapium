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
