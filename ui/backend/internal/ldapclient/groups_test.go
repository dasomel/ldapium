package ldapclient

import (
	"context"
	"errors"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

func TestCreateGroup_InvalidCNIsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		cn   string
	}{
		{
			// A blank cn cannot name a group and must fail before LDAP sees an
			// ambiguous add request.
			name: "empty cn",
		},
		{
			// Invalid UTF-8 cannot round-trip through ldap.EscapeDN, so reject
			// it before a malformed RDN can be sent to the directory.
			name: "invalid UTF-8 cn",
			cn:   string([]byte{0xff, 0xfe, 0x80}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &client{}
			_, err := c.CreateGroup(context.Background(), "ou=groups,dc=example,dc=com", domain.GroupInput{CN: tt.cn})
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Errorf("CreateGroup() error = %v, want domain.ErrInvalidInput", err)
			}
		})
	}
}

func TestBuildGroupDN_InvalidUTF8(t *testing.T) {
	tests := []struct {
		name string
		cn   string
	}{
		{
			// Invalid byte sequences cannot survive ldap.EscapeDN's rune-based
			// encoding, so accepting them would change the group being named.
			name: "invalid byte sequence",
			cn:   string([]byte{0xff, 0xfe, 0x80}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildGroupDN(tt.cn, "ou=groups,dc=example,dc=com")
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Errorf("buildGroupDN() error = %v, want domain.ErrInvalidInput", err)
			}
		})
	}
}
