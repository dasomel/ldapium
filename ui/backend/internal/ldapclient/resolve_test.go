package ldapclient

import (
	"errors"
	"testing"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

func TestLooksLikeDN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"uid=jdoe,ou=people,dc=example,dc=com", true},
		{"cn=Admins,ou=groups,dc=example,dc=com", true},
		{"jdoe", false},
		{"", false},
	}
	for _, c := range cases {
		if got := LooksLikeDN(c.in); got != c.want {
			t.Errorf("LooksLikeDN(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestBuildUserFilter(t *testing.T) {
	f, err := BuildUserFilter("(uid=%s)", "jdoe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f != "(uid=jdoe)" {
		t.Errorf("filter = %q, want (uid=jdoe)", f)
	}
}

func TestBuildUserFilter_EscapesInjection(t *testing.T) {
	f, err := BuildUserFilter("(uid=%s)", "jdoe)(uid=*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f == "(uid=jdoe)(uid=*)" {
		t.Fatalf("filter injection was not escaped: %q", f)
	}
	// The injected "(", ")" and "*" must be hex-encoded, not literal, so
	// they can't reopen/extend the filter expression.
	if want := `(uid=jdoe\29\28uid=\2a)`; f != want {
		t.Errorf("filter = %q, want %q", f, want)
	}
}

func TestBuildUserFilter_InvalidInput(t *testing.T) {
	tests := []struct {
		name     string
		template string
		uid      string
	}{
		{
			// A missing substitution would make every login search the same
			// configured identity instead of the account that was supplied.
			name:     "no placeholder",
			template: "(uid=jdoe)",
			uid:      "jdoe",
		},
		{
			// Reusing the uid in two clauses makes a configuration mistake look
			// valid and violates the one-identity lookup contract.
			name:     "duplicate placeholder",
			template: "(&(uid=%s)(cn=%s))",
			uid:      "jdoe",
		},
		{
			// An unclosed assertion would otherwise be sent to LDAP as a
			// malformed request instead of failing at configuration use.
			name:     "invalid LDAP grammar",
			template: "(uid=%s",
			uid:      "jdoe",
		},
		{
			// A literal fmt escape must not masquerade as a uid placeholder
			// because fmt.Sprintf would silently leave the uid unused.
			name:     "escaped percent is not placeholder",
			template: "(uid=%%s)",
			uid:      "jdoe",
		},
		{
			// Empty input has no account identity to safely substitute.
			name:     "empty uid",
			template: "(uid=%s)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildUserFilter(tt.template, tt.uid)
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Errorf("BuildUserFilter() error = %v, want domain.ErrInvalidInput", err)
			}
		})
	}
}

func TestResolveUID_InvalidFilterInput(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.Config
		uid  string
	}{
		{
			name: "missing filter",
			uid:  "jdoe",
		},
		{
			name: "duplicate uid placeholder",
			cfg:  config.Config{UserSearchFilter: "(&(uid=%s)(cn=%s))"},
			uid:  "jdoe",
		},
		{
			name: "invalid LDAP grammar",
			cfg:  config.Config{UserSearchFilter: "(uid=%s"},
			uid:  "jdoe",
		},
		{
			// A configured search filter without the substitution point would
			// resolve a fixed account regardless of who is logging in.
			name: "filter without uid placeholder",
			cfg:  config.Config{UserSearchFilter: "(uid=jdoe)"},
			uid:  "jdoe",
		},
		{
			// Empty identifiers must fail before a search request can turn an
			// absent value into an LDAP wildcard or a misleading server error.
			name: "empty uid",
			cfg:  config.Config{UserSearchFilter: "(uid=%s)"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveUID(nil, tt.cfg, tt.uid)
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Errorf("resolveUID() error = %v, want domain.ErrInvalidInput", err)
			}
		})
	}
}
