package ldapclient

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

const fuzzDNBase = "ou=people,dc=example,dc=com"

var ldapEscapingFuzzSeeds = []string{
	"",
	"*",
	"(",
	")",
	"\\",
	"\x00",
	",",
	"+",
	"\"",
	"<",
	">",
	";",
	" leading space",
	"trailing space ",
	strings.Repeat("a", 4096),
	string([]byte{0xff, 0xfe, 0x80}),
	"*)(uid=*))(|(uid=*",
	"admin)(&)",
}

func FuzzLDAPInputEscaping(f *testing.F) {
	for _, seed := range ldapEscapingFuzzSeeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		filter, err := BuildUserFilter("(uid=%s)", input)
		if input == "" {
			if err == nil {
				t.Fatal("BuildUserFilter() error = nil for an empty uid")
			}
		} else if err != nil {
			t.Fatalf("BuildUserFilter() unexpected error: %v", err)
		} else {
			if _, err := ldap.CompileFilter(filter); err != nil {
				t.Fatalf("ldap.CompileFilter(%q) error = %v", filter, err)
			}
			assertEscapedFilterValue(t, filter)
		}

		userDN, err := buildUserDN(input, fuzzDNBase)
		assertEscapedDN(t, userDN, err, "uid", input)

		groupDN, err := buildGroupDN(input, fuzzDNBase)
		assertEscapedDN(t, groupDN, err, "cn", input)
	})
}

func assertEscapedFilterValue(t *testing.T, filter string) {
	t.Helper()

	value := strings.TrimSuffix(strings.TrimPrefix(filter, "(uid="), ")")
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\\':
			// A literal backslash is only safe in a filter assertion value
			// when it introduces a two-digit RFC 4515 escape sequence.
			if i+2 >= len(value) || !isHex(value[i+1]) || !isHex(value[i+2]) {
				t.Fatalf("filter value %q contains an invalid escape", value)
			}
			i += 2
		case '(', ')', '*', 0:
			t.Fatalf("filter value %q contains an unescaped LDAP metacharacter", value)
		default:
			if value[i] >= 0x80 {
				t.Fatalf("filter value %q contains an unescaped non-ASCII byte", value)
			}
		}
	}
}

func assertEscapedDN(t *testing.T, dn string, err error, attribute, wantValue string) {
	t.Helper()
	if err != nil {
		if !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatalf("DN builder error = %v, want domain.ErrInvalidInput", err)
		}
		return
	}

	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		t.Fatalf("ldap.ParseDN(%q) error = %v", dn, err)
	}
	if len(parsed.RDNs) != 4 {
		t.Fatalf("ldap.ParseDN(%q) has %d RDNs, want 4", dn, len(parsed.RDNs))
	}
	first := parsed.RDNs[0]
	if len(first.Attributes) != 1 || first.Attributes[0].Type != attribute {
		t.Fatalf("ldap.ParseDN(%q) first RDN = %+v, want one %s attribute", dn, first, attribute)
	}
	if got := first.Attributes[0].Value; got != wantValue {
		t.Fatalf("ldap.ParseDN(%q) first RDN %s value = %q, want %q", dn, attribute, got, wantValue)
	}
}

func isHex(b byte) bool {
	return '0' <= b && b <= '9' || 'a' <= b && b <= 'f' || 'A' <= b && b <= 'F'
}
