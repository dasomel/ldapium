package ldapclient

import (
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
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

func TestEntryToDomainEntry_RedactsUserPasswordWithAttributeOptions(t *testing.T) {
	// "userPassword;binary" and "userPassword;lang-en" (RFC 4512 attribute
	// options) are distinct attribute descriptions from bare
	// "userPassword", not aliases of it -- a naive exact-match denylist
	// lookup on the full name would let either straight through, handing a
	// real hash back to the DIT browser from a root/admin bind that
	// bypasses ACLs entirely. The base type, ignoring options, must still
	// be redacted.
	e := ldap.NewEntry("uid=jdoe,ou=people,dc=example,dc=com", map[string][]string{
		"uid":                 {"jdoe"},
		"userPassword;binary": {"{ARGON2}$argon2id$v=19$m=7168,t=5,p=1$salt$hash"},
	})

	got := entryToDomainEntry(e)

	if _, present := got.Attributes["userPassword;binary"]; present {
		t.Error("Attributes contains userPassword;binary, want it redacted")
	}
	if len(got.Attributes) != 1 {
		t.Errorf("Attributes = %v, want only uid to survive redaction", got.Attributes)
	}
	if _, present := got.Attributes["uid"]; !present {
		t.Error("Attributes missing uid, want it preserved")
	}
}

func TestBuildMoveRequest_Valid(t *testing.T) {
	dn := "uid=jdoe,ou=people,dc=example,dc=org"
	newParent := "ou=engineering,dc=example,dc=org"

	req, err := buildMoveRequest(dn, newParent)
	if err != nil {
		t.Fatalf("buildMoveRequest(%q, %q) unexpected error: %v", dn, newParent, err)
	}

	if req.DN != dn {
		t.Errorf("req.DN = %q, want %q", req.DN, dn)
	}
	if req.NewRDN != "uid=jdoe" {
		t.Errorf("req.NewRDN = %q, want %q", req.NewRDN, "uid=jdoe")
	}
	if !req.DeleteOldRDN {
		t.Errorf("req.DeleteOldRDN = %v, want true", req.DeleteOldRDN)
	}
	if req.NewSuperior != newParent {
		t.Errorf("req.NewSuperior = %q, want %q", req.NewSuperior, newParent)
	}
}

// buildMoveRequest's newRDN must come from RelativeDN.String() (which
// re-escapes and re-joins the parsed RDN) rather than a naive
// Type+"="+Value reassembly: ldap.ParseDN decodes "\," "\+" etc into
// their literal characters, so rebuilding without re-escaping would emit a
// newRDN with the RDN/multi-value separators unescaped, corrupting the
// ModifyDN request's DN syntax.
func TestBuildMoveRequest_PreservesEscapedAndMultiValuedRDN(t *testing.T) {
	cases := []struct {
		name       string
		dn         string
		wantNewRDN string
	}{
		{
			name:       "escaped comma in value",
			dn:         `uid=Doe\, Jane,ou=people,dc=example,dc=org`,
			wantNewRDN: `uid=Doe\, Jane`,
		},
		{
			name:       "escaped plus in value",
			dn:         `cn=A\+B,ou=people,dc=example,dc=org`,
			wantNewRDN: `cn=A\+B`,
		},
		{
			name: "multi-valued RDN is preserved (and its attributes " +
				"normalized into sorted order by the underlying library)",
			dn:         "ou=Eng+cn=Doc,dc=example,dc=org",
			wantNewRDN: "cn=Doc+ou=Eng",
		},
	}

	newParent := "ou=engineering,dc=example,dc=org"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := buildMoveRequest(tc.dn, newParent)
			if err != nil {
				t.Fatalf("buildMoveRequest(%q, %q) unexpected error: %v", tc.dn, newParent, err)
			}
			if req.DN != tc.dn {
				t.Errorf("req.DN = %q, want %q", req.DN, tc.dn)
			}
			if req.NewRDN != tc.wantNewRDN {
				t.Errorf("req.NewRDN = %q, want %q", req.NewRDN, tc.wantNewRDN)
			}
			if !req.DeleteOldRDN {
				t.Errorf("req.DeleteOldRDN = %v, want true", req.DeleteOldRDN)
			}
			if req.NewSuperior != newParent {
				t.Errorf("req.NewSuperior = %q, want %q", req.NewSuperior, newParent)
			}
		})
	}
}

func TestBuildMoveRequest_RejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name      string
		dn        string
		newParent string
	}{
		{"empty dn", "", "ou=engineering,dc=example,dc=org"},
		{"empty new parent", "uid=jdoe,ou=people,dc=example,dc=org", ""},
		{"malformed dn", "not-a-dn", "ou=engineering,dc=example,dc=org"},
		{"malformed new parent", "uid=jdoe,ou=people,dc=example,dc=org", "not-a-dn"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildMoveRequest(tc.dn, tc.newParent)
			if err == nil {
				t.Fatalf("buildMoveRequest(%q, %q) expected error, got nil", tc.dn, tc.newParent)
			}
			if !errors.Is(err, domain.ErrInvalidInput) {
				t.Errorf("err = %v, want wrapping domain.ErrInvalidInput", err)
			}
		})
	}
}
